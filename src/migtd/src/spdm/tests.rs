// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::migration::session::ExchangeInformation;
use core::future::{pending, Future};
use core::task::{Context, Poll, Waker};
use spdmlib::{
    common::{session::SpdmSessionState, SpdmContext, INVALID_SESSION_ID},
    message::{SpdmMessageHeader, SpdmRequestResponseCode},
    protocol::SpdmVersion,
};

#[derive(Default)]
struct TestTransport {
    fail_read: bool,
    incoming: Vec<u8>,
    offset: usize,
}

impl AsyncRead for TestTransport {
    async fn read(&mut self, buffer: &mut [u8]) -> async_io::Result<usize> {
        if self.fail_read {
            return Err(async_io::ErrorKind::ConnectionAborted.into());
        }
        let size = buffer.len().min(self.incoming.len() - self.offset);
        if size == 0 {
            return pending().await;
        }
        buffer[..size].copy_from_slice(&self.incoming[self.offset..self.offset + size]);
        self.offset += size;
        Ok(size)
    }
}

impl AsyncWrite for TestTransport {
    async fn write(&mut self, buffer: &[u8]) -> async_io::Result<usize> {
        Ok(buffer.len())
    }
}

fn finish_or_cancel<T>(future: impl Future<Output = Result<T, SpdmStatus>>, fail_read: bool) {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    let result = future.as_mut().poll(&mut context);
    if fail_read {
        assert!(matches!(result, Poll::Ready(Err(_))));
    } else {
        assert!(result.is_pending());
    }
    // Dropping a pending exchange is how the outer session timeout cancels it.
}

#[test]
fn requester_migration_app_context_is_wiped_on_cancellation_and_error() {
    for fail_read in [false, true] {
        let (mut requester, _) = spdm_requester(TestTransport {
            fail_read,
            ..Default::default()
        })
        .unwrap();
        requester.common.app_context_data_buffer.fill(0xa5);
        let mig_info = MigtdMigrationInformation::default();
        let exchange_information = ExchangeInformation::default();

        finish_or_cancel(
            spdm_requester_transfer_msk(
                &mut requester,
                &mig_info,
                &exchange_information,
                #[cfg(feature = "policy_v2")]
                Vec::new(),
            ),
            fail_read,
        );

        assert!(requester
            .common
            .app_context_data_buffer
            .iter()
            .all(|byte| *byte == 0));
    }
}

#[test]
fn responder_migration_app_context_is_wiped_on_cancellation_and_error() {
    for fail_read in [false, true] {
        let (mut responder, _) = spdm_responder(TestTransport {
            fail_read,
            ..Default::default()
        })
        .unwrap();
        responder.mig_info_exchanged = true;
        responder
            .responder_context
            .common
            .app_context_data_buffer
            .fill(0xa5);
        let mig_info = MigtdMigrationInformation::default();
        let exchange_information = ExchangeInformation::default();

        finish_or_cancel(
            spdm_responder_transfer_msk(
                &mut responder,
                &mig_info,
                &exchange_information,
                #[cfg(feature = "policy_v2")]
                Vec::new(),
            ),
            fail_read,
        );

        assert!(!responder.mig_info_exchanged);
        assert!(responder
            .responder_context
            .common
            .app_context_data_buffer
            .iter()
            .all(|byte| *byte == 0));
    }
}

#[cfg(all(feature = "policy_v2", feature = "vmcall-raw"))]
#[test]
fn requester_rebind_app_context_is_wiped_on_cancellation_and_error() {
    for fail_read in [false, true] {
        let (mut requester, _) = spdm_requester(TestTransport {
            fail_read,
            ..Default::default()
        })
        .unwrap();
        requester.common.app_context_data_buffer.fill(0xa5);
        let mig_info = MigtdMigrationInformation::default();

        finish_or_cancel(
            spdm_requester_rebind_old(&mut requester, &mig_info, Vec::new()),
            fail_read,
        );

        assert!(requester
            .common
            .app_context_data_buffer
            .iter()
            .all(|byte| *byte == 0));
    }
}

#[cfg(all(feature = "policy_v2", feature = "vmcall-raw"))]
#[test]
fn responder_rebind_app_context_is_wiped_on_cancellation_and_error() {
    for fail_read in [false, true] {
        let (mut responder, _) = spdm_responder(TestTransport {
            fail_read,
            ..Default::default()
        })
        .unwrap();
        responder
            .responder_context
            .common
            .app_context_data_buffer
            .fill(0xa5);
        let mig_info = MigtdMigrationInformation::default();

        finish_or_cancel(
            spdm_responder_rebind_new(&mut responder, &mig_info, Vec::new()),
            fail_read,
        );

        assert!(responder
            .responder_context
            .common
            .app_context_data_buffer
            .iter()
            .all(|byte| *byte == 0));
    }
}

fn assert_teardown_clears_sessions(context: &mut SpdmContext) {
    for last_session_id in [Some(1), None] {
        for cancel in [false, true] {
            context.app_context_data_buffer.fill(0xa5);
            for (index, session) in context.session.iter_mut().enumerate() {
                session.setup(u32::try_from(index + 1).unwrap()).unwrap();
                session.set_session_state(if last_session_id.is_some() {
                    SpdmSessionState::SpdmSessionHandshaking
                } else {
                    SpdmSessionState::SpdmSessionEstablished
                });
                let mut secret = session.get_application_secret();
                secret.request_direction.encryption_key.data.fill(0xa5);
                secret.request_direction.encryption_key.data_size = 32;
                session.set_application_secret(secret);
            }
            // FINISH clears this field without removing the established session.
            context.runtime_info.set_last_session_id(last_session_id);

            for _ in 0..2 {
                let mut future = Box::pin(async {
                    let _guard = AppContextGuard {
                        context: &mut *context,
                        common: |context| context,
                    };
                    if cancel {
                        pending::<()>().await;
                    }
                });
                let mut task_context = Context::from_waker(Waker::noop());
                assert_eq!(future.as_mut().poll(&mut task_context).is_pending(), cancel);
                drop(future);

                assert!(context
                    .app_context_data_buffer
                    .iter()
                    .all(|byte| *byte == 0));
                for session in &context.session {
                    assert_eq!(session.get_session_id(), INVALID_SESSION_ID);
                    assert_eq!(
                        session.get_session_state(),
                        SpdmSessionState::SpdmSessionNotStarted
                    );
                    assert_eq!(session.get_application_secret(), Default::default());
                }
            }
        }
    }
}

#[test]
fn requester_teardown_clears_handshaking_and_established_sessions() {
    let (mut requester, _) = spdm_requester(TestTransport::default()).unwrap();
    assert_teardown_clears_sessions(&mut requester.common);
}

#[test]
fn responder_teardown_clears_handshaking_and_established_sessions() {
    let (mut responder, _) = spdm_responder(TestTransport::default()).unwrap();
    assert_teardown_clears_sessions(&mut responder.responder_context.common);
}

#[test]
fn responder_propagates_malformed_message_error() {
    // GET_VERSION needs a two-byte payload after its header.
    let mut incoming = vec![0u8; VMCALL_SPDM_MESSAGE_HEADER_SIZE + 2];
    let mut writer = Writer::init(&mut incoming);
    vmcall_msg::VmCallMessageHeader {
        version: vmcall_msg::VMCALL_SPDM_VERSION,
        msg_type: vmcall_msg::VmCallMessageType::SpdmMessage,
        length: 2,
    }
    .encode(&mut writer)
    .unwrap();
    SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion10,
        request_response_code: SpdmRequestResponseCode::SpdmRequestGetVersion,
    }
    .encode(&mut writer)
    .unwrap();

    let (mut responder, _) = spdm_responder(TestTransport {
        incoming,
        ..Default::default()
    })
    .unwrap();
    let mig_info = MigtdMigrationInformation::default();
    let exchange_information = ExchangeInformation::default();
    let mut future = Box::pin(spdm_responder_transfer_msk(
        &mut responder,
        &mig_info,
        &exchange_information,
        #[cfg(feature = "policy_v2")]
        Vec::new(),
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Err(SPDM_STATUS_INVALID_MSG_FIELD))
    );
}
