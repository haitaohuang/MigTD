// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::migration::session::ExchangeInformation;
use core::future::{pending, Future};
use core::task::{Context, Poll, Waker};

struct TestTransport {
    fail_read: bool,
}

impl AsyncRead for TestTransport {
    async fn read(&mut self, _buffer: &mut [u8]) -> async_io::Result<usize> {
        if self.fail_read {
            Err(async_io::ErrorKind::ConnectionAborted.into())
        } else {
            pending().await
        }
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
        let (mut requester, _) = spdm_requester(TestTransport { fail_read }).unwrap();
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
        let (mut responder, _) = spdm_responder(TestTransport { fail_read }).unwrap();
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
        let (mut requester, _) = spdm_requester(TestTransport { fail_read }).unwrap();
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
        let (mut responder, _) = spdm_responder(TestTransport { fail_read }).unwrap();
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
