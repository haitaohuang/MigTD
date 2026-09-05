// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use crate::{
    migration::MigtdMigrationInformation,
    spdm::{
        handshake::{requester_handshake_prelude, run_responder_message_loop},
        spdm_req::{send_and_receive_sdm_rebind_attest_info, send_and_receive_sdm_rebind_info},
        spdm_rsp::{ResponderContextEx, ResponderContextExInfo},
        PrivateKeyDer, SpdmAppContextData,
    },
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use spdmlib::{error::SpdmStatus, requester::RequesterContext};

pub async fn spdm_requester_rebind_old(
    spdm_requester: &mut RequesterContext,
    rebind_info: &MigtdMigrationInformation,
    peer_data: Vec<u8>,
) -> Result<(), SpdmStatus> {
    let guard = super::AppContextGuard {
        context: spdm_requester,
        buffer: |context| &mut context.common.app_context_data_buffer,
    };
    spdm_requester_rebind_old_inner(guard.context, rebind_info, peer_data).await
}

async fn spdm_requester_rebind_old_inner(
    spdm_requester: &mut RequesterContext,
    rebind_info: &MigtdMigrationInformation,
    peer_data: Vec<u8>,
) -> Result<(), SpdmStatus> {
    let session_id = requester_handshake_prelude(spdm_requester).await?;

    Box::pin(send_and_receive_sdm_rebind_attest_info(
        spdm_requester,
        rebind_info,
        session_id,
        peer_data,
    ))
    .await?;

    Box::pin(spdm_requester.send_receive_spdm_finish(Some(0xff), session_id)).await?;

    Box::pin(send_and_receive_sdm_rebind_info(
        spdm_requester,
        rebind_info,
        Some(session_id),
    ))
    .await?;

    Box::pin(spdm_requester.send_receive_spdm_end_session(session_id)).await?;
    Ok(())
}

pub async fn spdm_responder_rebind_new<'a>(
    spdm_responder_ex: &mut ResponderContextEx<'a>,
    rebind_info: &'a MigtdMigrationInformation,
    peer_data: Vec<u8>,
) -> Result<(), SpdmStatus> {
    let guard = super::AppContextGuard {
        context: spdm_responder_ex,
        buffer: |context| &mut context.responder_context.common.app_context_data_buffer,
    };
    let spdm_responder_ex = &mut *guard.context;

    spdm_responder_ex.info = ResponderContextExInfo::RebindInformation(rebind_info);

    let app_context = SpdmAppContextData {
        migration_info: MigtdMigrationInformation::default(),
        private_key: PrivateKeyDer::default(),
    };

    run_responder_message_loop(spdm_responder_ex, peer_data, app_context).await
}
