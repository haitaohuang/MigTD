// Copyright (c) 2021 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Quote parsing utilities for TD quotes
//!
//! This module provides shared functionality for parsing Intel TDX quotes
//! in both v4 and v5 formats. It's designed to work in both std and no-std
//! environments.

#![cfg_attr(feature = "no-std", no_std)]

use log::{debug, error};

/// Quote header size (48 bytes)
pub const QUOTE_HEADER_SIZE: usize = 48;

/// Quote v4 body size (584 bytes) - sgx_report2_body_t for TDX 1.0
pub const QUOTE_V4_BODY_SIZE: usize = 584;

/// Quote v5 body size for TD Report 1.0 (type=2, 584 bytes)
pub const QUOTE_V5_BODY_SIZE_10: usize = 584;

/// Quote v5 body size for TD Report 1.5 (type=3, 648 bytes)
pub const QUOTE_V5_BODY_SIZE_15: usize = 648;

/// Minimum quote v4 size
pub const MIN_QUOTE_V4_SIZE: usize = QUOTE_HEADER_SIZE + QUOTE_V4_BODY_SIZE + 4;

/// Minimum quote v5 size
pub const MIN_QUOTE_V5_SIZE: usize = QUOTE_HEADER_SIZE + 2 + 4 + QUOTE_V5_BODY_SIZE_10 + 4;

/// SGX Report2 Body structure (584 bytes) for TDX 1.0
///
/// Quote body structure (sgx_report2_body_t from Intel DCAP):
/// - Offset 0:   tee_tcb_svn       [16 bytes]
/// - Offset 16:  mr_seam           [48 bytes]
/// - Offset 64:  mrsigner_seam     [48 bytes]
/// - Offset 112: seam_attributes   [8 bytes]
/// - Offset 120: td_attributes     [8 bytes]
/// - Offset 128: xfam              [8 bytes]
/// - Offset 136: mr_td             [48 bytes]
/// - Offset 184: mr_config_id      [48 bytes]
/// - Offset 232: mr_owner          [48 bytes]
/// - Offset 280: mr_owner_config   [48 bytes]
/// - Offset 328: rt_mr[4]          [192 bytes = 4 x 48]
/// - Offset 520: report_data       [64 bytes]
/// Total: 584 bytes
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SgxReport2Body {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mrsigner_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rt_mr: [[u8; 48]; 4],
    pub report_data: [u8; 64],
}

/// SGX Report2 Body structure for TDX 1.5 (648 bytes)
///
/// Extended version with additional fields:
/// - [v5 only] Offset 584: tee_tcb_svn2  [16 bytes] (for TD preserving)
/// - [v5 only] Offset 600: mr_servicetd  [48 bytes] (service TD hash)
/// Total: 648 bytes
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SgxReport2BodyV15 {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mrsigner_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rt_mr: [[u8; 48]; 4],
    pub report_data: [u8; 64],
    pub tee_tcb_svn2: [u8; 16],
    pub mr_servicetd: [u8; 48],
}

/// Parse quote header to determine version and body location
///
/// Returns: (body_offset, body_size, header_version, tee_type)
pub fn parse_quote_header(quote_data: &[u8]) -> Result<(usize, usize, u16, u32), &'static str> {
    if quote_data.len() < QUOTE_HEADER_SIZE + 2 {
        error!(
            "Quote file too small: {} bytes (expected at least {})",
            quote_data.len(),
            QUOTE_HEADER_SIZE + 2
        );
        return Err("Quote file too small");
    }

    // Parse quote header (48 bytes)
    let header_version = u16::from_le_bytes([quote_data[0], quote_data[1]]);
    let tee_type = u32::from_le_bytes([
        quote_data[4],
        quote_data[5],
        quote_data[6],
        quote_data[7],
    ]);

    debug!(
        "Quote header - version: {}, tee_type: 0x{:02x}",
        header_version, tee_type
    );

    // Determine quote version and parse accordingly
    let (body_offset, body_size) = if header_version == 4 {
        // Quote v4: body starts immediately after header
        if quote_data.len() < MIN_QUOTE_V4_SIZE {
            error!(
                "Quote v4 file too small: {} bytes (expected at least {})",
                quote_data.len(),
                MIN_QUOTE_V4_SIZE
            );
            return Err("Invalid quote v4 file: too small");
        }
        debug!("Parsing Quote v4 format");
        (QUOTE_HEADER_SIZE, QUOTE_V4_BODY_SIZE)
    } else if header_version == 5 {
        // Quote v5: has type and size fields after header
        if quote_data.len() < MIN_QUOTE_V5_SIZE {
            error!(
                "Quote v5 file too small: {} bytes (expected at least {})",
                quote_data.len(),
                MIN_QUOTE_V5_SIZE
            );
            return Err("Invalid quote v5 file: too small");
        }

        let body_type = u16::from_le_bytes([quote_data[48], quote_data[49]]);
        let body_size =
            u32::from_le_bytes([quote_data[50], quote_data[51], quote_data[52], quote_data[53]])
                as usize;

        debug!(
            "Parsing Quote v5 format - body_type: {}, body_size: {}",
            body_type, body_size
        );

        // Body type 2 = TD Report 1.0 (584 bytes), type 3 = TD Report 1.5 (648 bytes)
        let expected_size = match body_type {
            2 => QUOTE_V5_BODY_SIZE_10,
            3 => QUOTE_V5_BODY_SIZE_15,
            _ => {
                error!("Unsupported Quote v5 body type: {}", body_type);
                return Err("Unsupported Quote v5 body type");
            }
        };

        if body_size != expected_size {
            error!(
                "Quote v5 body size mismatch: {} (expected {})",
                body_size, expected_size
            );
            return Err("Invalid Quote v5 body size");
        }

        (QUOTE_HEADER_SIZE + 6, body_size)
    } else {
        error!("Unsupported quote version: {}", header_version);
        return Err("Unsupported quote version");
    };

    Ok((body_offset, body_size, header_version, tee_type))
}

/// Parse quote body and extract report body and servtd_hash
///
/// Returns: (report_body, servtd_hash)
pub fn parse_quote_body(
    quote_data: &[u8],
    body_offset: usize,
    body_size: usize,
    header_version: u16,
) -> Result<(SgxReport2Body, [u8; 48]), &'static str> {
    if body_offset + body_size > quote_data.len() {
        error!("Quote body extends beyond data length");
        return Err("Quote body extends beyond data length");
    }

    // Get report body from quote
    let (report_body, servtd_hash) = if body_size == QUOTE_V5_BODY_SIZE_15 {
        // v5 with TD Report 1.5 (648 bytes) - includes mr_servicetd
        let report_v15 = unsafe {
            &*(quote_data[body_offset..body_offset + body_size].as_ptr()
                as *const SgxReport2BodyV15)
        };
        debug!("Successfully parsed TD quote v5.5 body (648 bytes)");

        // Extract the base report body fields
        let base_body = SgxReport2Body {
            tee_tcb_svn: report_v15.tee_tcb_svn,
            mr_seam: report_v15.mr_seam,
            mrsigner_seam: report_v15.mrsigner_seam,
            seam_attributes: report_v15.seam_attributes,
            td_attributes: report_v15.td_attributes,
            xfam: report_v15.xfam,
            mr_td: report_v15.mr_td,
            mr_config_id: report_v15.mr_config_id,
            mr_owner: report_v15.mr_owner,
            mr_owner_config: report_v15.mr_owner_config,
            rt_mr: report_v15.rt_mr,
            report_data: report_v15.report_data,
        };
        (base_body, report_v15.mr_servicetd)
    } else {
        // v4 or v5 with TD Report 1.0 (584 bytes)
        let report = unsafe {
            &*(quote_data[body_offset..body_offset + body_size].as_ptr() as *const SgxReport2Body)
        };
        debug!(
            "Successfully parsed TD quote v{} body (584 bytes)",
            header_version
        );

        // Copy the struct to move it out of the unsafe block
        let base_body = SgxReport2Body {
            tee_tcb_svn: report.tee_tcb_svn,
            mr_seam: report.mr_seam,
            mrsigner_seam: report.mrsigner_seam,
            seam_attributes: report.seam_attributes,
            td_attributes: report.td_attributes,
            xfam: report.xfam,
            mr_td: report.mr_td,
            mr_config_id: report.mr_config_id,
            mr_owner: report.mr_owner,
            mr_owner_config: report.mr_owner_config,
            rt_mr: report.rt_mr,
            report_data: report.report_data,
        };
        (base_body, [0u8; 48]) // SERVTD_HASH always zero for MigTD
    };

    Ok((report_body, servtd_hash))
}
