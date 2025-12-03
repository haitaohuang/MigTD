// Copyright (c) 2021 Intel Corporation
// Portions Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Shared mock TD report generation for testing purposes
//!
//! This module provides a shared implementation of mock TD report generation
//! that can be used by both the tdx-tdcall emulation layer and the attestation module.

use log::debug;
use original_tdx_tdcall::tdreport::{ReportMac, ReportType, TdInfo, TdxReport, TeeTcbInfo};
use crate::mock_quote_data::QUOTE;
use crate::quote_parser::{parse_quote_body, parse_quote_header};

/// Create a mock TD report from the provided quote data
///
/// This function parses the quote and extracts the necessary fields
/// to construct a TD report structure that matches the quote data.
///
/// # Arguments
/// * `quote_data` - The quote data to parse (can be from QUOTE constant or custom file)
pub fn create_mock_td_report(quote_data: &[u8]) -> TdxReport {
    debug!("Creating mock TD report from quote data ({} bytes)", quote_data.len());

    // Parse the quote using shared quote_parser module
    let (body_offset, body_size, header_version, tee_type) = match parse_quote_header(&quote_data) {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to parse quote header: {}", e);
            panic!("Invalid quote header");
        }
    };

    debug!("Quote header - version: {}, tee_type: 0x{:02x}", header_version, tee_type);

    // Parse quote body using shared quote_parser module
    let (report_body, servtd_hash) = match parse_quote_body(&quote_data, body_offset, body_size, header_version) {
        Ok(result) => result,
        Err(e) => {
            log::error!("Failed to parse quote body: {}", e);
            panic!("Invalid quote body");
        }
    };

    // Create TD report with values from parsed quote body
    let td_report = TdxReport {
        report_mac: ReportMac {
            report_type: ReportType {
                r#type: tee_type as u8,
                subtype: 0x00,
                version: header_version as u8,
                reserved: 0x00,
            },
            reserved0: [0u8; 12],
            cpu_svn: report_body.tee_tcb_svn,
            tee_tcb_info_hash: [0x42; 48], // Mock hash (not in quote)
            tee_info_hash: [0x43; 48],     // Mock hash (not in quote)
            report_data: report_body.report_data,
            reserved1: [0u8; 32],
            mac: [0xBB; 32], // Mock MAC, not used for policy tests
        },
        tee_tcb_info: TeeTcbInfo {
            valid: [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            tee_tcb_svn: report_body.tee_tcb_svn,
            mrseam: report_body.mr_seam,
            mrsigner_seam: report_body.mrsigner_seam,
            attributes: report_body.seam_attributes,
            reserved: [0u8; 111],
        },
        reserved: [0u8; 17],
        td_info: TdInfo {
            attributes: report_body.td_attributes,
            xfam: report_body.xfam,
            mrtd: report_body.mr_td,
            mrconfig_id: report_body.mr_config_id,
            mrowner: report_body.mr_owner,
            mrownerconfig: report_body.mr_owner_config,
            rtmr0: report_body.rt_mr[0],
            rtmr1: report_body.rt_mr[1],
            rtmr2: report_body.rt_mr[2],
            rtmr3: report_body.rt_mr[3],
            servtd_hash: servtd_hash,
            reserved: [0u8; 64],
        },
    };

    debug!("Mock TD report created successfully from quote file");

    td_report
}
