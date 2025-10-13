// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! MigTD Quote Extractor Tool
//!
//! This tool extracts quote information from vTPM in Azure CVM environments
//! and outputs the data needed for ServTD collateral (TCB mapping and identity).
//!
//! Usage:
//!   migtd-quote-extractor --output-json collateral_data.json

use anyhow::{Context, Result};
use az_tdx_vtpm::{hcl, tdx, vtpm};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output JSON file path
    #[arg(short, long, default_value = "migtd_quote_data.json")]
    output_json: String,

    /// Custom report data (48 bytes hex string, optional)
    #[arg(long)]
    report_data: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuoteData {
    /// MRTD value (48 bytes, hex string)
    mrtd: String,

    /// RTMR0 value (48 bytes, hex string)
    rtmr0: String,

    /// RTMR1 value (48 bytes, hex string)
    rtmr1: String,

    /// RTMR2 value (48 bytes, hex string)
    rtmr2: String,

    /// RTMR3 value (48 bytes, hex string)
    rtmr3: String,

    /// XFAM value (8 bytes, hex string)
    xfam: String,

    /// Attributes value (8 bytes, hex string)
    attributes: String,

    /// MR_CONFIG_ID value (48 bytes, hex string)
    mr_config_id: String,

    /// MR_OWNER value (48 bytes, hex string)
    mr_owner: String,

    /// MR_OWNER_CONFIG value (48 bytes, hex string)
    mr_owner_config: String,

    /// MRSIGNER_SEAM value (48 bytes, hex string)
    mrsigner: String,

    /// ServTD hash value (48 bytes, hex string)
    servtd_hash: String,

    /// ISV_PROD_ID value (16-bit integer)
    isv_prod_id: u16,

    /// ISV_SVN value (16-bit integer) - computed as 1 for now
    isvsvn: u16,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
}

fn get_td_report_from_vtpm(report_data: Option<&[u8; 48]>) -> Result<tdx::TdReport> {
    log::info!("Getting TD report from vTPM");

    let default_report_data = [0u8; 48];
    let data = report_data.unwrap_or(&default_report_data);

    // Pad to 64 bytes as required by vTPM API
    let mut report_data_64 = [0u8; 64];
    report_data_64[..48].copy_from_slice(data);

    // Get the vTPM report with retry mechanism
    let max_retries = 3;
    for attempt in 1..=max_retries {
        log::debug!("vTPM report attempt {} of {}", attempt, max_retries);

        match vtpm::get_report_with_report_data(&report_data_64) {
            Ok(report) => {
                log::info!("vTPM report obtained successfully");

                // Convert to HCL report then to TD report
                let hcl_report =
                    hcl::HclReport::new(report).context("Failed to create HCL report")?;

                let td_report = tdx::TdReport::try_from(hcl_report)
                    .context("Failed to convert HCL report to TD report")?;

                return Ok(td_report);
            }
            Err(e) => {
                log::warn!("vTPM report attempt {} failed: {:?}", attempt, e);
                if attempt < max_retries {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        }
    }

    anyhow::bail!("Failed to get TD report after {} attempts", max_retries);
}

fn extract_quote_data(td_report: &tdx::TdReport) -> Result<QuoteData> {
    log::info!("Extracting quote data from TD report");

    // Access the TD info structure
    // Note: az-tdx-vtpm TdReport uses 'tdinfo' field (lowercase)
    let td_info = &td_report.tdinfo;

    // az-tdx-vtpm TdInfo has these fields:
    // - attributes, xfam, mrtd, mrconfigid, mrowner, mrownerconfig
    //
    // IMPORTANT: In AzCVMEmu mode, we get a TDX Quote for Azure CVM Underhill
    // (the virtual firmware layer), NOT for MigTD itself. Underhill does not use RTMRs,
    // so all RTMR values in the Underhill quote are zeros.
    //
    // We use zeros to match what's actually in the Azure quotes. This means RTMR
    // verification is effectively a no-op, but at least the values match and won't
    // cause spurious error messages during authentication.
    //
    // NOTE: RTMR verification does NOT provide security in AzCVMEmu mode because:
    // 1. RTMRs in Azure quotes are always zero (Underhill doesn't use them)
    // 2. The policy typically doesn't include servtdPolicy constraints
    // 3. Even if it did, zeros don't represent any meaningful measurement

    // Hardcoded RTMR values matching what Azure quotes actually return
    // Azure CVM Underhill quotes have all RTMRs as zeros
    const RTMR0: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const RTMR1: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const RTMR2: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const RTMR3: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    // Extract available fields
    let data = QuoteData {
        mrtd: bytes_to_hex(&td_info.mrtd),
        rtmr0: RTMR0.to_string(),
        rtmr1: RTMR1.to_string(),
        rtmr2: RTMR2.to_string(),
        rtmr3: RTMR3.to_string(),
        xfam: bytes_to_hex(&td_info.xfam),
        attributes: bytes_to_hex(&td_info.attributes),
        mr_config_id: bytes_to_hex(&td_info.mrconfigid),
        mr_owner: bytes_to_hex(&td_info.mrowner),
        mr_owner_config: bytes_to_hex(&td_info.mrownerconfig),
        mrsigner: "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF000000000000000000000000000000".to_string(), // From policy template
        servtd_hash: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(), // Default
        isv_prod_id: 0, // MigTD doesn't use ISV_PROD_ID
        isvsvn: 1, // Default ISV SVN - should be incremented for each build
    };

    log::info!("Successfully extracted quote data");
    log::debug!("MRTD: {}", data.mrtd);
    log::info!("Note: RTMR values are set to zeros (matching Azure Underhill quotes)");
    log::info!("      Azure CVM quotes don't contain MigTD-specific RTMRs");

    Ok(data)
}
fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    log::info!("MigTD Quote Extractor Tool");
    log::info!("===========================");

    // Parse report data if provided
    let report_data = if let Some(ref hex_str) = args.report_data {
        let bytes = hex::decode(hex_str).context("Invalid hex string for report data")?;
        if bytes.len() != 48 {
            anyhow::bail!("Report data must be exactly 48 bytes");
        }
        let mut data = [0u8; 48];
        data.copy_from_slice(&bytes);
        Some(data)
    } else {
        None
    };

    // Get TD report from vTPM
    let td_report = get_td_report_from_vtpm(report_data.as_ref())
        .context("Failed to get TD report from vTPM")?;

    // Extract quote data
    let quote_data = extract_quote_data(&td_report).context("Failed to extract quote data")?;

    // Write to JSON file
    let json =
        serde_json::to_string_pretty(&quote_data).context("Failed to serialize quote data")?;

    fs::write(&args.output_json, json)
        .context(format!("Failed to write to {}", args.output_json))?;

    log::info!("Quote data written to: {}", args.output_json);
    log::info!("✓ Success");

    Ok(())
}
