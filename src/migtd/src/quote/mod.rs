// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Quote generation with retry logic for handling security updates
//!
//! This module provides a resilient GetQuote flow that can handle impactless security
//! updates. If an update happens after the REPORT is retrieved but before the QUOTE
//! is generated, the Quoting Enclave may reject the REPORT. This module handles
//! such scenarios with simple exponential backoff retry.

#![cfg(feature = "attestation")]

use alloc::vec::Vec;

#[cfg(not(feature = "AzCVMEmu"))]
use tdx_tdcall::tdreport::tdcall_report;

#[cfg(feature = "AzCVMEmu")]
use tdx_tdcall_emu::tdreport::tdcall_report;

/// Initial retry delay in milliseconds (5 seconds)
#[cfg(not(feature = "use-mock-quote"))]
const INITIAL_DELAY_MS: u64 = 5000;

/// Maximum number of retry attempts before giving up
const MAX_RETRIES: u32 = 5;

/// Error type for quote generation with retry
#[derive(Debug)]
pub enum QuoteError {
    /// Failed to generate TD report
    ReportGenerationFailed,
    /// Quote generation failed after all retry attempts
    QuoteGenerationFailed,
}

/// Get a quote with retry logic to handle potential security updates
///
/// On quote failure, fetches a new TD REPORT and retries with exponential backoff.
///
/// # Arguments
/// * `additional_data` - The 64-byte additional data to include in the TD REPORT
///
/// # Returns
/// * `Ok((quote, report))` - The generated quote and the TD REPORT used
/// * `Err(QuoteError)` - If TD report generation fails
pub fn get_quote_with_retry(additional_data: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), QuoteError> {
    let mut delay_ms = INITIAL_DELAY_MS;
    let mut last_error = None;

    for attempt in 0..=MAX_RETRIES {
        // Get TD REPORT
        let current_report = tdcall_report(additional_data).map_err(|e| {
            log::error!("Failed to get TD report: {:?}\n", e);
            QuoteError::ReportGenerationFailed
        })?;

        let report_bytes = current_report.as_bytes();

        // Attempt to get quote
        match get_quote_impl(report_bytes) {
            Ok(quote) => {
                log::info!("Quote generated successfully\n");
                return Ok((quote, report_bytes.to_vec()));
            }
            Err(e) => {
                log::warn!(
                    "GetQuote failed (attempt {}/{}): {:?}, retrying with delay of {}ms\n",
                    attempt + 1,
                    MAX_RETRIES + 1,
                    e,
                    delay_ms
                );
                last_error = Some(e);
                delay_milliseconds(delay_ms);
                delay_ms = delay_ms * 2;
            }
        }
    }

    log::error!(
        "GetQuote failed after {} attempts: {:?}\n",
        MAX_RETRIES + 1,
        last_error
    );
    Err(QuoteError::QuoteGenerationFailed)
}

/// Internal function to get quote from TD report
#[cfg(not(feature = "use-mock-quote"))]
fn get_quote_impl(report_bytes: &[u8]) -> Result<Vec<u8>, attestation::Error> {
    attestation::get_quote(report_bytes)
}

#[cfg(feature = "use-mock-quote")]
mod mock_quote_support;

#[cfg(feature = "use-mock-quote")]
use mock_quote_support::{get_quote_impl, INITIAL_DELAY_MS};

/// Delay for the specified number of milliseconds
#[cfg(feature = "AzCVMEmu")]
fn delay_milliseconds(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

#[cfg(not(feature = "AzCVMEmu"))]
fn delay_milliseconds(ms: u64) {
    use crate::driver::ticks::Timer;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use core::time::Duration;
    use td_payload::arch::apic::{disable, enable_and_hlt};

    let mut timer = Timer::after(Duration::from_millis(ms));
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    loop {
        if let Poll::Ready(()) = Pin::new(&mut timer).poll(&mut cx) {
            break;
        }
        enable_and_hlt();
        disable();
    }
}
