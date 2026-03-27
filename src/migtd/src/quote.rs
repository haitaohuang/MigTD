// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Quote generation with retry logic for handling transient errors
//!
//! This module provides a resilient GetQuote flow that handles two categories
//! of retriable errors:
//! - **Again**: Transient errors (VMCALL_RETRY, IN_FLIGHT) that
//!   should be retried immediately without delay, up to 5 retries.
//! - **Busy**: Service unavailable or error (QUOTE_ERROR, SERVICE_UNAVAILABLE)
//!   that should be retried with exponential backoff (1s initial delay, up to 5 retries).
//! Non-retriable errors cause immediate failure.

#![cfg(feature = "attestation")]

use alloc::vec::Vec;

#[cfg(not(feature = "AzCVMEmu"))]
use tdx_tdcall::tdreport::tdcall_report;

#[cfg(feature = "AzCVMEmu")]
use tdx_tdcall_emu::tdreport::tdcall_report;

/// Initial backoff delay in milliseconds for busy/unavailable errors
#[cfg(not(feature = "AzCVMEmu"))]
const BUSY_INITIAL_DELAY_MS: u64 = 1000;

#[cfg(feature = "AzCVMEmu")]
const BUSY_INITIAL_DELAY_MS: u64 = 20;

/// Maximum number of retries for each error category
const MAX_RETRIES: u32 = 5;

/// Error type for quote generation with retry
#[derive(Debug)]
pub enum QuoteError {
    /// Failed to generate TD report
    ReportGenerationFailed,
    /// Quote generation failed after all retry attempts
    QuoteGenerationFailed,
}

/// Get a quote with retry logic to handle transient and busy errors
///
/// On retriable errors (Again), retries immediately without delay.
/// On busy errors (Busy), retries with exponential backoff starting at 1s.
/// Non-retriable errors cause immediate failure.
///
/// # Arguments
/// * `additional_data` - The 64-byte additional data to include in the TD REPORT
///
/// # Returns
/// * `Ok((quote, report))` - The generated quote and the TD REPORT used
/// * `Err(QuoteError)` - If TD report/quote generation fails
pub fn get_quote_with_retry(additional_data: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), QuoteError> {
    let mut attempt: u32 = 0;
    let mut busy_delay_ms = BUSY_INITIAL_DELAY_MS;

    loop {
        // Get a fresh TD REPORT for each attempt
        let current_report = tdcall_report(additional_data).map_err(|e| {
            log::error!("Failed to get TD report: {:?}\n", e);
            QuoteError::ReportGenerationFailed
        })?;

        let report_bytes = current_report.as_bytes();

        match attestation::get_quote(report_bytes) {
            Ok(quote) => {
                log::info!("Quote generated successfully\n");
                return Ok((quote, report_bytes.to_vec()));
            }
            Err(attestation::Error::Again) => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    log::error!("GetQuote failed after {} attempts\n", MAX_RETRIES);
                    return Err(QuoteError::QuoteGenerationFailed);
                }
                log::warn!(
                    "GetQuote returned Again (attempt {}/{}), retrying immediately\n",
                    attempt,
                    MAX_RETRIES
                );
            }
            Err(attestation::Error::Busy) => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    log::error!("GetQuote failed after {} attempts\n", MAX_RETRIES);
                    return Err(QuoteError::QuoteGenerationFailed);
                }
                log::warn!(
                    "GetQuote returned Busy (attempt {}/{}), retrying in {}ms\n",
                    attempt,
                    MAX_RETRIES,
                    busy_delay_ms
                );
                delay_milliseconds(busy_delay_ms);
                busy_delay_ms *= 2;
            }
            Err(e) => {
                log::error!("GetQuote failed with non-retriable error: {:?}\n", e);
                return Err(QuoteError::QuoteGenerationFailed);
            }
        }
    }
}

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
