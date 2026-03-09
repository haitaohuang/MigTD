// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Mock quote support for testing the retry logic.
//!
//! All mock overrides are consolidated here so production code in `mod.rs`
//! stays free of test-specific values.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Shorter retry delay for testing (100ms instead of 5s)
pub const INITIAL_DELAY_MS: u64 = 100;

/// Flag to simulate a bad report on first attempt for testing.
static FIRST_ATTEMPT_BAD_REPORT: AtomicBool = AtomicBool::new(true);

/// Get quote implementation with mock support for testing.
/// Fails on the first call, then delegates to the real implementation.
pub fn get_quote_impl(report_bytes: &[u8]) -> Result<Vec<u8>, attestation::Error> {
    if FIRST_ATTEMPT_BAD_REPORT.swap(false, Ordering::Relaxed) {
        log::info!("Simulating bad report failure on first attempt (test mode)\n");
        return Err(attestation::Error::GetQuote);
    }

    attestation::get_quote(report_bytes)
}
