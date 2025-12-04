#![cfg(feature = "no-get-quote")]

use alloc::vec::Vec;
use log::debug;
use tdx_tdcall::tdreport::TdxReport;
use tdx_tdcall_mock_quote::mock_quote_data::QUOTE;

pub fn create_mock_td_report() -> TdxReport {
    // Use shared mock report generation from tdx_tdcall_mock_quote
    tdx_tdcall_mock_quote::mock_report::create_mock_td_report(QUOTE.as_ref())
}

pub fn get_mock_quote(_td_report_data: &[u8]) -> Vec<u8> {
    // Use shared mock quote data from mock_quote_data module
    debug!("Mock quote created with size: {}", QUOTE.len());
    QUOTE.to_vec()
}