// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use serde::Deserialize;

pub mod azure_thim;
pub mod intel_pcs;

#[derive(Debug)]
pub struct PlatformTcbRaw {
    pub fmspc: String,
    pub tcb: Vec<u8>,
    pub tcb_issuer_chain: String,
}

/// FMSPC information from Intel PCS
#[derive(Debug, Deserialize)]
pub struct Fmspc {
    pub fmspc: String,
    platform: String,
}

impl Fmspc {
    pub fn is_tdx_supported(&self) -> bool {
        // only E5 support TDX at this moment.
        self.platform.as_str() == "E5"
    }
}

/// Trait defining the interface for fetching collaterals from a service provider
pub trait CollateralServiceProvider {
    /// Fetch PCK Certificate Revocation List
    fn fetch_pck_crl(&self) -> Result<(Vec<u8>, String)>;

    /// Fetch root Certificate Authority
    fn fetch_root_ca(&self) -> Result<Vec<u8>>;

    /// Fetch Quoting Enclave identity
    fn fetch_qe_identity(&self) -> Result<(Vec<u8>, String)>;

    /// Get list of platform TCB information for all supported platforms
    fn get_platform_tcb_list(&self) -> Result<Vec<PlatformTcbRaw>>;

    /// Fetch platform TCB information for a specific FMSPC
    fn fetch_platform_tcb(&self, fmspc: &str) -> Result<Option<(Vec<u8>, String)>>;
}
