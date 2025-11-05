// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;

pub mod intel_pcs;
pub mod azure_thim;

#[derive(Debug)]
pub struct PlatformTcbRaw {
    pub fmspc: String,
    pub tcb: Vec<u8>,
    pub tcb_issuer_chain: String,
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
