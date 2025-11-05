// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use percent_encoding::percent_decode_str;

use super::{CollateralServiceProvider, Fmspc, PlatformTcbRaw};
use crate::http_client::fetch_data_from_url;

// Azure THIM uses Intel's root CA, so we use the Intel URL
const ROOT_CA_URL: &str = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer";
// Intel PCS URL to fetch FMSPC list
const INTEL_PCS_FMSPC_LIST_URL: &str =
    "https://api.trustedservices.intel.com/sgx/certification/v4/fmspcs";
// Azure THIM uses lowercase header names
const PCK_CRL_ISSUER_CHAIN: &str = "sgx-pck-crl-issuer-chain";
const QE_IDENTITY_ISSUER_CHAIN: &str = "sgx-enclave-identity-issuer-chain";
const TCB_INFO_ISSUER_CHAIN: &str = "tcb-info-issuer-chain";

pub struct AzureThimProvider {
    region: String,
    custom_fmspc_list: Option<Vec<String>>,
}

impl AzureThimProvider {
    pub fn new(region: String, custom_fmspc_list: Option<Vec<String>>) -> Self {
        Self {
            region,
            custom_fmspc_list,
        }
    }

    fn base_url(&self) -> String {
        format!("https://{}.thim.azure.net", self.region)
    }

    fn build_url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url(), path)
    }

    fn fetch_fmspc_list_from_intel(&self) -> Result<Vec<String>> {
        println!("Fetching FMSPC list from Intel PCS...");
        let pcs_response = fetch_data_from_url(INTEL_PCS_FMSPC_LIST_URL)?;
        match pcs_response.response_code {
            200 => {
                let fmspc_list = serde_json::from_slice::<Vec<Fmspc>>(&pcs_response.data)?;
                let tdx_fmspcs: Vec<String> = fmspc_list
                    .iter()
                    .filter(|f| f.is_tdx_supported())
                    .map(|f| f.fmspc.clone())
                    .collect();
                println!("Found {} TDX-supported FMSPCs from Intel", tdx_fmspcs.len());
                Ok(tdx_fmspcs)
            }
            _ => {
                eprintln!(
                    "Error fetching FMSPC list from Intel - {:?}",
                    pcs_response.response_code
                );
                Err(anyhow!("Failed to fetch FMSPC list from Intel PCS"))
            }
        }
    }

    fn get_fmspc_list(&self) -> Result<Vec<String>> {
        if let Some(ref custom_list) = self.custom_fmspc_list {
            Ok(custom_list.clone())
        } else {
            // Fetch from Intel PCS
            self.fetch_fmspc_list_from_intel()
        }
    }
}

impl CollateralServiceProvider for AzureThimProvider {
    fn fetch_pck_crl(&self) -> Result<(Vec<u8>, String)> {
        // Azure THIM uses v3 API for PCK CRL
        let url = self.build_url("sgx/certification/v3/pckcrl?ca=platform");
        let mut pcs_response = fetch_data_from_url(&url)?;
        match pcs_response.response_code {
            200 => {
                println!("Got PCK CRL from Azure THIM");
                let issuer_chain = pcs_response
                    .header_map
                    .remove(PCK_CRL_ISSUER_CHAIN)
                    .ok_or_else(|| anyhow!("Missing PCK CRL issuer chain header"))?;
                Ok((
                    pcs_response.data,
                    percent_decode_str(&issuer_chain).decode_utf8()?.to_string(),
                ))
            }
            _ => {
                eprintln!(
                    "Error fetching PCK CRL from Azure THIM - {:?}",
                    pcs_response.response_code
                );
                Err(anyhow!("AccessException"))
            }
        }
    }

    fn fetch_root_ca(&self) -> Result<Vec<u8>> {
        // Azure THIM doesn't cache root CA, use Intel's directly
        let pcs_response = fetch_data_from_url(ROOT_CA_URL)?;
        match pcs_response.response_code {
            200 => {
                println!("Got root CA from Intel");
                Ok(pcs_response.data)
            }
            _ => {
                eprintln!("Error fetching root CA - {:?}", pcs_response.response_code);
                Err(anyhow!("AccessException"))
            }
        }
    }

    fn fetch_qe_identity(&self) -> Result<(Vec<u8>, String)> {
        let url = self.build_url("tdx/certification/v4/qe/identity");
        let mut pcs_response = fetch_data_from_url(&url)?;
        match pcs_response.response_code {
            200 => {
                println!("Got QE identity from Azure THIM");
                let issuer_chain = pcs_response
                    .header_map
                    .remove(QE_IDENTITY_ISSUER_CHAIN)
                    .ok_or_else(|| anyhow!("Missing QE identity issuer chain header"))?;
                Ok((
                    pcs_response.data,
                    percent_decode_str(&issuer_chain).decode_utf8()?.to_string(),
                ))
            }
            _ => {
                eprintln!(
                    "Error fetching QE identity from Azure THIM - {:?}",
                    pcs_response.response_code
                );
                Err(anyhow!("AccessException"))
            }
        }
    }

    fn get_platform_tcb_list(&self) -> Result<Vec<PlatformTcbRaw>> {
        let fmspc_list = self.get_fmspc_list()?;
        let mut platform_tcb_list = Vec::new();

        println!(
            "Attempting to fetch TCB info for {} FMSPCs from Azure THIM ({})...",
            fmspc_list.len(),
            self.region
        );

        for fmspc in fmspc_list {
            if let Some(raw_tcb) = self.fetch_platform_tcb(&fmspc)? {
                platform_tcb_list.push(PlatformTcbRaw {
                    fmspc: fmspc.clone(),
                    tcb: raw_tcb.0,
                    tcb_issuer_chain: raw_tcb.1,
                });
            }
        }

        if platform_tcb_list.is_empty() {
            println!(
                "Warning: No TCB info available from Azure THIM in {} region.",
                self.region
            );
            println!("This is expected if the region doesn't have TDX platforms deployed yet.");
        } else {
            println!(
                "Successfully fetched TCB info for {} platform(s)",
                platform_tcb_list.len()
            );
        }

        Ok(platform_tcb_list)
    }

    fn fetch_platform_tcb(&self, fmspc: &str) -> Result<Option<(Vec<u8>, String)>> {
        let url = self.build_url(&format!("tdx/certification/v4/tcb?fmspc={}", fmspc));
        let mut pcs_response = fetch_data_from_url(&url)?;

        let result = if pcs_response.response_code == 200 {
            println!("Got TCB info from Azure THIM for fmspc - {}", fmspc);
            let issuer_chain = pcs_response
                .header_map
                .remove(TCB_INFO_ISSUER_CHAIN)
                .ok_or_else(|| anyhow!("Missing TCB info issuer chain header"))?;
            Some((
                pcs_response.data,
                percent_decode_str(&issuer_chain).decode_utf8()?.to_string(),
            ))
        } else if pcs_response.response_code == 404 {
            println!(
                "TCB info not found for fmspc {} (404 - may not be deployed in this region)",
                fmspc
            );
            None
        } else {
            eprintln!(
                "Error fetching TCB info from Azure THIM for fmspc {}: {:?}",
                fmspc, pcs_response.response_code
            );
            None
        };

        Ok(result)
    }
}
