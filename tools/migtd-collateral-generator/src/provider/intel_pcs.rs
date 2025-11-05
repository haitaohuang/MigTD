// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Result};
use percent_encoding::percent_decode_str;
use serde::Deserialize;

use crate::http_client::fetch_data_from_url;
use super::{CollateralServiceProvider, PlatformTcbRaw};

const PCS_PROD_URL: &str = "https://api.trustedservices.intel.com/";
const PCS_SBX_URL: &str = "https://sbx.api.trustedservices.intel.com/";
const ROOT_CA_URL: &str = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer";
const ROOT_CA_URL_SBX: &str = "https://sbx-certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer";
const PCK_CRL_ISSUER_CHAIN: &str = "SGX-PCK-CRL-Issuer-Chain";
const QE_IDENTITY_ISSUER_CHAIN: &str = "SGX-Enclave-Identity-Issuer-Chain";
const TCB_INFO_ISSUER_CHAIN: &str = "TCB-Info-Issuer-Chain";

pub struct IntelPcsProvider {
    for_production: bool,
}

impl IntelPcsProvider {
    pub fn new(for_production: bool) -> Self {
        Self { for_production }
    }

    fn build_url(&self, path: &str) -> String {
        let base = if self.for_production {
            PCS_PROD_URL
        } else {
            PCS_SBX_URL
        };
        format!("{}/{}", base, path)
    }

    fn root_ca_url(&self) -> &str {
        if self.for_production {
            ROOT_CA_URL
        } else {
            ROOT_CA_URL_SBX
        }
    }

    fn fetch_fmspc_list(&self) -> Result<Vec<Fmspc>> {
        let url = self.build_url("sgx/certification/v4/fmspcs");
        let pcs_response = fetch_data_from_url(&url)?;
        match pcs_response.response_code {
            200 => Ok(serde_json::from_slice::<Vec<Fmspc>>(&pcs_response.data)?),
            _ => {
                eprintln!(
                    "Error fetching fmspc list - {:?}",
                    pcs_response.response_code
                );
                Err(anyhow!("AccessException"))
            }
        }
    }

    fn get_tdx_supported_platforms<'a>(&self, list: &'a [Fmspc]) -> Vec<&'a Fmspc> {
        list.iter().filter(|p| p.is_tdx_supported()).collect()
    }
}

impl CollateralServiceProvider for IntelPcsProvider {
    fn fetch_pck_crl(&self) -> Result<(Vec<u8>, String)> {
        let url = self.build_url("sgx/certification/v4/pckcrl?ca=platform&encoding=pem");
        let mut pcs_response = fetch_data_from_url(&url)?;
        match pcs_response.response_code {
            200 => {
                println!("Got PCK CRL");
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
                eprintln!("Error fetching PCK CRL - {:?}", pcs_response.response_code);
                Err(anyhow!("AccessException"))
            }
        }
    }

    fn fetch_root_ca(&self) -> Result<Vec<u8>> {
        let url = self.root_ca_url();
        let pcs_response = fetch_data_from_url(url)?;
        match pcs_response.response_code {
            200 => Ok(pcs_response.data),
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
                println!("Got enclave identity");
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
                    "Error fetching enclave identity - {:?}",
                    pcs_response.response_code
                );
                Err(anyhow!("AccessException"))
            }
        }
    }

    fn get_platform_tcb_list(&self) -> Result<Vec<PlatformTcbRaw>> {
        let fmspc_list = self.fetch_fmspc_list()?;
        let mut platform_tcb_list = Vec::new();
        for platform in self.get_tdx_supported_platforms(&fmspc_list) {
            if let Some(raw_tcb) = self.fetch_platform_tcb(&platform.fmspc)? {
                platform_tcb_list.push(PlatformTcbRaw {
                    fmspc: platform.fmspc.clone(),
                    tcb: raw_tcb.0,
                    tcb_issuer_chain: raw_tcb.1,
                });
            }
        }
        Ok(platform_tcb_list)
    }

    fn fetch_platform_tcb(&self, fmspc: &str) -> Result<Option<(Vec<u8>, String)>> {
        let url = self.build_url(&format!("tdx/certification/v4/tcb?fmspc={}", fmspc));
        let mut pcs_response = fetch_data_from_url(&url)?;

        let result = if pcs_response.response_code == 200 {
            println!("Got TCB info of fmspc - {}", fmspc);
            let issuer_chain = pcs_response
                .header_map
                .remove(TCB_INFO_ISSUER_CHAIN)
                .ok_or_else(|| anyhow!("Missing TCB info issuer chain header"))?;
            Some((
                pcs_response.data,
                percent_decode_str(&issuer_chain).decode_utf8()?.to_string(),
            ))
        } else if pcs_response.response_code == 404 {
            // Ignore 404 errors
            None
        } else {
            eprintln!(
                "Error fetching details for fmspc {}: {:?}",
                fmspc, pcs_response.response_code
            );
            None
        };

        Ok(result)
    }
}

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
