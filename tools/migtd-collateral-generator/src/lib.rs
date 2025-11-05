// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::Result;
use std::{fs, io::Write, path::PathBuf};

use crate::collateral::Collaterals;
use crate::provider::{intel_pcs::IntelPcsProvider, azure_thim::AzureThimProvider};

pub mod collateral;
pub mod http_client;
pub mod provider;
pub mod pcs_client;
pub mod pcs_types;

/// Enum to specify which collateral service provider to use
#[derive(Debug, Clone)]
pub enum CollateralProvider {
    /// Intel PCS Production environment
    IntelPcsProduction,
    /// Intel PCS Pre-production/Sandbox environment
    IntelPcsPreProduction,
    /// Azure THIM service with region and optional FMSPC list
    AzureThim {
        region: String,
        fmspc_list: Option<Vec<String>>,
    },
}

/// Generate collaterals using the specified provider and return them
pub fn generate_collaterals(provider: CollateralProvider, output_collateral: &PathBuf) -> Result<Collaterals> {
    let collaterals = match provider {
        CollateralProvider::IntelPcsProduction => {
            let provider = IntelPcsProvider::new(true);
            collateral::get_collateral(&provider)?
        }
        CollateralProvider::IntelPcsPreProduction => {
            let provider = IntelPcsProvider::new(false);
            collateral::get_collateral(&provider)?
        }
        CollateralProvider::AzureThim { region, fmspc_list } => {
            let provider = AzureThimProvider::new(region, fmspc_list);
            collateral::get_collateral(&provider)?
        }
    };
    
    write_collaterals_file(output_collateral, &collaterals)?;
    Ok(collaterals)
}

/// Merge multiple collateral objects, removing duplicate FMSPCs
pub fn merge_collaterals(collaterals_list: Vec<Collaterals>, output_collateral: &PathBuf) -> Result<Collaterals> {
    if collaterals_list.is_empty() {
        return Err(anyhow::anyhow!("No collaterals to merge"));
    }
    
    // Start with the first one as base
    let mut merged = collaterals_list[0].clone();
    
    // Merge platforms from remaining collaterals, avoiding duplicates by FMSPC
    for collateral in &collaterals_list[1..] {
        for platform in &collateral.platforms {
            // Check if this FMSPC already exists
            if !merged.platforms.iter().any(|p| p.fmspc == platform.fmspc) {
                merged.platforms.push(platform.clone());
            }
        }
    }
    
    write_collaterals_file(output_collateral, &merged)?;
    Ok(merged)
}

fn write_collaterals_file(collateral_output: &PathBuf, collaterals: &Collaterals) -> Result<()> {
    let mut file = fs::File::create(collateral_output)?;
    file.write_all(serde_json::to_vec(collaterals)?.as_slice())?;
    Ok(())
}
