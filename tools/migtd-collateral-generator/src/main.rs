// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use clap::Parser;
use migtd_collateral_generator::{generate_collaterals, merge_collaterals, CollateralProvider};
use std::{path::PathBuf, process::exit};

// Constants for Azure multi-region support
const ALL_US_EUROPE_REGIONS: &[&str] = &["useast", "westus", "northeurope"];
const ALL_US_EUROPE_KEY: &str = "all-us-europe";
const DEFAULT_AZURE_REGION: &str = "useast";

#[derive(Debug, Clone, Parser)]
struct Config {
    /// Service provider: "intel" (default) or "azure-thim"
    #[clap(long, default_value = "intel")]
    provider: String,

    /// Set to use pre-production server. Only applies to Intel PCS provider.
    /// Production server is used by default.
    #[clap(long)]
    pre_production: bool,

    /// Azure region(s) for THIM service. Can specify single region or comma-separated list.
    /// Special value "all-us-europe" fetches from useast,westus,northeurope and merges.
    /// Only applies when provider is "azure-thim". Default: "useast"
    #[clap(long, default_value = DEFAULT_AZURE_REGION)]
    azure_region: String,

    /// Comma-separated list of FMSPCs to fetch TCB info for.
    /// Only applies to Azure THIM provider. If not specified, uses automatic discovery.
    #[clap(long, value_delimiter = ',')]
    fmspc: Option<Vec<String>>,

    /// Where to write the generated collaterals
    #[clap(long, short)]
    output: PathBuf,
}

/// Parse Azure regions from the configuration
fn parse_azure_regions(azure_region: &str) -> Vec<String> {
    if azure_region == ALL_US_EUROPE_KEY {
        ALL_US_EUROPE_REGIONS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        azure_region
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    }
}

/// Handle multi-region Azure THIM collateral fetching
fn handle_multi_region_azure(
    regions: &[String],
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Fetching collaterals from {} regions: {:?}",
        regions.len(),
        regions
    );

    let mut all_collaterals = Vec::new();
    for region in regions {
        println!("\nFetching from {}...", region);
        // Create temporary output path for this region
        let temp_output = config.output.with_file_name(format!(
            "{}_temp_{}.json",
            config.output.file_stem().unwrap().to_str().unwrap(),
            region
        ));

        let provider = CollateralProvider::AzureThim {
            region: region.clone(),
            fmspc_list: config.fmspc.clone(),
        };

        match generate_collaterals(provider, &temp_output) {
            Ok(collateral) => {
                println!("✓ {}: {} platform(s)", region, collateral.platforms.len());
                all_collaterals.push(collateral);
            }
            Err(e) => {
                eprintln!("⚠ Failed to fetch from {}: {}", region, e);
            }
        }
    }

    if all_collaterals.is_empty() {
        eprintln!("Error: Failed to fetch collaterals from any region");
        exit(1);
    }

    // Merge all collaterals
    println!(
        "\nMerging collaterals from {} region(s)...",
        all_collaterals.len()
    );
    match merge_collaterals(all_collaterals, &config.output) {
        Ok(merged) => {
            println!(
                "✓ Merged successfully: {} unique platform(s)",
                merged.platforms.len()
            );
            if !merged.platforms.is_empty() {
                println!("  FMSPCs:");
                for platform in &merged.platforms {
                    println!("    - {}", platform.fmspc);
                }
            }
        }
        Err(e) => {
            eprintln!("Error merging collaterals: {}", e);
            exit(1);
        }
    }
    Ok(())
}

fn main() {
    let config = Config::parse();

    let provider_type = match config.provider.to_lowercase().as_str() {
        "intel" => {
            if config.pre_production {
                CollateralProvider::IntelPcsPreProduction
            } else {
                CollateralProvider::IntelPcsProduction
            }
        }
        "azure-thim" | "azure" | "thim" => {
            // Handle multiple regions
            let regions = parse_azure_regions(&config.azure_region);

            if regions.len() > 1 {
                // Fetch from multiple regions and merge
                if let Err(e) = handle_multi_region_azure(&regions, &config) {
                    eprintln!("Error handling multi-region fetch: {}", e);
                    exit(1);
                }
                return;
            } else {
                CollateralProvider::AzureThim {
                    region: regions[0].clone(),
                    fmspc_list: config.fmspc.clone(),
                }
            }
        }
        _ => {
            eprintln!(
                "Error: Invalid provider '{}'. Valid options: 'intel', 'azure-thim'",
                config.provider
            );
            exit(1);
        }
    };

    if let Err(e) = generate_collaterals(provider_type, &config.output) {
        eprintln!("Error generating collaterals: {}", e);
        exit(1);
    }
}
