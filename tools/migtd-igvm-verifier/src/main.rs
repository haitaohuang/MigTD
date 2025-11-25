// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use igvm::{IgvmDirectiveHeader, IgvmFile};
use policy::RawPolicyData;
use serde::Deserialize;
use std::fs;
use td_shim_interface::td_uefi_pi::{fv, pi::fv::FV_FILETYPE_RAW};

// GUID constants for policy files (from config.rs)
const MIGTD_POLICY_FFS_GUID: r_efi::efi::Guid = r_efi::efi::Guid::from_fields(
    0x0BE92DC3,
    0x6221,
    0x4C98,
    0x87,
    0xC1,
    &[0x8E, 0xEF, 0xFD, 0x70, 0xDE, 0x5A],
);

const MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID: r_efi::efi::Guid = r_efi::efi::Guid::from_fields(
    0x3F2FB27A,
    0x9596,
    0x431C,
    0xA6,
    0x8D,
    &[0xD3, 0xEA, 0xB3, 0x9F, 0x8A, 0xEB],
);

#[derive(Deserialize)]
struct ImageLayout {
    #[serde(rename = "Config")]
    config: String,
}

#[derive(Deserialize)]
struct Metadata {
    #[serde(rename = "Sections")]
    sections: Vec<Section>,
}

#[derive(Deserialize)]
struct Section {
    #[serde(rename = "MemoryAddress")]
    memory_address: String,
    #[serde(rename = "MemoryDataSize")]
    memory_data_size: String,
    #[serde(rename = "Type")]
    section_type: String,
}

/// MigTD IGVM Verifier - Verify embedded policy in IGVM file can be initialized
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to IGVM file (e.g., migtd_final.igvm)
    #[arg(short, long)]
    igvm: String,

    /// Path to image_layout.json (default: config/image_layout.json)
    #[arg(long, default_value = "config/image_layout.json")]
    image_layout: String,

    /// Path to metadata.json (default: config/metadata.json)
    #[arg(long, default_value = "config/metadata.json")]
    metadata: String,

    /// Optional: Save extracted policy JSON to this path
    #[arg(long)]
    save_policy: Option<String>,

    /// Optional: Save extracted issuer chain to this path
    #[arg(long)]
    save_chain: Option<String>,

    /// Optional FMSPC string to verify in collaterals
    #[arg(short, long)]
    fmspc: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== MigTD Policy Verification Test ===\n");

    // Load configuration files
    println!("1. Loading build configuration...");
    println!("   Image layout: {}", args.image_layout);
    let image_layout_json = fs::read_to_string(&args.image_layout)
        .with_context(|| format!("Failed to read image_layout.json: {}", args.image_layout))?;
    let image_layout: ImageLayout = serde_json::from_str(&image_layout_json)
        .with_context(|| "Failed to parse image_layout.json")?;
    
    println!("   Metadata: {}", args.metadata);
    let metadata_json = fs::read_to_string(&args.metadata)
        .with_context(|| format!("Failed to read metadata.json: {}", args.metadata))?;
    let metadata: Metadata = serde_json::from_str(&metadata_json)
        .with_context(|| "Failed to parse metadata.json")?;
    
    // Extract CFV configuration
    let cfv_size = u64::from_str_radix(image_layout.config.trim_start_matches("0x"), 16)
        .with_context(|| "Failed to parse Config size from image_layout.json")?;
    
    let cfv_section = metadata.sections.iter()
        .find(|s| s.section_type == "CFV")
        .ok_or_else(|| anyhow!("CFV section not found in metadata.json"))?;
    
    let cfv_memory_addr = u64::from_str_radix(cfv_section.memory_address.trim_start_matches("0x"), 16)
        .with_context(|| "Failed to parse CFV MemoryAddress from metadata.json")?;
    
    println!("   ✓ CFV size: 0x{:x} ({} bytes)", cfv_size, cfv_size);
    println!("   ✓ CFV runtime address: 0x{:x}", cfv_memory_addr);

    // Read and parse IGVM file
    println!("\n2. Reading IGVM file: {}", args.igvm);
    let igvm_contents = fs::read(&args.igvm)
        .with_context(|| format!("Failed to read IGVM file: {}", args.igvm))?;

    // Extract CFV data from IGVM file
    println!("\n3. Extracting Configuration Firmware Volume from IGVM...");
    let cfv_data = extract_cfv_from_igvm(&igvm_contents, cfv_size, cfv_memory_addr)?;
    println!("   Configuration volume size: {} bytes", cfv_data.len());

    // Extract policy from CFV using the same GUID as runtime
    println!("\n4. Extracting policy from CFV (GUID: 0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A)...");
    let policy_data = extract_file_from_cfv(&cfv_data, MIGTD_POLICY_FFS_GUID)?;
    println!("   Policy size: {} bytes", policy_data.len());

    // Extract issuer chain from CFV
    println!("\n5. Extracting issuer chain from CFV (GUID: 3F2FB27A-9596-431C-A68D-D3EAB39F8AEB)...");
    let issuer_chain_data = extract_file_from_cfv(&cfv_data, MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID)?;
    println!("   Issuer chain size: {} bytes", issuer_chain_data.len());

    // Save extracted files if requested
    if let Some(path) = &args.save_policy {
        fs::write(path, &policy_data)?;
        println!("   Policy saved to: {}", path);
    }
    if let Some(path) = &args.save_chain {
        fs::write(path, &issuer_chain_data)?;
        println!("   Issuer chain saved to: {}", path);
    }

    // Test policy initialization (mimics init_policy() from mig_policy.rs)
    println!("\n6. Testing policy initialization (deserialize + verify)...");
    let raw_policy = RawPolicyData::deserialize_from_json(&policy_data)
        .map_err(|e| anyhow!("Failed to deserialize policy JSON: {:?}", e))?;
    println!("   ✓ Policy JSON deserialized successfully");

    let verified_policy = raw_policy
        .verify(&issuer_chain_data, None, None)
        .map_err(|e| anyhow!("Policy verification failed: {:?}", e))?;
    println!("   ✓ Policy signature verified with issuer chain");

    let version = verified_policy.get_version();
    println!("   ✓ Policy version: {}", version);

    // Verify root CA is present (needed for quote verification later)
    let root_ca = &verified_policy.get_collaterals().root_ca;
    println!("   ✓ Root CA present ({} bytes)", root_ca.len());

    // Convert to DER format (as init_policy does)
    let _root_ca_der = crypto::pem_cert_to_der(root_ca.as_bytes())
        .map_err(|_| anyhow!("Failed to convert root CA PEM to DER"))?;
    println!("   ✓ Root CA converted to DER format");

    // List all available FMSPCs in the policy
    println!("\n7. Available FMSPCs in policy collateral:");
    let collaterals = verified_policy.get_collaterals();
    let platforms = &collaterals.platforms;
    if platforms.is_empty() {
        println!("   No FMSPCs found in policy");
    } else {
        // Extract FMSPC values from policy JSON (fmspc field is private)
        let mut fmspcs = Vec::new();
        if let Ok(json_str) = std::str::from_utf8(&policy_data) {
            // Look for all occurrences of "fmspc":"VALUE" pattern
            let mut search_start = 0;
            while let Some(idx) = json_str[search_start..].find("\"fmspc\":\"") {
                let absolute_idx = search_start + idx;
                let start = absolute_idx + 9; // length of "fmspc":"
                if let Some(end_idx) = json_str[start..].find("\"") {
                    let fmspc = &json_str[start..start+end_idx];
                    // Filter out non-FMSPC values (FMSPCs are hex strings like "50806F000000")
                    if fmspc.len() == 12 && fmspc.chars().all(|c| c.is_ascii_hexdigit()) {
                        if !fmspcs.contains(&fmspc.to_string()) {
                            fmspcs.push(fmspc.to_string());
                        }
                    }
                    search_start = start + end_idx + 1;
                } else {
                    break;
                }
            }
        }
        
        if fmspcs.is_empty() {
            println!("   (Unable to extract FMSPC values from policy JSON)");
        } else {
            for fmspc in &fmspcs {
                println!("   - {}", fmspc);
            }
        }
    }

    // Check specific FMSPC if provided
    if let Some(fmspc) = args.fmspc {
        println!("\n8. Checking collateral for FMSPC: {}", fmspc);
        if collaterals.get_tcb_with_fmspc(&fmspc).is_some() {
            println!("   ✓ Collateral contains FMSPC: {}", fmspc);
        } else {
            println!("   ✗ Collateral does NOT contain FMSPC: {}", fmspc);
            std::process::exit(2);
        }
    }

    println!("\n=== TEST PASSED ===");
    println!("✓ IGVM file contains valid embedded policy");
    println!("✓ Policy can be extracted from CFV");
    println!("✓ Policy signature verification succeeds");
    println!("✓ Policy is properly signed with provided issuer chain");
    println!("✓ This IGVM file will successfully pass mig_policy::init_policy()");

    Ok(())
}

/// Extract Configuration Firmware Volume (CFV) data from IGVM file
/// Uses CFV size from image_layout.json and runtime address from metadata.json
fn extract_cfv_from_igvm(igvm_contents: &[u8], cfv_size: u64, cfv_runtime_addr: u64) -> Result<Vec<u8>> {
    let igvm = IgvmFile::new_from_binary(igvm_contents, None)
        .map_err(|e| anyhow!("Failed to parse IGVM file: {:?}", e))?;

    // CFV GPA in IGVM (this is a fixed mapping that gets relocated to cfv_runtime_addr at runtime)
    const CFV_GPA: u64 = 0x2000000;
    
    let mut all_pages: Vec<(u64, Vec<u8>)> = Vec::new();
    
    for dir in igvm.directives().iter()
        .filter(|x| matches!(x, IgvmDirectiveHeader::PageData { .. }))
    {
        if let IgvmDirectiveHeader::PageData { gpa, data, .. } = dir {
            all_pages.push((*gpa, data.clone()));
        }
    }
    
    if all_pages.is_empty() {
        return Err(anyhow!("No page data found in IGVM file"));
    }
    
    // Sort by GPA
    all_pages.sort_by_key(|(gpa, _)| *gpa);
    
    // Find CFV at the expected GPA from build configuration
    let start_gpa = all_pages.iter()
        .find(|(gpa, data)| *gpa == CFV_GPA && !data.is_empty())
        .map(|(gpa, _)| *gpa)
        .ok_or_else(|| anyhow!("CFV not found at expected GPA 0x{:x}", CFV_GPA))?;
    
    println!("   Found CFV at GPA: 0x{:x} (runtime address: 0x{:x})", start_gpa, cfv_runtime_addr);
    
    // Collect all pages starting from start_gpa for cfv_size bytes
    let mut cfv_data = Vec::new();
    let end_gpa = start_gpa + cfv_size;
    
    for (gpa, data) in &all_pages {
        if *gpa >= start_gpa && *gpa < end_gpa {
            cfv_data.extend_from_slice(data);
        }
    }
    
    // Pad to full CFV size if needed
    if cfv_data.len() < cfv_size as usize {
        let padding = cfv_size as usize - cfv_data.len();
        cfv_data.extend(std::iter::repeat(0).take(padding));
    }
    
    // The CFV might have padding before the FV header. Look for the FVH signature "_FVH"
    let fvh_signature = b"_FVH";
    if let Some(offset) = cfv_data.windows(4).position(|w| w == fvh_signature) {
        // Found FVH signature. The actual FV header structure starts some bytes before this.
        // Based on the UEFI PI spec, the signature is at offset 0x28 in the FV header
        if offset >= 0x28 {
            let fv_start = offset - 0x28;
            println!("   Found FV header at offset: 0x{:x}", fv_start);
            
            // Read the fv_length field from the header (at offset 0x20 from FV start)
            if fv_start + 0x28 < cfv_data.len() {
                let fv_length_offset = fv_start + 0x20;
                let fv_length_bytes = &cfv_data[fv_length_offset..fv_length_offset+8];
                let fv_length = u64::from_le_bytes([
                    fv_length_bytes[0], fv_length_bytes[1], fv_length_bytes[2], fv_length_bytes[3],
                    fv_length_bytes[4], fv_length_bytes[5], fv_length_bytes[6], fv_length_bytes[7],
                ]);
                println!("   FV length field in header: 0x{:x}", fv_length);
                
                // Extract exactly fv_length bytes starting from fv_start
                if fv_start + fv_length as usize <= cfv_data.len() {
                    cfv_data = cfv_data[fv_start..fv_start + fv_length as usize].to_vec();
                    println!("   Extracted FV data: {} bytes", cfv_data.len());
                } else {
                    // If FV extends beyond CFV data, just take from fv_start to end
                    cfv_data = cfv_data[fv_start..].to_vec();
                    println!("   Extracted FV data from offset: {} bytes", cfv_data.len());
                }
            }
        }
    }

    Ok(cfv_data)
}

/// Extract file from Configuration Firmware Volume using GUID
/// This mimics what config::get_policy() and config::get_policy_issuer_chain() do at runtime
fn extract_file_from_cfv(cfv_data: &[u8], guid: r_efi::efi::Guid) -> Result<Vec<u8>> {
    // Debug: print GUID bytes we're searching for
    let guid_bytes = guid.as_bytes();
    println!("   Searching for GUID: {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3],
        guid_bytes[4], guid_bytes[5], guid_bytes[6], guid_bytes[7],
        guid_bytes[8], guid_bytes[9], guid_bytes[10], guid_bytes[11],
        guid_bytes[12], guid_bytes[13], guid_bytes[14], guid_bytes[15]);
    
    // Use the firmware volume parser to extract file by GUID (same as runtime)
    let file_data = fv::get_file_from_fv(cfv_data, FV_FILETYPE_RAW, guid)
        .ok_or_else(|| anyhow!("Unable to find file with GUID in CFV"))?;

    Ok(file_data.to_vec())
}
