use anyhow::{Context, Result};
use clap::Parser;
use policy::RawPolicyData;
use std::fs;

/// MigTD Policy Verifier Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to signed policy file (JSON)
    #[arg(short, long)]
    policy: String,

    /// Path to issuer certificate chain (PEM)
    #[arg(short, long)]
    cert_chain: String,

    /// Optional FMSPC string to verify in collaterals
    #[arg(short, long)]
    fmspc: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let policy_bytes = fs::read(&args.policy)
        .with_context(|| format!("Failed to read policy file: {}", args.policy))?;
    let cert_chain_bytes = fs::read(&args.cert_chain)
        .with_context(|| format!("Failed to read cert chain file: {}", args.cert_chain))?;

    let policy = RawPolicyData::deserialize_from_json(&policy_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse policy: {:?}", e))?;
    let verified_policy = policy
        .verify(&cert_chain_bytes, None, None)
        .map_err(|e| anyhow::anyhow!("Policy verification failed: {:?}", e))?;

    println!("Policy signature and issuer chain verified successfully.");

    if let Some(fmspc) = args.fmspc {
        let collaterals = verified_policy.get_collaterals();
        if collaterals.contains_key(&fmspc) {
            println!("Collateral contains FMSPC key: {}", fmspc);
        } else {
            println!("Collateral does NOT contain FMSPC key: {}", fmspc);
            std::process::exit(2);
        }
    }

    Ok(())
}
