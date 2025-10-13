# MigTD AzCVMEmu Quote-Based Policy Generation

This documentation covers scripts and workflow for extracting measurements from live Azure vTPM and generating custom MigTD v2 policies. This is for AzCVMEmu mode only when running migtd as an app inside an Azure CVM with TDX.

## Overview

- **Quote-Based Generation**: Extract measurements from live Azure vTPM and generate custom policies.
- **Complete Workflow**: End-to-end automation combining all processes for AzCVMEmu.

## Script: `build_custom_policy_from_quote.sh`

**End-to-end automation for generating custom MigTD v2 policies from live Azure vTPM measurements.**

**Features**:
- Extracts TD measurements from Azure vTPM (MRTD, RTMRs, XFAM, Attributes)
- Updates policy templates with extracted measurements
- Generates certificate chain for signing
- Signs all components (td_identity, tcb_mapping, final policy)
- Creates **test-ready** signed policy
- Optionally tests the generated policy with migtdemu.sh

**Usage**:
```bash
# Complete workflow: extract measurements and generate signed policy
src/policy/sh_scripts/build_custom_policy_from_quote.sh

# Skip the integration test at the end
src/policy/sh_scripts/build_custom_policy_from_quote.sh --skip-test

# Use custom output directory
src/policy/sh_scripts/build_custom_policy_from_quote.sh --output-dir /secure/policies

# Show help
src/policy/sh_scripts/build_custom_policy_from_quote.sh --help
```

**Requirements**:
- Azure TDX CVM with vTPM access
- **sudo privileges** (required for vTPM device access)
- TPM 2.0 tools installed
- jq (JSON processor) installed

**What it does (13 steps)**:
1. Builds required tools (migtd-quote-extractor, json-signer, servtd-collateral-generator, migtd-policy-generator)
2. Extracts quote data from Azure vTPM **using sudo** for device access
3. Updates `td_identity.json` template with extracted measurements
4. Updates `tcb_mapping.json` template with extracted measurements
5. Generates certificate chain (root CA + policy signing cert)
6. Signs `td_identity.json` with policy signing key, **Testing only**
7. Signs `tcb_mapping.json` with policy signing key **Testing only**
8. Generates `servtd_collateral.json` from signed components
9. Merges policy data with collaterals
10. Signs final policy with policy signing key
11. Copies certificate chain to output directory
12. Securely deletes private key with `shred`
13. Optionally tests with `./migtdemu.sh`

**Outputs**:
- `config/policy_v2_signed.json` (196 KB) - Signed policy with your measurements
- `config/policy_issuer_chain.pem` (1.5 KB) - Certificate chain for verification

**Testing**:
```bash
# Unit test (signature verification)
cd src/policy
cargo test --features policy_v2 test_verify_policy_in_config

# Integration test (full migration flow)
./migtdemu.sh --policy-v2 \
  --policy-file ./config/policy_v2_signed.json \
  --policy-issuer-chain-file ./config/policy_issuer_chain.pem \
  --debug --both
```

**Expected result**: ✅ "Migration key exchange successful!"
