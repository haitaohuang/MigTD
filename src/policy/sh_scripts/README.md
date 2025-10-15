# MigTD Policy Script

This directory contains a script for generating MigTD policy v2 files with proper certificate management and signing.

## Overview

The policy script provides an end-to-end workflow for:
1. **Certificate Generation**: Creating P-384 ECDSA certificates and keys for policy signing
2. **Policy Generation**: Creating signed MigTD policy v2 files using templates or custom data
3. **Validation**: Verifying the generated policy and certificate chain

## Prerequisites

1. **Install required tools**:
   - OpenSSL (for certificate generation)
   - jq (optional, for JSON validation)

2. **Running the script**:
   The script should be run from the MigTD project root directory. The examples below assume you are in the project root (`/path/to/MigTD`).
   The script will automatically build required tools (`migtd-policy-generator`, `json-signer`, `migtd-policy-verifier`) if they are not found.

## Known Limitations

### Key Type Support

**Currently only P-384 (secp384r1) keys are supported** for signing and verification. The script will reject P-256 and P-521 key types with a clear error message.

**Technical Details:**

1. **Signing Limitation** (affects policy generation):
   - Location: `src/crypto/src/rustls_impl/ecdsa.rs:103`
   - Issue: The `ecdsa_sign()` function is hardcoded to use `ECDSA_P384_SHA384_ASN1_SIGNING`
   - Impact: P-256 and P-521 private keys are rejected with `KeyRejected("WrongAlgorithm")` error
   - Error occurs in: `json-signer` tool during policy signing

2. **Verification Bug** (affects policy validation):
   - Location: `src/crypto/src/lib.rs:267-272`
   - Issue: P-521 verification incorrectly uses `ECDSA_P384_SHA384_ASN1` instead of the proper P-521 algorithm
   - Impact: Even if P-521 signing worked, verification would fail due to algorithm mismatch
   - Error occurs in: `migtd-policy-verifier` and `verify_cert_chain_and_signature()` function

**Required Changes for Full Support:**

To support P-256:
- Modify `ecdsa_sign()` to detect key type and use `ECDSA_P256_SHA256_ASN1_SIGNING`
- Ensure verification correctly handles P-256 signatures (currently supported)

To support P-521:
- Modify `ecdsa_sign()` to detect key type and use appropriate P-521 signing algorithm
- Fix verification to use correct P-521 algorithm instead of P-384
- Note: Ring crate may not support P-521; alternative crypto library might be needed

**Workaround:**

The scripts now validate key types early and provide clear error messages:
```
Error: Only P-384 keys are currently supported.
P-256 and P-521 support is not yet implemented in the signing/verification code.
```

## Script

### `gen_signed_policy_and_cert_chain.sh`

End-to-end workflow script that generates P-384 ECDSA certificates and creates a signed MigTD policy v2 file.

**Features**:
- **Automatic Tool Building**: Checks for and builds required tools if not present
- **Certificate Generation**: Creates a CA certificate chain with P-384 keys
- **Policy Generation**: Merges policy data with collaterals using templates or custom files
- **Signing**: Signs the policy using json-signer with a temporary private key
- **Validation**: Verifies the policy and certificate chain with migtd-policy-verifier
- **Security**: Private key is automatically deleted after signing

**Usage**:
```bash
# Complete workflow with defaults (uses templates)
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh

# Custom certificate directory and policy output location
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh \
  --cert-dir /path/to/certs \
  --output /path/to/policy.json

# Use custom policy data instead of template
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh \
  --policy-data my_policy_data.json \
  --output my_policy.json

# Specify exact certificate chain path (useful for tests)
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh \
  --cert-chain src/policy/test/policy_v2/cert_chain/policy_issuer_chain.pem \
  --output src/policy/test/policy_v2/policy_v2.json \
  --policy-data src/policy/test/policy_v2/policy_data.json

# Use custom collaterals and ServTD collateral
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh \
  --collaterals my_collaterals.json \
  --servtd-collateral my_servtd_collateral.json \
  --output my_policy.json
```

**Options**:
- `-c, --cert-dir DIR`: Certificate output directory (default: ./certs)
- `--cert-chain FILE`: Specific path for certificate chain output
- `-o, --output FILE`: Policy output file (default: ./migtd_policy_v2.json)
- `-p, --policy-data FILE`: Custom raw policy data JSON (optional, uses template if not specified)
- `--collaterals FILE`: Custom collaterals JSON (optional, uses default if not specified)
- `--servtd-collateral FILE`: Custom ServTD collateral JSON (optional, uses template if not specified)
- `--no-templates`: Don't use default templates, require all inputs
- `-h, --help`: Display help message

**Output Files**:
- Certificate chain: `policy_issuer_chain.pem` (in cert-dir or specified path)
- Signed policy: Specified by `--output` option

**Templates Used** (when not using `--no-templates`):
- `config/templates/policy_v2_raw.json` - Base policy data (the raw 'policy' object to be combined with collaterals)
- `config/templates/servtd_collateral.json` - ServTD collateral (combined signed tcb_mapping and td_identity)
- `config/collateral_production_fmspc.json` - Default collaterals

## File Structure

```
src/policy/sh_scripts/
├── README.md                            # This documentation
└── gen_signed_policy_and_cert_chain.sh  # Complete workflow script
```

## Templates

The script uses templates from `config/templates/` which include:

- `policy_v2_raw.json` - Base policy data with correct structure, this is the raw 'policy' object before combined with collaterals.
- `servtd_collateral.json` - ServTD collateral after combining the signed tcb_mapping and td_identity
- `tcb_mapping.json` - TCB mapping data
- `td_identity.json` - TD identity data

These templates ensure the generated policies have the correct JSON structure and field names (e.g., `tdIdentity` instead of `td_identity`).

## Examples

### Quick Start

Generate a complete signed policy with default settings:
```bash
cd /path/to/MigTD
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh
```

This creates:
- `./certs/policy_issuer_chain.pem` - Certificate chain
- `./migtd_policy_v2.json` - Signed policy file

### Custom Policy Data

Generate a policy with custom policy data:
```bash
cd /path/to/MigTD

src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh \
  --policy-data my_custom_policy_data.json \
  --output my_policy.json
```

### Development and Testing

For development with custom inputs:
```bash
cd /path/to/MigTD

# Generate policy with all custom inputs
src/policy/sh_scripts/gen_signed_policy_and_cert_chain.sh \
  --policy-data test_policy_data.json \
  --servtd-collateral test_servtd_collateral.json \
  --collaterals test_collaterals.json \
  --cert-dir test_certs \
  --output test_policy.json
```

## Security Considerations

**This script is for development and testing purposes.**
