#!/bin/bash

# ==============================================================================
# MigTD Policy Complete Workflow Script
# ==============================================================================
#
# This script provides a complete workflow for certificate generation
# and MigTD policy creation. It is designed for development, testing, and CI/CD
# environments and runs directly within this repository. Private keys are automatically
# deleted after use.
#
# Features:
#   - Automatic building of required tools (migtd-policy-generator, json-signer,
#     migtd-policy-verifier)
#   - Certificate generation (CA chain with P256/P384/P521 support)
#   - Policy generation with template support using <repo_root>/config/templates
#   - Policy signing and verification
#   - Secure private key handling (automatically deleted after use)
#
# Dependencies:
#   - Rust toolchain (cargo)
#   - OpenSSL command-line tools (for certificate generation)
#   - jq (optional, for JSON validation and pretty-printing)
#
# Usage: ./gen_signed_policy_and_cert_chain.sh [OPTIONS]
#        Run with --help for detailed usage information
#
# ==============================================================================

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# ============================================================================
# TOOL BUILDING FUNCTIONS
# ============================================================================

# Function to check and build required tools
check_and_build_tools() {
    local tools_to_check=("migtd-policy-generator" "migtd-policy-verifier" "json-signer")
    local missing_tools=()

    echo "=== Checking Required Tools ==="

    for tool in "${tools_to_check[@]}"; do
        if [ ! -f "$PROJECT_ROOT/target/release/$tool" ]; then
            missing_tools+=("$tool")
            echo "✗ $tool not found"
        else
            echo "✓ $tool found"
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo
        echo "Building missing tools: ${missing_tools[*]}"
        cd "$PROJECT_ROOT"

        # Build migtd-policy-generator
        if [[ " ${missing_tools[*]} " =~ " migtd-policy-generator " ]]; then
            echo "Building migtd-policy-generator..."
            cargo build --release -p migtd-policy-generator
        fi

        # Build json-signer (as a separate binary)
        if [[ " ${missing_tools[*]} " =~ " json-signer " ]]; then
            echo "Building json-signer..."
            cargo build --release -p json-signer
        fi

        # Build migtd-policy-verifier
        if [[ " ${missing_tools[*]} " =~ " migtd-policy-verifier " ]]; then
            echo "Building migtd-policy-verifier..."
            cargo build --release -p migtd-policy-verifier
        fi

        echo "✓ All tools built successfully"
        cd - > /dev/null
    fi

    echo
}

# ============================================================================
# CERTIFICATE GENERATION FUNCTIONS
# ============================================================================

# Function to validate and get curve name from key type
get_curve_name() {
    # Only P384 is supported at this point
    echo "secp384r1"
}

# Function to get hash algorithm based on key type
get_hash_algorithm() {
    echo "sha384"
}

# Function to generate certificates
# Arguments:
#   $1 - output_dir: Directory where certificates will be generated
#   $2 - key_type: Key type (only P384 is currently supported)
#   $3 - cert_validity_days: Certificate validity in days (uses default 365 if not provided)
#   $4 - root_ca_subject: Root CA subject string (uses default "/CN=MigTD Root CA/O=Intel Corporation" if not provided)
#   $5 - leaf_subject: Leaf certificate subject string (uses default "/CN=MigTD Policy Issuer/O=Intel Corporation" if not provided)
generate_certificates() {
    local output_dir="$1"
    local key_type="$2"
    local cert_validity_days="${3:-365}"
    local root_ca_subject="${4:-/CN=MigTD Root CA/O=Intel Corporation}"
    local leaf_subject="${5:-/CN=MigTD Policy Issuer/O=Intel Corporation}"

    # Validate key type first
    if [ "$key_type" != "P384" ]; then
        echo "Error: Only P-384 keys are currently supported." >&2
        echo "P-256 and P-521 support is not yet implemented in the signing/verification code." >&2
        exit 1
    fi

    local curve_name=$(get_curve_name "$key_type")
    local hash_algo=$(get_hash_algorithm "$key_type")

    echo "=== Certificate Generation ==="
    echo "Output directory: $output_dir"
    echo "Key type: $key_type ($curve_name)"
    echo "Hash algorithm: $hash_algo"
    echo "Certificate validity: $cert_validity_days days"
    echo

    # Create output directory
    mkdir -p "$output_dir"

    echo "Generating CA certificate chain..."

    echo "1. Generating root CA private key..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve_name -out "$output_dir/root_ca.key"

    echo "2. Generating root CA certificate..."
    openssl req -new -x509 \
        -key "$output_dir/root_ca.key" \
        -days $cert_validity_days \
        -out "$output_dir/root_ca.pem" \
        -subj "$root_ca_subject" \
        -$hash_algo

    echo "3. Generating policy signing private key..."
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve_name -out "$output_dir/policy_signing.key"

    # Convert to PKCS8 format for json-signer
    echo "4. Converting key to PKCS8 format..."
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
        -in "$output_dir/policy_signing.key" \
        -out "$output_dir/policy_signing_pkcs8.key"

    echo "5. Generating certificate signing request..."
    openssl req -new \
        -key "$output_dir/policy_signing.key" \
        -out "$output_dir/policy_signing.csr" \
        -subj "$leaf_subject"

    echo "6. Signing leaf certificate with root CA..."
    openssl x509 -req \
        -in "$output_dir/policy_signing.csr" \
        -CA "$output_dir/root_ca.pem" \
        -CAkey "$output_dir/root_ca.key" \
        -CAcreateserial \
        -out "$output_dir/policy_signing.pem" \
        -days $cert_validity_days \
        -$hash_algo \
        -extensions v3_ca \
        -extfile <(echo -e "[v3_ca]\nkeyUsage = digitalSignature")

    # Create certificate chain (leaf + root)
    echo "7. Creating certificate chain..."
    cat "$output_dir/policy_signing.pem" "$output_dir/root_ca.pem" > "$output_dir/policy_issuer_chain.pem"

    # Clean up CSR
    rm -f "$output_dir/policy_signing.csr"

    echo "✓ CA certificate chain generated successfully!"
    echo "  Root CA key: $output_dir/root_ca.key"
    echo "  Root CA cert: $output_dir/root_ca.pem"
    echo "  Signing key: $output_dir/policy_signing.key"
    echo "  PKCS8 key: $output_dir/policy_signing_pkcs8.key"
    echo "  Signing cert: $output_dir/policy_signing.pem"
    echo "  Certificate chain: $output_dir/policy_issuer_chain.pem"

    echo
    echo "=== Certificate Information ==="
    openssl x509 -in "$output_dir/policy_issuer_chain.pem" -text -noout | grep -E "(Subject:|Issuer:|Signature Algorithm:|Public-Key:|Not Before:|Not After:)"

    echo
    echo "=== Verification ==="
    openssl verify -CAfile "$output_dir/root_ca.pem" "$output_dir/policy_signing.pem" 2>/dev/null && echo "✓ Certificate chain: OK" || echo "✗ Certificate chain: FAILED"
}

# ============================================================================
# POLICY GENERATION FUNCTIONS
# ============================================================================

# Function to check if file exists
check_file() {
    if [ ! -f "$1" ]; then
        echo "Error: File not found: $1" >&2
        exit 1
    fi
}

# Function to generate policy
# Arguments:
#   $1 - policy_data: Policy data JSON file path
#   $2 - collaterals: Collaterals JSON file path
#   $3 - servtd_collateral: ServTD collateral JSON file path
#   $4 - private_key: Private key path for signing in PKCS8 format
#   $5 - cert_chain: Certificate chain path for verification
#   $6 - output_file: Output policy file path
generate_policy() {
    local policy_data="$1"
    local collaterals="$2"
    local servtd_collateral="$3"
    local private_key="$4"
    local cert_chain="$5"
    local output_file="$6"

    local tools_dir="$PROJECT_ROOT/target/release"
    local json_signer="$tools_dir/json-signer"
    local policy_generator="$tools_dir/migtd-policy-generator"

    echo "=== Policy Generation ==="
    echo

    # Validate input files
    echo "Validating input files..."
    check_file "$policy_data"
    check_file "$collaterals"
    check_file "$servtd_collateral"
    check_file "$private_key"
    check_file "$cert_chain"
    echo "✓ All input files found"

    # Create temporary directory for intermediate files
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    echo
    echo "=== Policy Generation Process ==="

    echo "Step 1: Merging policy raw data with collaterals..."
    local merged_policy_data="$temp_dir/merged_policy_data.json"

    "$policy_generator" v2 \
        --policy-data "$policy_data" \
        --collaterals "$collaterals" \
        --servtd-collateral "$servtd_collateral" \
        --output "$merged_policy_data"

    echo "✓ Policy data merged with collaterals successfully"

    echo "Step 2: Signing the merged policy data..."

    "$json_signer" --sign --name policyData \
        --private-key "$private_key" \
        --input "$merged_policy_data" \
        --output "$output_file"

    echo "✓ Policy signed successfully"

    echo
    echo "=== Policy Generation Results ==="
    echo "Output file: $output_file"
    echo "File size: $(wc -c < "$output_file") bytes"

    # Validate the generated policy
    echo
    echo "=== Validation ==="
    if command -v jq >/dev/null 2>&1; then
        echo "Validating JSON structure..."
        if jq empty "$output_file" 2>/dev/null; then
            echo "✓ Valid JSON structure"

            # Show policy structure
            echo
            echo "Policy structure:"
            jq -r 'keys[]' "$output_file" 2>/dev/null | sed 's/^/  - /'

            # Verify the policy contains a signature
            if jq -e '.signature' "$output_file" >/dev/null 2>&1; then
                echo "✓ Policy is signed"
            else
                echo "✗ Policy is missing signature"
                exit 1
            fi
        else
            echo "✗ Invalid JSON structure"
            exit 1
        fi
    else
        echo "ℹ jq not available, skipping JSON validation"
    fi
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

# Default values
CERT_OUTPUT_DIR="./certs"
POLICY_OUTPUT_FILE="./migtd_policy_v2.json"
KEY_TYPE="P384"
USE_TEMPLATES=true
POLICY_DATA=""
COLLATERALS=""
SERVTD_COLLATERAL=""

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Complete workflow for MigTD policy generation with certificate creation.

This script will:
1. Generate CA certificate chain and keys for policy signing
2. Generate a signed MigTD policy using templates or custom inputs

OPTIONS:
    Certificate Generation:
    -c, --cert-dir DIR          Certificate output directory (default: ./certs)
    --cert-chain FILE           Specific path for certificate chain output
    -k, --key-type TYPE         Key type: only P384 is currently supported (default: P384)

    Policy Generation:
    -o, --output FILE           Policy output file (default: ./migtd_policy_v2.json)
    -p, --policy-data FILE      Custom policy data JSON file (optional if using config/templates)
    --collaterals FILE          Custom collaterals JSON file (optional if using config/templates)
    --servtd-collateral FILE    Custom ServTD collateral JSON file (optional)
    --no-templates              Don't use default templates, require all inputs

    General:
    -h, --help                  Display this help message

EXAMPLES:
    # Generate everything with defaults (P384, CA chain, templates)
    $0

    # Generate with custom output locations
    $0 --cert-dir /path/to/certs --output /path/to/policy.json

    # Generate with custom policy data
    $0 --policy-data my_policy_data.json

    # Generate with specific certificate and policy paths
    $0 --cert-chain src/policy/test/policy_v2/cert_chain/policy_issuer_chain.pem \\
       --output src/policy/test/policy_v2/policy_v2.json \\
       --policy-data src/policy/test/policy_v2/policy_data.json

NOTE:
    Currently only P-384 (secp384r1) keys are supported for signing and verification.
    P-256 and P-521 support requires additional implementation in the crypto library.

OUTPUT FILES:
    Certificate:
    - policy_issuer_chain.pem   (Certificate chain for verification)

    Policy:
    - [output-file]             (Signed MigTD policy JSON)

    Note: Private key is used only for signing and is securely deleted afterward.
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--cert-dir)
            CERT_OUTPUT_DIR="$2"
            shift 2
            ;;
        --cert-chain)
            CERT_CHAIN_PATH="$2"
            shift 2
            ;;
        -k|--key-type)
            KEY_TYPE="$2"
            shift 2
            ;;
        -o|--output)
            POLICY_OUTPUT_FILE="$2"
            shift 2
            ;;
        -p|--policy-data)
            POLICY_DATA="$2"
            shift 2
            ;;
        --collaterals)
            COLLATERALS="$2"
            shift 2
            ;;
        --servtd-collateral)
            SERVTD_COLLATERAL="$2"
            shift 2
            ;;
        --no-templates)
            USE_TEMPLATES=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

# Check and build required tools if needed
check_and_build_tools

echo "=== MigTD Policy Complete Workflow ==="
echo "Certificate directory: $CERT_OUTPUT_DIR"
echo "Policy output file: $POLICY_OUTPUT_FILE"
echo "Key type: $KEY_TYPE"
echo "Use templates: $USE_TEMPLATES"
echo

# Step 1: Generate certificates
echo "=== Step 1: Certificate Generation ==="

# Always use a temporary directory for certificate generation
TEMP_CERT_DIR=$(mktemp -d)

# Generate certificates using our function
generate_certificates "$TEMP_CERT_DIR" "$KEY_TYPE"

# Determine output paths
if [ -n "$CERT_CHAIN_PATH" ]; then
    # Custom certificate chain path specified
    CERT_CHAIN_DIR="$(dirname "$CERT_CHAIN_PATH")"
    mkdir -p "$CERT_CHAIN_DIR"
    cp "$TEMP_CERT_DIR/policy_issuer_chain.pem" "$CERT_CHAIN_PATH"
    echo "✓ Certificate chain: $CERT_CHAIN_PATH"
else
    mkdir -p "$CERT_OUTPUT_DIR"
    cp "$TEMP_CERT_DIR/policy_issuer_chain.pem" "$CERT_OUTPUT_DIR/"
    CERT_CHAIN_PATH="$CERT_OUTPUT_DIR/policy_issuer_chain.pem"
    echo "✓ Certificate chain: $CERT_CHAIN_PATH"
fi

# Private key stays in temporary location for signing only
PRIVATE_KEY_PATH="$TEMP_CERT_DIR/policy_signing_pkcs8.key"
echo "✓ Private key: temporary (will be deleted after signing)"

echo
echo "=== Step 2: Policy Generation ==="

# Prepare policy generation inputs
FINAL_POLICY_DATA="$POLICY_DATA"
FINAL_COLLATERALS="$COLLATERALS"
FINAL_SERVTD_COLLATERAL="$SERVTD_COLLATERAL"

# Set default files if using templates
if [ "$USE_TEMPLATES" = true ]; then
    if [ -z "$FINAL_POLICY_DATA" ]; then
        FINAL_POLICY_DATA="$PROJECT_ROOT/config/templates/policy_v2_raw.json"
        echo "Using policy data template: $FINAL_POLICY_DATA"
    fi

    if [ -z "$FINAL_SERVTD_COLLATERAL" ]; then
        FINAL_SERVTD_COLLATERAL="$PROJECT_ROOT/config/templates/servtd_collateral.json"
        echo "Using ServTD collateral template: $FINAL_SERVTD_COLLATERAL"
    fi
fi

# Set default collaterals if not specified
if [ -z "$FINAL_COLLATERALS" ]; then
    FINAL_COLLATERALS="$PROJECT_ROOT/config/collateral_production_fmspc.json"
    echo "Using default collaterals: $FINAL_COLLATERALS"
fi

# Generate the policy using our function
generate_policy "$FINAL_POLICY_DATA" "$FINAL_COLLATERALS" "$FINAL_SERVTD_COLLATERAL" \
    "$PRIVATE_KEY_PATH" "$CERT_CHAIN_PATH" "$POLICY_OUTPUT_FILE"

# Clean up temporary certificate directory (removes private key)
rm -rf "$TEMP_CERT_DIR"
echo "✓ Private key securely deleted"

echo
echo "=== Workflow Complete ==="
echo "✓ Certificate chain: $CERT_CHAIN_PATH"
echo "✓ Policy generated: $POLICY_OUTPUT_FILE"
echo
echo "Generated files:"
echo "  Certificate chain: $CERT_CHAIN_PATH"
echo "  Policy file: $POLICY_OUTPUT_FILE"
echo

echo "Verifying policy and certificate chain with migtd-policy-verifier..."
"$PROJECT_ROOT/target/release/migtd-policy-verifier" \
    --policy "$POLICY_OUTPUT_FILE" \
    --cert-chain "$CERT_CHAIN_PATH"

VERIFY_EXIT_CODE=$?
if [ $VERIFY_EXIT_CODE -eq 0 ]; then
    echo "✓ Policy and certificate chain verification succeeded."
else
    echo "✗ Verification failed: Policy or certificate chain is invalid."
fi
