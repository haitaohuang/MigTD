# MigTD IGVM Verifier

This tool verifies that the policy embedded in a MigTD IGVM file can be successfully initialized at runtime. It extracts the Configuration Firmware Volume (CFV) from the IGVM file, parses the embedded policy and issuer chain, and validates that the policy signature verification would succeed.

## Purpose

This integration test ensures that:
1. The IGVM file contains a valid Configuration Firmware Volume
2. The policy can be extracted from the CFV using the same GUID-based lookup as runtime
3. The policy JSON can be deserialized
4. The policy signature is valid and verified with the provided issuer chain
5. The policy will successfully pass `mig_policy::init_policy()` at runtime

This test does NOT require TDX hardware, as it only tests the policy initialization logic (not TCB info or attestation).

## Usage

### Basic verification (no hardware required):
```bash
cargo run --release --bin migtd-igvm-verifier -- --igvm /path/to/migtd_final.igvm
```

This will:
- Load build configuration from default paths (`config/image_layout.json` and `config/metadata.json`)
- Extract and verify the policy
- List all FMSPCs available in the policy collateral

### Specify custom configuration files:
```bash
cargo run --release --bin migtd-igvm-verifier -- \
  --igvm /path/to/migtd_final.igvm \
  --image-layout /path/to/image_layout.json \
  --metadata /path/to/metadata.json
```

### Verify policy contains specific FMSPC:
```bash
cargo run --release --bin migtd-igvm-verifier -- \
  --igvm /path/to/migtd_final.igvm \
  --fmspc 50806F000000
```

This will list all available FMSPCs and verify the specified FMSPC is present.

## Configuration Files

The tool requires two build configuration files to determine CFV location and size:

1. **image_layout.json**: Contains the `Config` field specifying CFV size (e.g., `"0x0A0000"` = 655360 bytes)
2. **metadata.json**: Contains the `Sections` array with CFV `MemoryAddress` (e.g., `"0xFF000000"`)

Default paths: `config/image_layout.json` and `config/metadata.json`

## Exit Codes

- `0`: Success - policy is valid and properly signed
- `1`: Error - policy extraction or verification failed
- `2`: FMSPC check failed - specified FMSPC not found in collateral

## Example Output

```
=== MigTD Policy Verification Test ===

1. Loading build configuration...
   Image layout: config/image_layout.json
   Metadata: config/metadata.json
   ✓ CFV size: 0xa0000 (655360 bytes)
   ✓ CFV runtime address: 0xff000000

2. Reading IGVM file: /path/to/migtd_final.igvm

3. Extracting Configuration Firmware Volume from IGVM...
   Found CFV at GPA: 0x2000000 (runtime address: 0xFF000000)
   Found FV header at offset: 0x0
   FV length field in header: 0xa0000
   Extracted FV data: 655360 bytes
   Configuration volume size: 655360 bytes

4. Extracting policy from CFV (GUID: 0BE92DC3-6221-4C98-87C1-8EEFFD70DE5A)...
   Policy size: 34528 bytes

5. Extracting issuer chain from CFV (GUID: B3C1DCFE-6BEF-449F-A183-63A84EA1E0B4)...
   Issuer chain size: 1494 bytes

6. Testing policy initialization (deserialize + verify)...
   ✓ Policy JSON deserialized successfully
   ✓ Policy signature verified with issuer chain
   ✓ Policy version: 2.0
   ✓ Root CA present (947 bytes)
   ✓ Root CA converted to DER format

7. Available FMSPCs in policy collateral:
   - 50806F000000
   - 00806F050000
   - 90C06F000000

8. Checking collateral for FMSPC: 50806F000000
   ✓ Collateral contains FMSPC: 50806F000000

=== TEST PASSED ===
✓ IGVM file contains valid embedded policy
✓ Policy can be extracted from CFV
✓ Policy signature verification succeeds
✓ Policy is properly signed with provided issuer chain
✓ This IGVM file will successfully pass mig_policy::init_policy()
```

## Integration with CI/CD

This tool can be integrated into CI/CD pipelines to validate IGVM builds:

```bash
# Build the IGVM file
./build_final.sh

# Verify the embedded policy
cargo run --release --bin migtd-igvm-verifier -- --igvm out/migtd_final.igvm --fmspc 50806F000000

# Check exit code
if [ $? -eq 0 ]; then
    echo "Policy verification passed"
else
    echo "Policy verification failed"
    exit 1
fi
```

## Technical Details

The tool uses build configuration files to ensure accurate CFV extraction:

**Build Configuration:**
- **CFV Size**: Read from `image_layout.json` → `Config` field (e.g., `"0x0A0000"` = 655360 bytes)
- **CFV Runtime Address**: Read from `metadata.json` → CFV section `MemoryAddress` (e.g., `"0xFF000000"`)
- **CFV GPA in IGVM**: Fixed at 0x2000000 (maps to runtime address via IGVM loader)

The tool mimics the runtime behavior of `mig_policy::init_policy()`:

1. **Configuration Loading**: Parses `image_layout.json` and `metadata.json` to get CFV size and runtime address
2. **CFV Extraction**: Parses IGVM PageData directives to find the Configuration Firmware Volume at GPA 0x2000000
3. **FV Parsing**: Uses `td-shim-interface::td_uefi_pi::fv` parser to extract files by GUID (same as runtime)
4. **Policy Deserialization**: Uses `policy::RawPolicyData::deserialize_from_json()`
5. **Signature Verification**: Verifies policy signature with issuer chain using `policy::verify_sig_with_chain()`
6. **CA Conversion**: Converts root CA from PEM to DER format (same as runtime initialization)

This ensures that the test uses the same configuration as the build process and accurately reflects whether `init_policy()` would succeed at runtime.
