# MigTD Quote Extractor Tool

This tool extracts TD quote information from vTPM in Azure CVM environments and outputs the data needed for ServTD collateral (TCB mapping and identity).

## Purpose

In AzCVMEmu mode, MigTD runs in Azure TDX CVMs where we get a TDX Quote for **Azure CVM Underhill** (the virtual firmware layer), NOT for MigTD itself. Underhill does not use RTMRs, so all RTMR values in the Underhill quote are zeros.

For MigTD policy generation, this tool:
1. Gets the Underhill TD report from vTPM using the `az-tdx-vtpm` library
2. Extracts MRTD and other base measurements from Underhill
3. Uses **hardcoded RTMR values** that represent MigTD's expected state after initialization
4. Outputs them in a JSON format suitable for policy generation

## Important: RTMR Values

**RTMRs are hardcoded to zeros** to match what's in Azure Underhill quotes:
- **RTMR0**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **RTMR1**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **RTMR2**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- **RTMR3**: `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`

**Why zeros?** Azure CVM quotes represent Underhill (the virtual firmware), which doesn't use RTMRs. All RTMR values in Underhill quotes are zero. By using zeros in the policy, we:
- ✅ Match the actual quote values (no RTMR mismatch errors)
- ✅ Maintain consistency between policy and runtime
- ⚠️  BUT: RTMR verification provides **no security** in AzCVMEmu mode

**Security Note**: In AzCVMEmu mode, security relies on:
- ✅ **MRTD verification** - Actual measurement from Underhill
- ✅ **TCB evaluation** - Platform TCB status, date, evaluation number
- ✅ **Quote signature verification** - Cryptographic attestation
- ❌ **NOT RTMRs** - All zeros, no meaningful verification

For production bare-metal TDX, you would need real MigTD quotes with actual RTMR measurements.

## Building

From the tool directory:
```bash
cd tools/migtd-quote-extractor
cargo build --release
```

## Usage

### Basic usage:
```bash
./target/release/migtd-quote-extractor --output-json quote_data.json
```

### With verbose logging:
```bash
./target/release/migtd-quote-extractor --output-json quote_data.json --verbose
```

### With custom report data:
```bash
# Provide 48 bytes of hex-encoded report data
./target/release/migtd-quote-extractor --output-json quote_data.json --report-data "0102030405..."
```

## Output Format

The tool generates a JSON file with the following structure:

```json
{
  "mrtd": "...",           // 48 bytes hex
  "rtmr0": "...",          // 48 bytes hex
  "rtmr1": "...",          // 48 bytes hex
  "rtmr2": "...",          // 48 bytes hex
  "rtmr3": "...",          // 48 bytes hex
  "xfam": "...",           // 8 bytes hex
  "attributes": "...",     // 8 bytes hex
  "mr_config_id": "...",   // 48 bytes hex
  "mr_owner": "...",       // 48 bytes hex
  "mr_owner_config": "...", // 48 bytes hex
  "mrsigner": "...",       // 48 bytes hex
  "servtd_hash": "...",    // 48 bytes hex
  "isv_prod_id": 0,        // u16
  "isvsvn": 1              // u16
}
```

## Integration with Policy Generation

The extracted quote data is used by `build_custom_policy_from_quote.sh` to:
1. Update the policy template with real measurements
2. Generate a signed policy that includes correct MRTD values
3. Enable MRTD verification in AzCVMEmu mode

See `src/policy/sh_scripts/build_custom_policy_from_quote.sh` for the complete workflow.

## Requirements

- Must be run in an Azure TDX CVM with vTPM access
- Requires `az-tdx-vtpm` crate dependencies
- Linux environment with standard tools (jq, etc.)

## Notes

- The tool uses retry logic (3 attempts with 5-second delays) for vTPM report generation
- RTMRs are extracted but will be bypassed during verification in AzCVMEmu mode
- MRTD is the primary measurement that will be verified
