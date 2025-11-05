## migtd-collateral-generator tool

This tool can be used to fetch the platform TCB and enclave information from provisioning certification service (PCS) and generate the migtd collaterals.

It supports multiple collateral service providers:
- **Intel PCS** (Production and Pre-production environments)
- **Azure THIM** (Trusted Hardware Identity Management service)

### How to build

```
pushd tools/migtd-collateral-generator
cargo build
popd
```

### How to use

#### Help 
```
./target/debug/migtd-collateral-generator -h
```

#### Intel PCS Provider

- Generate migtd collaterals for production TDX-supported platforms:
  ```
  ./target/debug/migtd-collateral-generator --provider intel -o config/collateral_production_fmspc.json
  ```

- Generate migtd collaterals for pre-production TDX-supported platforms:
  ```
  ./target/debug/migtd-collateral-generator --provider intel --pre-production -o config/collateral_pre_production_fmspc.json
  ```

#### Azure THIM Provider

- Generate migtd collaterals from Azure THIM (US East region):
  ```
  ./target/debug/migtd-collateral-generator --provider azure-thim --azure-region useast -o config/collateral_azure_thim.json
  ```
  
  The tool automatically fetches the complete FMSPC list from Intel PCS and tries each one against Azure THIM, collecting all available platforms in that region.

- Fetch collaterals from multiple regions with automatic merging:
  ```
  # Fetch from all US and Europe regions, automatically merge and deduplicate by FMSPC
  ./target/debug/migtd-collateral-generator --provider azure-thim --azure-region all-us-europe -o config/collateral_merged.json
  
  # Or specify multiple regions manually
  ./target/debug/migtd-collateral-generator --provider azure-thim --azure-region useast,westus,northeurope -o config/collateral_merged.json
  ```

- Using different Azure regions:
  ```
  # West US
  ./target/debug/migtd-collateral-generator --provider azure-thim --azure-region westus -o config/collateral_westus.json
  
  # North Europe
  ./target/debug/migtd-collateral-generator --provider azure-thim --azure-region northeurope -o config/collateral_europe.json
  ```

- Generate collaterals with custom FMSPCs (bypasses automatic discovery):
  ```
  ./target/debug/migtd-collateral-generator --provider azure-thim --azure-region useast --fmspc 00906ED50000,00606A000000 -o config/collateral_custom.json
  ```

### Provider-Specific Notes

#### Intel PCS
- Automatically discovers all TDX-supported platforms via FMSPC listing API
- Supports both production and pre-production/sandbox environments
- Fetches collaterals for all E5 platforms with TDX support

#### Azure THIM
- Uses Intel PCS-compatible APIs hosted on Azure infrastructure
- **Automatic FMSPC Discovery**: Fetches the complete list of TDX-supported FMSPCs from Intel PCS, then queries Azure THIM for each one
- **Multi-Region Support**: Can fetch from multiple regions and automatically merge collaterals, deduplicating by FMSPC
  - Use `all-us-europe` to fetch from useast, westus, and northeurope
  - Or specify comma-separated regions: `useast,westus`
  - Tool creates temporary files for each region, then merges into final output
- Gracefully handles 404 responses for FMSPCs not deployed in a specific region
- Allows custom FMSPC specification via `--fmspc` option (bypasses automatic discovery)
- Root CA and Root CRL are fetched from Intel's certificate service (THIM doesn't cache these)
- Available in multiple Azure regions (useast, westus, northeurope, etc.)
- Typically finds 1-5 deployed FMSPCs per region depending on available hardware

### Design

The tool uses a provider abstraction pattern:
- `CollateralServiceProvider` trait defines the interface
- `IntelPcsProvider` implements Intel PCS-specific logic
- `AzureThimProvider` implements Azure THIM-specific logic
- Shared HTTP client logic maximizes code reuse
- Easy to extend for additional providers in the future

