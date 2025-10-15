
## migtd-policy-verifier tool

This tool can be used to verify MigTD signed policy files and issuer certificate chains, and optionally check for a specific FMSPC key in the collaterals.

### How to build

```
pushd tools/migtd-policy-verifier
cargo build --release
popd
```

### How to use

- Help
    ```
    ./target/release/migtd-policy-verifier -h
    ```

- Verify a signed policy and issuer chain:
    ```
    ./target/release/migtd-policy-verifier --policy <path/to/policy_v2_signed.json> --cert-chain <path/to/policy_issuer_chain.pem>
    ```

- Verify and check for a specific FMSPC key:
    ```
    ./target/release/migtd-policy-verifier --policy <path/to/policy_v2_signed.json> --cert-chain <path/to/policy_issuer_chain.pem> --fmspc <FMSPC string>
    ```

### Exit Codes
- `0`: Success
- `1`: Verification or parsing error
- `2`: FMSPC not found in collaterals
