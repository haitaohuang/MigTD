---
name: run-local-ci
description: Run all CI tests that can be executed locally for the MigTD project. Use this when asked to run CI, run tests, run checks, or verify changes before pushing.
---

# Run Local CI Tests for MigTD

This skill runs all CI checks from the GitHub Actions workflows that can be executed locally (without special hardware like TDX, or GitHub-specific services like CodeQL/Scorecard/Trivy).

## Prerequisites

### Required environment variables

These must be set for the build to work (CI sets them in workflow `env:`):

```bash
export AS=nasm
export AR=llvm-ar
export CC=clang
```

### Required system packages

The CI installs these via `.github/actions/setup-build-environment/action.yml`:

- **Always needed**: nasm, llvm/clang (v10+), build-essential, ocaml, automake, autoconf, libtool, python3, libssl-dev, git, cmake, perl
- **For integration-emu tests**: jq, openssl
- **For fuzzing**: cargo-afl, cargo-fuzz
- **Rust target**: `x86_64-unknown-none` (add with `rustup target add x86_64-unknown-none`)

### Preparation

Run before any tests to patch vendored dependencies:

```bash
bash sh_script/preparation.sh
```

## Test Groups

Run these test groups in order. Stop and fix issues if any group fails before proceeding to the next.

### 1. Format Checks (from `.github/workflows/format.yml`)

```bash
cargo fmt -- --check
cargo check
cargo clippy --features stack-guard,virtio-vsock,virtio-serial,vmcall-interrupt
```

**Fixing issues:**
- `cargo fmt` failures: auto-fix with `cargo fmt`
- Clippy warnings in project `src/` code: fix with `cargo clippy --fix --allow-dirty --allow-staged --lib -p <crate>` for each affected crate, then `cargo fmt` to reformat any auto-fix output
- Clippy warnings in `spdmlib` (vendored dep submodule in `deps/spdm-rs`): **ignore** — not owned by this project
- Clippy warnings in `deps/td-shim` or `deps/td-shim-AzCVMEmu`: **ignore** — vendored submodules

### 2. Dependency Security (from `.github/workflows/deny.yml`)

```bash
cargo deny check advisories
cargo deny check bans
cargo deny check sources
```

- The `sources` check uses `continue-on-error` in CI, so treat failures as warnings

### 3. Library Crates Build & Test (from `.github/workflows/library.yml`)

```bash
cargo xtask lib-build
cargo xtask lib-test
```

### 4. Main Build Matrix (from `.github/workflows/main.yml`)

This builds MigTD binary images across all device/policy/protocol/build-type combinations, plus all tools.

#### 4a. Build MigTD images

The CI matrix covers 32 combinations: `device × policy_version × protocol × build_type`:
- **device**: virtio-vsock (default), virtio-serial, vmcall-vsock, vmcall-raw
- **policy_version**: v1 (default), v2
- **protocol**: tls (default), spdm
- **build_type**: release (default), debug

Build command construction rules:
1. Start with `cargo image`
2. If device is NOT virtio-vsock: add `--no-default-features --features stack-guard,<device>`
3. If protocol is spdm: add `,spdm_attestation` to features (or `--features spdm_attestation` for default device)
4. If policy is v2: add `--policy-v2 --policy config/templates/policy_v2_signed.json --policy-issuer-chain config/templates/policy_issuer_chain.pem`
5. If build_type is debug: add `--debug`

**Full matrix** (run all 32 — this is what CI does):

```bash
for device in virtio-vsock virtio-serial vmcall-vsock vmcall-raw; do
  for policy in v1 v2; do
    for protocol in tls spdm; do
      for build_type in release debug; do
        CMD="cargo image"
        if [ "$device" != "virtio-vsock" ]; then
          FEATURES="stack-guard,$device"
          if [ "$protocol" = "spdm" ]; then FEATURES="$FEATURES,spdm_attestation"; fi
          CMD="$CMD --no-default-features --features $FEATURES"
        else
          if [ "$protocol" = "spdm" ]; then CMD="$CMD --features spdm_attestation"; fi
        fi
        if [ "$policy" = "v2" ]; then
          CMD="$CMD --policy-v2 --policy config/templates/policy_v2_signed.json --policy-issuer-chain config/templates/policy_issuer_chain.pem"
        fi
        if [ "$build_type" = "debug" ]; then CMD="$CMD --debug"; fi
        echo "=== $device / $policy / $protocol / $build_type ==="
        $CMD
      done
    done
  done
done
```

**Quick smoke test** (representative subset covering each axis):

```bash
# Default: virtio-vsock, v1, tls, release
cargo image

# Non-default device
cargo image --no-default-features --features stack-guard,virtio-serial

# vmcall-vsock
cargo image --no-default-features --features stack-guard,vmcall-vsock

# vmcall-raw
cargo image --no-default-features --features stack-guard,vmcall-raw

# SPDM protocol
cargo image --features spdm_attestation

# Policy v2
cargo image --policy-v2 --policy config/templates/policy_v2_signed.json --policy-issuer-chain config/templates/policy_issuer_chain.pem

# Debug build
cargo image --debug
```

#### 4b. Build tools

```bash
cargo build -p json-signer
cargo build -p migtd-collateral-generator
cargo build -p migtd-hash
cargo build -p migtd-policy-generator
cargo build -p migtd-policy-verifier
cargo build -p servtd-collateral-generator
```

### 5. Integration Emulation Tests (from `.github/workflows/integration-emu.yml`)

These tests run MigTD in AzCVMEmu emulation mode. Always read the current matrix from the workflow file to catch any new entries:

```bash
grep 'test-command:' .github/workflows/integration-emu.yml
```

Run each test command with its corresponding timeout. The known matrix entries are:

#### 5a. Build and Test (Skip RA)
```bash
timeout 300 ./migtdemu.sh --skip-ra --both --no-sudo --log-level info
```

#### 5b. Policy v2 with Mock Report
```bash
timeout 900 ./migtdemu.sh --policy-v2 --policy-file ./config/AzCVMEmu/policy_v2_signed.json --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem --mock-report --both --no-sudo --log-level info
```

#### 5c. Policy v2 with Mock Report and IGVM Attest
```bash
timeout 900 ./migtdemu.sh --policy-v2 --policy-file ./config/AzCVMEmu/policy_v2_signed.json --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem --mock-report --features igvm-attest --both --no-sudo --log-level info
```

#### 5d. Rebind Prepare (Skip RA)
```bash
timeout 300 ./migtdemu.sh --operation rebind-prepare --policy-file ./config/AzCVMEmu/policy_v2_signed.json --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem --skip-ra --both --no-sudo --log-level info
```

#### 5e. Rebind Prepare (Mock Report)
```bash
timeout 900 ./migtdemu.sh --operation rebind-prepare --policy-file ./config/AzCVMEmu/policy_v2_signed.json --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem --mock-report --both --no-sudo --log-level info
```

**Verifying success:** Each test should exit 0. The `migtdemu.sh` script prints `✓✓✓ SUCCESS: (<operation>) completed! ✓✓✓` (e.g., `✓✓✓ SUCCESS: (migration) completed! ✓✓✓` or `✓✓✓ SUCCESS: (rebind-prepare) completed! ✓✓✓`) on success.

### 6. Fuzzing (from `.github/workflows/fuzz.yml`) — Optional

Fuzzing is time-intensive and typically not required for every change. Run when modifying parsing, crypto, or protocol code.

**Prerequisites:**
```bash
cargo install cargo-afl && cargo afl config --build --force
cargo install cargo-fuzz
```

**Run fuzz tests:**
```bash
# AFL fuzzing (quick 10-second runs per target)
bash sh_script/fuzzing.sh -n afl_all -t 10

# libFuzzer fuzzing (60-second runs per target)
bash sh_script/fuzzing.sh -n libfuzzer_all -t 60
```

Fuzz targets cover: `src/crypto`, `src/devices/vsock`, `src/devices/virtio`, `src/devices/virtio_serial`, `src/devices/vmcall_raw`, `src/policy`, `src/migtd`.

## Important Notes

- **Timeouts**: Integration tests have timeouts (300s for skip-ra/rebind, 900s for policy tests). A hang indicates a real problem.
- **No sudo**: Always use `--no-sudo` for local emulation testing unless TPM devices require elevated access.
- **Generated artifacts**: Policy v2 and rebind tests regenerate `config/AzCVMEmu/policy_v2_signed.json` and `config/AzCVMEmu/policy_issuer_chain.pem`. Revert with `git checkout -- config/AzCVMEmu/` after tests if these changes are unintentional.
- **Submodule warnings**: All warnings from code under `deps/` (spdm-rs, td-shim, td-shim-AzCVMEmu) are in vendored submodules. Do NOT attempt to fix them.
- **Port conflicts**: The emulation tests use port 8001 by default. Ensure no other process is listening on that port before running. Run tests sequentially, not in parallel.
- **Feature flags for testing**: The `use-mock-quote` feature enables mock quote retry logic testing (forces first attempt to fail, uses 100ms retry delay instead of 5s). Pass `--features use-mock-quote` to `migtdemu.sh` to exercise this path.
- **Log files**: `migtdemu.sh` creates log files named by operation (`migtd_migration_source.log`, `migtd_migration_destination.log`, `dest_migration_out.log`, and for rebind tests `migtd_rebind-prepare_source.log`, `migtd_rebind-prepare_destination.log`, `dest_rebind-prepare_out.log`). Check these for debugging failures.
- **Rust toolchain**: The project pins the toolchain in the `rust-toolchain` file at the repo root. Ensure it matches via `rustup show active-toolchain`.

## Workflows NOT runnable locally

These workflows require GitHub infrastructure or special hardware and should be skipped:

- `integration-tdx.yml` — requires TDX hardware (self-hosted runner)
- `codeql.yml` — GitHub CodeQL static analysis
- `dependency-review.yml` — GitHub dependency vulnerability scanning
- `scorecard.yml` — OpenSSF Scorecard (requires GitHub token and API)
- `trivy.yml` — Trivy container scanner (GitHub-specific upload)
- `oss-fuzz.yml` — Google OSS-Fuzz integration (CIFuzz infrastructure)
