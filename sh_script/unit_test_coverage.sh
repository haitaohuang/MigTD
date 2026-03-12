#!/bin/bash
# ============================================================================
# MigTD Code Coverage Collection (local)
#
# Runs all library unit tests AND emulation integration tests under
# cargo-llvm-cov and produces an HTML report.
#
# Prerequisites:
#   cargo install cargo-llvm-cov --locked
#   rustup component add llvm-tools-preview
#
# Usage:
#   ./sh_script/unit_test_coverage.sh              # all tests
#   ./sh_script/unit_test_coverage.sh --unit-only   # skip emulation tests
#
# The HTML report is written to target/llvm-cov/html/index.html
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

UNIT_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --unit-only) UNIT_ONLY=true ;;
        -h|--help)
            echo "Usage: $0 [--unit-only]"
            echo "  --unit-only   Run only library unit tests (skip emulation integration tests)"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# Verify cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "Error: cargo-llvm-cov not found. Install with:"
    echo "  cargo install cargo-llvm-cov --locked"
    exit 1
fi

# Override Cargo.toml profile settings that prevent coverage instrumentation
export CARGO_PROFILE_DEV_STRIP=false
export CARGO_PROFILE_DEV_LTO=false
export CARGO_PROFILE_RELEASE_LTO=false

# Work around a linker conflict: libservtd_attest_app.a defines its own
# atexit() which clashes with glibc when the coverage runtime
# (__llvm_profile_runtime) is linked in. --allow-multiple-definition lets
# the link succeed for the emulation binary builds.
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,--allow-multiple-definition"

COV_BINARIES_DIR="$PROJECT_ROOT/target/llvm-cov-binaries"
mkdir -p "$COV_BINARIES_DIR"

# Activate coverage instrumentation for all subsequent cargo invocations
echo "=== Configuring coverage environment ==="
LLVM_COV_ENV=$(cargo llvm-cov show-env --export-prefix)
eval "$LLVM_COV_ENV"

cargo llvm-cov clean --workspace

# =====================================================================
#  Library unit tests — mirrors `cargo xtask lib-test`
# =====================================================================
echo
echo "=== Running library unit tests ==="

cargo test -p crypto
cargo test -p attestation --features test
cargo test -p pci
cargo test -p virtio
cargo test -p vsock
cargo test -p migtd --features test_disable_ra_and_accept_all
cargo test -p migtd --features policy_v2
cargo test -p policy
cargo test -p policy --features policy_v2
cargo test -p migtd-collateral-generator

# =====================================================================
#  Emulation integration tests — mirrors integration-emu.yml
# =====================================================================
if [ "$UNIT_ONLY" = false ]; then
    echo
    echo "=== Running emulation integration tests ==="

    # --- skip-ra test ---
    echo "--- Emulation: skip-ra ---"
    chmod +x ./migtdemu.sh
    ./migtdemu.sh --skip-ra --both --no-sudo --log-level info
    cp target/release/migtd "$COV_BINARIES_DIR/migtd-skip-ra" 2>/dev/null || true

    # --- policy-v2 with mock report ---
    echo "--- Emulation: policy-v2 (mock report) ---"
    chmod +x ./sh_script/build_AzCVMEmu_policy_and_test.sh
    ./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report
    cp target/debug/migtd  "$COV_BINARIES_DIR/migtd-policy-v2-debug"  2>/dev/null || true
    cp target/release/migtd "$COV_BINARIES_DIR/migtd-policy-v2-release" 2>/dev/null || true

    # --- policy-v2 with mock report + igvm-attest ---
    echo "--- Emulation: policy-v2 (mock report + igvm-attest) ---"
    ./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report --extra-features igvm-attest
    cp target/debug/migtd  "$COV_BINARIES_DIR/migtd-policy-v2-igvm-debug"  2>/dev/null || true
    cp target/release/migtd "$COV_BINARIES_DIR/migtd-policy-v2-igvm-release" 2>/dev/null || true
fi

# =====================================================================
#  Generate HTML report
#
#  When emulation tests ran, we use the low-level llvm-profdata/llvm-cov
#  tools directly so we can pass --object for each snapshotted binary.
#  This merges coverage from unit tests AND emulation runs.
# =====================================================================
echo
echo "=== Generating HTML coverage report ==="

EMU_BINS=()
for bin in "$COV_BINARIES_DIR"/migtd-*; do
    [ -f "$bin" ] && EMU_BINS+=("$bin")
done

if [ "${#EMU_BINS[@]}" -gt 0 ]; then
    # Locate the llvm tools shipped with the Rust toolchain
    TOOLCHAIN_BIN="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"
    LLVM_PROFDATA="$TOOLCHAIN_BIN/llvm-profdata"
    LLVM_COV_BIN="$TOOLCHAIN_BIN/llvm-cov"

    # Merge all profraw files
    $LLVM_PROFDATA merge -sparse target/MigTD-*.profraw -o target/merged-all.profdata

    # Collect unit-test binaries from target/debug/deps
    ALL_BINS=()
    for b in target/debug/deps/*-????????????????; do
        if [ -f "$b" ] && [ -x "$b" ] && [[ ! "$b" == *.d ]] && [[ ! "$b" == *.so ]]; then
            ALL_BINS+=("$b")
        fi
    done
    ALL_BINS+=("${EMU_BINS[@]}")

    # Build -object flags (first binary is positional, rest use -object)
    OBJ_FLAGS=()
    for ((i=1; i<${#ALL_BINS[@]}; i++)); do
        OBJ_FLAGS+=("-object" "${ALL_BINS[$i]}")
    done

    mkdir -p target/llvm-cov/html
    $LLVM_COV_BIN show \
        --instr-profile=target/merged-all.profdata \
        "${ALL_BINS[0]}" "${OBJ_FLAGS[@]}" \
        --format=html \
        --output-dir=target/llvm-cov/html \
        --ignore-filename-regex='(\.cargo/registry|rustc/)'

    echo
    echo "=== Coverage summary ==="
    $LLVM_COV_BIN report \
        --instr-profile=target/merged-all.profdata \
        "${ALL_BINS[0]}" "${OBJ_FLAGS[@]}" \
        --ignore-filename-regex='(\.cargo/registry|rustc/)' \
        | tail -1
else
    cargo llvm-cov report \
        --html \
        --output-dir target/llvm-cov/html
fi

echo
echo "✅ Coverage report: target/llvm-cov/html/index.html"
