#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
TEST_DIR="$REPO_ROOT/target/policy-only-contract-test"
POLICY="$TEST_DIR/migtd.policy_v2.json"
EXPECTED="$TEST_DIR/expected.json"
ACTUAL="$TEST_DIR/actual.json"
MAKE_DRY_RUN="$TEST_DIR/make-dry-run.txt"

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"

make -C "$SCRIPT_DIR" generate-enrollment-policy \
    IGVM_POLICY_SIDECAR="${POLICY#$REPO_ROOT/}"

jq -e '
    keys == ["policyData"] and
    (.policyData | type == "object") and
    (has("signature") | not) and
    (.policyData | has("servtdCollateral") | not)
' "$POLICY" >/dev/null

jq -S 'del(.servtdCollateral)' "$REPO_ROOT/config/templates/policy_v2.json" > "$EXPECTED"
jq -S '.policyData' "$POLICY" > "$ACTUAL"
cmp "$EXPECTED" "$ACTUAL"

make -n -C "$SCRIPT_DIR" build-igvm \
    IGVM_POLICY_SIDECAR="${POLICY#$REPO_ROOT/}" > "$MAKE_DRY_RUN"
grep -F -- '--non-bootable-enrollment-artifact' "$MAKE_DRY_RUN" >/dev/null
grep -F -- "--policy ${POLICY#$REPO_ROOT/}" "$MAKE_DRY_RUN" >/dev/null
if grep -E -- '--root-ca|--policy-issuer-chain|--signer-anchor|--servtd-corim' "$MAKE_DRY_RUN" >/dev/null; then
    echo "public build command contains a forbidden enrollment input" >&2
    exit 1
fi
if grep -E -- 'servtd-corim-generator|private[_-]key|openssl gen' "$MAKE_DRY_RUN" >/dev/null; then
    echo "public build command invokes local signing or key generation" >&2
    exit 1
fi

grep -F 'TARGET="build-igvm"' "$SCRIPT_DIR/docker_build_igvm.sh" >/dev/null
grep -F 'migtd.policy_v2.json' "$SCRIPT_DIR/docker_build_igvm.sh" >/dev/null

echo "Policy-only enrollment artifact contract verified"
