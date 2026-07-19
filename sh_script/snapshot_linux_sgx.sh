#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
src_root=${1:-"${repo_root}/deps/linux-sgx"}
dst_root=${2:-"${repo_root}/deps/linux-sgx-snap"}

if [[ ! -d "${src_root}" ]]; then
    echo "source tree not found: ${src_root}" >&2
    exit 1
fi

if ! git -C "${src_root}" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "source tree is not a git checkout: ${src_root}" >&2
    exit 1
fi

readarray -t keep_paths <<'EOF'
Makefile
buildenv.mk
README.md
common/inc
common/src/sgx_read_rand.cpp
sdk/Makefile
sdk/Makefile.source
sdk/cpprt
sdk/edger8r
sdk/tlibc
sdk/tlibcxx
sdk/tlibthread
sdk/tmm_rsrv
sdk/trts
sdk/tsafecrt
sdk/tsetjmp
external/rdrand
external/sgx-emm/create_symlink.sh
external/sgx-emm/emm_src/include
external/sgx-emm/emm_src/LICENSE
external/sgx-emm/emm_src/README.md
external/dcap_source/README.md
external/dcap_source/QuoteGeneration/README.md
external/dcap_source/QuoteGeneration/Makefile
external/dcap_source/QuoteGeneration/buildenv.mk
external/dcap_source/QuoteGeneration/common/inc
external/dcap_source/QuoteGeneration/qpl/inc
external/dcap_source/QuoteGeneration/pce_wrapper/inc
external/dcap_source/QuoteGeneration/quote_wrapper/common/inc
external/dcap_source/QuoteGeneration/quote_wrapper/qgs_msg_lib
external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest
external/dcap_source/QuoteGeneration/quote_wrapper/tdx_attest
external/dcap_source/QuoteGeneration/quote_wrapper/tdx_verify
external/dcap_source/QuoteVerification/README.md
external/dcap_source/QuoteVerification/buildenv.mk
external/dcap_source/QuoteVerification/prepare_sgxssl.sh
external/dcap_source/QuoteVerification/QvE/Enclave
external/dcap_source/QuoteVerification/QvE/Include
external/dcap_source/QuoteVerification/QvE/Makefile
external/dcap_source/QuoteVerification/appraisal/common
external/dcap_source/QuoteVerification/dcap_quoteverify/inc
external/dcap_source/QuoteVerification/QVL/README.md
external/dcap_source/QuoteVerification/QVL/Src
external/dcap_source/external/jwt-cpp/LICENSE
external/dcap_source/external/jwt-cpp/README.md
external/dcap_source/external/jwt-cpp/include
EOF

keep_match() {
    local path=$1
    local keep
    for keep in "${keep_paths[@]}"; do
        if [[ "${path}" == "${keep}" || "${path}" == "${keep}/"* ]]; then
            return 0
        fi
    done
    return 1
}

copy_tracked_file() {
    local rel=$1
    mkdir -p "${dst_root}/$(dirname -- "${rel}")"
    cp -a "${src_root}/${rel}" "${dst_root}/${rel}"
}

rm -rf "${dst_root}"
mkdir -p "${dst_root}"

while IFS= read -r rel; do
    [[ -z "${rel}" ]] && continue
    if keep_match "${rel}"; then
        copy_tracked_file "${rel}"
    fi
done < <(git -C "${src_root}" ls-files --recurse-submodules)

mkdir -p "${dst_root}/external/dcap_source/QuoteVerification/sgxssl"
touch "${dst_root}/external/dcap_source/QuoteVerification/sgxssl/.gitkeep"
mkdir -p "${dst_root}/psw"
touch "${dst_root}/psw/.gitkeep"
mkdir -p "${dst_root}/external/dcap_source/prebuilt/openssl/inc"
touch "${dst_root}/external/dcap_source/prebuilt/openssl/inc/.gitkeep"

python3 - "${dst_root}/Makefile" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = """servtd_attest_preparation:\n# Only enable the download from git\n\tgit submodule update --init --recursive external/dcap_source external/sgx-emm/emm_src\n\t./external/sgx-emm/create_symlink.sh\n\t./external/dcap_source/QuoteVerification/prepare_sgxssl.sh nobuild\n"""
new = """servtd_attest_preparation:\n# Snapshot already vendors the traced source subset; only local prep remains.\n\t./external/sgx-emm/create_symlink.sh\n\t./external/dcap_source/QuoteVerification/prepare_sgxssl.sh nobuild\n"""
text = path.read_text()
if old not in text:
    raise SystemExit(f"failed to patch {path}: expected servtd_attest_preparation block not found")
path.write_text(text.replace(old, new, 1))
PY

linux_sgx_sha=$(git -C "${src_root}" rev-parse HEAD)
linux_sgx_tag=$(git -C "${src_root}" describe --tags --exact-match 2>/dev/null || echo "<none>")
if [[ "${linux_sgx_tag}" == "<none>" && "${linux_sgx_sha}" == "d6c45cc05aead731b1bd8f7df081488ad9aebaa9" ]]; then
    linux_sgx_tag="sgx_2.15"
fi
dcap_sha=$(git -C "${src_root}/external/dcap_source" rev-parse HEAD)
dcap_tag=$(git -C "${src_root}/external/dcap_source" describe --tags --exact-match 2>/dev/null || echo "<none>")
if [[ "${dcap_tag}" == "<none>" && "${dcap_sha}" == "a19c0c7703bc78d8adfb400ee966546aaaac93a8" ]]; then
    dcap_tag="LD_1.33"
fi
sgx_emm_sha=$(git -C "${src_root}/external/sgx-emm/emm_src" rev-parse HEAD)
sgx_emm_tag=$(git -C "${src_root}/external/sgx-emm/emm_src" describe --tags --exact-match 2>/dev/null || echo "<none>")
qvl_sha=$(git -C "${src_root}/external/dcap_source/QuoteVerification/QVL" rev-parse HEAD)
qvl_tag=$(git -C "${src_root}/external/dcap_source/QuoteVerification/QVL" describe --tags --exact-match 2>/dev/null || echo "<none>")
jwt_cpp_sha=$(git -C "${src_root}/external/dcap_source/external/jwt-cpp" rev-parse HEAD)
jwt_cpp_tag=$(git -C "${src_root}/external/dcap_source/external/jwt-cpp" describe --tags --exact-match 2>/dev/null || echo "<none>")
ipp_sha=$(git -C "${src_root}/external/ippcp_internal/ipp-crypto" rev-parse HEAD)
ipp_tag=$(git -C "${src_root}/external/ippcp_internal/ipp-crypto" describe --tags --exact-match 2>/dev/null || echo "<none>")

cat > "${dst_root}/PROVENANCE.md" <<EOF
# linux-sgx-snap provenance

This directory is a pruned, plain-file snapshot generated by
\`sh_script/snapshot_linux_sgx.sh\`. It is intended to replace the live
\`deps/linux-sgx\` build input for MigTD's attestation library path while
removing unrelated submodules and packaging trees from the shipped build.

## Source revisions

| Component | Revision | Tag | Status in snapshot |
|---|---|---|---|
| intel/linux-sgx | \`${linux_sgx_sha}\` | \`${linux_sgx_tag}\` | retained subset |
| intel/SGXDataCenterAttestationPrimitives | \`${dcap_sha}\` | \`${dcap_tag}\` | retained subset |
| intel/sgx-emm | \`${sgx_emm_sha}\` | \`${sgx_emm_tag}\` | retained subset (headers only) |
| intel/SGX-TDX-DCAP-QuoteVerificationLibrary | \`${qvl_sha}\` | \`${qvl_tag}\` | retained subset |
| Thalhammer/jwt-cpp | \`${jwt_cpp_sha}\` | \`${jwt_cpp_tag}\` | retained subset (headers only) |
| intel/ipp-crypto | \`${ipp_sha}\` | \`${ipp_tag}\` | pruned (no traced source-file opens) |

## Retained roots and rationale

The snapshot retains tracked files under these roots:

\`\`\`text
$(printf '%s\n' "${keep_paths[@]}")
\`\`\`

Why these are kept:

- \`Makefile\`, \`buildenv.mk\`, and the retained \`sdk/\` subset are the SGX SDK
  build machinery and trusted runtime sources actually opened when building
  \`servtd_attest_preparation\` and \`servtd_attest\`.
- \`common/inc\` plus \`common/src/sgx_read_rand.cpp\` are directly compiled or
  included by the traced build.
- \`external/dcap_source/QuoteGeneration/*\` retained above covers the traced
  quote-wrapper path: \`servtd_attest\`, \`tdx_attest\`, \`tdx_verify\`,
  \`qgs_msg_lib\`, and their shared headers.
- \`external/dcap_source/QuoteVerification/QvE\` and
  \`external/dcap_source/QuoteVerification/QVL/Src\` are load-bearing: the
  traced \`install_objs\` build compiled QvE objects and QVL parser/library
  sources into the final static archive.
- \`external/dcap_source/external/jwt-cpp/include\` is retained because
  \`QvE/Enclave/qve.cpp\` opened \`jwt-cpp/jwt.h\` during the traced build.
- \`external/sgx-emm/emm_src/include\` plus \`create_symlink.sh\` are retained
  because the traced build opened the symlinked \`common/inc/sgx_mm.h\` and
  \`common/inc/internal/emm_private.h\` headers produced from this source.
- \`external/rdrand\` is retained because \`quote_wrapper/servtd_attest\`
  configures and builds \`librdrand.a\` on the traced path.
- The empty \`external/dcap_source/QuoteVerification/sgxssl/\` directory is
  retained via a \`.gitkeep\` placeholder so \`prepare_sgxssl.sh\` can continue
  downloading Intel SGX SSL/OpenSSL at build time without vendoring those
  blobs into git history.
- An otherwise-empty \`psw/\` placeholder directory is retained only because the
  SGX SDK makefiles pass \`-I\$(ROOT)/psw\`; without the directory, GCC raises a
  fatal \`-Wmissing-include-dirs\` error even though no \`psw/\` source files are
  opened on the traced path.
- An otherwise-empty \`external/dcap_source/prebuilt/openssl/inc/\` placeholder
  directory is retained only to satisfy a non-fatal include-path reference in
  the QvE makefile without vendoring prebuilt OpenSSL headers.

## Pruned roots and rationale

The following notable trees were excluded because the traced build opened no
source files beneath them (or only the submodule's \`.git\` gitlink), so they
are not part of the live MigTD attestation-library build:

- \`external/openmp\`
- \`external/dnnl\`
- \`external/protobuf\`
- \`external/cbor\`
- \`external/ippcp_internal/ipp-crypto\`
- \`external/dcap_source/QuoteVerification/QuoteVerificationService\`
- \`external/dcap_source/external/wasm-micro-runtime\`
- \`psw/\`
- \`linux/installer/\`
- \`linux/reproducibility/\`
- \`SampleCode/\`
- all unlisted SGX SDK libraries/tools outside the retained \`sdk/\` subset
- all unlisted DCAP QuoteGeneration / QuoteVerification / tool / driver /
  packaging trees outside the retained roots above

Notes:

- \`QuoteVerificationService\` and \`wasm-micro-runtime\` were probed only via
  their submodule gitlink metadata during recursive submodule initialization;
  no source/header files under those trees were opened by the actual build.
- The snapshot keeps an empty \`psw/\` directory only as a compiler include-path
  compatibility shim; no \`psw/\` source files are vendored.
- The snapshot keeps an empty \`external/dcap_source/prebuilt/openssl/inc/\`
  directory only as an include-path compatibility shim; no prebuilt OpenSSL
  headers are vendored.
- The snapshot intentionally keeps the OpenSSL/SGXSSL download-at-build-time
  flow from \`prepare_sgxssl.sh\`; the downloaded source and built package are
  **not** vendored here.
- The snapshot is plain tracked files only: no \`.git\`, no nested gitlinks,
  and no \`.gitmodules\`.
EOF

echo "snapshot written to ${dst_root}"
