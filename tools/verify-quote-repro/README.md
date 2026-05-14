# `verify-quote-repro`

A minimal host-side reproducer for the heap-exhaustion / leak symptom
described in
`~/.copilot/session-state/.../files/servtd_attest_heap_issue.md`.

The tool loads a saved TDX quote and an Azure-THIM collateral JSON
(produced by `migtd-collateral-generator`) and calls
`verify_quote_integrity_ex()` in a loop, printing per-call RSS, the
tlibc dlmalloc high-water mark, and the dlmalloc verdict, so any leak
or fragmentation growth inside the C verifier is directly visible.

## Build modes

Two build modes drive different questions:

| Mode (default) | Build command | Allocator the verifier sees | Crypto library | Question it answers |
|---|---|---|---|---|
| `bounded-heap` | `cargo build --release` | Same tlibc dlmalloc + sbrk that MigTD links in-image, bounded by `--heap-size` | **SgxSSL** (bundled, `OPENSSL_malloc` → tlibc dlmalloc) — matches MigTD's in-image build | Does the **verifier itself** (QvE + SgxSSL) leak / grow heap usage across calls in the bounded arena? Reproduces in-MigTD `#UD` behaviour and gives a true `g_peak_heap_used`. |
| plain | `cargo build --release --no-default-features` | Host glibc malloc — `--heap-size` is effectively ignored | host `libcrypto` (SgxSSL stripped by `fixup-libservtd-attest-lib.sh`) — matches the AzCVMEmu build | Does the verifier leak **process memory** (allocations never returned to the OS)? Easy to also drive under valgrind / asan. |

The `bounded-heap` build does several non-trivial things in `build.rs`:

1. Runs the same `make` targets as `src/attestation/build.rs`, producing
   the **un-fixed-up** `libservtd_attest.a` (with SgxSSL bundled).
2. Copies that archive into a staging dir and `ar d`'s out two members:
   - `errno.o`: its `__errno` would conflict with our forwarder stub.
   - `sgx_read_rand.o`: upstream impl does an Intel-vendor cpuid check
     and aborts on AMD hosts; we override with a glibc-`rand()` shim.
3. Extracts tlibc's `malloc.o` + `sbrk.o` and splices everything into a
   single relocatable `.o` via `ld -r -u init_heap -u verify_quote_integrity_ex`.
   That forces only the transitively-needed members of the 1500+ -member
   archive to be pulled in. SgxSSL's `OPENSSL_malloc` etc. land in this
   combined object; they call into tlibc's `malloc`, so every X509 /
   EC_KEY / EVP / BIGNUM / error-queue allocation hits the bounded arena.
4. Generates a localize list dynamically (via `nm` over the combined
   object) so every export except the small API surface (`init_heap`,
   `verify_quote_integrity_ex`, `heap_base`, `heap_size`, `g_peak_heap_used`,
   `vqr_static_heap_*`, `servtd_get_quote`) becomes `LOCAL`. This is
   essential — otherwise the bundled libunwind / dwarf / memcpy / memset
   / OpenSSL symbols clash with libstd's dependencies and corrupt
   process startup. (No host `-lcrypto` is on the final link command,
   since SgxSSL is bundled inside.)
5. Adds a high-priority constructor (`stubs.c`) that pre-arms tlibc's
   heap with a 16 MiB static buffer *before* the QvE / PCK / SgxSSL
   C++ static initializers run — those would otherwise `malloc()`
   against `heap_base = NULL` and trap `ud2` from the C++ runtime.
   `main()` reads `g_peak_heap_used` immediately and reports the
   static-init cost (~60 KiB) before re-arming the heap to `--heap-size`.
6. Adds a `u_sgxssl_ftime` OCALL shim in `stubs.c` (host `gettimeofday`)
   so SgxSSL's `ftime` (used for OpenSSL random seeding) resolves.

## Get inputs

### 1. Quote

Capture a real TDX quote on a TDX-capable system. Easiest path is to run
the existing C harness inside the same MigTD VM image:

```bash
cd deps/linux-sgx/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux
make test_app_static
./test_app_static          # writes quote.dat in the working directory
```

If you have not collected one yet but already have a MigTD image running
on a TiP node, the easiest capture is to add a one-shot hexdump in
`src/attestation/src/igvmattest.rs::get_quote_igvm` (right after the
quote returns) that prints the full bytes; copy from the console log.

For convenience, `captured_quote.dat` (5006 bytes, FMSPC `90C06F000000`)
extracted from `migtd_spdm_cert_rot_failed_w_ticks_int_diags 1.txt` is
checked into this directory.

### 2. Collateral JSON

```bash
cargo build --release -p migtd-collateral-generator
target/release/migtd-collateral-generator \
    --provider azure-thim \
    --azure-region useast \
    --output collateral_thim.json
```

(See `sh_script/Azure/build_azure_mock_test.sh` step "Fetching Fresh
Collaterals from Azure THIM" — this tool encapsulates the same call.)

`collateral_thim_fresh.json` is checked in for convenience.

## Run

```bash
# Bounded mode (default). 512 KiB heap — the same size that crashed on TiP.
./target/release/verify-quote-repro \
    --quote captured_quote.dat \
    --collateral collateral_thim_fresh.json \
    --heap-size 0x80000 \
    --iterations 16

# Same with the 2 MiB workaround:
./target/release/verify-quote-repro \
    --quote captured_quote.dat \
    --collateral collateral_thim_fresh.json \
    --heap-size 0x200000 \
    --iterations 16

# Plain mode (host glibc) — easy to also drive under valgrind / asan.
cargo build --release --no-default-features
./target/release/verify-quote-repro \
    --quote captured_quote.dat \
    --collateral collateral_thim_fresh.json \
    --iterations 16
```

### Override FMSPC

By default the tool extracts the FMSPC from the PCK certificate
embedded in the quote and picks the matching platform in the collateral.
Pass `--fmspc 00c06f000000` to override.

## What the output means

Bounded mode prints `tlibc_peak_heap_used` per iteration — this is
tlibc's `g_peak_heap_used`, the sbrk high-water mark inside the
`init_heap`-supplied arena. It is monotonically non-decreasing; it
never shrinks even after `free()` because tlibc's `sbrk(-n)` only
fires if the very top of the heap is free.

A stable peak value across N iterations means the verifier reuses
its allocations — i.e. **no leak**. The value at which it stabilizes
is the verifier's effective working-set in the bounded arena, against
which `ATTEST_HEAP_SIZE` must be sized.

`rc=0x22` is `SGX_QL_QV_RESULT_OUT_OF_DATE` — a soft fail returned
*after* the verifier has walked the full crypto / cert-chain /
TCB-info / QE-identity / SgxSSL X509 paths, so every allocation site
that matters has been exercised. It does not affect the leak diagnosis.
If the captured quote's TCB SVN happens to match the current THIM
baseline, you would see `rc=0` instead — the heap behaviour is
identical either way.

## Caveats

* The `bounded-heap` build links the **un-fixed-up** `libservtd_attest.a`
  (SgxSSL bundled). The `plain` build links the AzCVMEmu fixed-up
  `libservtd_attest_app.a` (SgxSSL stripped) + host `-lcrypto`. So the
  two modes differ in BOTH allocator and crypto library, and they answer
  different questions (see table above).
* The bounded build runs on top of the host glibc startup, so the
  16 MiB pre-init buffer + a `__libc_start_main` driving the
  `.init_array` are needed to make the C++ static initializers happy.
  These are not present inside MigTD (no_std, no glibc crt), which is
  why the in-image build does not need this scaffolding.
* Expected per-call `tlibc_peak_heap_used` (bounded mode, with SgxSSL):
  **~324 KiB**, stable across iterations. The original MigTD
  `ATTEST_HEAP_SIZE` was 512 KiB → on TiP loopback (2 verifies + ~60 KiB
  C++ static init + ~80 KiB live MigTD state per call) the arena tips
  over. 2 MiB gives ample headroom.
