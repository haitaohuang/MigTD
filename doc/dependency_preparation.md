# Dependency Preparation

Run the repository preparation script after a fresh clone, submodule update, or
`git clean -fdx`:

```bash
bash sh_script/preparation.sh
```

## Static SymCrypt integration

Preparation applies the maintained patches in `sh_script/patches` without
resetting or cleaning a submodule. It is idempotent and fails if a patch cannot
be applied or recognized as already applied.

- `td-shim-symcrypt.patch` supplies the TD platform, native boot verification
  and image-tool crypto, backend-independent measurement hashing, and
  XMM-preserving interrupt entry. It includes the existing enroller checksum
  correction.
- `spdm-symcrypt-provider.patch` makes optional `std` feature forwarding weak,
  constrains the public spin-mutex ABI, and rejects duplicate asymmetric
  provider registration. MigTD patches the SDK's Git SPDM dependency to this
  local submodule, so callbacks and protocol users share one registry.

The tracked `deps/td-shim-AzCVMEmu` sources use the same hash implementation for
emulated TDINFO and mock reports without changing test-only attestation rules.
They are not a submodule and do not need a preparation patch.

The selected firmware and native image tools use the pinned
`haitaohuang/rust-symcrypt-static` backend. The historical `ring` submodules and
optional upstream backends are not selected by these builds; preparation no
longer patches or resets them. Intel QVL/SGXSSL remains unchanged.

Builds require CMake, Clang, and binutils (`objcopy` for native guard isolation
and the image's symbol-stripped shim copy).
All native-building workflows, including format checks, use the shared build
setup action's Clang 18.1.8. Clang 10 fails to compile the native backend with
speculative-load hardening; keep the hardening and use the shared compiler setup.
`python3 sh_script/check_crypto_dependencies.py` checks both
firmware protocols, shim boot profiles, and native image/signing tools. CI and
the local gauntlet run the same check. It does not claim to inspect QVL's native
dependency graph or unrelated host network/emulation libraries.

`cargo image` retains the original `td-shim` ELF for debugging and packages
`td-shim-for-image.elf` without non-runtime symbols. Debug logging and the
fixed IPL size limit are unchanged.

Symbol-preserving payload builds must match `xtask::BuildArgs::build_migtd`:
use the same `SPDM_CONFIG`, target C compiler/archive tool, features, and path
remapping flags. Omitting `SPDM_CONFIG` selects upstream protocol limits and
produces a different payload, not a diagnostic copy of the image.

## Initialization and compatibility

Native initialization precedes measurements. The TD entropy callback requires
RDSEED and checks success on every word, with bounded retries and no RDRAND,
VMM, or software fallback. A failed partial fill is wiped. The hardware entropy
source and its health-test guarantees still require platform qualification;
this is not a FIPS-validation claim.

The SDK owns a separately named, entropy-seeded native stack canary, isolated
from QVL's C runtime. Hash-only bootstrap does not instantiate a DRBG, but does
require entropy for that canary. Native fatal callbacks never unwind.

The common exception entry preserves x87/MXCSR/XMM state in an aligned 512-byte
FXSAVE area and wipes it after restoration using general-purpose registers.
It preserves the existing interrupt frame pointer and return layout. The
native dispatch excludes AVX/YMM/ZMM; interrupt handlers must not call crypto.
The additional exception-stack usage and real TD interrupt behavior require
on-target qualification.

SPDM keeps the same wire algorithms and raw-key format. Transcript checkpoints
use the SDK's versioned `SCH1` encoding, not ring's raw object bytes; an
in-flight checkpoint from the old backend cannot be resumed by the new one.
Application-buffer and session teardown remain mandatory on cancellation.

Optional RA-TLS keeps TLS 1.3, AES256-GCM/SHA384, P384 key exchange, and ECDSA/RSA
signature verification. It no longer advertises Ed25519, which SymCrypt does
not implement.

Binary redistribution must retain the wrapper's and native SymCrypt's MIT
copyright and license notices in [`SymCrypt-NOTICES.txt`](SymCrypt-NOTICES.txt).
Include that file alongside redistributed images and native tools. Static
linking and these integration checks do not establish FIPS validation or
deployment-policy approval.
