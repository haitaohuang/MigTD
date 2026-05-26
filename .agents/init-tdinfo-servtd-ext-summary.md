# Init_TDINFO and ServtdExt Usage Summary

*Last updated after removing the init-TDINFO relative-reference policy evaluation (see "Historical notes" below). The destination-side audit of the init→source historical transition is now `init_servtd_info_hash` integrity + the `servtd_tcb_mapping` allowlist gate only.*

## Definitions

### TDINFO_STRUCT (512 bytes) — `TdInfo`

The hardware-defined identity of a TD. Fields:

| Field | Size | Description |
|---|---|---|
| `attributes` | 8 B | TD attributes (debug, sept-ve-disable, etc.) |
| `xfam` | 8 B | Extended feature attribute mask |
| `mrtd` | 48 B | Measurement of the TD's initial memory contents |
| `mrconfig_id` | 48 B | Software-defined non-owner config ID |
| `mrowner` | 48 B | Software-defined owner ID (in MigTD: hash of policy signing key) |
| `mrownerconfig` | 48 B | Owner-defined config (in MigTD: first 4 bytes = policy SVN as LE u32, rest zero) |
| `rtmr0..rtmr3` | 4×48 B | Runtime-extendable measurement registers |
| `servtd_hash` | 48 B | Hash of bound service TDs' TDINFO_STRUCTs |
| `reserved` | 64 B | Must be zero |

**Init_TDINFO** is the TDINFO_STRUCT of the *original MigTD* that was first bound to the target TD at launch time. The source-side MigTD obtains this from the VMM (or falls back to its own self-report if VMM doesn't provide it).

### SERVTD_EXT_STRUCT (272 bytes) — `ServtdExt`

Metadata stored in the target TD's TDCS, read by the *current* MigTD via `TDG.SERVTD.RD`. Fields:

| Field | Size | Description |
|---|---|---|
| `init_servtd_info_hash` | 48 B | SHA-384 hash identifying the *initial* bound MigTD (computed from init TDINFO + type + attr; set at first binding) |
| `init_attr` | 8 B | SERVTD_ATTR at initial binding time. Bits 15:0 = SERVTD_TYPE (0=MigTD). Bits 40:32 = IGNORE flags controlling which TDINFO fields are zeroed before hashing |
| `init_cpusvn` | 16 B | Platform CPU SVN at initial binding |
| `init_tee_tcb_svn` | 16 B | TEE TCB SVN at initial binding |
| `init_tee_model` | 12 B | TEE model info at initial binding |
| `cur_servtd_info_hash` | 48 B | Hash identifying the *currently* bound MigTD |
| `cur_servtd_attr` | 8 B | SERVTD_ATTR of the currently bound MigTD |
| reserved fields | 116 B | Padding |

---

## Wire-protocol contract (SPDM)

This codebase deliberately decouples the SERVTD_EXT wire encoding from the
target TD's `TDCS.ATTRIBUTES` bit 17 (SERVTDEXT):

* **`ServtdExt` (272 bytes) is ALWAYS sent.** When the source's target TD has
  SERVTD_EXT opted out (bit 17 = 0), `TDG.SERVTD.RD` returns zero for every
  SERVTD_EXT_* TDCS field; the resulting structure is therefore zero-filled
  but well-formed. `read_servtd_ext()` returns `(ServtdExt, has_servtd_ext)`
  and never short-circuits the field reads.
* **`Init_TDINFO` length is the SOLE opt-in signal.** Length 0 means the
  source's target TD has SERVTD_EXT opted out; length 512 means opted in.
  No other length is valid.
* **Source rejects VMM-provided init_tdinfo when opted out.** If the VMM
  populated `init_td_info` but the target TD has bit 17 = 0, the init_tdinfo
  cannot be integrity-bound to the source's `init_servtd_info_hash` (it's
  zero) and so the destination has no way to verify it. Source aborts with
  `SPDM_STATUS_INVALID_STATE_LOCAL` rather than send unverifiable data.
* **Destination accepts the empty case unconditionally.** It uses
  `init_tdinfo.is_empty()` as the opt-in branch: empty → skip init-tdinfo
  verification, run only the standard quote / event-log / policy checks
  against the source's current TDREPORT. Non-empty → run the full init
  verification path described below.
* **`write_approved_servtd_ext_hash` / `write_servtd_rebind_attr` always
  run** on the destination side. These writes target MigTD's *own* TDCS via
  `TDG.VM.WR` (not the target TD's TDCS), so they always succeed regardless
  of bit 17.

The single goal of this contract is **"if bit 17 is zero, do not crash or
hang"** while preserving full verification when bit 17 is one.

---

## Usage in each path (SPDM only)

### Migration (source → destination)

**Source side** (`spdm_req`):
1. Reads `ServtdExt` from its bound target TD via `TDG.SERVTD.RD`
   (`read_servtd_ext()`). Always succeeds; returns `(ServtdExt, has_servtd_ext)`.
2. If `!has_servtd_ext` and the VMM provided `init_td_info`, aborts with a
   misconfiguration error (cannot be verified).
3. If `has_servtd_ext`, obtains Init_TDINFO from VMM or falls back to local
   self-report. If `!has_servtd_ext`, sends a zero-length Init_TDINFO VDM
   element.
4. Sends the 272-byte ServtdExt and the (possibly empty) Init_TDINFO as VDM
   elements to the destination.

**Destination side** (`spdm_rsp` → `authenticate_migration_source_with_init_tdinfo`):
1. Receives ServtdExt (always 272 bytes — rejects any other length) and
   Init_TDINFO (0 or 512 bytes) from wire.
2. Stores ServtdExt in responder context for later use during MSK exchange.
3. If Init_TDINFO is **empty**: runs only `authenticate_remote()` (standard
   quote/event-log/policy checks against the source's current TDREPORT) and
   skips the init-tdinfo verification block.
4. If Init_TDINFO is **non-empty** (source's target TD has bit 17 = 1):
   - **Standard policy checks** (POL-SRCv2-01..04): `authenticate_remote_common` (quote verification, event log, policy signature) → `evaluate_policy_common` + `evaluate_policy_backward` with local TCB as relative reference.
   - **Init_TDINFO cross-check** (POL-SRCv2-05): calls `verify_peer_init_tdinfo_against_suppl_data()` — extracts `mrowner` and `mrownerconfig` from the source's *verified quote supplemental data*, then checks:
     - Init_TDINFO's `mrowner` == source's quote `mrowner` (same policy signer)
     - Init_TDINFO's `mrownerconfig[0..4]` (init policy SVN) ≤ source's quote `mrownerconfig[0..4]` (current policy SVN)
     - Both `mrownerconfig[4..48]` must be all zeros
     - ⚠️ **REVERT_ME TEST MODE**: failures are logged but do not abort.
   - **Init_TDINFO integrity verification** (POL-SRCv2-06): calls `verify_init_tdinfo()` → `verify_servtd_hash()`:
     - Computes `SHA384(SHA384(masked_tdinfo) || SERVTD_TYPE || init_attr)` and compares to `init_servtd_info_hash`.
     - **Enforced** (hard-fail): any mismatch — including an all-zero `init_servtd_info_hash` — returns `Err(PolicyError::InvalidTdReport)`. There is no all-zero bypass or soft-fail.
   - **Allowlist gate** (POL-SRCv2-07): `get_engine_svn_by_measurements()` — init MigTD's `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`, `rtmr3` must be in `servtd_tcb_mapping`. **Enforced** (hard-fail on `SvnMismatch`). Skipped under `use-mock-quote` feature (mock binary has different MRTD). This is the **only** policy-side gate applied to the init→source historical transition.
   - **NO init-TDINFO relative-reference policy evaluation.** Earlier versions called `evaluate_policy_common(eval_data_src, init_reference, skip_global=true)` here; that has been removed (see Historical notes). The destination's current `mig_policy` is evaluated against the source's *current* TDREPORT/quote (POL-SRCv2-03..04 above) — not retroactively against the historical init→source transition, which may have spanned several intermediate MigTDs whose evidence we do not have.
5. **SERVTD_ATTR check** (at MSK exchange, `exchange_msk` in `session.rs`): both source and destination call `verify_servtd_attr()` on their own bound target TD. Reads `CURR_SERVTD_ATTR` from TDCS via `TDG.SERVTD.RD` and checks:
   - `cur_servtd_attr == EXPECTED_SERVTD_ATTR` (hardcoded `0x0`) — ensures the VMM wrote the correct SERVTD_ATTR value (since SERVTD_ATTR is written by the untrusted VMM).
   - When the destination's target TD has bit 17 = 0, `cur_servtd_attr` reads as zero and the check passes trivially.
6. **Approved hash write**: after MSK exchange, destination always computes `SHA384(ServtdExt with cur_servtd_info_hash and cur_servtd_attr zeroed)` and writes it to `APPROVED_SERVTD_EXT_HASH` in MigTD's own TDCS via `TDG.VM.WR`. No bit-17 gating — the destination MigTD writes to its own TDCS, not the target TD's.

### Rebinding (old MigTD → new MigTD)

**Old MigTD side** (SPDM requester, `spdm_req`):
1. Reads `ServtdExt` from its bound target TD via `TDG.SERVTD.RD`. Always succeeds.
2. If `!has_servtd_ext` and the VMM provided `init_td_info`, aborts with a misconfiguration error.
3. If `has_servtd_ext`, obtains Init_TDINFO from VMM or local fallback. Otherwise sends zero-length Init_TDINFO.
4. Sends the 272-byte ServtdExt and the (possibly empty) Init_TDINFO as VDM elements.

**New MigTD side** (SPDM responder, `spdm_rsp`):
1. Receives ServtdExt (always 272 bytes — rejects any other length) and Init_TDINFO (0 or 512 bytes) from wire.
2. Calls `authenticate_rebinding_old()` which does:
   - If Init_TDINFO is **empty** (old MigTD's target TD has bit 17 = 0): skip the init-tdinfo verification block entirely. Evaluate the source's current TDREPORT against the local-TCB reference policy (`evaluate_policy_common` with `get_local_tcb_evaluation_info` as the reference, `skip_global=true`). Continue to backward-policy evaluation.
   - If Init_TDINFO is **non-empty**:
     - **Init_TDINFO cross-check against TDREPORT**: calls `verify_peer_init_tdinfo_against_owner()` — uses `mrowner` and `mrownerconfig` from the old MigTD's *verified TDREPORT* (not quote supplemental data). Same checks as migration: mrowner match + init SVN ≤ current SVN. ⚠️ **REVERT_ME TEST MODE**: logged, non-fatal.
     - **Init_TDINFO integrity verification against ServtdExt**: calls `verify_init_tdinfo()` → `verify_servtd_hash()`. Same logic as migration (hard-fail on any mismatch, including all-zero `init_servtd_info_hash`).
     - **Allowlist gate**: same `get_engine_svn_by_measurements()` check using `mrtd`, `rtmr0..rtmr3` as in migration. **Enforced** — the only policy-side gate for the init→source historical transition.
     - **NO init-TDINFO relative-reference policy evaluation** (removed; see Historical notes). The new MigTD's current policy is evaluated against the old MigTD's *current* TDREPORT only, via `evaluate_policy_common` / `evaluate_policy_backward` with `get_local_tcb_evaluation_info` as the reference (run unconditionally, outside the init_tdinfo branch).
3. Stores ServtdExt in responder context.
4. **Approved hash write**: always computes `SHA384(ServtdExt with cur fields zeroed)` and writes to `APPROVED_SERVTD_EXT_HASH` in MigTD's own TDCS via `TDG.VM.WR`. No bit-17 gating.
5. **Rebind attr write**: additionally writes `ServtdExt.cur_servtd_attr` via `write_servtd_rebind_attr()` — rebind-specific, not done in migration. The new MigTD writes the expected value and the TDX module enforces that the actual SERVTD_ATTR matches what the MigTD wrote.

---

## Differences between migration and rebinding

| Check | Migration (destination) | Rebinding (new MigTD) |
|---|---|---|
| Init_TDINFO integrity vs `ServtdExt.init_servtd_info_hash` | ✅ `verify_init_tdinfo` (TEST MODE soft-fail) | ✅ `verify_init_tdinfo` (TEST MODE soft-fail) |
| Init_TDINFO cross-check (mrowner + SVN) | ✅ Against quote suppl data (TEST MODE) | ✅ Against TDREPORT (TEST MODE) |
| Allowlist gate (`get_engine_svn_by_measurements`) | ✅ Enforced (skipped under `use-mock-quote`) | ✅ Same |
| `verify_servtd_attr` (cur==hardcoded) | ✅ Both sides, at MSK exchange | ✅ Old side at MSK exchange; new side reads full ServtdExt |
| `write_approved_servtd_ext_hash` | ✅ Destination writes | ✅ New MigTD writes |
| `write_servtd_rebind_attr` | ❌ Not needed (MigTD verifies `cur == 0x0`) | ✅ New MigTD writes `cur_servtd_attr`; TDX module enforces match |

Migration and rebinding are symmetric for Init_TDINFO verification. The only structural differences are `write_servtd_rebind_attr` (rebinding-only) and the cross-check data source (quote suppl data vs TDREPORT).

### REVERT_ME / TEST MODE summary

Several checks are currently soft-fail to enable testing against hosts that haven't been fully updated:

| Check | Status | Notes |
|---|---|---|
| `verify_peer_init_tdinfo_against_suppl_data` / `_against_owner` | ⚠️ Soft-fail | MROWNER/MROWNERCONFIG may not be provisioned yet |
| `verify_servtd_hash` (hash mismatch, including all-zero) | Enforced | Hard-fail: returns `Err(PolicyError::InvalidTdReport)` |
| `verify_init_tdinfo` (parse + dispatch) | Enforced | Malformed input is a hard error |
| `get_engine_svn_by_measurements` | Enforced | Hard-fail on `SvnMismatch` (skipped under `use-mock-quote`) |

---

## Why init-TDINFO is NOT used as a policy-evaluation reference

The init→source transition is **historical** and may have traversed several intermediate MigTDs whose evidence we do not have. The destination's *current* policy cannot be applied retroactively to that historical chain — only the integrity of the initial binding (`servtd_ext.init_servtd_info_hash`) and an allowlist match on the init MigTD's measurements (`servtd_tcb_mapping.get_engine_svn_by_measurements`) are meaningful audits of that history.

The audited evidence chain is therefore:

| Verifies | How |
|---|---|
| Initial MigTD's binary identity is in the known-good allowlist | `servtd_tcb_mapping` lookup over `mrtd, rtmr0..rtmr3` |
| Wire-claimed Init_TDINFO matches the binding recorded at first bind | `SHA-384(masked_tdinfo ‖ SERVTD_TYPE ‖ init_attr) == servtd_ext.init_servtd_info_hash` |
| Policy signer / SVN ordering is consistent with the peer's current self-report | `verify_peer_init_tdinfo_against_{owner,suppl_data}` (TEST MODE soft-fail) |
| Source MigTD's *current* TCB satisfies the destination's *current* policy | `evaluate_policy_common` + `evaluate_policy_backward` over the source's quote/TDREPORT (local-TCB relative reference) |

The `mig_policy` rules with `"reference": "init"` are evaluated only when `"reference": "self"` (i.e., the local-TCB reference) is in effect — they compare the peer's current evaluation data against the local reference, not against an Init_TDINFO-derived reference. There is no remaining call site that builds a relative reference from Init_TDINFO.

---

## Historical notes — commit origins

| Check | Function | Commit | Author |
|---|---|---|---|
| Startup self-check: `MROWNER==signer`, `MROWNERCONFIG==SVN` | `verify_own_tdinfo()` | `67b49e5` feat: support tdinfo_init | Michal Tarnacki |
| Init MigTDData binding: `MROWNER==signer`, `SVN<=my SVN` | `verify_init_migtd_data_policy_binding()` | `67b49e5` (same) | Michal Tarnacki |
| Peer cross-check against TDREPORT owner fields | `verify_peer_init_tdinfo_against_owner()` | `ccfd611` refactor: move init-TDINFO cross-check into policy layer | Haitao Huang |
| Peer cross-check against quote suppl data | `verify_peer_init_tdinfo_against_suppl_data()` | `ccfd611` (same) | Haitao Huang |
| Destination-side init_TDINFO integrity + policy eval (init reference) | `authenticate_migration_source_with_init_tdinfo()` | `bae6f54` feat: verify init_TDINFO integrity and policy on migration destination (later expanded in `3be857a`) | Haitao Huang |
| Rebind-path init-reference policy eval | `authenticate_rebinding_old()` via `setup_evaluation_data_with_tdinfo()` | `f2ea0ef` refactor(attestation): verify policy against TDINFO_STRUCT | Michal Tarnacki |
| **Removed**: init-TDINFO relative-reference policy evaluation (both paths); `setup_evaluation_data_with_tdinfo` deleted | partial revert of `f2ea0ef`, `bae6f54`, `3be857a` | see commit titled `refactor(mig_policy): drop init-reference policy evaluation from rebind/migration` | Haitao Huang |
| `SERVTD_ATTR` hardcoded check (`cur == 0x0`) | `verify_servtd_attr()` | `a7c6ac0` feat: verify SERVTD_ATTR using SERVTD.RD api | Michal Tarnacki |
| `SERVTD_ATTR` vs `INIT_ATTR` check (`cur == init`) | `verify_servtd_attr()` | `d4336bb` fix: verify SERVTD_ATTR against INIT_ATTR (PR [#832](https://github.com/intel/MigTD/pull/832), issue [#831](https://github.com/intel/MigTD/issues/831), no review comments). **Reverted** — after rebind, `CURR_SERVTD_ATTR` can legitimately differ from `INIT_ATTR` | Stanislaw Grams |
