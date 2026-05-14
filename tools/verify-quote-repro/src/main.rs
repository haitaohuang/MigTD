// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Minimal host-side reproducer for the heap-exhaustion / leak symptom we hit on
// TiP nodes when MigTD calls `verify_quote_integrity_ex()` more than ~2 times
// per process lifetime (commit 3c44ea9 removed `LOCAL_TCB_INFO` caching, so a
// single migration now does up to 4 calls).
//
// This binary:
//   1. Loads a quote captured from a real TDX guest (`--quote quote.dat`).
//   2. Loads a THIM collateral JSON produced by `migtd-collateral-generator`
//      (`--collateral collateral_thim.json`).
//   3. Auto-detects the FMSPC from the quote (or honours `--fmspc`).
//   4. Calls `init_heap()` once with `--heap-size` (default 0x80000 = 512 KiB,
//      which is the original size that crashed in TiP).
//   5. Calls `verify_quote_integrity_ex()` in a loop `--iterations` times
//      (default 8), printing peak RSS after each iteration so a heap leak (in
//      either the wrapper's private arena under tlibc or the host malloc under
//      the AzCVMEmu/_app build) is visible.
//
// Build notes:
//   - This crate is a standalone workspace; build with:
//       cd tools/verify-quote-repro
//       cargo build --release
//   - The build.rs links `libservtd_attest_app.a` (host glibc malloc +
//     host openssl libcrypto). That variant DOES NOT reproduce the exact
//     `#UD` because host glibc malloc is unbounded, but it DOES exercise the
//     same API path and is the easiest harness for `valgrind` / asan leak
//     detection. To reproduce the on-target `#UD`, run inside the MigTD
//     image or under the bounded-arena tlibc build.
//
// Usage:
//   verify-quote-repro \
//       --quote quote.dat \
//       --collateral config/Azure/collateral_thim.json \
//       --heap-size 0x80000 \
//       --iterations 8

use std::ffi::{c_char, c_void, CString};
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

// ---------------------------------------------------------------------------
// FFI bindings — match `src/attestation/src/binding.rs`.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QveCollateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: *const c_char,
    pub pck_crl_issuer_chain_size: u32,
    pub root_ca_crl: *const c_char,
    pub root_ca_crl_size: u32,
    pub pck_crl: *const c_char,
    pub pck_crl_size: u32,
    pub tcb_info_issuer_chain: *const c_char,
    pub tcb_info_issuer_chain_size: u32,
    pub tcb_info: *const c_char,
    pub tcb_info_size: u32,
    pub qe_identity_issuer_chain: *const c_char,
    pub qe_identity_issuer_chain_size: u32,
    pub qe_identity: *const c_char,
    pub qe_identity_size: u32,
}

extern "C" {
    fn init_heap(p_td_heap_base: *const c_void, td_heap_size: u32) -> i32;

    fn verify_quote_integrity_ex(
        p_quote: *const c_void,
        quote_size: u32,
        root_pub_key: *const c_void,
        root_pub_key_size: u32,
        p_collateral: *const QveCollateral,
        p_tdx_report_verify: *mut c_void,
        p_tdx_report_verify_size: *mut u32,
    ) -> i32;
}

// Globals exported by tlibc's sbrk.o (and pre-init constructor in stubs.c).
// Only present in the bounded-heap build. Rust-side names differ from C-side
// to avoid colliding with the `Cli::heap_size` field.
#[cfg(bounded_heap)]
extern "C" {
    #[link_name = "heap_base"]
    static mut TLIBC_HEAP_BASE: *mut c_void;
    #[link_name = "heap_size"]
    static mut TLIBC_HEAP_SIZE: usize;
    #[link_name = "g_peak_heap_used"]
    static TLIBC_PEAK_HEAP_USED: usize;
    fn vqr_static_heap_base() -> *const c_void;
    fn vqr_static_heap_size() -> usize;
}

// Intel Root Public Key — exact copy from
// deps/.../servtd_attest/test_servtd_attest.cpp:234
const INTEL_ROOT_PUB_KEY: [u8; 65] = [
    0x04, 0x4f, 0xfa, 0x0f, 0xfd, 0x56, 0x1c, 0xda, 0xd6, 0xc0, 0xf9, 0x8d, 0x30, 0x8c, 0x81, 0x28,
    0xc5, 0xb9, 0x27, 0xa2, 0x73, 0x32, 0xc8, 0xe8, 0xeb, 0x13, 0xf6, 0xbe, 0x42, 0xb5, 0x71, 0xd6,
    0x46, 0x6f, 0x53, 0xc6, 0x44, 0xff, 0xc2, 0xff, 0xc1, 0x02, 0x82, 0x20, 0xe4, 0x9a, 0x49, 0x66,
    0xcf, 0x02, 0xf3, 0x2e, 0x2f, 0xb4, 0xd3, 0x49, 0xbb, 0x2c, 0xba, 0xed, 0x28, 0x90, 0x37, 0xa0,
    0x2d,
];

const TD_REPORT_VERIFY_SIZE: usize = 1024;

// ---------------------------------------------------------------------------
// Collateral JSON — match what `migtd-collateral-generator` writes.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Collaterals {
    major_version: u16,
    minor_version: u16,
    tee_type: u32,
    #[allow(dead_code)]
    root_ca: String,
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    platforms: Vec<Platform>,
    qe_identity_issuer_chain: String,
    qe_identity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Platform {
    fmspc: String,
    tcb_info_issuer_chain: String,
    tcb_info: String,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(about = "Repeatedly call verify_quote_integrity_ex to surface heap growth/leak")]
struct Cli {
    /// Quote bytes captured from a real TDX guest (e.g. quote.dat written by
    /// `test_servtd_attest`'s `test_app` or saved by a MigTD trace).
    #[arg(long)]
    quote: PathBuf,

    /// THIM collateral JSON (output of
    /// `migtd-collateral-generator --provider azure-thim ...`).
    #[arg(long)]
    collateral: PathBuf,

    /// Heap size handed to init_heap(). Defaults to 0x80000 (512 KiB) — the
    /// original size that crashed on TiP. Try 0x200000 to confirm the fix.
    #[arg(long, default_value = "0x80000", value_parser = parse_size)]
    heap_size: usize,

    /// Number of back-to-back verify_quote_integrity_ex() calls.
    #[arg(long, default_value_t = 8)]
    iterations: usize,

    /// Optional 12-hex FMSPC override (otherwise auto-detect from quote).
    #[arg(long)]
    fmspc: Option<String>,
}

fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16)
    } else {
        s.parse::<usize>()
    };
    v.map_err(|e| format!("bad size {s:?}: {e}"))
}

// ---------------------------------------------------------------------------
// FMSPC extraction from the PCK cert embedded in the quote (PEM block).
// Mirrors `src/policy/src/v2/collaterals.rs::get_fmspc_from_quote`.
// ---------------------------------------------------------------------------

const PCK_FMSPC_EXTENSION_OID: &str = "1.2.840.113741.1.13.1";
const PCK_FMSPC_OID: &str = "1.2.840.113741.1.13.1.4";

fn get_fmspc_from_quote(quote: &[u8]) -> Result<[u8; 6]> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let text = String::from_utf8_lossy(quote);
    let begin = text
        .find(BEGIN)
        .ok_or_else(|| anyhow!("no PEM certificate found in quote"))?;
    let end_off = text[begin..]
        .find(END)
        .ok_or_else(|| anyhow!("no end-of-PEM marker found in quote"))?;
    let end = begin + end_off + END.len();
    let pem = &text[begin..end];

    // Strip header/footer/whitespace then base64-decode.
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64_decode(&body)?;

    parse_fmspc(&der)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    // Pure-stdlib base64 decoder so we don't pull in another dependency.
    fn val(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => return None, // pad
            _ => return None,
        })
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.len() % 4 != 0 {
        bail!("bad base64 length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let q = &bytes[i..i + 4];
        let mut buf = [0u32; 4];
        let mut pads = 0;
        for (k, &c) in q.iter().enumerate() {
            if c == b'=' {
                buf[k] = 0;
                pads += 1;
            } else {
                buf[k] = val(c).ok_or_else(|| anyhow!("invalid b64 char {c:#x}"))? as u32;
            }
        }
        let triple = (buf[0] << 18) | (buf[1] << 12) | (buf[2] << 6) | buf[3];
        out.push((triple >> 16) as u8);
        if pads < 2 {
            out.push((triple >> 8) as u8);
        }
        if pads < 1 {
            out.push(triple as u8);
        }
        i += 4;
    }
    Ok(out)
}

fn parse_fmspc(pck_der: &[u8]) -> Result<[u8; 6]> {
    let (_, cert) = X509Certificate::from_der(pck_der)
        .map_err(|e| anyhow!("PCK cert parse failed: {e}"))?;
    let target_ext: Oid = PCK_FMSPC_EXTENSION_OID
        .parse()
        .expect("static OID");
    let target_inner: Oid = PCK_FMSPC_OID.parse().expect("static OID");

    for ext in cert.extensions() {
        if ext.oid == target_ext {
            // The extension value is a SEQUENCE OF { OID, ANY }. Walk it with
            // x509-parser's der_parser.
            return walk_fmspc_sequence(ext.value, &target_inner)
                .ok_or_else(|| anyhow!("FMSPC inner OID not found in extension"));
        }
    }
    bail!("PCK extension {PCK_FMSPC_EXTENSION_OID} not found")
}

fn walk_fmspc_sequence(value: &[u8], target_inner: &Oid) -> Option<[u8; 6]> {
    use der_parser::der::parse_der;

    let (_, top) = parse_der(value).ok()?;
    let inner_seq = top.as_sequence().ok()?;
    for elem in inner_seq {
        let kv = elem.as_sequence().ok()?;
        if kv.len() != 2 {
            continue;
        }
        let oid = kv[0].as_oid().ok()?;
        if oid == target_inner {
            let octets = kv[1].as_slice().ok()?;
            if octets.len() == 6 {
                let mut out = [0u8; 6];
                out.copy_from_slice(octets);
                return Some(out);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn rss_kib() -> Option<usize> {
    let s = fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kib: usize = rest
                .trim()
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            return Some(kib);
        }
    }
    None
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let quote = fs::read(&cli.quote)
        .with_context(|| format!("cannot read quote file {}", cli.quote.display()))?;
    println!("quote: {} bytes", quote.len());

    let collat_bytes = fs::read(&cli.collateral)
        .with_context(|| format!("cannot read collateral file {}", cli.collateral.display()))?;
    let collat: Collaterals = serde_json::from_slice(&collat_bytes)
        .context("collateral JSON did not match expected schema")?;
    println!(
        "collateral: tee_type=0x{:x}, {} platforms",
        collat.tee_type,
        collat.platforms.len()
    );

    let fmspc_bytes = match cli.fmspc.as_deref() {
        Some(s) => {
            let v = hex::decode(s).map_err(|e| anyhow!("bad --fmspc hex: {e}"))?;
            if v.len() != 6 {
                bail!("--fmspc must be 12 hex chars");
            }
            let mut a = [0u8; 6];
            a.copy_from_slice(&v);
            a
        }
        None => get_fmspc_from_quote(&quote)?,
    };
    let fmspc_hex = hex::encode(fmspc_bytes);
    println!("fmspc: {fmspc_hex}");

    let platform = collat
        .platforms
        .iter()
        .find(|p| p.fmspc.eq_ignore_ascii_case(&fmspc_hex))
        .ok_or_else(|| {
            anyhow!(
                "no platform with fmspc={fmspc_hex} in collateral (have: {:?})",
                collat
                    .platforms
                    .iter()
                    .map(|p| &p.fmspc)
                    .collect::<Vec<_>>()
            )
        })?;

    // Build C strings (null-terminated) for the QveCollateral pointers.
    let pck_crl_issuer_chain = CString::new(collat.pck_crl_issuer_chain.as_str())?;
    let root_ca_crl = CString::new(collat.root_ca_crl.as_str())?;
    let pck_crl = CString::new(collat.pck_crl.as_str())?;
    let tcb_info_issuer_chain = CString::new(platform.tcb_info_issuer_chain.as_str())?;
    let tcb_info = CString::new(platform.tcb_info.as_str())?;
    let qe_identity_issuer_chain = CString::new(collat.qe_identity_issuer_chain.as_str())?;
    let qe_identity = CString::new(collat.qe_identity.as_str())?;

    let qve = QveCollateral {
        major_version: collat.major_version,
        minor_version: collat.minor_version,
        tee_type: collat.tee_type,
        pck_crl_issuer_chain: pck_crl_issuer_chain.as_ptr(),
        pck_crl_issuer_chain_size: pck_crl_issuer_chain.as_bytes_with_nul().len() as u32,
        root_ca_crl: root_ca_crl.as_ptr(),
        root_ca_crl_size: root_ca_crl.as_bytes_with_nul().len() as u32,
        pck_crl: pck_crl.as_ptr(),
        pck_crl_size: pck_crl.as_bytes_with_nul().len() as u32,
        tcb_info_issuer_chain: tcb_info_issuer_chain.as_ptr(),
        tcb_info_issuer_chain_size: tcb_info_issuer_chain.as_bytes_with_nul().len() as u32,
        tcb_info: tcb_info.as_ptr(),
        tcb_info_size: tcb_info.as_bytes_with_nul().len() as u32,
        qe_identity_issuer_chain: qe_identity_issuer_chain.as_ptr(),
        qe_identity_issuer_chain_size: qe_identity_issuer_chain.as_bytes_with_nul().len() as u32,
        qe_identity: qe_identity.as_ptr(),
        qe_identity_size: qe_identity.as_bytes_with_nul().len() as u32,
    };

    // ---------------------------------------------------------------------
    // Heap setup
    // ---------------------------------------------------------------------
    //
    // Bounded mode: stubs.c's high-priority constructor has already called
    // init_heap() with a 16 MiB static buffer (necessary so the QvE/PCK
    // static initializers, which run before main() via .init_array, have
    // a working heap). We can either (a) leave that 16 MiB arena in place,
    // or (b) re-arm the heap base/cap to a smaller `--heap-size` so we can
    // reproduce the in-image OOM. Re-arming is what `--heap-size` toggles.
    //
    // Plain mode: init_heap is just a soft hint — the underlying malloc is
    // glibc's. We still call it with a posix_memalign-allocated buffer to
    // keep behaviour identical to MigTD.
    if cli.heap_size & 0xfff != 0 {
        bail!(
            "--heap-size must be a multiple of 0x1000 (got 0x{:x})",
            cli.heap_size
        );
    }

    #[cfg(bounded_heap)]
    {
        // The early constructor already ran. heap_base/heap_size point into
        // the 16 MiB static buffer. Tell the user where it is, then re-arm.
        let early_base = unsafe { vqr_static_heap_base() };
        let early_size = unsafe { vqr_static_heap_size() };
        let peak = unsafe { core::ptr::read_volatile(&TLIBC_PEAK_HEAP_USED) };
        println!(
            "bounded mode: early constructor armed heap @ {:p} size={:#x}; \
             post-static-init peak_heap_used={:#x}",
            early_base, early_size, peak
        );
        // Re-arm: clear heap_base so init_heap can be invoked again, then
        // sub-allocate `cli.heap_size` *out of* the early static buffer (so
        // we don't leak host glibc memory). This shrinks the arena bound
        // that the verifier sees. Note that anything the static
        // initializers have already allocated lives at low addresses and
        // becomes inaccessible — but on this host harness none of the
        // verifier's static state is actually consulted by
        // `verify_quote_integrity_ex`, so this is safe in practice.
        if cli.heap_size > early_size {
            bail!(
                "--heap-size {:#x} exceeds static early buffer ({:#x})",
                cli.heap_size,
                early_size
            );
        }
        unsafe {
            TLIBC_HEAP_BASE = core::ptr::null_mut();
            TLIBC_HEAP_SIZE = 0;
        }
        let init_rc = unsafe { init_heap(early_base, cli.heap_size as u32) };
        if init_rc != 0 {
            bail!(
                "second init_heap returned {init_rc:#x} (heap_base={:p})",
                unsafe { TLIBC_HEAP_BASE }
            );
        }
        println!(
            "init_heap(base={:p}, size={:#x})  [bounded: tlibc dlmalloc + sbrk]",
            early_base, cli.heap_size
        );
    }

    #[cfg(not(bounded_heap))]
    {
        let mut heap_ptr: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { libc::posix_memalign(&mut heap_ptr, 0x1000, cli.heap_size) };
        if rc != 0 || heap_ptr.is_null() {
            bail!("posix_memalign failed: rc={rc}");
        }
        unsafe { std::ptr::write_bytes(heap_ptr as *mut u8, 0, cli.heap_size) };
        println!(
            "init_heap(base={:p}, size=0x{:x})  [host glibc malloc — heap arg ignored]",
            heap_ptr, cli.heap_size
        );
        let init_rc = unsafe { init_heap(heap_ptr, cli.heap_size as u32) };
        if init_rc != 0 {
            bail!("init_heap returned {init_rc:#x}");
        }
    }

    if let Some(k) = rss_kib() {
        println!("baseline RSS: {k} KiB");
    }

    let mut peak_rss: usize = 0;
    let mut report_buf = vec![0u8; TD_REPORT_VERIFY_SIZE];
    for i in 1..=cli.iterations {
        let mut report_size = TD_REPORT_VERIFY_SIZE as u32;
        let rc = unsafe {
            verify_quote_integrity_ex(
                quote.as_ptr() as *const c_void,
                quote.len() as u32,
                INTEL_ROOT_PUB_KEY.as_ptr() as *const c_void,
                INTEL_ROOT_PUB_KEY.len() as u32,
                &qve as *const QveCollateral,
                report_buf.as_mut_ptr() as *mut c_void,
                &mut report_size as *mut u32,
            )
        };
        let rss = rss_kib().unwrap_or(0);
        peak_rss = peak_rss.max(rss);
        #[cfg(bounded_heap)]
        let tlibc_peak = Some(unsafe { core::ptr::read_volatile(&TLIBC_PEAK_HEAP_USED) });
        #[cfg(not(bounded_heap))]
        let tlibc_peak: Option<usize> = None;
        match tlibc_peak {
            Some(p) => println!(
                "iter {i:>3}: rc={rc:#06x} report_size={report_size} RSS={rss} KiB \
                 (peak_RSS={peak_rss} KiB)  tlibc_peak_heap_used={p:#x} ({} KiB)",
                p / 1024
            ),
            None => println!(
                "iter {i:>3}: rc={rc:#06x} report_size={report_size} RSS={rss} KiB \
                 (peak_RSS={peak_rss} KiB)"
            ),
        }
        if rc != 0 {
            eprintln!("verify_quote_integrity_ex returned error on iter {i}");
        }
    }

    println!("done. peak RSS: {peak_rss} KiB.");
    #[cfg(bounded_heap)]
    {
        let final_peak = unsafe { core::ptr::read_volatile(&TLIBC_PEAK_HEAP_USED) };
        println!(
            "Final tlibc g_peak_heap_used = {:#x} ({} KiB) out of arena {:#x} ({} KiB).",
            final_peak,
            final_peak / 1024,
            cli.heap_size,
            cli.heap_size / 1024
        );
        println!(
            "Mode: BOUNDED (tlibc dlmalloc backed by sbrk(heap_base/heap_size)).\n\
             This is the same allocator MigTD uses in-image. The arena bound is\n\
             whatever was last passed to init_heap; an OOM inside dlmalloc\n\
             results in a #UD via abort/ud2 (NOT a sane return code)."
        );
    }
    #[cfg(not(bounded_heap))]
    {
        println!(
            "Mode: HOST glibc malloc (libservtd_attest_app.a). Allocations are NOT\n\
             confined to the --heap-size arena; that argument is essentially ignored\n\
             by the underlying allocator. RSS growth across iterations therefore\n\
             tracks *real* leaks (the wrapper failing to free), not the in-MigTD\n\
             high-water-mark fragmentation issue. Rebuild with --features bounded-heap\n\
             (default) to drive the tlibc arena and reproduce the #UD."
        );
    }

    // libc::free will reclaim the memory when this process exits.
    Ok(())
}
