// Build script: ensure libservtd_attest_app.a exists, then tell rustc to link
// against it (and the host openssl libcrypto, which the AzCVMEmu flavour of the
// servtd_attest wrapper relies on for the QvE / SgxSSL replacement).
//
// With `bounded-heap` feature (default), we use the *un-fixed-up*
// `libservtd_attest.a` archive instead — i.e. the same one MigTD links in
// production, with SgxSSL still embedded and `OPENSSL_malloc` hooked into
// tlibc dlmalloc. That means every SgxSSL allocation (X509 / EC_KEY / EVP /
// BIGNUM / error queue) also lands in the bounded arena, matching MigTD's
// real heap accounting via `g_peak_heap_used`. Without this, my earlier
// repro linked host glibc libcrypto and undercounted the per-call peak.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Declare the cfg we emit so rustc doesn't warn about an unknown cfg name.
    println!("cargo:rustc-check-cfg=cfg(bounded_heap)");

    // Resolve repo root from the package directory: tools/verify-quote-repro -> ../../
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("cannot find repo root")
        .to_path_buf();

    let linux_sgx = repo_root.join("deps/linux-sgx");
    let servtd_lib_dir = linux_sgx
        .join("external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux");
    let lib_app = servtd_lib_dir.join("libservtd_attest_app.a");
    let lib_full = servtd_lib_dir.join("libservtd_attest.a");
    let tlibc_a = linux_sgx.join("sdk/tlibc/libtlibc.a");
    let bounded = env::var_os("CARGO_FEATURE_BOUNDED_HEAP").is_some();

    // 1. Run the same `make` targets that src/attestation/build.rs runs so
    //    libservtd_attest.a is in place.
    for target in ["servtd_attest_preparation", "servtd_attest"] {
        let status = Command::new("make")
            .arg("-C")
            .arg(&linux_sgx)
            .arg(target)
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn make {target}: {e}"));
        assert!(status.success(), "make {target} failed");
    }

    // 2. Plain mode needs the AzCVMEmu fixup script's output. Bounded mode
    //    uses `libservtd_attest.a` directly (with SgxSSL embedded), so we
    //    don't need the fixup script there.
    if !bounded {
        if !lib_app.exists() {
            let attestation_crate = repo_root.join("src/attestation");
            let script = attestation_crate.join("fixup-libservtd-attest-lib.sh");
            let status = Command::new("bash")
                .arg(&script)
                .current_dir(&attestation_crate)
                .status()
                .unwrap_or_else(|e| panic!("failed to run {}: {e}", script.display()));
            assert!(status.success(), "fixup-libservtd-attest-lib.sh failed");
        }
        assert!(lib_app.exists(), "expected to find {}", lib_app.display());
    }

    // 3. Compile the stubs into a .o we can drop on the link command line.
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let stub_obj = out_dir.join("vqr_stubs.o");
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    {
        let mut cmd = Command::new(&cc);
        cmd.args(["-c", "-fPIC"]);
        if bounded {
            cmd.arg("-DVQR_BOUNDED_HEAP=1");
        }
        cmd.arg("src/stubs.c").arg("-o").arg(&stub_obj);
        let status = cmd
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn {cc}: {e}"));
        assert!(status.success(), "compiling src/stubs.c failed");
    }

    if bounded {
        let combined = build_bounded_combined_object(&out_dir, &lib_full, &tlibc_a, &stub_obj);
        // Link the combined object only. SgxSSL is bundled inside, so we
        // intentionally do NOT link `-lcrypto` from the host. The host
        // `libstdc++` is still needed for the C++ runtime (operator new,
        // pure-virtual stub, exception bits used by RAII destructors).
        //
        // `__ImageBase=0` matches the trick that the upstream
        // servtd_attest/linux Makefile uses to satisfy the SGX-only
        // `get_enclave_base()` helper that we end up dragging in.
        println!("cargo:rustc-link-arg={}", combined.display());
        println!("cargo:rustc-link-arg=-Wl,--defsym,__ImageBase=0");
        println!("cargo:rustc-link-arg=-lstdc++");
        println!("cargo:rustc-link-arg=-lm");
        println!("cargo:rustc-cfg=bounded_heap");
    } else {
        // Plain mode: link app archive + stubs, allocator goes through host glibc.
        println!("cargo:rustc-link-arg=-Wl,--start-group");
        println!("cargo:rustc-link-arg={}", stub_obj.display());
        println!("cargo:rustc-link-arg={}", lib_app.display());
        println!("cargo:rustc-link-arg=-Wl,--end-group");
        println!("cargo:rustc-link-arg=-lcrypto");
        println!("cargo:rustc-link-arg=-lstdc++");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/stubs.c");
    println!(
        "cargo:rerun-if-changed={}",
        repo_root
            .join("src/attestation/fixup-libservtd-attest-lib.sh")
            .display()
    );
}

// Build a single relocatable object that bundles:
//   - libservtd_attest.a (unfixed): QvE wrapper + servtd_qve_utils + DCAP
//     attestation library + SgxSSL libcrypto + tlibc. We use the un-fixed-up
//     archive so SgxSSL stays in and its `OPENSSL_malloc` calls hit tlibc's
//     dlmalloc — exactly like MigTD's production build.
//   - tlibc malloc.o + sbrk.o (explicitly pulled to guarantee they're picked
//     before any other `malloc`/`sbrk` decls).
//   - Our stubs (sgx_read_rand replacement for AMD hosts, u_sgxssl_ftime
//     OCALL shim, servtd_get_quote stub, __errno forwarder, 16 MiB early
//     heap + pre-init constructor).
//
// We strip:
//   - `sgx_read_rand.o`: upstream Intel-only impl aborts on AMD.
//   - `errno.o`: provides `__errno`, which conflicts with our forwarder.
//
// Driven by `ld -r -u init_heap -u verify_quote_integrity_ex` so only the
// transitively-needed objects from the 1500+ archive members are dragged in.
//
// Then localize every export except a tiny API whitelist, so the host's
// glibc/libstd dependencies (memcpy/memset/unwinder/etc.) aren't shadowed
// by SgxSSL's bundled copies — those collisions corrupt process startup
// in subtle ways (return-address ROP-like trap mid-instruction).
fn build_bounded_combined_object(
    out_dir: &Path,
    lib_full: &Path,
    tlibc_a: &Path,
    stub_obj: &Path,
) -> PathBuf {
    assert!(
        tlibc_a.exists(),
        "tlibc archive not found at {}; rebuild with src/attestation/build.rs first",
        tlibc_a.display()
    );
    assert!(
        lib_full.exists(),
        "libservtd_attest.a not found at {}; did `make servtd_attest` succeed?",
        lib_full.display()
    );

    let stage = out_dir.join("bounded_stage");
    if stage.exists() {
        fs::remove_dir_all(&stage).expect("cleanup stage dir");
    }
    fs::create_dir_all(&stage).expect("create stage dir");

    // 1) Copy the full (un-fixed-up) archive and strip the two objects that
    //    would conflict with our stubs.
    let full_trimmed = stage.join("libservtd_attest_trimmed.a");
    fs::copy(lib_full, &full_trimmed).expect("copy full archive");
    // `ar d` is idempotent: it succeeds even if the member is absent.
    run(
        Command::new("ar")
            .arg("d")
            .arg(&full_trimmed)
            .arg("sgx_read_rand.o"),
        "ar d sgx_read_rand",
    );
    run(
        Command::new("ar")
            .arg("d")
            .arg(&full_trimmed)
            .arg("errno.o"),
        "ar d errno",
    );

    // 2) Extract tlibc malloc.o + sbrk.o into the staging dir.
    run(
        Command::new("ar")
            .arg("x")
            .arg(tlibc_a)
            .arg("malloc.o")
            .arg("sbrk.o")
            .current_dir(&stage),
        "ar x tlibc",
    );

    // 3) Copy the precompiled vqr_stubs.o into the stage with a deterministic
    //    name.
    let local_stub = stage.join("vqr_stubs.o");
    fs::copy(stub_obj, &local_stub).expect("copy stub");

    // 4) ld -r driven by -u init_heap / -u verify_quote_integrity_ex.
    let combined = out_dir.join("servtd_bounded_combined.o");
    run(
        Command::new("ld")
            .arg("-r")
            .arg("-u")
            .arg("init_heap")
            .arg("-u")
            .arg("verify_quote_integrity_ex")
            .arg("-z")
            .arg("noexecstack")
            .arg("-o")
            .arg(&combined)
            .arg(stage.join("malloc.o"))
            .arg(stage.join("sbrk.o"))
            .arg(&local_stub)
            .arg(&full_trimmed),
        "ld -r",
    );

    // 5) Localize ALL exported symbols from the combined object, with a small
    //    whitelist of symbols the Rust harness needs to call/observe. We do
    //    this dynamically (run nm + filter) instead of maintaining a static
    //    block-list, because the combined object pulls in a long tail of
    //    libunwind/dwarf/openssl symbols that would otherwise clash with
    //    Rust's libstd dependencies (libgcc_s for unwinding, glibc for
    //    memcpy/memset, etc.) and corrupt the process at startup.
    //
    //    Whitelist: the few APIs Rust calls into.
    let keep_global: &[&str] = &[
        "init_heap",
        "verify_quote_integrity_ex",
        // tlibc globals the harness reads via FFI to track / re-arm the heap.
        "heap_base",
        "heap_size",
        "g_peak_heap_used",
        // helpers from vqr_stubs.o that the harness calls.
        "vqr_static_heap_base",
        "vqr_static_heap_size",
        "servtd_get_quote",
    ];
    let nm_out = Command::new("nm")
        .arg("--defined-only")
        .arg("--extern-only")
        .arg(&combined)
        .output()
        .expect("run nm on combined.o");
    if !nm_out.status.success() {
        panic!(
            "nm failed: {}",
            String::from_utf8_lossy(&nm_out.stderr)
        );
    }
    let mut hide = String::new();
    for line in String::from_utf8_lossy(&nm_out.stdout).lines() {
        // nm output: "addr type name"
        let mut parts = line.split_whitespace();
        let _addr = parts.next();
        let typ = parts.next();
        let name = parts.next();
        let (Some(typ), Some(name)) = (typ, name) else { continue };
        // Defined globals: T, R, D, B (capital letters). nm capitalised
        // because we used --extern-only.
        if !matches!(typ, "T" | "R" | "D" | "B" | "W" | "V") {
            continue;
        }
        if keep_global.contains(&name) {
            continue;
        }
        hide.push_str(name);
        hide.push('\n');
    }
    let hide_list = out_dir.join("bounded_hide.txt");
    fs::write(&hide_list, &hide).expect("write hide list");
    run(
        Command::new("objcopy")
            .arg(format!("--localize-symbols={}", hide_list.display()))
            .arg(&combined),
        "objcopy localize",
    );

    combined
}

fn run(cmd: &mut Command, label: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {label}: {e}"));
    assert!(status.success(), "{label} failed (exit {status})");
}
