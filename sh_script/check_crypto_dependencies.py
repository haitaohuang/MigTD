#!/usr/bin/env python3
"""Check selected crypto implementations, not optional Cargo.lock entries."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = {
    "ring", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys", "openssl", "openssl-sys",
    "sha1", "sha2", "sha3", "hmac", "hkdf", "aes", "aes-gcm",
    "chacha20", "chacha20poly1305", "poly1305", "p256", "p384", "rsa",
    "ecdsa", "ed25519", "ed25519-dalek", "curve25519-dalek", "x25519-dalek",
}


def check(name, target, selection):
    result = subprocess.run(
        [
            "cargo", "tree", "--locked", "--target", target,
            "--edges", "normal", "--prefix", "none", "--format", "{p}",
            *selection,
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    packages = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    rejected = sorted(packages & FORBIDDEN)
    if rejected:
        raise SystemExit(f"{name}: unexpected crypto implementations: {', '.join(rejected)}")
    if "symcrypt-static-sys" not in packages:
        raise SystemExit(f"{name}: native SymCrypt implementation missing")
    print(f"{name}: selected normal dependencies use SymCrypt (QVL/SGXSSL excluded)")


def main():
    firmware = "vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,igvm-attest,servtd_corim"
    for protocol, extra in (("SPDM", ",spdm_attestation"), ("TLS", "")):
        check(
            f"MigTD {protocol}", "x86_64-unknown-none",
            ["-p", "migtd", "--no-default-features", "--features", firmware + extra],
        )
    shim = ["--manifest-path", "deps/td-shim/Cargo.toml"]
    for boot, extra in (("measured boot", ""), ("secure boot", ",secure-boot")):
        check(
            f"td-shim {boot}", "x86_64-unknown-none",
            [*shim, "-p", "td-shim", "--no-default-features",
             "--features", "main,tdx,symcrypt-hash" + extra],
        )
    check(
        "td-shim native tools", "x86_64-unknown-linux-gnu",
        [*shim, "-p", "td-shim-tools"],
    )
    check(
        "MigTD native image/signing tools", "x86_64-unknown-linux-gnu",
        ["-p", "migtd-hash", "-p", "json-signer"],
    )


if __name__ == "__main__":
    main()
