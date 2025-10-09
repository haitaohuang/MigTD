// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

fn main() {
    println!("cargo:rustc-link-arg=-defsym=__ImageBase=0");

    // Only add attestation library linking for AzCVMEmu if not in test mode
    #[cfg(all(feature = "AzCVMEmu", not(feature = "test_disable_ra_and_accept_all")))]
    {
        println!("cargo:rustc-link-arg=-lservtd_attest_app");
        println!("cargo:rustc-link-arg=-lcrypto");
        // OpenSSL's static libcrypto.a requires symbols from libc like atexit
        // When linking with -nodefaultlibs, we need to explicitly link libc
        println!("cargo:rustc-link-arg=-lc");
    }
}
