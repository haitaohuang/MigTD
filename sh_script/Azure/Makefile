#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#

IGVM_FILE ?= target/release/migtd.igvm
LOG_LEVEL ?= info
# Common features for IGVM images
IGVM_FEATURES_BASE ?= vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,igvm-attest
# test_disable_ra_and_accept_all feature disables remote attestation and skips policy verification, bypassing RATLS security
# test feature skips the compilation of attestation library when the remote attestation is not enabled or needed
IGVM_FEATURES_DISABLE_RA_AND_ACCEPT_ALL ?= $(IGVM_FEATURES_BASE),test_disable_ra_and_accept_all
IGVM_MANIFEST ?= config/Azure/servtd_info.json

.PHONY: generate-hash-accept-all-tls build-igvm-accept-all-tls build-igvm-accept-all-tls-all
.PHONY: pre-build build-igvm generate-hash build-igvm-all
.PHONY: build-igvm-debug build-igvm-debug-all
.PHONY: generate-hash-verbose generate-hash-accept-all-tls-verbose

.DEFAULT_GOAL := build-igvm-all

help:
	@echo "Available targets:"
	@echo "  build-igvm-all                  - Build IGVM"
	@echo "  build-igvm-accept-all-tls-all   - Build IGVM with disabled RA and accept all policy with TLS"
	@echo "  build-igvm-debug                - Build IGVM with debug information"

pre-build:
	@if ! command -v rustc >/dev/null 2>&1 || ! rustc --version | grep -q "1.83.0"; then \
		echo "Installing Rust 1.83.0..."; \
		curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.83.0; \
		. ~/.cargo/env; \
	else \
		echo "Rust 1.83.0 already installed"; \
	fi
	@if ! rustup target list --installed | grep -q "x86_64-unknown-none"; then \
		echo "Adding x86_64-unknown-none target..."; \
		rustup target add x86_64-unknown-none; \
	else \
		echo "x86_64-unknown-none target already installed"; \
	fi
	cd ../../ && git submodule update --init --recursive
	chmod +x ../../sh_script/preparation.sh
	cd ../../ && ./sh_script/preparation.sh

build-igvm-accept-all-tls:
	cd ../../ && cargo image --no-default-features --features $(IGVM_FEATURES_DISABLE_RA_AND_ACCEPT_ALL) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

generate-hash-accept-all-tls:
	cd ../../ &&  cargo run -p migtd-hash -- --image $(IGVM_FILE) --test-disable-ra-and-accept-all --manifest $(IGVM_MANIFEST)

generate-hash-accept-all-tls-verbose:
	cd ../../ &&  cargo run -p migtd-hash -- --image $(IGVM_FILE) --test-disable-ra-and-accept-all --verbose

build-igvm-accept-all-tls-all: pre-build build-igvm-accept-all-tls generate-hash-accept-all-tls

generate-hash:
	cd ../../ &&  cargo run -p migtd-hash -- --image $(IGVM_FILE) --manifest $(IGVM_MANIFEST)

build-igvm:
	cd ../../ && cargo image --no-default-features --features $(IGVM_FEATURES_BASE) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

build-igvm-all: pre-build build-igvm generate-hash

build-igvm-debug:
	cd ../../ && cargo image --no-default-features --features $(IGVM_FEATURES_BASE) --log-level debug --image-format igvm --output $(IGVM_FILE) --debug

build-igvm-debug-all: pre-build build-igvm-debug generate-hash

generate-hash-verbose:
	cd ../../ &&  cargo run -p migtd-hash -- --image $(IGVM_FILE) --verbose --manifest $(IGVM_MANIFEST)