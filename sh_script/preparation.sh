#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

apply_dependency_patch() {
    local repository="$1"
    local patch="$2"
    if git -C "$repository" apply --reverse --check "$patch" 2>/dev/null; then
        printf '%s: already prepared\n' "$repository"
    else
        git -C "$repository" apply --check "$patch"
        git -C "$repository" apply "$patch"
    fi
}

apply_dependency_patch deps/td-shim ../../sh_script/patches/td-shim-symcrypt.patch
apply_dependency_patch deps/spdm-rs ../../sh_script/patches/spdm-symcrypt-provider.patch
