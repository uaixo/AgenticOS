#!/bin/sh
#
# Build a Microkit SDK for qemu_virt_aarch64 from pinned sources.
#
# Copyright 2026 the AgenticOS authors
# SPDX-License-Identifier: BSD-2-Clause
#
# We do not vendor a kernel (D1: stock seL4, built with Microkit, nothing of
# ours in it). This script pins the exact revisions the prototype was built
# and tested against, so a fresh checkout reproduces the same image.
#
# Needs: git, cmake, ninja, python3, a rust toolchain, an aarch64 cross
# compiler, qemu-system-aarch64 with its ROMs, dtc, and xmllint, which seL4
# validates its syscall XML with. On Debian or Ubuntu:
#
#   apt-get install -y build-essential cmake ninja-build python3 python3-pip \
#       gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu device-tree-compiler \
#       libxml2-utils qemu-system-arm qemu-system-data ipxe-qemu
#   pip3 install jinja2 ply pyyaml pyelftools lxml
#   rustup target add aarch64-unknown-none aarch64-unknown-none-softfloat
#
# seL4's build also needs pyfdt, which does not install cleanly from PyPI on
# recent setuptools; the simplest fix is to drop its package directory into
# site-packages by hand.
#
set -eu

SEL4_REV=6e7c3b733d296cfd88d5fbf635c96e447a882374
MICROKIT_REV=ec86afdcd662b5976d11d4994acf1b11a2979882
BOARD=qemu_virt_aarch64
CONFIG=debug
PREFIX=aarch64-linux-gnu

cd "$(dirname "$0")/.."
root=$PWD
work=${SDK_WORK_DIR:-$root/.sdk-build}
out=${SDK_OUT_DIR:-$root/sdk}

mkdir -p "$work"

if [ ! -d "$work/seL4" ]; then
    git clone https://github.com/seL4/seL4.git "$work/seL4"
fi
git -C "$work/seL4" checkout -q "$SEL4_REV"

if [ ! -d "$work/microkit" ]; then
    git clone https://github.com/seL4/microkit.git "$work/microkit"
fi
git -C "$work/microkit" fetch -q --depth 1 origin "$MICROKIT_REV"
git -C "$work/microkit" checkout -q "$MICROKIT_REV"

command -v "${PREFIX}-gcc" >/dev/null 2>&1 || {
    echo "${PREFIX}-gcc not found; install an aarch64 cross compiler" >&2
    exit 1
}

cd "$work/microkit"
python3 build_sdk.py \
    --sel4 "$work/seL4" \
    --boards "$BOARD" \
    --configs "$CONFIG" \
    --tool-target-triple "$(rustc -vV | sed -n 's/^host: //p')" \
    --gcc-toolchain-prefix-aarch64 "$PREFIX" \
    --skip-docs --skip-tar

version=$(cat VERSION)
mkdir -p "$out"
rm -rf "$out/microkit-sdk-$version"
cp -r "release/microkit-sdk-$version" "$out/"

echo
echo "SDK at $out/microkit-sdk-$version"
echo "  make MICROKIT_SDK=$out/microkit-sdk-$version run"
