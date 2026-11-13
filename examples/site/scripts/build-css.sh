#!/usr/bin/env bash
# Build the site stylesheet with the Tailwind CSS standalone CLI and daisyUI, without Node.
#
#   scripts/build-css.sh OUTPUT_PATH   build styles/input.css (minified) into OUTPUT_PATH
#   scripts/build-css.sh --print-hashes   download the pinned versions and print their SHA256s
#
# Downloads are cached in .cache/ next to this directory and verified on every run.
set -euo pipefail

# Renovate bumps the versions below but cannot update the hashes: after a bump, run
# `scripts/build-css.sh --print-hashes` and paste its output over the *_SHA256 lines.
# renovate: datasource=github-releases depName=tailwindlabs/tailwindcss versioning=semver
TAILWIND_VERSION=4.3.3
TAILWIND_SHA256_LINUX_X64=dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a
TAILWIND_SHA256_LINUX_ARM64=55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195
# renovate: datasource=github-releases depName=saadeghi/daisyui versioning=semver
DAISYUI_VERSION=5.8.0
DAISYUI_SHA256=85819d3fe86a852237b439b13f481481aac58e562ac47694cd11c3038e994f2a

SITE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
CACHE_DIR=$SITE_DIR/.cache
INPUT_CSS=$SITE_DIR/styles/input.css

tailwind_url() { # ARCH
    echo "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-$1"
}
daisyui_url() {
    echo "https://github.com/saadeghi/daisyui/releases/download/v${DAISYUI_VERSION}/daisyui.mjs"
}

# python:3.14-slim has no curl, but it has Python.
fetch() { # URL DEST
    local tmp=$2.part
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$tmp" "$1"
    else
        python3 - "$1" "$tmp" <<'EOF'
import shutil, sys, urllib.request
with urllib.request.urlopen(sys.argv[1]) as r, open(sys.argv[2], "wb") as f:
    shutil.copyfileobj(r, f)
EOF
    fi
    mv -- "$tmp" "$2"
}

# Download URL to DEST unless cached, then verify it against SHA256.
fetch_verified() { # URL DEST SHA256
    if [[ ! -f $2 ]]; then
        echo "Downloading $1" >&2
        fetch "$1" "$2"
    fi
    if ! echo "$3  $2" | sha256sum -c --quiet --strict -; then
        rm -f -- "$2"
        echo "error: SHA256 mismatch for $1 (removed $2)" >&2
        exit 1
    fi
}

print_hashes() {
    local arch
    tmp=$(mktemp -d) # global: the EXIT trap runs after this function returns
    trap 'rm -rf -- "$tmp"' EXIT
    for arch in x64 arm64; do
        fetch "$(tailwind_url "$arch")" "$tmp/tailwindcss-$arch"
    done
    fetch "$(daisyui_url)" "$tmp/daisyui.mjs"
    echo "TAILWIND_SHA256_LINUX_X64=$(sha256sum "$tmp/tailwindcss-x64" | cut -d' ' -f1)"
    echo "TAILWIND_SHA256_LINUX_ARM64=$(sha256sum "$tmp/tailwindcss-arm64" | cut -d' ' -f1)"
    echo "DAISYUI_SHA256=$(sha256sum "$tmp/daisyui.mjs" | cut -d' ' -f1)"
}

usage() {
    echo "usage: $0 OUTPUT_PATH | --print-hashes" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
case $1 in
    --print-hashes)
        print_hashes
        exit 0
        ;;
    -*) usage ;;
esac
output=$1

case $(uname -m) in
    x86_64 | amd64)
        arch=x64
        tailwind_sha=$TAILWIND_SHA256_LINUX_X64
        ;;
    aarch64 | arm64)
        arch=arm64
        tailwind_sha=$TAILWIND_SHA256_LINUX_ARM64
        ;;
    *)
        echo "error: unsupported architecture $(uname -m)" >&2
        exit 1
        ;;
esac

mkdir -p -- "$CACHE_DIR"
tailwind=$CACHE_DIR/tailwindcss-$TAILWIND_VERSION-linux-$arch
daisyui=$CACHE_DIR/daisyui-$DAISYUI_VERSION.mjs
fetch_verified "$(tailwind_url "$arch")" "$tailwind" "$tailwind_sha"
fetch_verified "$(daisyui_url)" "$daisyui" "$DAISYUI_SHA256"
chmod +x -- "$tailwind"
# input.css loads the plugin from this fixed path.
cp -- "$daisyui" "$CACHE_DIR/daisyui.mjs"

mkdir -p -- "$(dirname -- "$output")"
"$tailwind" --input "$INPUT_CSS" --output "$output" --minify
