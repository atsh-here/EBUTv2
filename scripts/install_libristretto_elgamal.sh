#!/usr/bin/env bash
set -euo pipefail

# Build the external invertible Ristretto/Elligator codec used by
# src/ristretto_elligator_codec.rs.
#
# This script intentionally vendors the upstream implementation from:
#   https://github.com/oblivious-file-sharing/libristretto-elgamal
#
# The Rust crate will link it only when EBUT_RISTRETTO_ELGAMAL_LIB_DIR points
# at the directory containing libristretto_elgamal.a.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="${ROOT_DIR}/vendor/libristretto-elgamal"
UPSTREAM="https://github.com/oblivious-file-sharing/libristretto-elgamal.git"
PIN="04b9219a84dda9812a72e8a184188b705daa8aeb"

mkdir -p "${ROOT_DIR}/vendor"
if [[ ! -d "${VENDOR_DIR}/.git" ]]; then
  git clone "${UPSTREAM}" "${VENDOR_DIR}"
fi
cd "${VENDOR_DIR}"
git fetch --depth 1 origin "${PIN}"
git checkout "${PIN}"

# Upstream treats warnings as errors.  Newer GCC versions emit -Warray-parameter
# for src/f_arithmetic.c vs src/f_field.h, which is harmless here but breaks
# the pinned 2018-era Makefile.  Remove -Werror in the vendored checkout so
# modern compilers can build the exact pinned source without changing code.
if grep -q -- "-Werror" Makefile; then
  sed -i 's/ -Werror//g; s/-Werror //g' Makefile
fi

# Upstream uses OpenSSL SHA functions and OpenMP. Install libssl-dev and
# build-essential if this fails.  Build only the static library, not all
# upstream test/demo binaries.
make clean || true
make lib -j"$(nproc)"

# The pinned upstream Makefile archives the Ristretto-ElGamal objects into
# build/lib/libristretto255.a.  Our Rust build expects the purpose-specific
# name libristretto_elgamal.a, so create a copy with that name.
if [[ -f "${VENDOR_DIR}/build/lib/libristretto255.a" ]]; then
  cp "${VENDOR_DIR}/build/lib/libristretto255.a" "${VENDOR_DIR}/build/lib/libristretto_elgamal.a"
fi

LIB_PATH="$(find "${VENDOR_DIR}" -path '*/build/lib/libristretto_elgamal.a' -print -quit)"
if [[ -z "${LIB_PATH}" ]]; then
  echo "Could not find build/lib/libristretto_elgamal.a after build" >&2
  exit 1
fi
LIB_DIR="$(dirname "${LIB_PATH}")"
cat <<MSG

Built libristretto_elgamal:
  ${LIB_PATH}

Use it with EBUT:
  export EBUT_RISTRETTO_ELGAMAL_LIB_DIR="${LIB_DIR}"
  cargo test --all-features

If linking complains about OpenMP/libgomp, install build-essential or libgomp1.
MSG
