#!/usr/bin/env bash
# =============================================================================
# download_ptau.sh — fetch the public Powers-of-Tau ceremony file used as the
# Phase-1 trusted setup for Viche's Groth16 circuit.
#
# !!! DEV-ONLY !!!  The hermez powersOfTau28_hez_final_*.ptau files are the
# output of a community ceremony. They are acceptable for testnets / demos,
# but before any mainnet deployment Viche MUST run its own ceremony. See
# docs/crypto.md for the exact `snarkjs powersoftau ...` command sequence.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEPTH="${MERKLE_TREE_DEPTH:-20}"
PTAU_DIR="${ROOT}/ptau"
PTAU_FILE="${PTAU_DIR}/powersOfTau28_hez_final_${DEPTH}.ptau"

mkdir -p "${PTAU_DIR}"

if [[ -f "${PTAU_FILE}" ]]; then
    echo "Already present: ${PTAU_FILE}"
    exit 0
fi

echo "Downloading ptau (depth ${DEPTH}) ..."
# The original Hermez/iden3 mirror (storage.googleapis.com/zkevm/ptau/) started
# returning 403 AccessDenied at some point after this was last verified working
# — the bucket's ACL changed upstream, nothing this repo controls. Using the
# PSE (Ethereum Foundation Privacy & Scaling Explorations) "Perpetual Powers of
# Tau" mirror instead: a different ceremony transcript, but Powers-of-Tau
# phase 1 is circuit-agnostic, so any ceremony's output works as long as it
# covers enough constraints (this one goes up to depth 28; our circuit needs
# nowhere near that at depth 20). If THIS mirror ever goes down too, check
# https://github.com/privacy-ethereum/perpetualpowersoftau for the current
# location — do not just retry the old URL blindly.
#
# -f/--fail makes curl exit nonzero on an HTTP error instead of writing the
# error response body to disk as if it were the file — which is exactly how
# this broke silently: the old URL's 403 response (a few hundred bytes of
# XML) got written to PTAU_FILE, this script "succeeded", and the failure
# didn't surface until snarkjs choked on it two steps later with a
# confusing "Invalid File format" error.
curl -fL "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_${DEPTH}.ptau" \
    -o "${PTAU_FILE}"

# Belt-and-suspenders: -f catches HTTP error responses, but a sanity size
# check catches other silent-corruption modes too (a redirect to something
# that still returns 200, a truncated transfer, ...). Real ptau files are
# tens of MB at minimum; anything under 1MB is definitely not one.
MIN_BYTES=1000000
actual_bytes=$(wc -c < "${PTAU_FILE}")
if [[ "${actual_bytes}" -lt "${MIN_BYTES}" ]]; then
    echo "ERROR: downloaded ptau file is only ${actual_bytes} bytes (expected >= ${MIN_BYTES}) — likely corrupt or an error page. Contents:" >&2
    head -c 500 "${PTAU_FILE}" >&2
    echo >&2
    rm -f "${PTAU_FILE}"
    exit 1
fi

echo "Done: ${PTAU_FILE} (${actual_bytes} bytes)"
