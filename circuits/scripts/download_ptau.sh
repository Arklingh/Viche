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

echo "Downloading powersOfTau28_hez_final_${DEPTH}.ptau ..."
# The Hermez / iden3 mirror hosts the canonical files. Depth N supports
# circuits with up to 2^N constraints.
curl -L "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${DEPTH}.ptau" \
    -o "${PTAU_FILE}"

echo "Done: ${PTAU_FILE}"
