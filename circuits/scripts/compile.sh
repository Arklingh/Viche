#!/usr/bin/env bash
# =============================================================================
# compile.sh — full Groth16 pipeline for a Viche circuit.
#
# Inputs (env, with sensible defaults):
#   CIRCUIT            circuit base name (default: vote)
#   MERKLE_TREE_DEPTH  tree depth baked into the witness (default: 20)
#
# Stages:
#   1. circom           compile -> r1cs + witness wasm
#   2. (download_ptau)  Powers-of-Tau file (DEV CEREMONY — see warning)
#   3. groth16 setup    r1cs + ptau -> phase-2 zkey (vote_0000.zkey)
#   4. contribute       random beacon contribution -> vote_final.zkey
#   5. export vkey      verification key (json)
#   6. export verifier  contracts/src/verifier/Groth16Verifier.sol
#
# !!! WARNING !!!
#   The public `powersOfTau28_hez_final_*.ptau` file is the HERMEZ community
#   ceremony. It is fine for testnets / hackathons / demo deployments, but
#   ANYONE who contributed to that ceremony could in principle have retained
#   their toxic waste. Before mainnet, Viche MUST run its own ceremony:
#       snarkjs powersoftau new <depth> | snarkjs powersoftau contribute ... |
#       snarkjs powersoftau export phase2 | snarkjs groth16 setup ...
#   See docs/crypto.md.
# =============================================================================
set -euo pipefail

CIRCUIT="${CIRCUIT:-vote}"
MERKLE_TREE_DEPTH="${MERKLE_TREE_DEPTH:-20}"

# Resolve directories relative to THIS script, so it works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"

CIRCUITS_SRC="${ROOT_DIR}/circuits"
BUILD_DIR="${ROOT_DIR}/build"
PTAU_DIR="${ROOT_DIR}/ptau"
PTAU_FILE="${PTAU_DIR}/powersOfTau28_hez_final_${MERKLE_TREE_DEPTH}.ptau"

CONTRACTS_VERIFIER_DIR="${REPO_ROOT}/contracts/src/verifier"

R1CS="${BUILD_DIR}/${CIRCUIT}.r1cs"
WASM_DIR="${BUILD_DIR}/${CIRCUIT}_js"
PHASE2_ZKEY="${BUILD_DIR}/${CIRCUIT}_0000.zkey"
FINAL_ZKEY="${BUILD_DIR}/${CIRCUIT}_final.zkey"
VKEY="${BUILD_DIR}/${CIRCUIT}_vkey.json"

echo "=================================================================="
echo " Viche circuit compile"
echo "   circuit          : ${CIRCUIT}"
echo "   merkle depth     : ${MERKLE_TREE_DEPTH}"
echo "   circuits dir     : ${ROOT_DIR}"
echo "   build dir        : ${BUILD_DIR}"
echo "=================================================================="

mkdir -p "${BUILD_DIR}" "${PTAU_DIR}" "${CONTRACTS_VERIFIER_DIR}"

# ---------------------------------------------------------------------------
# 0. Sanity: required binaries on PATH.
# ---------------------------------------------------------------------------
command -v circom   >/dev/null 2>&1 || { echo "ERROR: circom not found. Install: https://docs.circom.io/getting-started/installation/"; exit 1; }
command -v snarkjs  >/dev/null 2>&1 || { echo "ERROR: snarkjs not found. Install: npm i -g snarkjs"; exit 1; }

# ---------------------------------------------------------------------------
# 1. circom compile -> r1cs + wasm witness generator.
#    -l adds node_modules (circomlib) to the include path.
#    --r1cs / --wasm emit the artefacts snarkjs needs.
#    We intentionally skip --c (C witness) — the wasm witness is enough for
#    snarkjs and is what the browser prover uses.
# ---------------------------------------------------------------------------
echo ">> [1/6] circom compile"
circom "${CIRCUITS_SRC}/${CIRCUIT}.circom" \
    -l "${ROOT_DIR}/node_modules" \
    --r1cs --wasm \
    -o "${BUILD_DIR}" \
    -c # -c copies inputs, -n forces prime=bn128 explicitly

# ---------------------------------------------------------------------------
# 2. Powers-of-Tau (dev ceremony). Phase-1 (MPC) trusted setup file.
# ---------------------------------------------------------------------------
if [[ ! -f "${PTAU_FILE}" ]]; then
    echo ">> [2/6] downloading ptau (depth ${MERKLE_TREE_DEPTH})"
    curl -L "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${MERKLE_TREE_DEPTH}.ptau" \
        -o "${PTAU_FILE}"
else
    echo ">> [2/6] ptau present, skipping download"
fi

# ---------------------------------------------------------------------------
# 3. Phase-2 setup: combine r1cs + ptau into a circuit-specific zkey.
# ---------------------------------------------------------------------------
echo ">> [3/6] groth16 setup (phase 2)"
snarkjs groth16 setup "${R1CS}" "${PTAU_FILE}" "${PHASE2_ZKEY}"

# ---------------------------------------------------------------------------
# 4. Contribute a random beacon to the phase-2 zkey and produce the final key.
#    In a real deployment you'd run `groth16 contribute` interactively with
#    multiple participants first. For dev we just beacon with a fixed string
#    mixed with randomness so reruns differ.
# ---------------------------------------------------------------------------
echo ">> [4/6] contribute beacon -> final zkey"
BEacon_ENTROPY="${BEACON_ENTROPY:-0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f}"
snarkjs zkey contribute "${PHASE2_ZKEY}" "${FINAL_ZKEY}" \
    --name="Viche dev contribution" \
    -e="${BEacon_ENTROPY}" -v

# ---------------------------------------------------------------------------
# 5. Export the verification key (consumed by snarkjs to verify proofs).
# ---------------------------------------------------------------------------
echo ">> [5/6] export verification key"
snarkjs zkey export verificationkey "${FINAL_ZKEY}" "${VKEY}"

# ---------------------------------------------------------------------------
# 6. Export the Solidity verifier contract into the Foundry project.
#    `--verifier` selects the template; the default already targets 0.8.x.
# ---------------------------------------------------------------------------
echo ">> [6/6] export Solidity verifier -> ${CONTRACTS_VERIFIER_DIR}/Groth16Verifier.sol"
snarkjs zkey export solidityverifier "${FINAL_ZKEY}" \
    "${CONTRACTS_VERIFIER_DIR}/Groth16Verifier.sol"

echo "=================================================================="
echo " Done. Outputs:"
echo "   ${R1CS}"
echo "   ${WASM_DIR}"
echo "   ${FINAL_ZKEY}"
echo "   ${VKEY}"
echo "   ${CONTRACTS_VERIFIER_DIR}/Groth16Verifier.sol"
echo "=================================================================="
echo " Next: from the repo root, \`make build-contracts\` then \`make test-contracts\`."
