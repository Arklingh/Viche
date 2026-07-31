# Viche Cryptography

This document is the canonical reference for every cryptographic choice in
Viche. Every circuit, contract and (future) Rust implementation must agree
with what's written here; the smallest deviation makes proofs unverifiable
on-chain.

---

## 1. The big picture

A Viche poll proves three things without revealing the voter's identity:

1. **Membership** — "I have an identity commitment in this poll's whitelist."
2. **Ownership** — "I know the secret behind that commitment."
3. **Uniqueness** — "I have not voted in this poll yet."

All three are bundled into a single Groth16 proof produced from
[`circuits/circuits/vote.circom`](../circuits/circuits/vote.circom). The
contract (`VotingManager`) checks the proof against three public signals —
`voteId`, `merkleRoot`, `nullifierHash` — and rejects duplicate nullifiers.

---

## 2. Field

Everything happens in the **BN254 scalar field** (also called BN256, alt_bn128):

```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
```

> **Gotcha #1:** every signal that flows into the circuit — `secret`,
> `voteId`/`pollId`, every Merkle hash — MUST be reduced into `[0, p)`. The
> frontend must do this before building the witness; the contract never sees
> raw values above `p` because `uint256` is wider than the field, but the
> prover will reject them.

---

## 3. Hash function: Poseidon (BN254, circomlib parameters)

Viche uses Poseidon over the BN254 field with the parameter set shipped by
[`circomlib`](https://github.com/iden3/circomlib):

| Poseidon instance   | arity (`t`) | full rounds `R_F` | partial rounds `R_P` |
|---------------------|-------------|-------------------|----------------------|
| `Poseidon(1)` (commitment) | 2 | 8 | 57 |
| `Poseidon(2)` (nullifier, Merkle parent) | 3 | 8 | 57 |

Round constants and the MDS matrix are derived deterministically from a seed
in circomlib; **any Rust/JS re-implementation must load those exact constants**.
The reference JS is `circomlibjs` (`buildPoseidon`).

- **Identity commitment** (the leaf registered off-chain):
  `commitment = Poseidon(secret)`
- **Nullifier** (the per-poll double-voting tag):
  `nullifierHash = Poseidon(secret, voteId)`
- **Merkle parent**:
  `parent = Poseidon(leftChild, rightChild)`

> **Gotcha #2:** the Rust implementation in `viche-core` MUST use the
> identical Poseidon parameters. Using a different `R_F`/`R_P`, a different
> MDS, or even a different round-constant seed produces different hashes and
> silently breaks proofs. The reference test: hashing `[1, 2]` with
> `Poseidon(2)` must equal
> `0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a`.

---

## 4. Sparse Poseidon Merkle tree

The whitelist is a binary Merkle tree of depth **20** (≤ 2²⁰ ≈ 1M voters,
matches the standard `powersOfTau28_hez_final_20.ptau`). Sparse trees let us
insert a handful of commitments without materialising 2²⁰ leaves.

**Zero-hash chain** (must match `merkle_tree.circom`):

```
zeros[0] = 0
zeros[i] = Poseidon(zeros[i-1], zeros[i-1])    for i = 1..depth
```

**Insertion / proof:**

- `parent = Poseidon(leftChild, rightChild)`
- `pathIndices[i]`: at level `i`,
  - `0` ⟹ our node is the LEFT child, `pathElements[i]` is the RIGHT sibling,
  - `1` ⟹ our node is the RIGHT child, `pathElements[i]` is the LEFT sibling.

The reference implementation is
[`circuits/scripts/gen_input.js`](../circuits/scripts/gen_input.js). The
Phase-2/3 Rust port in `viche-core::merkle` must reproduce `root()` and
`proof()` bit-for-bit.

---

## 5. Public-signal ordering

snarkjs exposes public inputs in the order they are declared in the circuit,
with **no** outputs after them. For `vote.circom`:

```
pubSignals = [voteId, merkleRoot, nullifierHash]
```

Every consumer — `VotingManager.castVote`, the relayer's proof packer, the
frontend's snarkjs glue — MUST assemble the array in this exact order. The
verifier's 4-byte selector is computed over the *whole* signature including
the fixed-length `uint256[3]` of public inputs, so reordering or switching to
a dynamic array silently breaks every call.

---

## 6. Trusted setup (Groth16)

Groth16 needs a **per-circuit** trusted setup in two phases:

1. **Powers of Tau** (circuit-agnostic) — produces `*.ptau`.
2. **Circuit phase** (per `.circom`) — combines the r1cs with the ptau into a
   `*.zkey`, then multiple contributors each add randomness.

For **testnet / hackathon**, Viche uses the public
[`powersOfTau28_hez_final_20.ptau`](https://storage.googleapis.com/zkevm/ptau/)
from the Hermez community ceremony and a single random beacon contribution.
This is convenient but carries a toxic-waste assumption shared with thousands
of other projects.

> **Before mainnet**, run a fresh ceremony:
> ```bash
> snarkjs powersoftau new 20 pot0.ptau -v
> snarkjs powersoftau contribute pot0.ptau pot1.ptau --name="Viche contributor 1" -v -e=<random>
> # ... one contribution per participant, then a final beacon
> snarkjs powersoftau beacon pot1.ptau pot_beacon.ptau <beacon-hash> 0 -v
> snarkjs powersoftau prepare phase2 pot_beacon.ptau final.ptau -v
> snarkjs groth16 setup build/vote.r1cs final.ptau build/vote_0000.zkey
> # phase-2 contributions per participant, then beacon
> snarkjs zkey contribute build/vote_0000.zkey build/vote_final.zkey --name=... -e=<random>
> ```
> **Destroy** the randomness (`-e` values) after each step. The security of
> the entire voting system rests on the integrity of this ceremony.

---

## 7. Anonymity — what is and isn't private

| Quantity                          | Private? | Notes |
|-----------------------------------|----------|-------|
| `secret`                          | ✅       | The voter's only long-term secret. Never leaves the browser. |
| `pathElements`, `pathIndices`     | ✅       | Locates the leaf; without these the ballot can't be tied to an address. |
| `voteId` (= `pollId`)             | ❌       | Public; selects the poll. |
| `merkleRoot`                      | ❌       | Public; identifies the whitelist snapshot. |
| `nullifierHash`                   | ❌       | Public; the double-voting tag. One-way under Poseidon, so it leaks no identity. |
| `voteOption`                      | ❌       | Submitted in the clear and tallied on-chain. |

**Viche v1 makes voter identity anonymous, not vote choice.** Encrypted-choice
voting (e.g. MACI-style) is explicitly future work.

---

## 8. Where to look next

- Circuit source: [`circuits/circuits/vote.circom`](../circuits/circuits/vote.circom)
- On-chain logic: [`contracts/src/VotingManager.sol`](../contracts/src/VotingManager.sol)
- Reference off-chain tree/proof: [`circuits/scripts/`](../circuits/scripts/)
- Rust ports (Phase 2/3): [`crates/viche-core/src/lib.rs`](../crates/viche-core/src/lib.rs)
