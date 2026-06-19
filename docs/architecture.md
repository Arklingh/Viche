# Viche Architecture

A four-layer stack: a Circom circuit, a Solidity contract, a Rust relayer and
a Rust→WASM frontend. Each layer is independent except for the small,
well-defined invariants documented in [`crypto.md`](./crypto.md).

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                           BROWSER  (Leptos / WASM)                        │
│                                                                          │
│   wallet (EIP-1193)  ──►  viche-frontend                                 │
│                            ├── viche-core: Poseidon tree, build witness  │
│                            ├── snarkjs wasm: groth16 prove               │
│                            └── gloo-net: POST {proof,nullifier,option}   │
│                                          │                                │
└──────────────────────────────────────────┼───────────────────────────────┘
                                           │  HTTPS  (proof only — never the secret)
                                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          RELAYER  (Axum + alloy)                         │
│                                                                          │
│   POST /api/vote ──►  validate ──►  build castVote calldata              │
│                                      │                                   │
│                                      ├── sign with relayer key           │
│                                      └── broadcast via alloy provider    │
└──────────────────────────────────────────┼───────────────────────────────┘
                                           │  JSON-RPC
                                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    ON-CHAIN  (Foundry / Solidity)                        │
│                                                                          │
│   VotingManager                                                          │
│     ├── createPoll(root, numOptions, deadline, metadata)  [owner]        │
│     ├── castVote(pollId, proof, nullifier, option)                       │
│     │      └── Groth16Verifier.verifyProof(pA,pB,pC, [voteId,root,null]) │
│     │          rejects if nullifier already used                         │
│     └── views: getPoll / getOptionTally / hasVoted                       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Layer responsibilities

### 1. Circuit (`circuits/`)
Defines the statement being proved. Built with `circom` + `snarkjs` into a
Groth16 zkey and a Solidity verifier. Pure, deterministic, stateless.

### 2. Contracts (`contracts/`)
`VotingManager` is the **only** state-bearing component. It stores polls,
nullifiers, and tallies; it never learns identities. It treats the verifier
as an `IVerifier` so the contract compiles even before `make circuits` has
emitted the real generated verifier.

### 3. Relayer (`crates/viche-relayer`)
A small Axum service whose job is to **pay gas**. It does not generate
proofs, does not see the voter's secret, and cannot forge or replay a vote.
Trust assumption: liveness only — a malicious relayer can censor, never forge.

### 4. Frontend (`crates/viche-frontend`)
Leptos SPA compiled to `wasm32-unknown-unknown`. Owns: wallet connection,
Merkle-tree construction (via `viche-core`), in-page proof generation (via
snarkjs wasm), and the HTTP call to the relayer.

## Trust model summary

| Threat                             | Mitigation                                          |
|------------------------------------|-----------------------------------------------------|
| Relayer forges a vote              | Impossible — no valid proof without `secret`.       |
| Relayer double-votes for a voter   | Impossible — nullifier is fixed by `secret + pollId`. |
| Relayer censors votes              | Accepted (liveness only). Voter can self-submit.    |
| Observer links ballot to identity  | Impossible — `pathElements`/`pathIndices` stay private. |
| Voter votes twice                  | Impossible — same nullifier twice → `AlreadyVoted`. |
| Toxic-waste holder breaks soundness| Run a fresh trusted setup before mainnet.           |
| Voter's choice is exposed          | Accepted (v1). Vote *option* is public; identity is not. |

## Phases

- **Phase 1 (this work)** — circuit + contracts + build pipeline + workspace
  scaffold. Verified with `MockVerifier`-based unit tests.
- **Phase 2** — `viche-relayer` Axum service + `viche-core` field/Poseidon/
  Merkle implementations.
- **Phase 3** — `viche-frontend` Leptos SPA, wallet connection, browser proof
  generation.
