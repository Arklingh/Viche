# Viche — Decentralized Anonymous Voting dApp

**Viche** is a decentralized voting application built for small-to-medium
communities. Named after the traditional self-governing assemblies of
history, it modernizes grassroots democracy with cryptographic guarantees of
anonymity, integrity and verifiability.

By leveraging **zero-knowledge proofs**, Viche solves the fundamental paradox
of electronic voting: verifying that a ballot is valid and comes from an
eligible voter *without revealing who that voter is*.

> **Status:** Phase 1 complete — Circom circuit, Solidity contracts and the
> Groth16 build pipeline are implemented and unit-tested. The Rust relayer
> (Phase 2) and Leptos frontend (Phase 3) are scaffolded as compile-clean
> stubs. See [Phases](#-phases).

---

## 🚀 Principles & cryptographic guarantees

- **Anonymity** — a voter's identity is decoupled from their ballot. Only a
  per-poll nullifier is published; the secret and Merkle path stay in the
  browser.
- **Integrity** — every vote is recorded on an immutable ledger via smart
  contract; no third party can alter, delete or inject ballots.
- **Public verifiability** — anyone can audit the tally; the contract only
  credits a vote that arrives with a valid Groth16 proof.
- **Double-voting prevention** — a `Poseidon(secret, pollId)` nullifier is
  unique per voter per poll; the contract rejects duplicates.
- **Gasless voting** — a Rust relayer pays gas and submits the transaction,
  so end users never need ETH.

---

## 🏗️ Architecture

Four layers, documented in [`docs/architecture.md`](docs/architecture.md):

```text
Browser (Leptos/WASM)  ──proof only──►  Relayer (Axum + alloy)  ──►  VotingManager (Solidity)
   generate Groth16 proof                  pay gas, broadcast          verify proof, tally
```

- **Frontend & crypto** — Rust + [Leptos](https://leptos.dev) compiled to
  `wasm32-unknown-unknown`. Connects the injected EIP-1193 wallet, builds the
  Poseidon Merkle witness, and generates the Groth16 proof in-page via
  snarkjs wasm.
- **Relayer** — Axum service using [`alloy`](https://github.com/alloy-rs/alloy)
  to accept a proof, sign and broadcast `castVote`. Never sees the voter's
  secret.
- **Smart contracts** — Solidity via [Foundry](https://getfoundry.sh). Stores
  the whitelist Merkle root and the nullifier set; verifies proofs via a
  generated Groth16 verifier.
- **Cryptography** — [Circom](https://docs.circom.io) circuits +
  [snarkjs](https://github.com/iden3/snarkjs) Groth16 + Poseidon over BN254.

---

## 📁 Repository layout

```text
Viche/
├── contracts/        # Foundry Solidity project (VotingManager + verifier)
├── circuits/         # Circom circuit + Groth16 build pipeline (snarkjs)
├── crates/
│   ├── viche-core/      # shared: Poseidon Merkle tree, field, wire types
│   ├── viche-relayer/   # Axum + alloy gasless relayer
│   └── viche-frontend/  # Leptos WASM SPA
├── docs/             # architecture + crypto reference
├── Cargo.toml        # Rust workspace manifest
├── foundry.toml      # Solidity build config
├── Makefile          # top-level orchestration (setup / circuits / build / test)
└── .env.example      # environment template
```

---

## 📦 Prerequisites

- **Rust** 1.74+ (`cargo`, `rustc`, and the `wasm32-unknown-unknown` target)
- **Node.js** 18+ and `npm`
- **Foundry** (`forge`, `cast`, `anvil`) — install via `curl -L https://foundry.paradigm.xyz | bash`
- **circom** 2.x — <https://docs.circom.io/getting-started/installation/>
- **snarkjs** — `npm install -g snarkjs`
- `make`

---

## 🔧 Quick start

### 1. Clone

```bash
git clone https://github.com/Arklingh/Viche.git
cd Viche
```

### 2. One-time setup

```bash
make setup
```

This installs `forge-std`, the JS dependencies (`circomlib`, `snarkjs`,
`circomlibjs`) and downloads the dev Powers-of-Tau file. (See
[`docs/crypto.md`](docs/crypto.md) for why dev setups must not go to mainnet.)

### 3. Compile the ZK circuit → Solidity verifier

```bash
make circuits
```

Produces `circuits/build/vote_final.zkey`, the verification key, and
**overwrites** `contracts/src/verifier/Groth16Verifier.sol` (currently a
permissive placeholder) with the cryptographically-sound generated verifier.

### 4. Build & test the contracts

```bash
make build-contracts   # forge build
make test-contracts    # forge test -vvv
```

> The unit tests use a `MockVerifier`, so they pass even before step 3. The
> deploy script auto-deploys the real verifier when it runs.

### 5. Generate a sample proof (optional sanity check)

```bash
make proof-demo
```

Runs `circuits/scripts/gen_proof.js`, which builds a Poseidon Merkle tree
from sample commitments, computes the witness, proves it, and verifies the
proof locally. Useful for end-to-end circuit validation.

### 6. Relayer & frontend (Phases 2 & 3)

The relayer and frontend crates are scaffolded today. Once implemented:

```bash
cp .env.example .env       # fill in RPC_URL, RELAYER_PRIVATE_KEY, contract addresses
make build-rs              # cargo build --workspace --release
# relayer:
cargo run --release -p viche-relayer
# frontend (Phase 3, via Trunk + Tailwind):
cd crates/viche-frontend && trunk serve
```

---

## 🔒 Security & privacy model

- **Client-side proving** — the voter's `secret` never leaves the browser.
  The relayer and contract see only the proof, nullifier and chosen option.
- **Per-poll nullifiers** — `Poseidon(secret, pollId)` is unique per voter per
  poll, so proofs cannot be replayed across polls.
- **Cross-poll binding** — the contract pins `voteId == pollId` and
  `merkleRoot == poll root` from on-chain state when assembling the public
  inputs, so a valid proof for one poll cannot be replayed against another.
- **Relayer trust = liveness only** — a malicious relayer can censor or
  reorder, but cannot forge (no valid proof) or double-vote (nullifier fixed
  by the voter's secret).
- **Trusted setup** — the dev pipeline uses the public Hermez Powers-of-Tau.
  **Run a fresh ceremony before mainnet.** See [`docs/crypto.md`](docs/crypto.md).

### Scope

Viche v1 anonymises **identity**, not **vote choice** — the selected option
is tallied in the clear. Encrypted-choice voting (MACI-style) is future work.

---

## 🧪 Phases

| Phase | Scope                                              | Status |
|-------|----------------------------------------------------|--------|
| 1     | Circom circuit, Solidity contracts, build pipeline | ✅ Done |
| 2     | Rust relayer (`viche-relayer`) + `viche-core`      | ⏳ Scaffolded |
| 3     | Leptos WASM frontend (`viche-frontend`)            | ⏳ Scaffolded |

---

## 📄 License

Licensed under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE)
for the full text.
