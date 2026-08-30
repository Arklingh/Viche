# Production trusted-setup ceremony (runbook)

**Status: not yet done.** Do this before any mainnet / real-money deployment.
Skip it for testnet, demos, or further development — the current setup
(public Hermez `ptau` + one automated beacon contribution, see
[`docs/crypto.md`](crypto.md#6-trusted-setup-groth16)) is fine for that.

## Why this matters

Groth16's proving key encodes secret randomness ("toxic waste") from whoever
ran the setup. Anyone who still holds it can forge a proof for *any* vote —
no valid secret, no real Merkle membership, nothing — and it will verify as
legitimate on-chain. The scheme is only as anonymous-and-unforgeable as the
setup is: `castVote`'s guarantees (one vote per identity, no forged ballots)
are void if the toxic waste survives anywhere.

The current setup's toxic waste is derivable by anyone who can replicate a
public ptau file + a public automated beacon — i.e. by design, no one is
actually trusted not to have it. A real ceremony fixes this via **1-of-N
honesty**: as long as *one* participant genuinely destroys their randomness,
the final key is safe, even if every other participant is malicious or
compromised.

## Who

- **3–5 participants minimum**, each running on their own machine, ideally
  air-gapped or freshly booted/offline for the contribution step.
- Participants must be mutually independent — not all Viche core
  maintainers. Pull in community members, an auditor, another project's
  team, anyone with no reason to collude with the others.
- Each participant needs: `snarkjs` installed, a source of real entropy
  (mashing the keyboard is fine — snarkjs prompts for it), and a way to
  publish a hash of their contribution afterward (a tweet, a signed commit,
  a Discord/Telegram message with a timestamp — anything public and
  attributable).

## What: phase 1 (Powers of Tau)

Circuit-agnostic — can be skipped by reusing a large reputable public
ceremony (Hermez, or the Ethereum KZG ceremony's Powers-of-Tau equivalent)
**if** you're comfortable with 1-of-thousands trust for this phase. To run a
fresh one instead:

```bash
snarkjs powersoftau new bn128 20 pot_0000.ptau -v

# Each participant, in turn, on their own machine:
snarkjs powersoftau contribute pot_N.ptau pot_N+1.ptau \
    --name="<participant name>" -v
# snarkjs prompts for entropy interactively — type random garbage.
# Immediately after: publish sha256sum(pot_N+1.ptau) publicly, then
# securely delete pot_N+1.ptau from this machine (the entropy that
# produced it, not the file itself, is the actual secret — deleting the
# file is a reasonable proxy since re-deriving the entropy from it is
# the attack you're defending against).

# After all contributions, apply a public randomness beacon (drand, a
# recent Bitcoin block hash, etc.) so the transcript has a verifiable end:
snarkjs powersoftau beacon pot_final.ptau pot_beacon.ptau \
    <beacon-hash> 10 -v

snarkjs powersoftau prepare phase2 pot_beacon.ptau final.ptau -v
snarkjs powersoftau verify final.ptau   # MUST print "Powers of Tau OK!"
```

## What: phase 2 (circuit-specific)

```bash
snarkjs groth16 setup circuits/build/vote.r1cs final.ptau vote_0000.zkey

# Each participant contributes again (can be the same or a different set
# of people from phase 1):
snarkjs zkey contribute vote_N.zkey vote_N+1.zkey \
    --name="<participant name>" -v
# Same rule: publish the hash, destroy the entropy, move on.

snarkjs zkey beacon vote_final_pre.zkey vote_final.zkey \
    <beacon-hash> 10 -v -n="Final Beacon"

snarkjs zkey verify circuits/build/vote.r1cs final.ptau vote_final.zkey
# MUST print "ZKey Ok!" -- this is the step that actually checks every
# contribution was applied correctly. Do not skip it, and do not proceed
# if it fails.
```

## Publish, for anyone to audit later

- The full transcript: every intermediate `.ptau`/`.zkey` hash, in order,
  with participant names/handles attached.
- The beacon values used and where they came from (block explorer link,
  drand round number, etc.) — must be something nobody could have predicted
  in advance.
- The final `vote_final.zkey`'s hash and the exported verification key
  (`vote_final.zkey` -> `vkey.json` via `snarkjs zkey export verificationkey`).

A ceremony nobody can independently verify provides none of the security
benefit — publishing is not optional.

## Cutover checklist

`VotingManager`'s verifier address is set once, in the constructor, and is
`immutable` — swapping the zkey file alone does **nothing** for an already-
deployed contract. Deploying the new ceremony's output means:

1. Regenerate `contracts/src/verifier/Groth16Verifier.sol` from the new
   `vote_final.zkey` (`make verifier`, or
   `snarkjs zkey export solidityverifier`).
2. Deploy a **new** `VotingManager` pointing at the **new** `Groth16Verifier`
   (`forge script script/DeployVotingManager.s.sol`) — the old contract and
   any polls on it are unaffected and stay on the old (weaker) setup.
3. Update `VOTING_MANAGER_ADDRESS` / `VERIFIER_ADDRESS` in the relayer's and
   frontend's config for the new deployment.
4. Replace `circuits/ptau/powersOfTau28_hez_final_20.ptau` and
   `circuits/build/vote_final.zkey` with the ceremony's output, and ship the
   new `vote.wasm`/`vote_final.zkey` pair to wherever the frontend serves
   circuit assets from (`crates/viche-frontend/public/circuits/` locally;
   the CDN/object store in production — see `proofgen.rs`'s doc comment).
5. Regenerate the demo whitelist / any test fixtures that assumed the old
   verifying key, if applicable.
