# Viche Deployment Runbook

This is the practical guide to running Viche outside a local `anvil` dev
loop: a public testnet (Sepolia is assumed throughout; swap RPC/chain id for
any other EVM chain), a persistent relayer host, and static hosting for the
frontend. It intentionally stays provider-agnostic — pick whatever RPC
provider, relayer host, and static host you already trust; nothing here is
locked to a specific vendor.

For local development, see the root `README.md` and `Dockerfile.dev` /
`docker-compose.yml` instead — this doc is specifically about a deployment
that outlives your terminal session.

---

## 1. Prerequisites

- An RPC endpoint for your target network (Infura, Alchemy, a self-hosted
  node, etc.) — both an HTTP(S) URL for deploying/relaying and, ideally, an
  Etherscan (or equivalent) API key for contract verification.
- A funded deployer EOA (pays for `VotingManager` + `Groth16Verifier`
  deployment) and a **separate** funded relayer EOA (pays gas for every
  `castVote`). Keep these different from your local anvil throwaway keys.
- A **third**, separate EOA for `ADMIN_PRIVATE_KEY` if you want the
  relayer's `/api/admin/*` HTTP path available (optional — the admin UI's
  wallet-direct `createPoll`/`closePoll` path needs no relayer key at all).
  See `crates/viche-relayer/.env.example` for why these are kept apart.
- `make circuits` already run, so `circuits/build/vote_final.zkey`,
  `circuits/build/vote_js/vote.wasm`, and
  `contracts/src/verifier/Groth16Verifier.sol` are all present and mutually
  consistent (the same zkey the verifier was exported from). **If you
  regenerate the zkey (e.g. after a real trusted-setup ceremony — see
  `docs/trusted-setup-ceremony.md`), re-run
  `node circuits/scripts/export_verifier.js` and resync
  `crates/viche-frontend/public/circuits/` before deploying anything** — a
  verifier contract built from a different zkey than the one voters prove
  against will reject every vote with `InvalidProof`, and it fails silently
  (proofs still generate fine, they just never verify on-chain).

---

## 2. Deploy the contracts

Set the network env vars `foundry.toml`'s `[rpc_endpoints]`/`[etherscan]`
profiles expect:

```bash
export SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/<your-key>"
export ETHERSCAN_API_KEY="<your-etherscan-key>"
export DEPLOYER_PRIVATE_KEY="0x..."   # the funded deployer EOA
```

Then run the existing deploy script against the named network profile:

```bash
forge script contracts/script/DeployVotingManager.s.sol \
  --rpc-url sepolia \
  --broadcast \
  --verify \
  --private-key "$DEPLOYER_PRIVATE_KEY"
```

This deploys a fresh `Groth16Verifier` (from the current
`contracts/src/verifier/Groth16Verifier.sol`) and `VotingManager` wired to
it, and — because of `--verify` plus the `[etherscan]` profile — verifies
both on Etherscan automatically. Note the two addresses it prints
(`Groth16Verifier` and `VotingManager`); you'll need `VotingManager`'s
address for both the relayer and the frontend.

If you already have a verifier deployed (e.g. redeploying `VotingManager`
without a new circuit), set `VERIFIER_ADDRESS` to skip deploying a new one —
see the script's own doc comment.

---

## 3. Deploy the relayer

The relayer is a single stateless-ish binary (see
`crates/viche-relayer/src/registration.rs` for its one deliberate exception:
a small JSON file for pre-poll voter registration — give it a persistent
volume, not ephemeral storage, or registrations collected between polls can
be lost on restart).

### 3.1 Build the image

```bash
docker build -f Dockerfile.relayer -t viche-relayer .
```

(Build context must be the repo root — the relayer has a workspace path
dependency on `viche-core`.)

### 3.2 Configure

Copy `crates/viche-relayer/.env.example` and fill in real values for the
target network:

```bash
cp crates/viche-relayer/.env.example crates/viche-relayer/.env.sepolia
```

```
RELAYER_PRIVATE_KEY=<funded relayer EOA, NOT the deployer key>
ADMIN_PRIVATE_KEY=<VotingManager owner key — separate from the above>
ADMIN_API_KEY=<a real random secret, e.g. `openssl rand -hex 32`>
RPC_URL=https://sepolia.infura.io/v3/<your-key>
VOTING_MANAGER_ADDRESS=<from step 2>
VERIFIER_ADDRESS=<from step 2, optional — only read by the deploy script>
RELAYER_LISTEN_ADDR=0.0.0.0
RELAYER_LISTEN_PORT=3000
```

`ADMIN_API_KEY=dev-only-change-me` (the local-dev default) **must** be
replaced — it gates the registration-management and admin HTTP endpoints.

### 3.3 Run

```bash
docker run -d \
  --name viche-relayer \
  --restart unless-stopped \
  -p 3000:3000 \
  --env-file crates/viche-relayer/.env.sepolia \
  -v viche-registrations:/data \
  viche-relayer
```

The `-v viche-registrations:/data` volume persists
`REGISTRATIONS_FILE=/data/registrations.json` (set by the image's
`ENV`) across container restarts/redeploys — voters who registered before a
poll was created shouldn't have to re-register just because the container
recycled.

Any container host that can run a long-lived process with a persistent
volume works here (a small VPS running plain `docker run`, a managed
container platform, a Kubernetes `Deployment` + `PersistentVolumeClaim`,
etc.) — this repo doesn't prescribe one. Put it behind TLS (a reverse proxy
or your platform's built-in HTTPS) before pointing a real frontend at it;
the relayer itself speaks plain HTTP.

### 3.4 Smoke test

```bash
curl https://relayer.example.com/health
curl https://relayer.example.com/api/polls
```

---

## 4. Deploy the frontend

`trunk build --release` produces a fully static bundle in
`crates/viche-frontend/dist/` — any static host works (Cloudflare Pages,
Netlify, Vercel, S3+CloudFront, GitHub Pages, etc.). There's no server-side
rendering and no API routes to configure on the hosting side; it's just
files.

### 4.1 Configure the target network at build time

The frontend reads its network config from compile-time env vars (see
`crates/viche-frontend/src/config.rs`):

```bash
export VICHE_RELAYER_URL="https://relayer.example.com"
export VICHE_VOTING_MANAGER_ADDRESS="0x..."   # from step 2
export VICHE_CHAIN_ID="0xaa36a7"              # 11155111 (Sepolia) in hex
```

### 4.2 Build

```bash
make circuits          # if not already done — see prerequisites
make frontend-assets   # syncs vote.wasm / vote_final.zkey into the Trunk public dir
cd crates/viche-frontend && trunk build --release
```

Deploy the contents of `crates/viche-frontend/dist/` to your static host.

### 4.3 Runtime override (no rebuild needed)

The same three values can be set at runtime instead, via `window` globals —
useful for a single build serving multiple environments, or for overriding
without a rebuild:

```html
<script>
  window.__VICHE_RELAYER_URL__ = "https://relayer.example.com";
  window.__VICHE_VOTING_MANAGER_ADDRESS__ = "0x...";
  window.__VICHE_CHAIN_ID__ = "0xaa36a7";
</script>
```

Add this before the Trunk-injected `<script type="module">` tag in
`index.html` (or inject it from your hosting platform's own templating, if
it has one) if you'd rather not rebuild per environment.

---

## 5. Post-deploy checklist

- [ ] `GET /health` on the relayer returns `200`.
- [ ] `GET /api/polls` on the relayer returns `{"polls":[]}` (or existing
      polls, if `VotingManager` wasn't freshly deployed).
- [ ] The frontend loads and "Connect Wallet" successfully detects a
      testnet wallet (MetaMask set to the target network).
- [ ] Register a test commitment via the "Register to Vote" page, confirm
      it shows up via `GET /api/admin/registrations/pending` (with your
      `ADMIN_API_KEY`).
- [ ] As the `VotingManager` owner wallet: build a whitelist, create a
      poll, and cast one real vote end-to-end — confirming the deployed
      verifier actually accepts proofs generated against the deployed
      zkey (this is the exact failure mode called out in the
      Prerequisites section, and it doesn't show up until a vote is
      actually cast).

---

## 6. Mainnet differences

Everything above applies to mainnet too, with three additions:

1. **A real trusted-setup ceremony** — the local/testnet ptau mirror and
   single-beacon-contribution zkey are explicitly not meant for mainnet.
   See `docs/trusted-setup-ceremony.md` for the full runbook. This produces
   a *new* `vote_final.zkey` and therefore a *new* `Groth16Verifier.sol` —
   redeploy `VotingManager` against it (the verifier is `immutable`, so an
   existing deployment can't be upgraded in place).
2. **Real secrets management** for `RELAYER_PRIVATE_KEY` /
   `ADMIN_PRIVATE_KEY` — a `.env` file on a VPS is fine for a testnet, but
   mainnet keys holding real funds belong in a proper secrets manager
   (your cloud provider's, or a self-hosted one) injected into the
   container at runtime, not committed or left in a plaintext file.
3. **`VICHE_CHAIN_ID="0x1"`** (or omit it — `0x1` is already the frontend's
   default).
