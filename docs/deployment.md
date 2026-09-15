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

You also need `VKEY_HASH` — the `keccak256` of the runtime bytecode of the
verifier you are deploying. **The script fails closed without it**, because
`VotingManager.verifier` is immutable and a verifier built from a trusted
setup whose toxic waste still exists lets its holder forge unlimited votes:

```bash
export VKEY_HASH="0x..."   # see docs/trusted-setup-ceremony.md
```

Running without it aborts the deploy and prints the codehash it computed, so
a first attempt tells you the value. Do not paste that value back in
reflexively — it is only meaningful once you know which setup produced the
verifier. `ALLOW_DEV_VERIFIER=true` bypasses the check entirely and is for
local anvil only; it has no legitimate use on a network in this document.

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
see the script's own doc comment. The `VKEY_HASH` check applies to that
address too, and it is the case where it matters most: a typo'd or
wrong-network `VERIFIER_ADDRESS` would otherwise be baked into an immutable
field.

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

If the relayer is served from a **different origin** than the frontend, also
set `VICHE_CSP_CONNECT_SRC` — the frontend ships a `default-src 'self'`
Content-Security-Policy, and a cross-origin relayer has to be named in
`connect-src` or every API call is blocked by the browser:

```bash
export VICHE_CSP_CONNECT_SRC="https://relayer.example.com"
```

Space-separate multiple origins. Leave it unset for the default topology,
where a reverse proxy exposes the relayer under `/api` on the frontend's own
origin (covered by `'self'`). See §4.5.

### 4.2 Build

```bash
make circuits          # if not already done — see prerequisites
make frontend-assets   # syncs vote.wasm / vote_final.zkey into the Trunk public dir
make frontend          # npm ci + Tailwind + trunk build --release + CSP checks
```

Prefer `make frontend` over a bare `trunk build --release`: it runs `npm ci`
first, which the build now needs. The stylesheet is compiled from source by the
Tailwind CLI (the `cdn.tailwindcss.com` play CDN is gone), and that compile is
a Trunk `pre_build` hook — so a bare `trunk build` works too **provided**
`npm ci` has been run at the repo root at least once. Without it the build
fails with an explicit message rather than emitting an unstyled page.

Deploy the contents of `crates/viche-frontend/dist/` to your static host.
`dist/` is generated output and is not tracked in git; never edit it in place
except for `viche_env.js` (§4.3).

### 4.3 Runtime override (no rebuild needed)

The same three values can be set at runtime instead, via `window` globals —
useful for a single build serving multiple environments, or for overriding
without a rebuild. Edit **`dist/viche_env.js`** in the deployed bundle:

```js
window.__VICHE_RELAYER_URL__ = "https://relayer.example.com";
window.__VICHE_VOTING_MANAGER_ADDRESS__ = "0x...";
window.__VICHE_CHAIN_ID__ = "0xaa36a7";
```

That file ships empty (all lines commented out) and is loaded first, before
anything else on the page, so `src/config.rs` sees the globals as soon as the
wasm boots.

> **Do not paste a `<script>` block into `index.html` for this.** Earlier
> revisions of this runbook suggested exactly that; it no longer works. The
> app's CSP is `script-src 'self' 'wasm-unsafe-eval'` with no
> `'unsafe-inline'`, so the browser refuses an inline script — silently, as far
> as the app is concerned: the overrides just never apply and the frontend
> quietly falls back to same-origin `/api`. `viche_env.js` exists to be the
> one obvious place for this.

Pointing `__VICHE_RELAYER_URL__` at a **different origin** at runtime also
needs that origin in `connect-src`, which `viche_env.js` cannot change (the
policy is already parsed by then). Either rebuild with `VICHE_CSP_CONNECT_SRC`
(§4.1) or send a `Content-Security-Policy` header from the reverse proxy that
includes it (§4.5) — the header overrides nothing, but the *intersection* of
header and meta policies is enforced, so the header must be at least as
permissive on `connect-src` as you need **and** the meta tag must be too. In
practice: if the relayer is cross-origin, set `VICHE_CSP_CONNECT_SRC` at build
time.

### 4.4 Third-party JavaScript: there is none

The frontend loads **no code from any third-party origin**. snarkjs and
circomlibjs are vendored into the bundle and served same-origin from
`/vendor/`; the Tailwind stylesheet is pre-built.

This is deliberate and it is a correctness property of the voting system, not
a performance preference. snarkjs consumes the voter's `secret` in cleartext
during witness generation and circomlibjs derives the Poseidon commitment from
that same secret — both in the browser. Any party who can change those bytes
can exfiltrate every voter's secret, which means total loss of ballot
anonymity *and* the ability to forge a valid vote for every registered voter.

`crates/viche-frontend/public/vendor/VENDOR.md` records the upstream source and
a SHA-256 of every vendored file, and is deployed alongside them — so the
hashes are verifiable against the live site:

```bash
curl -sS https://vote.example.com/vendor/snarkjs.min.js | sha256sum
curl -sS https://vote.example.com/vendor/vendor-manifest.json | jq -r '.artifacts[]|"\(.sha256)  \(.file)"'
```

`make frontend-vendor-check` verifies the committed bytes still match
`package-lock.json`; it is worth running in CI. If a future change genuinely
needs a remote script, it must carry an SRI `integrity` attribute plus
`crossorigin="anonymous"` and an exact immutable version URL — never a floating
tag and never a `/+esm`-style generated artifact. The release build refuses to
emit an `index.html` containing any `http(s)://` asset URL, so this is enforced,
not just advised.

### 4.5 Security headers for the static host / reverse proxy

The bundle ships a `<meta http-equiv="Content-Security-Policy">` so the policy
holds even on a dumb static host. Header-based CSP is strictly stronger
(`frame-ancestors`, `report-uri` and `sandbox` are *ignored* in a meta tag, and
a header applies to every response including the web worker), so send both.

Recommended response headers for `crates/viche-frontend/dist/`:

```
Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; child-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; manifest-src 'self'; connect-src 'self' blob:
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Frame-Options: DENY
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Strict-Transport-Security: max-age=63072000; includeSubDomains
```

Keep this string in sync with the `<meta>` tag in
`crates/viche-frontend/index.html`, plus whatever you set in
`VICHE_CSP_CONNECT_SRC` — append the same origins to `connect-src` here.

Why each of the non-obvious ones:

- **`script-src 'wasm-unsafe-eval'`** — Chromium refuses
  `WebAssembly.compile()`/`instantiate()` from bytes without it, and three
  separate things here need it: the Leptos wasm-bindgen module, the Poseidon
  wasm that circomlibjs builds at runtime, and snarkjs's Groth16 prover. It is
  *not* `'unsafe-eval'`: JS `eval()` and `new Function()` stay blocked.
- **`worker-src`/`child-src 'self' blob:`** — `'self'` covers
  `/zk_worker.js`; `blob:` covers the worker pool snarkjs builds from
  `URL.createObjectURL(new Blob([...]))` to parallelise BN254 arithmetic.
  Without `blob:`, proof generation fails — at the exact moment a voter votes.
- **`connect-src blob:`** — `asset_cache.js` serves the cached
  `vote.wasm`/`vote_final.zkey` as `blob:` URLs that snarkjs then fetches.
- **`style-src 'unsafe-inline'`** — one inline `style` attribute remains
  (`components/poll_detail.rs` sets the results-bar width). Inline style
  *attributes* require it. `style-src-attr 'unsafe-inline'` would scope it more
  tightly, but Safari ignores `style-src-attr` and falls back to `style-src`,
  which would break the bar. Styling-only surface.
- **`Referrer-Policy: no-referrer`** — deliberately the strictest value, not
  `strict-origin-when-cross-origin`. This is a voting app: a `Referer` header
  leaking a poll-specific URL to the relayer, an RPC provider or a block
  explorer is a privacy problem in itself, and nothing in the app needs
  referrers.
- **`frame-ancestors 'none'` + `X-Frame-Options: DENY`** — prevents a
  clickjacking frame around the voting UI. The redundancy is for older
  browsers.

The wallet is unaffected: MetaMask and other EIP-1193 providers are injected by
a browser-extension content script running in an isolated world, which is
exempt from the page's CSP, and the app never contacts an RPC endpoint itself
(the wallet does). Verified against this exact policy.

**Check it after deploying.** Open the site, open devtools, and confirm the
console shows no `Refused to …` messages and that the network tab lists no
third-party origins. A CSP that blocks proof generation fails only when
somebody tries to vote, which is the worst possible time to find out.

---

### 4.6 Poll governance — what the owner key can and cannot do

The `VotingManager` owner is a single address with total administrative
power, so the contract deliberately constrains *which* powers exist rather
than relying on that address behaving well.

**Ending a poll.** There are three distinct operations, and the differences
are load-bearing:

| Operation | When it is allowed | What happens to the tally |
|---|---|---|
| `closePoll` | Only **after** the deadline | Stands. It is the result. |
| `cancelPoll` | Only while **`totalVotes == 0`** | There is none. Nobody voted. |
| `voidPoll` | Any time while the poll is open | **Discarded.** Unreadable afterwards. |

`closePoll` used to be callable at any moment. That was an integrity hole:
the tally is public and updates per vote, so an admin could watch it and
freeze the count exactly when it favoured them. Closing now requires the
deadline to have passed, at which point voting is already rejected and the
call decides nothing.

The emergency case — a whitelist found to contain a Sybil batch, a broken
circuit discovered mid-vote — is served by `voidPoll`, which **destroys the
result rather than freezing it**. That is the whole design: an admin who
stops a poll mid-flight cannot keep the favourable partial count, so the
only outcome of using the power is "no result". Removing the payoff is a
stronger guarantee than trying to forbid the action. Both `cancelPoll` and
`voidPoll` require a `reason`, recorded on-chain for audit, and `voidPoll`
emits the vote count at the moment of voiding so observers can judge the
decision.

**Handing over ownership** is two steps: the current owner calls
`transferOwnership(newOwner)`, then the new owner calls `acceptOwnership()`
from its own address. Ownership does not move until that second call. This
exists because a single-step transfer to a mistyped address — or to a
multisig whose signing threshold cannot actually be met — permanently bricks
poll administration, as the contract has no other privileged role and no
recovery path. Requiring the recipient to transact proves it can.
`cancelOwnershipTransfer()` withdraws a proposal before acceptance.

> **Use a multisig.** `owner` is a plain `address`, so it can be an EOA, a
> multisig, or a timelock with no code change. For any real election it
> should not be one person's key. The two-step handover above is what makes
> moving to one safe to attempt.

## 5. Post-deploy checklist

- [ ] `GET /health` on the relayer returns `200`.
- [ ] `GET /api/polls` on the relayer returns `{"polls":[]}` (or existing
      polls, if `VotingManager` wasn't freshly deployed).
- [ ] The frontend loads and "Connect Wallet" successfully detects a
      testnet wallet (MetaMask set to the target network).
- [ ] Browser devtools console shows **zero** `Refused to …` CSP messages on
      load, and the network tab shows no third-party origins (§4.5).
- [ ] `make frontend-vendor-check` passes, and the SHA-256 of
      `/vendor/snarkjs.min.js` on the live site matches
      `crates/viche-frontend/public/vendor/VENDOR.md` (§4.4).
- [ ] Register a test commitment via the "Register to Vote" page, confirm
      it shows up via `GET /api/admin/registrations/pending` (with your
      `ADMIN_API_KEY`).
- [ ] As the `VotingManager` owner wallet: build a whitelist, create a
      poll, and cast one real vote end-to-end — confirming the deployed
      verifier actually accepts proofs generated against the deployed
      zkey (this is the exact failure mode called out in the
      Prerequisites section, and it doesn't show up until a vote is
      actually cast).
- [ ] `owner` is a multisig, not a single EOA (§4.6). If it is still the
      deploying EOA, hand it over now — `transferOwnership` then
      `acceptOwnership` from the multisig — and confirm `owner()` reflects
      the change before announcing any poll.
- [ ] Confirm `closePoll` on a live poll reverts with `PollStillOpen`. This
      is the close-time guard; if it succeeds, you are running a build that
      still permits freezing a tally mid-vote.

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
