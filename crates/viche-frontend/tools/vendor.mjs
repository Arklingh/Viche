// vendor.mjs — produce the same-origin copies of the ZK JS stack.
//
// WHY THIS EXISTS
// ---------------
// snarkjs handles the voter's `secret` during witness generation and
// circomlibjs derives the Poseidon commitment from that same secret, entirely
// in the browser. Loading either one from a third-party CDN means a CDN
// compromise, a DNS/MITM attack, or a maliciously republished package version
// exfiltrates every voter's secret — which is simultaneously a total loss of
// anonymity and the ability to forge a valid vote for every registered voter.
// So the bytes live in this repo, are hashed, and are served same-origin.
//
// This script regenerates `public/vendor/` from the pinned npm packages in the
// repo-root `package.json` + `package-lock.json`, and rewrites
// `public/vendor/VENDOR.md` with the upstream provenance and a SHA-256 of
// every emitted file. Run it via `make frontend-vendor`; the emitted files are
// committed, so a normal build does not need npm at all.
//
// Usage:  node crates/viche-frontend/tools/vendor.mjs [--check]
//         --check  regenerate into a temp dir and fail if anything differs
//                  from what is committed (for CI drift detection).

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = resolve(HERE, "..");
const REPO_ROOT = resolve(FRONTEND_DIR, "..", "..");
const VENDOR_DIR = join(FRONTEND_DIR, "public", "vendor");
const NODE_MODULES = join(REPO_ROOT, "node_modules");

const checkOnly = process.argv.includes("--check");

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const sriB64 = (buf) => createHash("sha256").update(buf).digest("base64");

function pkgVersion(name) {
  return JSON.parse(readFileSync(join(NODE_MODULES, name, "package.json"), "utf8")).version;
}

// --- Pinned upstream versions -------------------------------------------
// Keep these in lockstep with the repo-root package.json devDependencies.
const SNARKJS_VERSION = "0.7.4";
const CIRCOMLIBJS_VERSION = "0.1.7";

for (const [name, want] of [
  ["snarkjs", SNARKJS_VERSION],
  ["circomlibjs", CIRCOMLIBJS_VERSION],
]) {
  const got = pkgVersion(name);
  if (got !== want) {
    console.error(
      `[vendor] ${name} is ${got} in node_modules but this script pins ${want}.\n` +
        `         Run \`npm ci\` at the repo root, or update the pin here and in package.json together.`
    );
    process.exit(1);
  }
}

mkdirSync(VENDOR_DIR, { recursive: true });

/** @type {{file: string, bytes: Buffer, upstream: string, note: string}[]} */
const artifacts = [];

// --- 1. snarkjs -----------------------------------------------------------
// snarkjs ships a prebuilt browser bundle. It is byte-identical to what
// jsdelivr serves for the same version (verified: see VENDOR.md), so this is a
// straight copy of the npm tarball's file — no local rebundling, nothing to
// second-guess when auditing.
{
  const bytes = readFileSync(join(NODE_MODULES, "snarkjs", "build", "snarkjs.min.js"));
  artifacts.push({
    file: "snarkjs.min.js",
    bytes,
    upstream: `npm:snarkjs@${SNARKJS_VERSION} -> build/snarkjs.min.js`,
    note:
      "Verbatim copy of the file in the npm tarball. Exposes the global " +
      "`snarkjs` (used as `window.snarkjs.groth16.fullProve` by " +
      "`src/proofgen.rs`, and as `self.snarkjs` inside `zk_worker.js`).",
  });
}

// --- 2. circomlibjs (Poseidon only) --------------------------------------
// circomlibjs is published as ESM-with-dependencies; there is no prebuilt
// browser bundle in the tarball. The old code pulled jsdelivr's `/+esm`
// artifact, which is generated on jsdelivr's side and pinned to nothing we can
// verify. We bundle it ourselves instead, from the locked npm tree.
//
// The entry deliberately points at `src/poseidon_wasm.js` rather than the
// package's `main.js` barrel: `main.js` re-exports eddsa, smt, evmasm and the
// *_gencontract helpers, which drag in `ethers`, `blake-hash` ->
// `readable-stream` -> node `buffer`/`events`/`assert`. None of that is
// reachable from `buildPoseidon`, but bundling the barrel would ship it (and
// the node-builtin shims it needs) into the page. `poseidon_wasm.js` needs
// only `ffjavascript` + the local constants table, which is exactly the code
// path that touches the voter's secret.
const CIRCOMLIBJS_ENTRY = "./node_modules/circomlibjs/src/poseidon_wasm.js";
{
  const result = await esbuild.build({
    stdin: {
      contents: `export { buildPoseidon } from "${CIRCOMLIBJS_ENTRY}";\n`,
      resolveDir: REPO_ROOT,
      sourcefile: "viche-circomlibjs-poseidon-entry.js",
    },
    bundle: true,
    format: "iife",
    globalName: "circomlibjs",
    platform: "browser",
    target: ["es2020"],
    minify: true,
    legalComments: "inline",
    write: false,
    // ffjavascript reaches for these only on its Node thread-pool path; in a
    // browser it takes the Web Worker branch and never evaluates them.
    external: ["os", "worker_threads", "crypto", "readline", "fs", "path", "url"],
  });

  for (const w of result.warnings) {
    console.warn(`[vendor] esbuild warning: ${w.text}`);
  }

  const banner = Buffer.from(
    `/* Viche vendored bundle: circomlibjs@${CIRCOMLIBJS_VERSION} buildPoseidon.\n` +
      `   Generated by crates/viche-frontend/tools/vendor.mjs from the locked npm\n` +
      `   tree. Do not edit by hand. See VENDOR.md for provenance + hashes. */\n`
  );
  const bytes = Buffer.concat([banner, Buffer.from(result.outputFiles[0].contents)]);

  artifacts.push({
    file: "circomlibjs-poseidon.js",
    bytes,
    upstream: `npm:circomlibjs@${CIRCOMLIBJS_VERSION} -> src/poseidon_wasm.js (+ its ffjavascript dependency, from package-lock.json)`,
    note:
      "esbuild IIFE bundle (format=iife, globalName=circomlibjs, platform=browser, " +
      "target=es2020, minify). Exposes `window.circomlibjs.buildPoseidon`. " +
      "Replaces the unpinnable `cdn.jsdelivr.net/npm/circomlibjs@0.1.7/+esm` artifact.",
  });
}

// --- Emit ----------------------------------------------------------------
const manifestRows = artifacts.map((a) => ({
  file: a.file,
  size: a.bytes.length,
  sha256: sha256(a.bytes),
  sri: `sha256-${sriB64(a.bytes)}`,
  upstream: a.upstream,
  note: a.note,
}));

const vendorMd = `<!-- GENERATED by crates/viche-frontend/tools/vendor.mjs — do not edit by hand. -->
# Vendored third-party JavaScript

Everything in this directory is served **same-origin** from the Viche frontend
bundle. Nothing here is fetched from a CDN at runtime, and the app's
Content-Security-Policy (\`script-src 'self' 'wasm-unsafe-eval'\`) makes that a
hard guarantee rather than a convention: a script tag pointing anywhere else
would simply be refused by the browser.

## Why

\`snarkjs\` performs witness generation, which consumes the voter's \`secret\`
in cleartext in the browser. \`circomlibjs\` derives the Poseidon commitment
from that same secret. Both therefore sit inside the anonymity boundary of the
whole system. Loading them over a bare \`<script src="https://cdn…">\` with no
Subresource Integrity meant a CDN compromise, a DNS/MITM attack, or a
maliciously republished package version could exfiltrate every voter's secret
— which is both a total loss of ballot anonymity and the ability to forge a
valid vote for every registered voter.

## Reproducing these bytes

\`\`\`bash
npm ci                    # repo root; installs the pinned versions
make frontend-vendor      # == node crates/viche-frontend/tools/vendor.mjs
git diff --exit-code crates/viche-frontend/public/vendor/
\`\`\`

\`make frontend-vendor-check\` does the same thing non-destructively and exits
non-zero if the committed bytes drift from what the locked npm tree produces.

The exact versions are pinned in the repo-root \`package.json\` /
\`package-lock.json\` **and** re-asserted in \`vendor.mjs\`, which refuses to run
if \`node_modules\` disagrees.

## Provenance

${manifestRows
  .map(
    (r) => `### \`${r.file}\`

| | |
|---|---|
| Upstream | ${r.upstream} |
| Size | ${r.size} bytes |
| SHA-256 | \`${r.sha256}\` |
| SRI | \`${r.sri}\` |

${r.note}
`
  )
  .join("\n")}
## Upstream cross-check (snarkjs)

\`snarkjs.min.js\` as published on npm is byte-identical to the file jsdelivr
served at the URL this app used to load:

\`\`\`
$ curl -sS https://cdn.jsdelivr.net/npm/snarkjs@0.7.4/build/snarkjs.min.js | sha256sum
0f3a73ec17fe32e923d16f8372b0cd1d8428edb5dddea8261a3aa82533ea216c
$ sha256sum node_modules/snarkjs/build/snarkjs.min.js
0f3a73ec17fe32e923d16f8372b0cd1d8428edb5dddea8261a3aa82533ea216c
\`\`\`

So vendoring changed *where the bytes come from*, not *which bytes run*. There
is no equivalent check for \`circomlibjs-poseidon.js\`: jsdelivr's \`/+esm\`
artifact is generated by jsdelivr's own bundler and is not reproducible from
the npm tarball, which is precisely why it is no longer used.

## Machine-readable manifest

See \`vendor-manifest.json\` next to this file.

## Licenses

- snarkjs — GPL-3.0 (iden3). https://github.com/iden3/snarkjs
- circomlibjs — GPL-3.0 (iden3). https://github.com/iden3/circomlibjs
`;

const manifestJson =
  JSON.stringify(
    {
      $comment:
        "Generated by crates/viche-frontend/tools/vendor.mjs. Hashes cover the exact bytes served from /vendor/.",
      generator: "crates/viche-frontend/tools/vendor.mjs",
      artifacts: manifestRows,
    },
    null,
    2
  ) + "\n";

const outputs = [
  ...artifacts.map((a) => [a.file, a.bytes]),
  ["VENDOR.md", Buffer.from(vendorMd)],
  ["vendor-manifest.json", Buffer.from(manifestJson)],
];

if (checkOnly) {
  let drift = false;
  const known = new Set(outputs.map(([n]) => n));
  for (const existing of readdirSync(VENDOR_DIR)) {
    if (!known.has(existing)) {
      console.error(`[vendor] stale file not produced by this script: vendor/${existing}`);
      drift = true;
    }
  }
  for (const [name, bytes] of outputs) {
    let current;
    try {
      current = readFileSync(join(VENDOR_DIR, name));
    } catch {
      console.error(`[vendor] missing: vendor/${name}`);
      drift = true;
      continue;
    }
    if (!current.equals(bytes)) {
      console.error(
        `[vendor] DRIFT in vendor/${name}\n  committed: sha256 ${sha256(current)}\n  rebuilt:   sha256 ${sha256(bytes)}`
      );
      drift = true;
    }
  }
  if (drift) {
    console.error("\n[vendor] Committed vendor bytes do not match the locked npm tree.");
    process.exit(1);
  }
  console.log("[vendor] OK — committed bytes match the locked npm tree.");
} else {
  for (const [name, bytes] of outputs) {
    writeFileSync(join(VENDOR_DIR, name), bytes);
  }
  for (const r of manifestRows) {
    console.log(`[vendor] vendor/${r.file}  ${r.size} bytes  sha256:${r.sha256}`);
  }
  console.log(`[vendor] wrote vendor/VENDOR.md and vendor/vendor-manifest.json`);
}
