// postbuild.mjs — Trunk `post_build` hook. Makes the emitted bundle
// CSP-clean and then proves it.
//
// Three jobs:
//
//   1. EXTERNALISE TRUNK'S INLINE LOADER.
//      Trunk injects its wasm bootstrap as an inline `<script type="module">`.
//      One inline script is enough to force `'unsafe-inline'` into script-src,
//      which would defeat the entire policy — and `'unsafe-inline'` cannot be
//      narrowed with a hash here because the hash changes on every build (the
//      snippet embeds the content-hashed bundle filename), which would in turn
//      make the "copy these headers into your reverse proxy" instructions in
//      docs/deployment.md wrong after every rebuild. So the snippet is written
//      out to its own file and referenced by src.
//
//   2. RESOLVE THE connect-src PLACEHOLDER.
//      index.html ships `__VICHE_CSP_CONNECT_SRC__` inside connect-src. This
//      hook replaces it with $VICHE_CSP_CONNECT_SRC (space-separated origins),
//      so one deployment's relayer host is never baked into the repo. Empty by
//      default: the default topology serves the relayer same-origin under
//      /api, which `'self'` already covers.
//
//   3. AUDIT.
//      For release builds, fail hard if the emitted HTML still contains an
//      inline script or references any http(s) URL. This is the regression
//      test for the whole exercise: re-adding a CDN <script> tag breaks the
//      build instead of quietly shipping.
//
// Debug builds additionally get a relaxed CSP, because `trunk serve` splices
// its live-reload client into the HTTP response *after* hooks run (it carries
// {{__TRUNK_ADDRESS__}} placeholders substituted per-request, so it cannot be
// externalised) and talks over a WebSocket.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const profile = process.env.TRUNK_PROFILE ?? "release";
const isRelease = profile === "release";

/** Token index.html carries inside connect-src, replaced below. */
const PLACEHOLDER = "__VICHE_CSP_CONNECT_SRC__";

// Trunk assembles into the staging dir and moves it to dist; depending on
// version/ordering either may be the live one. Prefer staging.
const candidates = [process.env.TRUNK_STAGING_DIR, process.env.TRUNK_DIST_DIR].filter(Boolean);
const outDir = candidates.find((d) => existsSync(join(d, "index.html")));
if (!outDir) {
  console.error(
    `[csp] could not find index.html in any of: ${candidates.join(", ") || "(no TRUNK_*_DIR set)"}`
  );
  process.exit(1);
}

const indexPath = join(outDir, "index.html");
let html = readFileSync(indexPath, "utf8");

/**
 * index.html is heavily commented, and several of those comments quote tag
 * syntax (`<script>`, `<style>`, CDN URLs) while explaining why the real thing
 * is not there any more. Scanning the raw HTML would flag the documentation as
 * the violation it documents, so every check below runs against a
 * comment-stripped copy.
 */
const stripComments = (s) => s.replace(/<!--[\s\S]*?-->/g, "");

// --- 1. Externalise the inline module loader -----------------------------
const INLINE_MODULE = /<script\s+type="module">([\s\S]*?)<\/script>/g;
const inlineModules = [...stripComments(html).matchAll(INLINE_MODULE)];

if (inlineModules.length === 0) {
  console.error(
    "[csp] expected exactly one inline <script type=\"module\"> (Trunk's wasm loader) but found none.\n" +
      "[csp] Trunk's output format may have changed; re-check this hook before trusting the CSP."
  );
  process.exit(1);
}
if (inlineModules.length > 1) {
  console.error(
    `[csp] found ${inlineModules.length} inline module scripts; expected only Trunk's loader.\n` +
      "[csp] Application code must live in its own file under public/ so script-src can stay 'self'."
  );
  process.exit(1);
}

{
  const [full, body] = inlineModules[0];
  const digest = createHash("sha256").update(body).digest("hex").slice(0, 16);
  const filename = `trunk-init-${digest}.js`;
  writeFileSync(join(outDir, filename), body);
  html = html.replace(full, `<script type="module" src="/${filename}"></script>`);
  console.log(`[csp] externalised Trunk's inline wasm loader -> /${filename}`);
}

// --- 2. connect-src placeholder ------------------------------------------
const CSP_META = /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")/;
const extraConnect = (process.env.VICHE_CSP_CONNECT_SRC ?? "").trim();
const cspMatch = html.match(CSP_META);
if (!cspMatch) {
  console.error('[csp] no <meta http-equiv="Content-Security-Policy"> in index.html.');
  process.exit(1);
}
if (!cspMatch[2].includes(PLACEHOLDER)) {
  console.error(`[csp] the CSP meta has no ${PLACEHOLDER} placeholder inside connect-src.`);
  process.exit(1);
}
// Scoped to the meta's content attribute on purpose: the placeholder name also
// appears in the explanatory comment above the tag, and a document-wide
// replace would substitute there and leave the actual policy unchanged.
html = html.replace(CSP_META, (_m, pre, policy, post) => {
  const resolved = policy.replace(
    new RegExp(`\\s*${PLACEHOLDER}`),
    extraConnect ? ` ${extraConnect}` : ""
  );
  return `${pre}${resolved}${post}`;
});
if (extraConnect) {
  console.log(`[csp] connect-src extended with: ${extraConnect}`);
} else {
  console.log("[csp] connect-src left at 'self' blob: (same-origin relayer; set VICHE_CSP_CONNECT_SRC to add one)");
}

// --- 3. Debug relaxation for `trunk serve` -------------------------------
// Reuse CSP_META, which tolerates the multi-line <meta ...> formatting in
// index.html. (An earlier version of this branch used its own regex with a
// literal single space and silently matched nothing, so `trunk serve` shipped
// the strict policy and Chrome blocked Trunk's live-reload client — hot reload
// just stopped working, with only a console message to say why.)
if (!isRelease) {
  let relaxedOnce = false;
  html = html.replace(CSP_META, (_m, pre, policy, post) => {
    relaxedOnce = true;
    const relaxed = policy
      // Trunk's live-reload client is inlined into the response after hooks
      // run, carrying {{__TRUNK_ADDRESS__}} placeholders it substitutes
      // per-request — so it cannot be externalised the way the wasm loader is.
      .replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")
      // ...and it opens a WebSocket back to the dev server.
      .replace("connect-src 'self'", "connect-src 'self' ws: wss:");
    return `${pre}${relaxed}${post}`;
  });
  if (!relaxedOnce) {
    console.error("[csp] debug relaxation matched nothing — dev hot reload would be blocked.");
    process.exit(1);
  }
  console.log(
    "[csp] DEBUG build: relaxed script-src with 'unsafe-inline' and connect-src with ws: " +
      "for Trunk's live-reload client. Release builds ship the strict policy."
  );
}

writeFileSync(indexPath, html);

// --- 4. Audit -------------------------------------------------------------
// Release only: a `trunk serve` bundle legitimately carries Trunk's inline
// live-reload client, which would trip the inline-script check on every
// rebuild. The gate that matters is the one on what actually ships.
if (!isRelease) {
  console.log("[csp] debug build: skipping the release CSP/supply-chain audit.");
  process.exit(0);
}

const problems = [];
const auditable = stripComments(html);

const finalCsp = auditable.match(CSP_META)?.[2] ?? "";
if (finalCsp.includes(PLACEHOLDER)) {
  problems.push(`${PLACEHOLDER} survived into the shipped CSP`);
}
for (const required of ["default-src 'self'", "object-src 'none'", "base-uri 'self'"]) {
  if (!finalCsp.includes(required)) problems.push(`CSP lost its \`${required}\` directive`);
}
const scriptSrc =
  finalCsp
    .split(";")
    .map((d) => d.trim())
    .find((d) => d.startsWith("script-src ")) ?? "";
for (const forbidden of ["'unsafe-eval'", "'unsafe-inline'"]) {
  // 'wasm-unsafe-eval' is fine and expected; 'unsafe-eval' is not. Compare
  // against space-delimited tokens so the former does not match the latter.
  if (scriptSrc.split(/\s+/).includes(forbidden)) {
    problems.push(`script-src contains ${forbidden}`);
  }
}

for (const m of auditable.matchAll(/<script\b([^>]*)>/g)) {
  const attrs = m[1];
  if (!/\bsrc\s*=/.test(attrs)) {
    problems.push(`inline <script${attrs}> — inline scripts require 'unsafe-inline'`);
  }
}
if (/<style\b/.test(auditable)) {
  problems.push("inline <style> block — move it into styles/app.css");
}
for (const m of auditable.matchAll(/\b(?:src|href)\s*=\s*["'](https?:\/\/[^"']+)["']/g)) {
  problems.push(`remote asset reference ${m[1]} — vendor it under public/vendor/ instead`);
}

if (problems.length) {
  console.error(`[csp] ${problems.length} CSP/supply-chain problem(s) in the built index.html:`);
  for (const p of problems) console.error(`[csp]   - ${p}`);
  console.error(
    "[csp] Refusing to emit a release bundle that the shipped CSP would block\n" +
      "[csp] (or that loads third-party code into the page that handles voter secrets)."
  );
  process.exit(1);
} else {
  console.log("[csp] audit clean: no inline scripts, no inline styles, no remote asset URLs.");
}
