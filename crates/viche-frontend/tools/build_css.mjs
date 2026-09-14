// build_css.mjs — compile styles/app.css -> styles/tailwind.generated.css.
//
// Runs as a Trunk `pre_build` hook (see Trunk.toml), so `trunk build` and
// `trunk serve` both regenerate the stylesheet automatically and nobody has to
// remember a separate command. Also exposed as `make frontend-css`.
//
// Why node-invoked rather than `npx tailwindcss` in the hook: Trunk hooks take
// a bare executable, and `npx`/`npm` are `.cmd` shims on Windows that Trunk
// cannot spawn directly. `node` is a real executable everywhere, so this
// script resolves the Tailwind CLI out of node_modules itself.

import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = resolve(HERE, "..");
const REPO_ROOT = resolve(FRONTEND_DIR, "..", "..");

const INPUT = join(FRONTEND_DIR, "styles", "app.css");
const OUTPUT = join(FRONTEND_DIR, "styles", "tailwind.generated.css");
const CONFIG = join(FRONTEND_DIR, "tailwind.config.js");

// Trunk sets TRUNK_PROFILE=debug|release for hooks. Minify only for release so
// dev rebuilds stay fast and the served CSS is readable in devtools.
const profile = process.env.TRUNK_PROFILE ?? "release";
const isRelease = profile === "release";

if (!existsSync(join(REPO_ROOT, "node_modules", "tailwindcss"))) {
  console.error(
    "\n[css] tailwindcss is not installed.\n" +
      "[css] The frontend no longer uses the Tailwind play CDN; the stylesheet is\n" +
      "[css] built from source. Run `npm ci` at the repo root (or `make frontend`,\n" +
      "[css] which does it for you) and try again.\n"
  );
  process.exit(1);
}

const require = createRequire(join(REPO_ROOT, "node_modules", "noop.js"));
// tailwindcss v3 ships its CLI entry at lib/cli.js; resolve it through the
// package so a version bump that moves the file fails loudly here rather than
// silently producing no stylesheet.
const cliEntry = require.resolve("tailwindcss/lib/cli.js");

const args = [
  cliEntry,
  "--config", CONFIG,
  "--input", INPUT,
  "--output", OUTPUT,
];
if (isRelease) args.push("--minify");

console.log(`[css] tailwind (${profile}) -> ${relative(REPO_ROOT, OUTPUT).replace(/\\/g, "/")}`);

const result = spawnSync(process.execPath, args, {
  cwd: FRONTEND_DIR,
  stdio: "inherit",
});

if (result.error) {
  console.error("[css] failed to run the Tailwind CLI:", result.error);
  process.exit(1);
}
if (result.status !== 0) {
  console.error(`[css] Tailwind CLI exited with ${result.status}`);
  process.exit(result.status ?? 1);
}
if (!existsSync(OUTPUT)) {
  console.error(`[css] Tailwind reported success but ${OUTPUT} was not written.`);
  process.exit(1);
}
