// =============================================================================
// export_verifier.js — regenerate ONLY the Solidity verifier from the final
// zkey, without re-running circom / the trusted setup. Handy after tweaking
// verifier comments or when the on-chain verifier must be refreshed.
//
// Output: contracts/src/verifier/Groth16Verifier.sol
// =============================================================================
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { zKey } from "snarkjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(ROOT, "..");

const CIRCUIT = process.env.CIRCUIT ?? "vote";
const FINAL_ZKEY = path.join(ROOT, "build", `${CIRCUIT}_final.zkey`);
const OUT_DIR = path.join(REPO_ROOT, "contracts", "src", "verifier");
const OUT_FILE = path.join(OUT_DIR, "Groth16Verifier.sol");

const solidity = await zKey.exportSolidityVerifier(FINAL_ZKEY, {});
await mkdir(OUT_DIR, { recursive: true });
await writeFile(OUT_FILE, solidity);

console.log("Wrote:", OUT_FILE);
