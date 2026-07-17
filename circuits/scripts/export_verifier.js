import { mkdir, writeFile, readFile } from "node:fs/promises";
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

const templatePath = path.resolve(
    __dirname,
    "../node_modules/snarkjs/templates/verifier_groth16.sol.ejs"
);

const groth16Template = await readFile(templatePath, "utf8");

const solidity = await zKey.exportSolidityVerifier(FINAL_ZKEY, {
    groth16: groth16Template
});

await mkdir(OUT_DIR, { recursive: true });
await writeFile(OUT_FILE, solidity);

console.log("Wrote:", OUT_FILE);