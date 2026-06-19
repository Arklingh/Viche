// =============================================================================
// gen_proof.js — generate a real Groth16 proof for the Viche `vote` circuit
// using the sample input from gen_input.js.
//
// Pipeline (all via snarkjs):
//   1. (re)build input.json   — call gen_input.js logic inline if missing
//   2. calculate witness      — input.json + wasm -> witness.wtns
//   3. groth16 prove          — witness + final.zkey -> {public, proof}.json
//   4. verify                 — sanity-check against vkey.json
//
// The emitted `public.json` follows the circuit's public-signal order:
//   [voteId, merkleRoot, nullifierHash]
// and the `proof.json` has the snarkjs shape
//   { pi_a, pi_b, pi_c, protocol, curve }.
//
// The relayer/frontend repack these into the Solidity ABI the
// `Groth16Verifier.verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])`
// selector expects.
// =============================================================================
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import snarkjs from "snarkjs";
import wtns from "snarkjs/wtns.js";
import { readR1cs } from "snarkjs/r1csfile.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const CIRCUIT = process.env.CIRCUIT ?? "vote";
const BUILD = path.join(ROOT, "build");
const WASM = path.join(BUILD, `${CIRCUIT}_js`, `${CIRCUIT}.wasm`);
const FINAL_ZKEY = path.join(BUILD, `${CIRCUIT}_final.zkey`);
const VKEY = path.join(BUILD, `${CIRCUIT}_vkey.json`);
const INPUT = path.join(BUILD, "input.json");
const WITNESS = path.join(BUILD, "witness.wtns");
const PROOF = path.join(BUILD, "proof.json");
const PUBLIC = path.join(BUILD, "public.json");

async function fail(msg) {
    console.error("ERROR:", msg);
    process.exit(1);
}

// ---------------------------------------------------------------------------
async function main() {
    await mkdir(BUILD, { recursive: true });

    // 0. Pre-flight.
    try {
        await readFile(FINAL_ZKEY);
    } catch {
        await fail(`Missing ${FINAL_ZKEY}. Run \`make circuits\` first.`);
    }
    try {
        await readFile(INPUT);
    } catch {
        console.log("input.json missing — regenerating via gen_input.js ...");
        await import("./gen_input.js");
    }

    // 1. Compute witness from input.json + the compiled wasm.
    console.log(">> calculating witness");
    const input = JSON.parse(await readFile(INPUT, "utf8"));
    // snarkjs wtnsUtil.calculate directly takes the wasm path + input object.
    const { wtns: wtnsUtil } = await import("snarkjs");
    await wtnsUtil.calculate({ wasm: WASM, input }, WITNESS);

    // 2. Prove.
    console.log(">> groth16 prove");
    const { proof, publicSignals } = await snarkjs.groth16.prove(
        FINAL_ZKEY,
        WITNESS
    );

    await writeFile(PROOF, JSON.stringify(proof, null, 2));
    await writeFile(PUBLIC, JSON.stringify(publicSignals, null, 2));

    // 3. Verify locally as a sanity check.
    console.log(">> verifying proof against vkey");
    const vkey = JSON.parse(await readFile(VKEY, "utf8"));
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    if (!ok) await fail("Proof FAILED local verification — circuit build is broken.");
    console.log(">> proof verified OK");

    // 4. Emit a Solidity-ready payload so a developer can paste the values
    //    straight into a Foundry test or a curl call to the relayer.
    console.log("\n=== public signals (order: voteId, merkleRoot, nullifierHash) ===");
    console.log(publicSignals);
    console.log("\n=== proof ===");
    console.log(JSON.stringify(proof, null, 2));
    console.log(`\nWrote ${PROOF} and ${PUBLIC}`);
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
