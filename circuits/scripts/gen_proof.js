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
import * as snarkjs from "snarkjs";

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

    const input = JSON.parse(await readFile(INPUT, "utf8"));

    // 1. Prove.
    console.log(">> generating witness & groth16 prove");
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, 
        WASM, 
        FINAL_ZKEY
    );

    await writeFile(PROOF, JSON.stringify(proof, null, 2));
    await writeFile(PUBLIC, JSON.stringify(publicSignals, null, 2));

    // 2. Verify locally as a sanity check.
    console.log(">> verifying proof against vkey");
    const vkey = JSON.parse(await readFile(VKEY, "utf8"));
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    if (!ok) await fail("Proof FAILED local verification — circuit build is broken.");
    console.log(">> proof verified OK");

    // 3. Emit a Solidity-ready payload so Foundry integration tests and relayers
    //    can import matching proof vectors dynamically.
    const TEST_PROOF = path.join(BUILD, "test_proof.json");
    const formattedTestProof = {
        pA: [proof.pi_a[0], proof.pi_a[1]],
        pB: [
            [proof.pi_b[0][1], proof.pi_b[0][0]],
            [proof.pi_b[1][1], proof.pi_b[0][0] === proof.pi_b[1][0] ? proof.pi_b[1][0] : proof.pi_b[1][0]]
        ],
        pC: [proof.pi_c[0], proof.pi_c[1]],
        voteId: publicSignals[0],
        merkleRoot: publicSignals[1],
        nullifierHash: publicSignals[2]
    };
    // Ensure pB[1] uses Y.c1 and Y.c0
    formattedTestProof.pB[1] = [proof.pi_b[1][1], proof.pi_b[1][0]];

    await writeFile(TEST_PROOF, JSON.stringify(formattedTestProof, null, 2));

    console.log("\n=== public signals (order: voteId, merkleRoot, nullifierHash) ===");
    console.log(publicSignals);
    console.log("\n=== proof ===");
    console.log(JSON.stringify(proof, null, 2));
    console.log(`\nWrote ${PROOF}, ${PUBLIC}, and ${TEST_PROOF}`);
}

main()
    .then(() => {
        // snarkjs's WASM curve backend (used by fullProve/verify above)
        // spins up worker_threads for parallel field arithmetic and never
        // tears them down, so the event loop never empties on its own —
        // the process hangs forever after finishing real work. snarkjs's
        // own CLI works around this the same way: exit explicitly instead
        // of relying on the event loop draining. Mirrors the `fail()`
        // path above, which already does this on error.
        process.exit(0);
    })
    .catch((e) => {
        console.error(e);
        process.exit(1);
    });
