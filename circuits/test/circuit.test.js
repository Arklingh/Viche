import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const BUILD = path.join(ROOT, "build");
const WASM = path.join(BUILD, "vote_js", "vote.wasm");
const FINAL_ZKEY = path.join(BUILD, "vote_final.zkey");
const VKEY = path.join(BUILD, "vote_vkey.json");

// Poseidon Merkle Tree helper matching gen_input.js
class MerkleTree {
    constructor(depth, poseidon) {
        this.depth = depth;
        this.poseidon = poseidon;
        this.F = poseidon.F;
        this.poseidon2 = (x, y) => this.F.toObject(this.poseidon([x, y]));

        // Build zero chain
        this.zeros = [0n];
        for (let i = 1; i <= depth; i++) {
            this.zeros[i] = this.poseidon2(this.zeros[i - 1], this.zeros[i - 1]);
        }

        this.nodes = Array.from({ length: depth + 1 }, () => new Map());
        this.nextIndex = 0;
    }

    insert(leaf) {
        const index = this.nextIndex++;
        this.nodes[0].set(index, leaf);
        this._recompute(0, index);
        return index;
    }

    _recompute(level, index) {
        let node = this.nodes[level].get(index);
        for (let l = level; l < this.depth; l++) {
            const sibling =
                index % 2 === 0
                    ? this._get(l, index + 1)
                    : this._get(l, index - 1);
            const [left, right] =
                index % 2 === 0 ? [node, sibling] : [sibling, node];
            node = this.poseidon2(left, right);
            index = Math.floor(index / 2);
            this.nodes[l + 1].set(index, node);
        }
        return node;
    }

    _get(level, index) {
        if (this.nodes[level].has(index)) return this.nodes[level].get(index);
        return this.zeros[level];
    }

    root() {
        return this.nodes[this.depth].get(0) ?? this.zeros[this.depth];
    }

    proof(index) {
        const pathElements = [];
        const pathIndices = [];
        for (let level = 0; level < this.depth; level++) {
            const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
            pathElements.push(this._get(level, siblingIndex).toString());
            pathIndices.push(index % 2 === 0 ? 0 : 1);
            index = Math.floor(index / 2);
        }
        return { pathElements, pathIndices };
    }
}

test("Viche Groth16 Circuit Test Suite", async (t) => {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const poseidon1 = (x) => F.toObject(poseidon([x]));
    const poseidon2 = (x, y) => F.toObject(poseidon([x, y]));

    const vkey = JSON.parse(await readFile(VKEY, "utf8"));
    const depth = 20;

    await t.test("1. Valid proof generation and local verification", async () => {
        const tree = new MerkleTree(depth, poseidon);
        const secret = 12345678901234567890n;
        const commitment = poseidon1(secret);
        const voterIndex = tree.insert(commitment);
        const voteId = 100n;

        const root = tree.root();
        const { pathElements, pathIndices } = tree.proof(voterIndex);
        const nullifierHash = poseidon2(secret, voteId);

        const input = {
            secret: secret.toString(),
            pathElements,
            pathIndices,
            voteId: voteId.toString(),
            merkleRoot: root.toString(),
            nullifierHash: nullifierHash.toString(),
        };

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            WASM,
            FINAL_ZKEY
        );

        assert.equal(publicSignals[0], voteId.toString());
        assert.equal(publicSignals[1], root.toString());
        assert.equal(publicSignals[2], nullifierHash.toString());

        const verified = await snarkjs.groth16.verify(vkey, publicSignals, proof);
        assert.equal(verified, true, "Proof should verify cleanly");
    });

    await t.test("2. Rejection of invalid Merkle root in public signals", async () => {
        const tree = new MerkleTree(depth, poseidon);
        const secret = 999999999n;
        const commitment = poseidon1(secret);
        const voterIndex = tree.insert(commitment);
        const voteId = 1n;

        const root = tree.root();
        const { pathElements, pathIndices } = tree.proof(voterIndex);
        const nullifierHash = poseidon2(secret, voteId);

        const input = {
            secret: secret.toString(),
            pathElements,
            pathIndices,
            voteId: voteId.toString(),
            merkleRoot: root.toString(),
            nullifierHash: nullifierHash.toString(),
        };

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            WASM,
            FINAL_ZKEY
        );

        // Corrupt public root signal
        const corruptedSignals = [...publicSignals];
        corruptedSignals[1] = "12345"; // fake root

        const verified = await snarkjs.groth16.verify(vkey, corruptedSignals, proof);
        assert.equal(verified, false, "Proof with corrupted Merkle root should fail verification");
    });

    await t.test("3. Rejection of corrupted proof elements", async () => {
        const tree = new MerkleTree(depth, poseidon);
        const secret = 888888888n;
        const commitment = poseidon1(secret);
        const voterIndex = tree.insert(commitment);
        const voteId = 2n;

        const root = tree.root();
        const { pathElements, pathIndices } = tree.proof(voterIndex);
        const nullifierHash = poseidon2(secret, voteId);

        const input = {
            secret: secret.toString(),
            pathElements,
            pathIndices,
            voteId: voteId.toString(),
            merkleRoot: root.toString(),
            nullifierHash: nullifierHash.toString(),
        };

        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            WASM,
            FINAL_ZKEY
        );

        // Corrupt pi_a element
        const corruptedProof = JSON.parse(JSON.stringify(proof));
        corruptedProof.pi_a[0] = "1";

        const verified = await snarkjs.groth16.verify(vkey, publicSignals, corruptedProof);
        assert.equal(verified, false, "Corrupted proof should fail verification");
    });

    await t.test("4. Witness calculation fails if secret does not match commitment in Merkle tree", async () => {
        const tree = new MerkleTree(depth, poseidon);
        const realSecret = 111111111n;
        const fakeSecret = 222222222n;
        const commitment = poseidon1(realSecret);
        const voterIndex = tree.insert(commitment);
        const voteId = 1n;

        const root = tree.root();
        const { pathElements, pathIndices } = tree.proof(voterIndex);
        const nullifierHash = poseidon2(fakeSecret, voteId);

        const input = {
            secret: fakeSecret.toString(), // Wrong secret!
            pathElements,
            pathIndices,
            voteId: voteId.toString(),
            merkleRoot: root.toString(),
            nullifierHash: nullifierHash.toString(),
        };

        await assert.rejects(
            async () => {
                await snarkjs.groth16.fullProve(input, WASM, FINAL_ZKEY);
            },
            /Error/i,
            "Witness generation should fail when leaf commitment doesn't match secret"
        );
    });

    await t.test("5. Double-spend nullifier is deterministic and distinct per voteId", () => {
        const secret = 7777777n;
        const poll1 = 1n;
        const poll2 = 2n;

        const nullifier1 = poseidon2(secret, poll1);
        const nullifier1Repeat = poseidon2(secret, poll1);
        const nullifier2 = poseidon2(secret, poll2);

        assert.equal(nullifier1, nullifier1Repeat, "Same voter + pollId must produce identical nullifier");
        assert.notEqual(nullifier1, nullifier2, "Same voter + different pollId must produce distinct nullifiers");
    });
});
