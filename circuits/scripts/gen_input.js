// =============================================================================
// gen_input.js — build a witness input.json for the Viche `vote` circuit.
//
// This is the REFERENCE off-chain implementation of the Poseidon Merkle tree
// and the nullifier/commitment formulas. The Rust code in `crates/viche-core`
// (Phase 2/3) MUST reproduce every value bit-for-bit, because the on-chain
// Groth16 verifier checks the recomputed root against the value we put in
// `merkleRoot`, and the nullifier against `nullifierHash`.
//
// Conventions (mirror circuits/circuits/merkle_tree.circom):
//   * leaf           = Poseidon(secret)              // identity commitment
//   * parent         = Poseidon(leftChild, rightChild)
//   * zeros[0]       = 0
//   * zeros[i]       = Poseidon(zeros[i-1], zeros[i-1])
//   * pathIndices[i] : 0 => our node is the LEFT child, sibling is RIGHT
//                      1 => our node is the RIGHT child, sibling is LEFT
//
// Usage:
//   node scripts/gen_input.js
// writes build/input.json (and prints it).
// =============================================================================
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { buildPoseidon } from "circomlibjs";
import { mod, Field } from "ffjavascript";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

// ---- config ---------------------------------------------------------------
const MERKLE_TREE_DEPTH = Number(process.env.MERKLE_TREE_DEPTH ?? 20);
const VOTE_ID = BigInt(process.env.VOTE_ID ?? 1);

// ---------------------------------------------------------------------------
// Poseidon helper. `buildPoseidon` returns a wasm-backed instance whose
// `F` is the BN254 scalar field arithmetic object; values are bigints.
// ---------------------------------------------------------------------------
const poseidon = await buildPoseidon();
const F = poseidon.F;

const poseidon1 = (x) => F.toObject(poseidon([x]));
const poseidon2 = (x, y) => F.toObject(poseidon([x, y]));

// ---------------------------------------------------------------------------
// Zero-hash chain: zeros[i] is the root of an entirely-empty subtree of
// depth i. Sparse trees pad missing leaves with these so a partial tree
// collapses to the same root as a full one.
// ---------------------------------------------------------------------------
function buildZeros(depth) {
    const zeros = [0n];
    for (let i = 1; i <= depth; i++) {
        zeros[i] = poseidon2(zeros[i - 1], zeros[i - 1]);
    }
    return zeros;
}

// ---------------------------------------------------------------------------
// Insert `leaf` into a sparse Poseidon Merkle tree, returning the new root
// and the list of filled nodes. We only build a small tree here (enough for
// the sample leaves), padding the rest with the zero chain.
// ---------------------------------------------------------------------------
class MerkleTree {
    constructor(depth) {
        this.depth = depth;
        this.zeros = buildZeros(depth);
        this.nodes = Array.from({ length: depth + 1 }, () => new Map());
        // Seed every level's "zeroth" empty tree with its zero root.
        // leaves at level 0 default to zeros[0] = 0.
        this.nextIndex = 0;
    }

    insert(leaf) {
        const index = this.nextIndex++;
        this.nodes[0].set(index, leaf);
        this._recompute(0, index);
        return index;
    }

    // Recompute hashes from `index` up to the root.
    _recompute(level, index) {
        let node = this.nodes[level].get(index);
        for (let l = level; l < this.depth; l++) {
            const sibling =
                index % 2 === 0
                    ? this._get(l, index + 1)  // right sibling
                    : this._get(l, index - 1); // left sibling
            const [left, right] =
                index % 2 === 0 ? [node, sibling] : [sibling, node];
            node = poseidon2(left, right);
            index = Math.floor(index / 2);
            this.nodes[l + 1].set(index, node);
        }
        return node;
    }

    _get(level, index) {
        if (this.nodes[level].has(index)) return this.nodes[level].get(index);
        return this.zeros[level]; // sparse padding
    }

    root() {
        // Root sits at (depth, 0). If nothing was inserted there, fall back
        // to the all-zeros root.
        return this.nodes[this.depth].get(0) ?? this.zeros[this.depth];
    }

    // Produce the membership proof for the leaf at `index`.
    // Returns { pathElements, pathIndices } matching the circuit convention.
    proof(index) {
        const pathElements = [];
        const pathIndices = [];
        for (let level = 0; level < this.depth; level++) {
            const siblingIndex =
                index % 2 === 0 ? index + 1 : index - 1;
            pathElements.push(this._get(level, siblingIndex).toString());
            pathIndices.push(index % 2 === 0 ? 0 : 1);
            index = Math.floor(index / 2);
        }
        return { pathElements, pathIndices };
    }
}

// ---------------------------------------------------------------------------
// Main: build a sample whitelist, insert one voter, emit input.json.
// ---------------------------------------------------------------------------
const tree = new MerkleTree(MERKLE_TREE_DEPTH);

// Sample voters — secrets are arbitrary bigints < BN254 scalar field.
// In production these are generated client-side and never leave the browser.
const voters = [
    12345678901234567890n,
    98765432109876543210n,
    55555555555555555555n,
];

const commitments = [];
for (const secret of voters) {
    const commitment = poseidon1(secret);
    commitments.push(commitment);
    tree.insert(commitment);
}

// The voter who actually casts a ballot (index 1).
const voterIndex = 1;
const voterSecret = voters[voterIndex];
const merkleRoot = tree.root();
const { pathElements, pathIndices } = tree.proof(voterIndex);

const nullifierHash = poseidon2(voterSecret, VOTE_ID);

// circom reads inputs as decimal STRINGS for big numbers (avoids JSON
// precision loss). Public inputs appear in the SAME ORDER declared in the
// circuit, which is also the order the on-chain verifier expects:
//   [voteId, merkleRoot, nullifierHash]
const input = {
    secret: voterSecret.toString(),
    pathElements,
    pathIndices,
    voteId: VOTE_ID.toString(),
    merkleRoot: merkleRoot.toString(),
    nullifierHash: nullifierHash.toString(),
};

const outDir = path.join(ROOT, "build");
await mkdir(outDir, { recursive: true });
const outPath = path.join(outDir, "input.json");
await writeFile(outPath, JSON.stringify(input, null, 2));

console.log("Wrote:", outPath);
console.log("  merkleRoot    :", input.merkleRoot);
console.log("  nullifierHash :", input.nullifierHash);
console.log("  voteId        :", input.voteId);
console.log("  commitments   :", commitments.map((c) => c.toString()));
