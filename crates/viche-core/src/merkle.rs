//! Sparse Poseidon Merkle tree for Viche.
//!
//! This is the off-chain Merkle tree used to build identity-commitment
//! whitelists for polls. It **must** produce roots and proofs that match the
//! circuit's `merkle_tree.circom` and the reference implementation in
//! `circuits/scripts/gen_input.js`.
//!
//! ## Conventions (load-bearing, must match circom)
//!
//! ```text
//! leaf           = Poseidon(secret)
//! parent         = Poseidon(left, right)
//! zeros[0]       = 0
//! zeros[i]       = Poseidon(zeros[i-1], zeros[i-1])
//! pathIndices[i] : 0 => our node is the LEFT child, sibling is RIGHT
//!                   1 => our node is the RIGHT child, sibling is LEFT
//! ```
//!
//! The tree is **sparse**: instead of allocating `2^DEPTH` leaf slots, it stores
//! only filled nodes at each level in a `HashMap`. Missing nodes resolve to the
//! pre-computed zero hash at that level.
//!
//! ## Generic over hasher
//!
//! The tree is parameterised by a [`PoseidonProvider`] so the same code works
//! with:
//!   * a circomlibjs bridge in the browser (via `wasm-bindgen`), or
//!   * a future native Rust Poseidon implementation for testing/relayer use.

use crate::poseidon::PoseidonProvider;
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;

/// Default Merkle tree depth. Matches `vote.circom`'s `MERKLE_TREE_DEPTH = 20`.
pub const DEFAULT_DEPTH: usize = 20;

/// Maximum tree depth supported (arbitrary safety bound).
pub const MAX_DEPTH: usize = 32;

/// A Merkle membership proof for a leaf at a given index.
///
/// `path_elements[i]` is the sibling hash at level `i`.
/// `path_indices[i]` is `false` if our node is the LEFT child at level `i`
/// (i.e. the sibling is on the right), `true` if RIGHT.
///
/// In the circom circuit, `pathIndices[i]` is `0` for LEFT and `1` for RIGHT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root.
    pub path_elements: Vec<U256>,
    /// Path direction at each level: `false` = LEFT, `true` = RIGHT.
    pub path_indices: Vec<bool>,
}

impl MerkleProof {
    /// Create a proof from the raw sibling/paths arrays.
    ///
    /// # Panics
    ///
    /// Panics if `path_elements.len() != path_indices.len()`.
    pub fn new(path_elements: Vec<U256>, path_indices: Vec<bool>) -> Self {
        assert_eq!(
            path_elements.len(),
            path_indices.len(),
            "MerkleProof: path_elements and path_indices must have the same length"
        );
        Self {
            path_elements,
            path_indices,
        }
    }

    /// The depth of this proof (number of levels).
    pub fn depth(&self) -> usize {
        self.path_elements.len()
    }
}

/// A sparse Poseidon Merkle tree.
///
/// Generic over the hasher so the same data structure can be used in native
/// Rust (with a native Poseidon impl) and in the browser (with a circomlibjs
/// bridge).
///
/// # Type parameters
///
/// - `H`: A [`PoseidonProvider`] implementation.
/// - `DEPTH`: The number of levels in the tree. Default is 20 (~1M leaves).
#[derive(Debug, Clone)]
pub struct SparseMerkleTree<H: PoseidonProvider, const DEPTH: usize = DEFAULT_DEPTH> {
    /// Filled nodes at each level. `level_nodes[i][index]` is the hash at
    /// level `i`, position `index`. Level 0 = leaves.
    level_nodes: Vec<HashMap<usize, U256>>,
    /// Pre-computed zero hashes. `zeros[i]` is the root of an entirely-empty
    /// subtree of depth `i`.
    zeros: Vec<U256>,
    /// The next leaf index to assign.
    next_index: u64,
    /// Phantom marker for the hasher type parameter.
    _hasher: PhantomData<H>,
}

impl<H: PoseidonProvider, const DEPTH: usize> SparseMerkleTree<H, DEPTH> {
    /// Create a new empty sparse Merkle tree.
    ///
    /// # Panics
    ///
    /// Panics if `DEPTH == 0` or `DEPTH > MAX_DEPTH`.
    pub fn new(hasher: &H) -> Self {
        assert!(DEPTH > 0, "Merkle tree depth must be > 0");
        assert!(
            DEPTH <= MAX_DEPTH,
            "Merkle tree depth must be <= {}",
            MAX_DEPTH
        );

        // Build the zero-hash chain: zeros[0] = 0, zeros[i] = H(zeros[i-1], zeros[i-1]).
        let mut zeros = vec![U256::ZERO];
        for i in 1..=DEPTH {
            let z = hasher
                .hash_2(&zeros[i - 1], &zeros[i - 1])
                .expect("failed to compute zero hash — hasher not ready or input out of field");
            zeros.push(z);
        }

        // Allocate level maps. Level 0 = leaves, level DEPTH = root.
        let level_nodes = (0..=DEPTH).map(|_| HashMap::new()).collect();

        Self {
            level_nodes,
            zeros,
            next_index: 0,
            _hasher: PhantomData,
        }
    }

    /// Insert a leaf (identity commitment) into the tree, returning its index.
    ///
    /// Recomputes all ancestor hashes up to the root.
    pub fn insert(&mut self, hasher: &H, leaf: U256) -> u64 {
        let index = self.next_index;
        self.next_index += 1;

        // Store the leaf at level 0.
        self.level_nodes[0].insert(index as usize, leaf);
        self.recompute(hasher, 0, index as usize);
        index
    }

    /// Get the current root hash.
    ///
    /// Returns `zeros[DEPTH]` (the empty-tree root) if no leaves have been
    /// inserted yet.
    pub fn root(&self) -> U256 {
        self.level_nodes[DEPTH]
            .get(&0)
            .copied()
            .unwrap_or_else(|| self.zeros[DEPTH])
    }

    /// Generate a Merkle membership proof for the leaf at `index`.
    ///
    /// Returns [`MerkleProof`] with `path_elements` and `path_indices` arrays
    /// of length `DEPTH`, matching the circuit's expected input format.
    ///
    /// # Panics
    ///
    /// Panics if `index >= next_index` (leaf not yet inserted).
    pub fn proof(&self, index: u64) -> MerkleProof {
        assert!(
            index < self.next_index,
            "Merkle proof requested for uninserted leaf index {} (next_index = {})",
            index,
            self.next_index
        );

        let mut path_elements = Vec::with_capacity(DEPTH);
        let mut path_indices = Vec::with_capacity(DEPTH);
        let mut idx = index as usize;

        for level in 0..DEPTH {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = self.get(level, sibling_idx);
            path_elements.push(sibling);
            // circom convention: 0 = our node is LEFT, 1 = our node is RIGHT.
            path_indices.push(idx % 2 != 0);
            idx /= 2;
        }

        MerkleProof {
            path_elements,
            path_indices,
        }
    }

    /// The number of leaves currently inserted.
    pub fn len(&self) -> u64 {
        self.next_index
    }

    /// Whether the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// Get the node at `(level, index)`, falling back to the zero hash.
    fn get(&self, level: usize, index: usize) -> U256 {
        self.level_nodes[level]
            .get(&index)
            .copied()
            .unwrap_or_else(|| self.zeros[level])
    }

    /// Recompute hashes from `(level, index)` up to the root.
    fn recompute(&mut self, hasher: &H, level: usize, mut index: usize) {
        let mut node = self.get(level, index);
        for l in level..DEPTH {
            let sibling_idx = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = self.get(l, sibling_idx);
            let (left, right) = if index % 2 == 0 {
                (node, sibling)
            } else {
                (sibling, node)
            };
            node = hasher.hash_2(&left, &right).expect(
                "failed to compute Merkle parent hash — hasher not ready or input out of field",
            );
            index /= 2;
            self.level_nodes[l + 1].insert(index, node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock Poseidon provider for unit tests.
    ///
    /// Uses a trivial hash (H(a) = a + 1, H(a, b) = a + b + MODULUS/2) that
    /// is NOT cryptographically correct but exercises the tree logic correctly.
    /// Real correctness is validated against circomlibjs in integration tests.
    #[derive(Debug, Clone)]
    struct MockPoseidon;

    impl PoseidonProvider for MockPoseidon {
        fn hash_1(&self, x: &U256) -> Result<U256, crate::poseidon::PoseidonError> {
            Ok(*x + U256::from(1u64))
        }

        fn hash_2(&self, x: &U256, y: &U256) -> Result<U256, crate::poseidon::PoseidonError> {
            // Arbitrary non-trivial function for testing structure.
            Ok(*x + y + U256::from(999u64))
        }
    }

    #[test]
    fn empty_tree_root_is_zero_chain_top() {
        let tree: SparseMerkleTree<MockPoseidon, 4> = SparseMerkleTree::new(&MockPoseidon);
        let root = tree.root();
        // zeros[0] = 0, zeros[1] = H(0,0) = 999+0+0 = 999, zeros[2] = H(999,999) = 2997, etc.
        // We just check it's not the default U256::ZERO.
        assert_ne!(root, U256::ZERO);
    }

    #[test]
    fn insert_single_leaf_and_prove() {
        let mut tree: SparseMerkleTree<MockPoseidon, 4> = SparseMerkleTree::new(&MockPoseidon);
        let leaf = U256::from(42u64);
        let idx = tree.insert(&MockPoseidon, leaf);
        assert_eq!(idx, 0);

        let proof = tree.proof(0);
        assert_eq!(proof.depth(), 4);
        assert_eq!(proof.path_elements.len(), 4);
        assert_eq!(proof.path_indices.len(), 4);
        // Leaf 0 is LEFT at every level (index is always even: 0 -> 0 -> 0 -> 0).
        assert!(proof.path_indices.iter().all(|&p| !p));
    }

    #[test]
    fn insert_two_leaves_differing_paths() {
        let mut tree: SparseMerkleTree<MockPoseidon, 4> = SparseMerkleTree::new(&MockPoseidon);
        tree.insert(&MockPoseidon, U256::from(10u64));
        tree.insert(&MockPoseidon, U256::from(20u64));

        let proof0 = tree.proof(0);
        let proof1 = tree.proof(1);

        // At level 0: leaf 0 is LEFT (path_index false), leaf 1 is RIGHT (true).
        assert!(!proof0.path_indices[0]);
        assert!(proof1.path_indices[0]);
        // Their level-0 siblings are the other leaf's value (the leaf is stored
        // directly at level 0, NOT hashed with hash_1 — hash_1 is for identity
        // commitments, not for tree storage).
        assert_eq!(proof0.path_elements[0], U256::from(20u64));
        assert_eq!(proof1.path_elements[0], U256::from(10u64));
    }

    #[test]
    fn proof_panics_for_uninserted_index() {
        let mut tree: SparseMerkleTree<MockPoseidon, 4> = SparseMerkleTree::new(&MockPoseidon);
        tree.insert(&MockPoseidon, U256::from(1u64));
        // Index 1 has not been inserted.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tree.proof(1);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn tree_len_and_empty() {
        let mut tree: SparseMerkleTree<MockPoseidon, 4> = SparseMerkleTree::new(&MockPoseidon);
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);

        tree.insert(&MockPoseidon, U256::from(1u64));
        assert!(!tree.is_empty());
        assert_eq!(tree.len(), 1);

        tree.insert(&MockPoseidon, U256::from(2u64));
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn root_changes_after_inserts() {
        let mut tree: SparseMerkleTree<MockPoseidon, 4> = SparseMerkleTree::new(&MockPoseidon);
        let root0 = tree.root();

        tree.insert(&MockPoseidon, U256::from(100u64));
        let root1 = tree.root();
        assert_ne!(root0, root1); // at least one real leaf changes the root

        tree.insert(&MockPoseidon, U256::from(200u64));
        let root2 = tree.root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn depth_20_tree_works() {
        let mut tree: SparseMerkleTree<MockPoseidon, 20> = SparseMerkleTree::new(&MockPoseidon);
        let idx = tree.insert(&MockPoseidon, U256::from(42u64));
        assert_eq!(idx, 0);

        let proof = tree.proof(0);
        assert_eq!(proof.depth(), 20);
    }
}
