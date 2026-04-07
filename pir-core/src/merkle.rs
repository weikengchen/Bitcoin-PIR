//! SHA-256 Merkle tree construction and proof verification.
//!
//! The tree is built over INDEX entries (one leaf per scripthash). Each leaf
//! hash commits to the scripthash, its sorted position (tree_loc), and the
//! hash of its data chunks:
//!
//!   leaf_hash = SHA256(scripthash || tree_loc_u32_le || data_hash)
//!
//! Internal nodes: parent = SHA256(left_child || right_child)
//!
//! The tree is binary. If the number of leaves is not a power of 2, the
//! tree is padded with zero-hash leaves.

use std::collections::HashMap;

/// Size of a SHA-256 hash in bytes.
pub const HASH_SIZE: usize = 32;

/// A 32-byte SHA-256 hash.
pub type Hash256 = [u8; HASH_SIZE];

/// The zero hash (all zeros) used for padding leaves.
pub const ZERO_HASH: Hash256 = [0u8; HASH_SIZE];

// ─── SHA-256 (minimal, no-dependency implementation) ────────────────────────

/// Compute SHA-256 of input data.
pub fn sha256(data: &[u8]) -> Hash256 {
    // SHA-256 constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process blocks
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e; e = d.wrapping_add(temp1);
            d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        result[i*4..i*4+4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

// ─── Leaf hash computation ─────────────────────────────────────────────────

/// Compute a leaf hash: SHA256(scripthash || tree_loc || data_hash).
pub fn compute_leaf_hash(scripthash: &[u8; 20], tree_loc: u32, data_hash: &Hash256) -> Hash256 {
    let mut preimage = Vec::with_capacity(20 + 4 + 32);
    preimage.extend_from_slice(scripthash);
    preimage.extend_from_slice(&tree_loc.to_le_bytes());
    preimage.extend_from_slice(data_hash);
    sha256(&preimage)
}

/// Compute the hash of a data chunk (the raw UTXO/delta data for a scripthash).
pub fn compute_data_hash(chunk_data: &[u8]) -> Hash256 {
    sha256(chunk_data)
}

/// Per-bucket bin Merkle: leaf = SHA256(bin_index_u32_LE || bin_content).
///
/// Each leaf in a per-PBC-group Merkle tree commits to the bin index and
/// all slot data at that bin. This binds the cuckoo placement to the tree.
pub fn compute_bin_leaf_hash(bin_index: u32, bin_content: &[u8]) -> Hash256 {
    let mut preimage = Vec::with_capacity(4 + bin_content.len());
    preimage.extend_from_slice(&bin_index.to_le_bytes());
    preimage.extend_from_slice(bin_content);
    sha256(&preimage)
}

/// Compute an internal node (binary): SHA256(left || right).
pub fn compute_parent(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(left);
    preimage[32..].copy_from_slice(right);
    sha256(&preimage)
}

/// Compute an internal node (arity N): SHA256(child_0 || child_1 || ... || child_{N-1}).
pub fn compute_parent_n(children: &[Hash256]) -> Hash256 {
    let mut preimage = Vec::with_capacity(children.len() * HASH_SIZE);
    for child in children {
        preimage.extend_from_slice(child);
    }
    sha256(&preimage)
}

// ─── Tree construction ─────────────────────────────────────────────────────

/// A complete binary Merkle tree stored as a flat array.
///
/// Tree layout (1-indexed, like a heap):
///   - Node 1 = root
///   - Node i's children: 2i (left), 2i+1 (right)
///   - Leaves at indices [num_leaves, 2*num_leaves)
///
/// `num_leaves` is always a power of 2 (padded with ZERO_HASH).
pub struct MerkleTree {
    /// All node hashes, 1-indexed. nodes[0] is unused.
    pub nodes: Vec<Hash256>,
    /// Number of leaves (power of 2, includes padding).
    pub num_leaves: usize,
    /// Number of real (non-padding) leaves.
    pub num_real_leaves: usize,
    /// Total depth (root is at depth 0, leaves at depth `depth`).
    pub depth: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf hashes.
    ///
    /// Pads to the next power of 2 with ZERO_HASH leaves.
    pub fn build(leaf_hashes: &[Hash256]) -> Self {
        let num_real = leaf_hashes.len();
        let num_leaves = num_real.next_power_of_two();
        let depth = (num_leaves as f64).log2() as usize;
        let total_nodes = 2 * num_leaves; // 1-indexed, so [1, 2*num_leaves)

        let mut nodes = vec![ZERO_HASH; total_nodes];

        // Fill leaves
        for (i, hash) in leaf_hashes.iter().enumerate() {
            nodes[num_leaves + i] = *hash;
        }
        // Padding leaves are already ZERO_HASH

        // Build bottom-up
        for i in (1..num_leaves).rev() {
            nodes[i] = compute_parent(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        MerkleTree { nodes, num_leaves, num_real_leaves: num_real, depth }
    }

    /// Get the root hash.
    pub fn root(&self) -> &Hash256 {
        &self.nodes[1]
    }

    /// Get the hash at a specific node index (1-based).
    pub fn node(&self, index: usize) -> &Hash256 {
        &self.nodes[index]
    }

    /// Get the sibling hash for a node at a given index.
    pub fn sibling(&self, index: usize) -> &Hash256 {
        &self.nodes[index ^ 1]
    }

    /// Get the sibling hash for leaf `leaf_idx` at tree level `level`.
    ///
    /// Level 0 = siblings of leaves, level 1 = siblings of level-1 parents, etc.
    /// Returns (sibling_node_index, sibling_hash).
    pub fn sibling_at_level(&self, leaf_idx: usize, level: usize) -> (usize, &Hash256) {
        let node_idx = (self.num_leaves + leaf_idx) >> level;
        let sibling_idx = node_idx ^ 1;
        (sibling_idx, &self.nodes[sibling_idx])
    }

    /// Extract all sibling hashes needed for a proof of leaf `leaf_idx`.
    ///
    /// Returns a Vec of (level, sibling_hash) pairs from bottom to top.
    pub fn proof(&self, leaf_idx: usize) -> Vec<(usize, Hash256)> {
        let mut proof = Vec::with_capacity(self.depth);
        let mut idx = self.num_leaves + leaf_idx;
        for level in 0..self.depth {
            let sibling_idx = idx ^ 1;
            proof.push((level, self.nodes[sibling_idx]));
            idx >>= 1;
        }
        proof
    }

    /// Extract sibling hashes at a specific level for all real leaves.
    ///
    /// Returns a map: node_index_at_level → sibling_hash.
    /// Used to build the per-level sibling PIR databases.
    pub fn siblings_at_level(&self, level: usize) -> HashMap<u32, Hash256> {
        let mut siblings = HashMap::new();
        let nodes_at_level = self.num_leaves >> level;
        for node_idx in 0..nodes_at_level {
            // The absolute index in the tree at this level
            let abs_idx = (self.num_leaves >> level) + node_idx;
            if abs_idx < self.nodes.len() {
                let sibling_abs = abs_idx ^ 1;
                if sibling_abs < self.nodes.len() {
                    siblings.insert(node_idx as u32, self.nodes[sibling_abs]);
                }
            }
        }
        siblings
    }

    /// Extract the tree-top cache: all node hashes at and above a given level.
    ///
    /// Returns nodes in order of index. The number of nodes is 2^(depth - cache_depth).
    /// For cache_depth = depth - 10, this gives 1024 nodes = 32KB.
    pub fn tree_top_cache(&self, cache_from_level: usize) -> Vec<Hash256> {
        let start_idx = 1; // root
        let end_idx = 1 << cache_from_level; // exclusive: 2^cache_from_level
        // Nodes at indices [1, 2^cache_from_level)
        let mut cache = Vec::with_capacity(end_idx);
        for i in start_idx..end_idx {
            cache.push(self.nodes[i]);
        }
        cache
    }
}

// ─── N-ary Merkle tree ────────────────────────────────────────────────────

/// An N-ary Merkle tree stored level-by-level.
///
/// `levels[0]` = leaf hashes (padded to a multiple of arity^depth)
/// `levels[depth]` = `[root_hash]`
///
/// At each level L, `levels[L+1][i] = SHA256(levels[L][i*A] || ... || levels[L][i*A + A-1])`
pub struct MerkleTreeN {
    /// Per-level hash arrays. levels[0] = leaves, levels[depth] = [root].
    pub levels: Vec<Vec<Hash256>>,
    /// Branching factor.
    pub arity: usize,
    /// Number of real (non-padding) leaves.
    pub num_real_leaves: usize,
}

impl MerkleTreeN {
    /// Build an N-ary Merkle tree from leaf hashes.
    ///
    /// Pads leaves to the next power of `arity` with ZERO_HASH.
    pub fn build(leaf_hashes: &[Hash256], arity: usize) -> Self {
        assert!(arity >= 2, "arity must be >= 2");
        let num_real = leaf_hashes.len();

        // Pad to next power of arity
        let num_leaves = next_power_of(num_real, arity);

        let mut levels: Vec<Vec<Hash256>> = Vec::new();

        // Level 0: leaves
        let mut level0 = Vec::with_capacity(num_leaves);
        level0.extend_from_slice(leaf_hashes);
        level0.resize(num_leaves, ZERO_HASH);
        levels.push(level0);

        // Build bottom-up
        loop {
            let prev = levels.last().unwrap();
            if prev.len() <= 1 {
                break;
            }
            let next_len = (prev.len() + arity - 1) / arity;
            let mut next_level = Vec::with_capacity(next_len);
            for i in 0..next_len {
                let start = i * arity;
                let end = (start + arity).min(prev.len());
                let mut children: Vec<Hash256> = prev[start..end].to_vec();
                // Pad if last group is incomplete
                children.resize(arity, ZERO_HASH);
                next_level.push(compute_parent_n(&children));
            }
            levels.push(next_level);
        }

        MerkleTreeN { levels, arity, num_real_leaves: num_real }
    }

    /// Number of levels (0 = leaves, depth = root).
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Number of leaves (including padding).
    pub fn num_leaves(&self) -> usize {
        self.levels[0].len()
    }

    /// Root hash.
    pub fn root(&self) -> &Hash256 {
        &self.levels[self.depth()][0]
    }

    /// Get the A-1 sibling hashes for node at `local_idx` at `level`.
    ///
    /// Returns the sibling hashes in order (all children of the same parent,
    /// excluding the node itself).
    pub fn siblings_of(&self, level: usize, local_idx: usize) -> Vec<Hash256> {
        let a = self.arity;
        let parent_idx = local_idx / a;
        let first_child = parent_idx * a;
        let level_nodes = &self.levels[level];

        let mut sibs = Vec::with_capacity(a - 1);
        for c in first_child..first_child + a {
            if c == local_idx {
                continue;
            }
            if c < level_nodes.len() {
                sibs.push(level_nodes[c]);
            } else {
                sibs.push(ZERO_HASH);
            }
        }
        sibs
    }

    /// Extract the tree-top cache: all hashes at levels where nodes ≤ threshold.
    ///
    /// Returns (cache_from_level, cached_levels) where cache_from_level is the
    /// first level (from leaves) that is fully cached.
    /// Each cached level is a Vec<Hash256> of all node hashes at that level.
    pub fn tree_top_cache(&self, threshold: usize) -> (usize, Vec<Vec<Hash256>>) {
        let mut cache_from_level = self.depth();
        for (level_idx, level) in self.levels.iter().enumerate() {
            if level.len() <= threshold {
                cache_from_level = level_idx;
                break;
            }
        }
        let cached: Vec<Vec<Hash256>> = self.levels[cache_from_level..].to_vec();
        (cache_from_level, cached)
    }
}

/// Compute the smallest power of `base` that is >= `n`.
fn next_power_of(n: usize, base: usize) -> usize {
    if n <= 1 { return 1; }
    let mut v = 1;
    while v < n {
        v *= base;
    }
    v
}

/// Verify an N-ary Merkle proof.
///
/// `siblings_per_level[i]` contains A-1 sibling hashes at level i (from leaves up).
/// `child_index_per_level[i]` is the position within the parent's children at level i.
pub fn verify_proof_n(
    leaf_hash: &Hash256,
    leaf_idx: usize,
    arity: usize,
    siblings_per_level: &[Vec<Hash256>],
    root: &Hash256,
) -> bool {
    let mut current = *leaf_hash;
    let mut idx = leaf_idx;

    for level_siblings in siblings_per_level {
        let pos_in_parent = idx % arity; // which child am I?
        // Reconstruct all children: insert `current` at pos_in_parent
        let mut children = Vec::with_capacity(arity);
        let mut sib_iter = level_siblings.iter();
        for c in 0..arity {
            if c == pos_in_parent {
                children.push(current);
            } else {
                children.push(*sib_iter.next().unwrap_or(&ZERO_HASH));
            }
        }
        current = compute_parent_n(&children);
        idx /= arity;
    }

    current == *root
}

// ─── Proof verification (binary, legacy) ──────────────────────────────────

/// Verify a Merkle proof for a leaf hash.
///
/// `leaf_hash`: the hash of the leaf being verified.
/// `leaf_idx`: the position of the leaf in the tree.
/// `siblings`: the sibling hashes from bottom to top (one per level).
/// `root`: the expected root hash.
///
/// Returns true if the proof is valid.
pub fn verify_proof(
    leaf_hash: &Hash256,
    leaf_idx: usize,
    siblings: &[Hash256],
    root: &Hash256,
) -> bool {
    let mut current = *leaf_hash;
    let mut idx = leaf_idx;

    for sibling in siblings {
        if idx & 1 == 0 {
            // Current is left child
            current = compute_parent(&current, sibling);
        } else {
            // Current is right child
            current = compute_parent(sibling, &current);
        }
        idx >>= 1;
    }

    current == *root
}

/// Full verification: given a scripthash's data, verify against a known root.
///
/// Steps:
/// 1. Compute data_hash = SHA256(chunk_data)
/// 2. Compute leaf_hash = SHA256(scripthash || tree_loc || data_hash)
/// 3. Walk the proof up to the root
/// 4. Compare against tree-top cache or known root
pub fn verify_entry(
    scripthash: &[u8; 20],
    tree_loc: u32,
    chunk_data: &[u8],
    expected_data_hash: &Hash256,
    siblings: &[Hash256],
    root: &Hash256,
) -> bool {
    // Step 1: Verify data_hash
    let computed_data_hash = compute_data_hash(chunk_data);
    if computed_data_hash != *expected_data_hash {
        return false;
    }

    // Step 2: Compute leaf_hash
    let leaf_hash = compute_leaf_hash(scripthash, tree_loc, expected_data_hash);

    // Step 3-4: Verify proof
    verify_proof(&leaf_hash, tree_loc as usize, siblings, root)
}

// ─── Sibling group slot format ────────────────────────────────────────────

/// Compute sibling group slot size for a given arity.
/// Layout: [4B group_index][arity × 32B child_hashes]
/// One entry per parent group (N/arity entries per level, not N).
/// The client queries group_id = node_idx / arity, then uses position
/// node_idx % arity to identify itself among the A children.
pub fn merkle_sibling_slot_size(arity: usize) -> usize {
    4 + arity * HASH_SIZE
}

/// Legacy binary sibling slot size (arity=2): [4B node_index][32B hash] = 36 bytes.
pub const MERKLE_SIBLING_SLOT_SIZE: usize = 4 + 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        // Known SHA-256 of empty string
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_merkle_tree_4_leaves() {
        let leaves: Vec<Hash256> = (0..4u8)
            .map(|i| sha256(&[i]))
            .collect();

        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.num_leaves, 4);
        assert_eq!(tree.depth, 2);

        // Verify proof for each leaf
        let root = *tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof_siblings: Vec<Hash256> = tree.proof(i).into_iter().map(|(_, h)| h).collect();
            assert!(verify_proof(leaf, i, &proof_siblings, &root));
        }
    }

    #[test]
    fn test_merkle_tree_non_power_of_2() {
        let leaves: Vec<Hash256> = (0..5u8)
            .map(|i| sha256(&[i]))
            .collect();

        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.num_leaves, 8); // Padded to next power of 2
        assert_eq!(tree.num_real_leaves, 5);
        assert_eq!(tree.depth, 3);

        // Verify proofs for real leaves
        let root = *tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof_siblings: Vec<Hash256> = tree.proof(i).into_iter().map(|(_, h)| h).collect();
            assert!(verify_proof(leaf, i, &proof_siblings, &root));
        }
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![sha256(b"only")];
        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.num_leaves, 1);
        assert_eq!(tree.depth, 0);
        assert_eq!(tree.root(), &leaves[0]);
    }

    #[test]
    fn test_verify_entry() {
        let scripthash: [u8; 20] = [0xAA; 20];
        let chunk_data = b"some utxo data here for testing";
        let data_hash = compute_data_hash(chunk_data);
        let tree_loc: u32 = 42;

        let leaf_hash = compute_leaf_hash(&scripthash, tree_loc, &data_hash);

        // Build a small tree with this leaf
        let mut leaves = vec![ZERO_HASH; 64];
        leaves[tree_loc as usize] = leaf_hash;
        let tree = MerkleTree::build(&leaves);

        let proof_siblings: Vec<Hash256> = tree.proof(tree_loc as usize)
            .into_iter()
            .map(|(_, h)| h)
            .collect();

        assert!(verify_entry(
            &scripthash,
            tree_loc,
            chunk_data,
            &data_hash,
            &proof_siblings,
            tree.root(),
        ));

        // Tampered data should fail
        assert!(!verify_entry(
            &scripthash,
            tree_loc,
            b"tampered data",
            &data_hash,
            &proof_siblings,
            tree.root(),
        ));
    }

    #[test]
    fn test_tree_top_cache() {
        let leaves: Vec<Hash256> = (0..16u8)
            .map(|i| sha256(&[i]))
            .collect();

        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.depth, 4);

        // Cache top 2 levels: nodes at indices [1, 4) → 3 nodes (root + 2 children)
        let cache = tree.tree_top_cache(2);
        assert_eq!(cache.len(), 3);
        assert_eq!(cache[0], *tree.root());
    }
}
