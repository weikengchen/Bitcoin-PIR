//! Hash functions for PBC group assignment, cuckoo hashing, and fingerprint tags.
//!
//! All functions are parameterized — they accept explicit seeds, group counts,
//! etc. rather than reading global constants. This allows the same code to work
//! for INDEX, CHUNK, MERKLE, and DELTA sub-tables with different parameters.

// ─── Primitive mixers ───────────────────────────────────────────────────────

/// Splitmix64 finalizer — bijective 64-bit mixer.
#[inline]
pub fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

/// Golden ratio constant used in nonce-based hashing.
pub const GOLDEN_RATIO: u64 = 0x9e3779b97f4a7c15;

/// Secondary mixing constant for cuckoo key derivation.
pub const CUCKOO_KEY_MIX: u64 = 0x517cc1b727220a95;

// ─── Script hash field extraction ───────────────────────────────────────────

/// Read first 8 bytes of a script_hash as u64 (LE).
#[inline]
pub fn sh_a(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes([
        script_hash[0], script_hash[1], script_hash[2], script_hash[3],
        script_hash[4], script_hash[5], script_hash[6], script_hash[7],
    ])
}

/// Read bytes 8..16 of a script_hash as u64 (LE).
#[inline]
pub fn sh_b(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes([
        script_hash[8], script_hash[9], script_hash[10], script_hash[11],
        script_hash[12], script_hash[13], script_hash[14], script_hash[15],
    ])
}

/// Read bytes 16..20 of a script_hash as u32 (LE), zero-extended to u64.
#[inline]
pub fn sh_c(script_hash: &[u8]) -> u64 {
    u32::from_le_bytes([
        script_hash[16], script_hash[17], script_hash[18], script_hash[19],
    ]) as u64
}

// ─── PBC group assignment (byte-keyed, for script hashes) ──────────────────

/// Hash a script_hash with a nonce for PBC group assignment.
#[inline]
pub fn hash_for_group(script_hash: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(script_hash).wrapping_add(nonce.wrapping_mul(GOLDEN_RATIO));
    h ^= sh_b(script_hash);
    splitmix64(h ^ sh_c(script_hash))
}

/// Derive `num_hashes` distinct PBC group indices for a script_hash.
pub fn derive_groups(script_hash: &[u8], k: usize, num_hashes: usize) -> Vec<usize> {
    let mut groups = Vec::with_capacity(num_hashes);
    let mut nonce: u64 = 0;

    while groups.len() < num_hashes {
        let h = hash_for_group(script_hash, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;

        if !groups.contains(&group) {
            groups.push(group);
        }
    }

    groups
}

/// Derive exactly 3 group indices into a fixed-size array (common case).
///
/// This is equivalent to `derive_groups(script_hash, k, 3)` but avoids
/// allocation and returns a `[usize; 3]` for backward compatibility.
pub fn derive_groups_3(script_hash: &[u8], k: usize) -> [usize; 3] {
    let mut groups = [0usize; 3];
    let mut nonce: u64 = 0;
    let mut count = 0;

    while count < 3 {
        let h = hash_for_group(script_hash, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;

        // Reject duplicates of groups already chosen in this derivation.
        // Iterating the first `count` slots via `.iter().take(count)` is
        // semantically equivalent to the old `for i in 0..count` index
        // loop and avoids the clippy::needless_range_loop warning.
        if groups.iter().take(count).any(|&g| g == group) {
            continue;
        }

        groups[count] = group;
        count += 1;
    }

    groups
}

// ─── PBC group assignment (integer-keyed, for chunk IDs) ───────────────────

/// Hash a u32 item ID with a nonce for PBC group assignment.
#[inline]
pub fn hash_int_for_group(id: u32, nonce: u64) -> u64 {
    splitmix64((id as u64).wrapping_add(nonce.wrapping_mul(GOLDEN_RATIO)))
}

/// Derive `num_hashes` distinct PBC group indices for an integer ID.
pub fn derive_int_groups(id: u32, k: usize, num_hashes: usize) -> Vec<usize> {
    let mut groups = Vec::with_capacity(num_hashes);
    let mut nonce: u64 = 0;

    while groups.len() < num_hashes {
        let h = hash_int_for_group(id, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;

        if !groups.contains(&group) {
            groups.push(group);
        }
    }

    groups
}

/// Derive exactly 3 PBC group indices for an integer ID (common case).
pub fn derive_int_groups_3(id: u32, k: usize) -> [usize; 3] {
    let mut groups = [0usize; 3];
    let mut nonce: u64 = 0;
    let mut count = 0;

    while count < 3 {
        let h = hash_int_for_group(id, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;

        // Mirror of `derive_groups_3` above — reject duplicates via
        // a take-count iterator to satisfy clippy::needless_range_loop.
        if groups.iter().take(count).any(|&g| g == group) {
            continue;
        }

        groups[count] = group;
        count += 1;
    }

    groups
}

// ─── Cuckoo hashing ────────────────────────────────────────────────────────

/// Derive a cuckoo hash function key for a given (group_id, hash_fn) pair.
#[inline]
pub fn derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((group_id as u64).wrapping_mul(GOLDEN_RATIO))
            .wrapping_add((hash_fn as u64).wrapping_mul(CUCKOO_KEY_MIX)),
    )
}

/// Cuckoo hash for byte-keyed items (script hashes): map to a bin index.
#[inline]
pub fn cuckoo_hash(script_hash: &[u8], key: u64, num_bins: usize) -> usize {
    let mut h = sh_a(script_hash) ^ key;
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    (h % num_bins as u64) as usize
}

/// Cuckoo hash for integer-keyed items (chunk IDs): map to a bin index.
#[inline]
pub fn cuckoo_hash_int(id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((id as u64) ^ key) % num_bins as u64) as usize
}

// ─── Fingerprint tags ──────────────────────────────────────────────────────

/// Compute an 8-byte fingerprint tag for a script_hash using a keyed hash.
#[inline]
pub fn compute_tag(tag_seed: u64, script_hash: &[u8]) -> u64 {
    let mut h = sh_a(script_hash) ^ tag_seed;
    h ^= sh_b(script_hash);
    splitmix64(h ^ sh_c(script_hash))
}

// ─── File header reading ───────────────────────────────────────────────────

/// Read bins_per_table (and optionally tag_seed) from a cuckoo file header.
///
/// The header layout at offset 16 always contains bins_per_table as u32 LE.
/// If `has_tag_seed` is true, tag_seed is at offset 32 as u64 LE.
pub fn read_cuckoo_header(data: &[u8], expected_magic: u64, header_size: usize, has_tag_seed: bool) -> (usize, u64) {
    assert!(data.len() >= header_size, "File too small for header");
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, expected_magic, "Bad magic number: expected 0x{:016x}, got 0x{:016x}", expected_magic, magic);
    let bins_per_table = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let tag_seed = if has_tag_seed {
        u64::from_le_bytes(data[32..40].try_into().unwrap())
    } else {
        0
    };
    (bins_per_table, tag_seed)
}

/// Read bins_per_table and tag_seed from an INDEX-level cuckoo header.
///
/// Convenience wrapper using INDEX_PARAMS defaults.
pub fn read_index_cuckoo_header(data: &[u8]) -> (usize, u64) {
    use crate::params::INDEX_PARAMS;
    read_cuckoo_header(data, INDEX_PARAMS.magic, INDEX_PARAMS.header_size, INDEX_PARAMS.has_tag_seed)
}

/// Read bins_per_table from a CHUNK-level cuckoo header.
///
/// Convenience wrapper using CHUNK_PARAMS defaults. Returns (bins_per_table, 0).
pub fn read_chunk_cuckoo_header(data: &[u8]) -> usize {
    use crate::params::CHUNK_PARAMS;
    let (bins, _) = read_cuckoo_header(data, CHUNK_PARAMS.magic, CHUNK_PARAMS.header_size, CHUNK_PARAMS.has_tag_seed);
    bins
}

// ─── Backward-compatible wrappers ──────────────────────────────────────────
// These use the legacy global constants so existing build/runtime code
// can import from pir_core::hash::* without changing call sites.

/// Derive 3 INDEX-level group indices (uses K=75).
pub fn derive_groups_legacy(script_hash: &[u8]) -> [usize; 3] {
    derive_groups_3(script_hash, crate::params::K)
}

/// Derive INDEX-level cuckoo key (uses MASTER_SEED).
pub fn derive_cuckoo_key_legacy(group_id: usize, hash_fn: usize) -> u64 {
    derive_cuckoo_key(crate::params::MASTER_SEED, group_id, hash_fn)
}

/// Derive 3 CHUNK-level group indices (uses K_CHUNK=80).
pub fn derive_chunk_groups_legacy(chunk_id: u32) -> [usize; 3] {
    derive_int_groups_3(chunk_id, crate::params::K_CHUNK)
}

/// Derive CHUNK-level cuckoo key (uses CHUNK_MASTER_SEED).
pub fn derive_chunk_cuckoo_key_legacy(group_id: usize, hash_fn: usize) -> u64 {
    derive_cuckoo_key(crate::params::CHUNK_MASTER_SEED, group_id, hash_fn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_splitmix64_known_values() {
        // Splitmix64 is deterministic
        assert_eq!(splitmix64(0), 0); // 0 is a fixed point of this finalizer
        assert_ne!(splitmix64(1), splitmix64(2));
        // Bijective: different non-zero inputs → different outputs
        let vals: Vec<u64> = (1..101).map(splitmix64).collect();
        for i in 0..vals.len() {
            for j in (i + 1)..vals.len() {
                assert_ne!(vals[i], vals[j]);
            }
        }
    }

    #[test]
    fn test_derive_groups_3_distinct() {
        let sh = [0u8; 20];
        let groups = derive_groups_3(&sh, 75);
        assert_ne!(groups[0], groups[1]);
        assert_ne!(groups[0], groups[2]);
        assert_ne!(groups[1], groups[2]);
        for &g in &groups {
            assert!(g < 75);
        }
    }

    #[test]
    fn test_derive_int_groups_3_distinct() {
        let groups = derive_int_groups_3(42, 80);
        assert_ne!(groups[0], groups[1]);
        assert_ne!(groups[0], groups[2]);
        assert_ne!(groups[1], groups[2]);
        for &g in &groups {
            assert!(g < 80);
        }
    }

    #[test]
    fn test_legacy_compat() {
        // Legacy wrappers should produce the same results as parameterized versions
        let sh = [1u8; 20];
        assert_eq!(
            derive_groups_legacy(&sh),
            derive_groups_3(&sh, 75)
        );
        assert_eq!(
            derive_cuckoo_key_legacy(5, 0),
            derive_cuckoo_key(0x71a2ef38b4c90d15, 5, 0)
        );
        assert_eq!(
            derive_chunk_groups_legacy(100),
            derive_int_groups_3(100, 80)
        );
    }

    #[test]
    fn test_cuckoo_hash_deterministic() {
        let sh = [2u8; 20];
        let key = derive_cuckoo_key(0x71a2ef38b4c90d15, 0, 0);
        let bin1 = cuckoo_hash(&sh, key, 1000);
        let bin2 = cuckoo_hash(&sh, key, 1000);
        assert_eq!(bin1, bin2);
        assert!(bin1 < 1000);
    }

    #[test]
    fn test_compute_tag_deterministic() {
        let sh = [3u8; 20];
        let tag1 = compute_tag(0xd4e5f6a7b8c91023, &sh);
        let tag2 = compute_tag(0xd4e5f6a7b8c91023, &sh);
        assert_eq!(tag1, tag2);
        // Different seed → different tag
        let tag3 = compute_tag(0x1234567890abcdef, &sh);
        assert_ne!(tag1, tag3);
    }
}
