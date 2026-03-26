"""
Hash functions for the Batch PIR system.

Ports the splitmix64-based functions from web/src/hash.ts / build/src/common.rs.
All 64-bit arithmetic uses Python int masked with & MASK64.
"""

import hashlib
import struct
from .pir_constants import (
    K, K_CHUNK, NUM_HASHES,
    MASTER_SEED, CHUNK_MASTER_SEED,
    MASK64,
)

# ── Core functions ─────────────────────────────────────────────────────────


def splitmix64(x: int) -> int:
    """splitmix64 finalizer (matches Rust exactly)."""
    x = (x ^ (x >> 30)) & MASK64
    x = (x * 0xbf58476d1ce4e5b9) & MASK64
    x = (x ^ (x >> 27)) & MASK64
    x = (x * 0x94d049bb133111eb) & MASK64
    x = (x ^ (x >> 31)) & MASK64
    return x


def _sh_a(data: bytes) -> int:
    """Read first 8 bytes of a script_hash as u64 LE."""
    return struct.unpack_from('<Q', data, 0)[0]


def _sh_b(data: bytes) -> int:
    """Read bytes 8..16 of a script_hash as u64 LE."""
    return struct.unpack_from('<Q', data, 8)[0]


def _sh_c(data: bytes) -> int:
    """Read bytes 16..20 of a script_hash as u32 LE, zero-extended to u64."""
    return struct.unpack_from('<I', data, 16)[0]


# ── Fingerprint tag computation ────────────────────────────────────────────


def compute_tag(tag_seed: int, script_hash: bytes) -> int:
    """Compute an 8-byte fingerprint tag for a script_hash using a keyed hash."""
    h = (_sh_a(script_hash) ^ tag_seed) & MASK64
    h = (h ^ _sh_b(script_hash)) & MASK64
    h = splitmix64((h ^ _sh_c(script_hash)) & MASK64)
    return h


# ── Index-level bucket assignment ──────────────────────────────────────────


def _hash_for_bucket(script_hash: bytes, nonce: int) -> int:
    """Hash script_hash with a nonce for bucket assignment."""
    h = (_sh_a(script_hash) + ((nonce * 0x9e3779b97f4a7c15) & MASK64)) & MASK64
    h = (h ^ _sh_b(script_hash)) & MASK64
    h = splitmix64((h ^ _sh_c(script_hash)) & MASK64)
    return h


def derive_buckets(script_hash: bytes) -> list[int]:
    """Derive NUM_HASHES (3) distinct bucket indices for a script_hash."""
    buckets: list[int] = []
    nonce = 0
    while len(buckets) < NUM_HASHES:
        h = _hash_for_bucket(script_hash, nonce)
        bucket = h % K
        nonce += 1
        if bucket not in buckets:
            buckets.append(bucket)
    return buckets


# ── Index-level cuckoo hashing ─────────────────────────────────────────────


def derive_cuckoo_key(bucket_id: int, hash_fn: int) -> int:
    """Derive a cuckoo hash function key for (bucket_id, hash_fn)."""
    return splitmix64(
        (MASTER_SEED
         + ((bucket_id * 0x9e3779b97f4a7c15) & MASK64)
         + ((hash_fn * 0x517cc1b727220a95) & MASK64)
         ) & MASK64
    )


def cuckoo_hash(script_hash: bytes, key: int, num_bins: int) -> int:
    """Cuckoo hash: hash a script_hash with a derived key, return a bin index."""
    h = (_sh_a(script_hash) ^ key) & MASK64
    h = (h ^ _sh_b(script_hash)) & MASK64
    h = splitmix64((h ^ _sh_c(script_hash)) & MASK64)
    return h % num_bins


# ── Chunk-level bucket assignment ──────────────────────────────────────────


def _hash_chunk_for_bucket(chunk_id: int, nonce: int) -> int:
    """Hash a chunk_id with a nonce for chunk-level bucket assignment."""
    return splitmix64(
        (chunk_id + ((nonce * 0x9e3779b97f4a7c15) & MASK64)) & MASK64
    )


def derive_chunk_buckets(chunk_id: int) -> list[int]:
    """Derive 3 distinct chunk-level bucket indices for a chunk_id."""
    buckets: list[int] = []
    nonce = 0
    while len(buckets) < NUM_HASHES:
        h = _hash_chunk_for_bucket(chunk_id, nonce)
        bucket = h % K_CHUNK
        nonce += 1
        if bucket not in buckets:
            buckets.append(bucket)
    return buckets


# ── Chunk-level cuckoo hashing ─────────────────────────────────────────────


def derive_chunk_cuckoo_key(bucket_id: int, hash_fn: int) -> int:
    """Derive a cuckoo hash function key for chunk-level (bucket_id, hash_fn)."""
    return splitmix64(
        (CHUNK_MASTER_SEED
         + ((bucket_id * 0x9e3779b97f4a7c15) & MASK64)
         + ((hash_fn * 0x517cc1b727220a95) & MASK64)
         ) & MASK64
    )


def cuckoo_hash_int(chunk_id: int, key: int, num_bins: int) -> int:
    """Cuckoo hash for chunk_ids: map a chunk_id to a bin index."""
    return splitmix64((chunk_id ^ key) & MASK64) % num_bins


# ── Script hash computation ───────────────────────────────────────────────


def sha256(data: bytes) -> bytes:
    """Compute SHA256 hash."""
    return hashlib.sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    """Compute RIPEMD160 hash."""
    return hashlib.new('ripemd160', data).digest()


def hash160(script_pubkey: bytes) -> bytes:
    """Compute HASH160 = RIPEMD160(SHA256(script))."""
    return ripemd160(sha256(script_pubkey))
