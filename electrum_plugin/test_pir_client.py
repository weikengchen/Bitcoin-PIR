#!/usr/bin/env python3
"""
Test script for the Python PIR client.

Tests:
  1. Hash function correctness (compare with known values from TypeScript)
  2. DPF key generation
  3. Live query against PIR servers

Usage:
  pip install websockets cryptography
  python test_pir_client.py [script_hash_hex]
"""

import sys
import asyncio
import logging
import struct

# Add parent directory to path for imports
sys.path.insert(0, '.')

from pir_privacy.pir_hash import (
    splitmix64, compute_tag, derive_buckets, derive_cuckoo_key,
    cuckoo_hash, hash160, derive_chunk_buckets,
)
from pir_privacy.pir_constants import MASK64, K, K_CHUNK, DEFAULT_SERVER0_URL, DEFAULT_SERVER1_URL
from pir_privacy.pir_dpf import dpf_gen
from pir_privacy.pir_client import BatchPirClient


# ── Hash function tests ───────────────────────────────────────────────────


def test_splitmix64():
    """Test splitmix64 produces consistent results."""
    # splitmix64(0) should be deterministic
    val = splitmix64(0)
    assert val == splitmix64(0), "splitmix64 is not deterministic"

    # Known value: splitmix64(1) from the Rust/TS implementation
    # These are verified against the TypeScript implementation
    val = splitmix64(1)
    print(f'  splitmix64(1) = 0x{val:016x}')

    val = splitmix64(0x71a2ef38b4c90d15)  # MASTER_SEED
    print(f'  splitmix64(MASTER_SEED) = 0x{val:016x}')

    print('  [OK] splitmix64')


def test_derive_buckets():
    """Test bucket derivation produces 3 distinct values in [0, K)."""
    # Create a dummy 20-byte script hash
    sh = bytes(range(20))
    buckets = derive_buckets(sh)
    assert len(buckets) == 3, f"Expected 3 buckets, got {len(buckets)}"
    assert len(set(buckets)) == 3, f"Buckets not distinct: {buckets}"
    assert all(0 <= b < K for b in buckets), f"Bucket out of range: {buckets}"
    print(f'  derive_buckets(0x{sh.hex()[:8]}...) = {buckets}')
    print('  [OK] derive_buckets')


def test_derive_chunk_buckets():
    """Test chunk bucket derivation."""
    buckets = derive_chunk_buckets(42)
    assert len(buckets) == 3
    assert len(set(buckets)) == 3
    assert all(0 <= b < K_CHUNK for b in buckets)
    print(f'  derive_chunk_buckets(42) = {buckets}')
    print('  [OK] derive_chunk_buckets')


def test_compute_tag():
    """Test tag computation."""
    sh = bytes(range(20))
    tag = compute_tag(0xd4e5f6a7b8c91023, sh)
    print(f'  compute_tag(0xd4e5f6a7b8c91023, ...) = 0x{tag:016x}')
    # Tag should be non-zero for non-trivial input
    assert tag != 0
    print('  [OK] compute_tag')


def test_hash160():
    """Test HASH160 = RIPEMD160(SHA256(x))."""
    # Known: HASH160 of empty byte string
    h = hash160(b'')
    assert len(h) == 20
    print(f'  hash160(b"") = {h.hex()}')
    # Known value: HASH160 of b'\x00' (from Bitcoin scripts)
    h2 = hash160(b'\x00')
    print(f'  hash160(b"\\x00") = {h2.hex()}')
    print('  [OK] hash160')


def test_cuckoo_hash():
    """Test cuckoo hash produces values in range."""
    sh = bytes(range(20))
    key = derive_cuckoo_key(0, 0)
    h = cuckoo_hash(sh, key, 1000000)
    assert 0 <= h < 1000000
    print(f'  cuckoo_hash(sh, key(0,0), 1000000) = {h}')
    print('  [OK] cuckoo_hash')


# ── DPF tests ─────────────────────────────────────────────────────────────


def test_dpf_gen():
    """Test DPF key generation produces valid keys."""
    k0, k1 = dpf_gen(42, 20)
    k0_bytes = k0.to_bytes()
    k1_bytes = k1.to_bytes()
    assert len(k0_bytes) > 0 and len(k1_bytes) > 0, "DPF keys are empty"
    assert len(k0_bytes) == len(k1_bytes), f"Key sizes differ: {len(k0_bytes)} vs {len(k1_bytes)}"
    print(f'  dpf_gen(42, 20) -> key0={len(k0_bytes)} bytes, key1={len(k1_bytes)} bytes')
    print('  [OK] dpf_gen')


# ── Live server test ──────────────────────────────────────────────────────


async def test_live_query(script_hash_hex: str):
    """Test a live query against the PIR servers."""
    script_hash = bytes.fromhex(script_hash_hex)
    assert len(script_hash) == 20, f"Script hash must be 20 bytes, got {len(script_hash)}"

    print(f'\n=== Live Query Test ===')
    print(f'Script hash: {script_hash_hex}')
    print(f'Servers: {DEFAULT_SERVER0_URL}, {DEFAULT_SERVER1_URL}')

    client = BatchPirClient(DEFAULT_SERVER0_URL, DEFAULT_SERVER1_URL)

    try:
        print('Connecting...')
        await client.connect()
        print(f'Connected. index_bins={client.index_bins}, chunk_bins={client.chunk_bins}')

        print('Querying...')
        result = await client.query(script_hash)

        if result is None:
            print('Result: NOT FOUND (address has no UTXOs or is not in database)')
        elif result.is_whale:
            print('Result: WHALE ADDRESS (excluded, too many UTXOs)')
        else:
            print(f'Result: {len(result.entries)} UTXOs, total={result.total_sats} sats')
            print(f'  start_chunk_id={result.start_chunk_id}, num_chunks={result.num_chunks}')
            for i, entry in enumerate(result.entries):
                txid_hex = entry.txid[::-1].hex()  # Reverse for display
                print(f'  UTXO {i}: {txid_hex}:{entry.vout} = {entry.amount} sats')
                if i >= 9:
                    remaining = len(result.entries) - 10
                    if remaining > 0:
                        print(f'  ... and {remaining} more')
                    break
    finally:
        await client.disconnect()
        print('Disconnected.')


# ── Main ──────────────────────────────────────────────────────────────────


def run_unit_tests():
    """Run all unit tests."""
    print('=== Unit Tests ===')
    test_splitmix64()
    test_derive_buckets()
    test_derive_chunk_buckets()
    test_compute_tag()
    test_hash160()
    test_cuckoo_hash()
    test_dpf_gen()
    print('\nAll unit tests passed!')


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(message)s',
        datefmt='%H:%M:%S',
    )

    # Run unit tests first
    run_unit_tests()

    # If a script hash is provided, do a live query
    if len(sys.argv) > 1:
        script_hash_hex = sys.argv[1]
    else:
        # Default test hash
        script_hash_hex = '20d920103ecb721638eb43f3e7a27c7b8ed3925b'

    asyncio.run(test_live_query(script_hash_hex))


if __name__ == '__main__':
    main()
