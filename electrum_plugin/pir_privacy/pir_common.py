"""
Shared utilities for all three PIR protocol clients (DPF, HarmonyPIR, OnionPIR).

Provides PBC cuckoo placement, round planning, varint decoding, UTXO data
parsing, and index/chunk result scanning. These are pure functions with no
protocol-specific dependencies.

Mirrors web/src/pbc.ts + web/src/codec.ts and build/src/common.rs.
"""

from __future__ import annotations

import struct
import time
import logging
from typing import Optional, TYPE_CHECKING

from .pir_constants import (
    TAG_SIZE, INDEX_ENTRY_SIZE,
    CHUNK_SIZE, CHUNK_SLOT_SIZE,
    MASK64,
)
from .pir_hash import splitmix64

if TYPE_CHECKING:
    from .pir_client import UtxoEntry

logger = logging.getLogger(__name__)


# ── PBC cuckoo placement ─────────────────────────────────────────────────────


def cuckoo_place(
    cand_buckets: list,
    buckets: list,
    qi: int,
    max_kicks: int,
    num_hashes: int,
) -> bool:
    """Cuckoo placement with eviction. Returns True if item qi was placed."""
    cands = cand_buckets[qi]

    # Try direct placement
    for c in cands:
        if buckets[c] is None:
            buckets[c] = qi
            return True

    # Eviction loop
    current_qi = qi
    current_bucket = cand_buckets[current_qi][0]

    for kick in range(max_kicks):
        evicted_qi = buckets[current_bucket]
        buckets[current_bucket] = current_qi
        ev_cands = cand_buckets[evicted_qi]

        for offset in range(num_hashes):
            c = ev_cands[(kick + offset) % num_hashes]
            if c == current_bucket:
                continue
            if buckets[c] is None:
                buckets[c] = evicted_qi
                return True

        next_bucket = ev_cands[0]
        for offset in range(num_hashes):
            c = ev_cands[(kick + offset) % num_hashes]
            if c != current_bucket:
                next_bucket = c
                break
        current_qi = evicted_qi
        current_bucket = next_bucket

    return False


def plan_rounds(
    item_buckets: list,
    num_buckets: int,
    num_hashes: int,
    max_kicks: int = 500,
) -> list[list[tuple[int, int]]]:
    """
    Plan multi-round PBC placement for items with candidate buckets.
    Returns rounds, each round is a list of (item_index, bucket_id) tuples.
    """
    remaining = list(range(len(item_buckets)))
    rounds: list[list[tuple[int, int]]] = []

    while remaining:
        cand_buckets = [item_buckets[i] for i in remaining]
        bucket_owner: list[Optional[int]] = [None] * num_buckets
        placed_local: list[int] = []

        for li in range(len(cand_buckets)):
            if len(placed_local) >= num_buckets:
                break
            saved = list(bucket_owner)
            if cuckoo_place(cand_buckets, bucket_owner, li, max_kicks, num_hashes):
                placed_local.append(li)
            else:
                for b in range(num_buckets):
                    bucket_owner[b] = saved[b]

        round_entries: list[tuple[int, int]] = []
        for b in range(num_buckets):
            local_idx = bucket_owner[b]
            if local_idx is not None:
                round_entries.append((remaining[local_idx], b))

        if not round_entries:
            logger.error(f'Could not place any items, {len(remaining)} remaining')
            break

        placed_orig = {remaining[li] for li in placed_local}
        remaining = [i for i in remaining if i not in placed_orig]
        rounds.append(round_entries)

    return rounds


# ── Varint decoder ────────────────────────────────────────────────────────────


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a LEB128 unsigned varint from data at offset.
    Returns (value, bytes_read). Consistent with Rust/TS convention.
    """
    result = 0
    shift = 0
    bytes_read = 0
    while True:
        if offset + bytes_read >= len(data):
            raise ValueError('Unexpected end of data while reading varint')
        byte = data[offset + bytes_read]
        bytes_read += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift >= 64:
            raise ValueError('VarInt too large')
    return (result, bytes_read)


# ── UTXO data decoder ────────────────────────────────────────────────────────


def decode_utxo_data(full_data: bytes) -> tuple[list, int]:
    """Decode varint-encoded UTXO entries from chunk data.

    Format: [varint numEntries][per entry: 32B txid, varint vout, varint amount]
    Returns (entries: list[UtxoEntry], total_sats: int).
    """
    from .pir_client import UtxoEntry

    pos = 0
    num_entries, count_bytes = read_varint(full_data, pos)
    pos += count_bytes

    entries: list[UtxoEntry] = []
    total_sats = 0

    for i in range(num_entries):
        if pos + 32 > len(full_data):
            logger.error(f'Data truncated at entry {i}')
            break

        txid = full_data[pos:pos + 32]
        pos += 32

        vout, vr = read_varint(full_data, pos)
        pos += vr

        amount, ar = read_varint(full_data, pos)
        pos += ar

        total_sats += amount
        entries.append(UtxoEntry(txid=txid, vout=vout, amount=amount))

    return (entries, total_sats)


# ── Index result scanning ─────────────────────────────────────────────────────


def find_entry_in_index_result(
    data: bytes,
    expected_tag: int,
    num_slots: int = 3,
    slot_size: int = INDEX_ENTRY_SIZE,
) -> Optional[tuple[int, int]]:
    """Search cuckoo bin slots for matching tag.
    Returns (start_chunk_id, num_chunks) or None.
    """
    for slot in range(num_slots):
        offset = slot * slot_size
        if offset + slot_size > len(data):
            break
        slot_tag = struct.unpack_from('<Q', data, offset)[0]
        if slot_tag == expected_tag:
            start_chunk_id = struct.unpack_from('<I', data, offset + TAG_SIZE)[0]
            num_chunks = data[offset + TAG_SIZE + 4]
            return (start_chunk_id, num_chunks)
    return None


# ── Chunk result scanning ─────────────────────────────────────────────────────


def find_chunk_in_result(
    data: bytes,
    target_chunk_id: int,
    num_slots: int = 3,
    slot_size: int = CHUNK_SLOT_SIZE,
) -> Optional[bytes]:
    """Search chunk bin slots for matching chunk_id.
    Returns the chunk data bytes or None.
    """
    target = struct.pack('<I', target_chunk_id)
    for slot in range(num_slots):
        offset = slot * slot_size
        if offset + slot_size > len(data):
            break
        if data[offset:offset + 4] == target:
            return data[offset + 4:offset + 4 + CHUNK_SIZE]
    return None


# ── PRNG for dummy queries ────────────────────────────────────────────────────


class DummyRng:
    """Splitmix64-based PRNG for generating deterministic dummy query data."""

    def __init__(self):
        self.state = splitmix64(int(time.time() * 1000) & MASK64)

    def next_u64(self) -> int:
        self.state = (self.state + 0x9e3779b97f4a7c15) & MASK64
        return splitmix64(self.state)
