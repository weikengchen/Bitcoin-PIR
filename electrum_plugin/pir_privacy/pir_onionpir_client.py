"""
OnionPIRv2 1-server client for Electrum — using native C++ FFI via ctypes.

Single-server FHE-based PIR using the OnionPIRv2 scheme.
Provides computational privacy (lattice-based) — no trust assumptions
between servers, but slower than DPF.

Build the shared library:
  cd /path/to/OnionPIRv2
  mkdir build && cd build
  cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
  make -j$(nproc)
"""

from __future__ import annotations

import asyncio
import struct
import logging
import time
import random
from typing import Optional, Callable

from .pir_constants import (
    K, K_CHUNK, NUM_HASHES,
    CHUNK_SIZE, TAG_SIZE,
    MASK64,
)
from .pir_hash import (
    derive_buckets, derive_cuckoo_key, cuckoo_hash, compute_tag,
    derive_chunk_buckets, splitmix64,
)
from .pir_ws_client import PirConnection
from .pir_client import QueryResult, UtxoEntry, BatchPirClient

logger = logging.getLogger(__name__)

# Try to import the native FFI module
try:
    import sys
    import os
    _onion_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'onionpir-python')
    if _onion_dir not in sys.path:
        sys.path.insert(0, _onion_dir)
    from onionpir_ffi import OnionPirClientFFI, get_params_info
    HAS_NATIVE = True
except (ImportError, FileNotFoundError) as e:
    HAS_NATIVE = False
    logger.warning(f'OnionPIR native library not found: {e}')

# OnionPIR wire protocol constants
REQ_GET_INFO = 0x01
RESP_INFO = 0x01
REQ_REGISTER_KEYS = 0x30
REQ_ONIONPIR_INDEX_QUERY = 0x31
REQ_ONIONPIR_CHUNK_QUERY = 0x32
RESP_KEYS_ACK = 0x30
RESP_ONIONPIR_INDEX_RESULT = 0x31
RESP_ONIONPIR_CHUNK_RESULT = 0x32

# Chunk cuckoo parameters (matching Rust onionpir_client.rs)
CHUNK_CUCKOO_NUM_HASHES = 6
CHUNK_CUCKOO_MAX_KICKS = 10000
CHUNK_CUCKOO_SEED = 0xa3f7c2d918e4b065
PACKED_ENTRY_SIZE = 3840
INDEX_CUCKOO_NUM_HASHES = 2
EMPTY_U32 = 0xFFFFFFFF


def _chunk_derive_cuckoo_key(group_id: int, hash_fn: int) -> int:
    return splitmix64(
        (CHUNK_CUCKOO_SEED
         + ((group_id * 0x9e3779b97f4a7c15) & MASK64)
         + ((hash_fn * 0x517cc1b727220a95) & MASK64)
        ) & MASK64
    )


def _chunk_cuckoo_hash(entry_id: int, key: int, num_bins: int) -> int:
    return splitmix64((entry_id ^ key) & MASK64) % num_bins


def _build_chunk_reverse_index(total_entries: int) -> list[list[int]]:
    """Build reverse index: group → sorted entry_ids."""
    index = [[] for _ in range(K_CHUNK)]
    for eid in range(total_entries):
        buckets = derive_chunk_buckets(eid)
        for g in buckets:
            index[g].append(eid)
    return index


def _build_chunk_cuckoo_for_group(
    group_id: int,
    reverse_index: list[list[int]],
    bins_per_table: int,
) -> list[int]:
    """Build the chunk cuckoo table for a specific group (deterministic)."""
    entries = reverse_index[group_id]
    keys = [_chunk_derive_cuckoo_key(group_id, h) for h in range(CHUNK_CUCKOO_NUM_HASHES)]
    table = [EMPTY_U32] * bins_per_table

    for entry_id in entries:
        placed = False
        for h in range(CHUNK_CUCKOO_NUM_HASHES):
            b = _chunk_cuckoo_hash(entry_id, keys[h], bins_per_table)
            if table[b] == EMPTY_U32:
                table[b] = entry_id
                placed = True
                break

        if placed:
            continue

        current_id = entry_id
        current_hash_fn = 0
        current_bin = _chunk_cuckoo_hash(entry_id, keys[0], bins_per_table)
        success = False

        for kick in range(CHUNK_CUCKOO_MAX_KICKS):
            evicted = table[current_bin]
            table[current_bin] = current_id

            for h_off in range(CHUNK_CUCKOO_NUM_HASHES):
                try_h = (current_hash_fn + 1 + h_off) % CHUNK_CUCKOO_NUM_HASHES
                b = _chunk_cuckoo_hash(evicted, keys[try_h], bins_per_table)
                if b == current_bin:
                    continue
                if table[b] == EMPTY_U32:
                    table[b] = evicted
                    success = True
                    break

            if success:
                break

            alt_h = (current_hash_fn + 1 + kick % (CHUNK_CUCKOO_NUM_HASHES - 1)) % CHUNK_CUCKOO_NUM_HASHES
            alt_bin = _chunk_cuckoo_hash(evicted, keys[alt_h], bins_per_table)
            if alt_bin == current_bin:
                h2 = (alt_h + 1) % CHUNK_CUCKOO_NUM_HASHES
                alt_bin = _chunk_cuckoo_hash(evicted, keys[h2], bins_per_table)

            current_id = evicted
            current_hash_fn = alt_h
            current_bin = alt_bin

        if not success:
            raise RuntimeError(f'Client cuckoo failed for entry_id={entry_id}')

    return table


def _find_entry_in_cuckoo(
    table: list[int], entry_id: int,
    keys: list[int], bins_per_table: int,
) -> Optional[int]:
    """Find which bin holds entry_id in a cuckoo table."""
    for h in range(CHUNK_CUCKOO_NUM_HASHES):
        b = _chunk_cuckoo_hash(entry_id, keys[h], bins_per_table)
        if table[b] == entry_id:
            return b
    return None


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a varint from data at pos. Returns (value, new_pos)."""
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if byte & 0x80 == 0:
            return value, pos
        shift += 7
    raise ValueError('Unexpected end of varint')


class OnionPirClient:
    """
    OnionPIRv2 single-server FHE PIR client.

    Key differences from DPF:
      - Single server (no non-collusion assumption)
      - FHE-based (computationally secure)
      - Slower queries
      - One-time key registration step
      - Uses entry_id/byte_offset instead of chunk_id
    """

    def __init__(self, server_url: str):
        if not HAS_NATIVE:
            raise ImportError(
                'OnionPIR requires the native C++ library. '
                'Build with: cd OnionPIRv2 && mkdir build && cd build && '
                'cmake .. -DBUILD_SHARED_LIBS=ON && make -j'
            )

        self.server_url = server_url
        self._conn: Optional[PirConnection] = None

        # Server parameters (from GetInfo)
        self.index_bins = 0
        self.chunk_bins = 0
        self.index_k = 0
        self.chunk_k = 0
        self.tag_seed = 0
        self.total_packed_entries = 0
        self.index_cuckoo_bucket_size = 0
        self.index_slot_size = 0

        # FHE clients (shared secret key)
        self._index_client: Optional[OnionPirClientFFI] = None
        self._chunk_client: Optional[OnionPirClientFFI] = None
        self._client_id = 0
        self._secret_key: Optional[bytes] = None
        self._keys_registered = False

        # Chunk cuckoo cache
        self._reverse_index: Optional[list[list[int]]] = None
        self._cuckoo_cache: dict[int, list[int]] = {}

    @property
    def is_connected(self) -> bool:
        return self._conn is not None and self._conn.is_connected

    async def connect(self) -> None:
        """Connect to the OnionPIR server and get server info."""
        self._conn = PirConnection(self.server_url)
        await self._conn.connect()
        await self._fetch_server_info()
        logger.info(f'OnionPIR info: index_bins={self.index_bins}, chunk_bins={self.chunk_bins}')

    async def disconnect(self) -> None:
        if self._conn:
            await self._conn.close()
        if self._index_client:
            self._index_client.close()
        if self._chunk_client:
            self._chunk_client.close()

    async def _fetch_server_info(self) -> None:
        """Fetch server info using OnionPIR's v2 format."""
        # Send REQ_GET_INFO
        req = struct.pack('<IB', 1, REQ_GET_INFO)
        raw = await self._conn.send_request(req)
        payload = raw[4:]  # skip length prefix

        if payload[0] != RESP_INFO:
            raise ValueError(f'Unexpected response type: 0x{payload[0]:02x}')

        # OnionPIR v2 format:
        # [1B variant][1B index_k][1B chunk_k][4B index_bins][4B chunk_bins]
        # [8B tag_seed][4B total_packed][2B bucket_size][1B slot_size]
        if len(payload) < 26:
            raise ValueError(f'GetInfo response too short: {len(payload)}')

        self.index_k = payload[1]
        self.chunk_k = payload[2]
        self.index_bins = struct.unpack_from('<I', payload, 3)[0]
        self.chunk_bins = struct.unpack_from('<I', payload, 7)[0]
        self.tag_seed = struct.unpack_from('<Q', payload, 11)[0]
        self.total_packed_entries = struct.unpack_from('<I', payload, 19)[0]
        self.index_cuckoo_bucket_size = struct.unpack_from('<H', payload, 23)[0]
        self.index_slot_size = payload[25]

    async def initialize(self) -> None:
        """Initialize FHE keys and register with the server (single registration)."""
        if not self.is_connected:
            raise ConnectionError('Not connected. Call connect() first.')

        logger.info('Initializing OnionPIR FHE keys...')
        t0 = time.time()

        # Create a keygen client (num_entries=0 for key generation)
        keygen_client = OnionPirClientFFI(num_entries=0)
        self._client_id = keygen_client.client_id
        galois = keygen_client.generate_galois_keys()
        gsw = keygen_client.generate_gsw_keys()
        self._secret_key = keygen_client.export_secret_key()
        keygen_client.close()

        # Create per-level clients sharing the same secret key
        self._index_client = OnionPirClientFFI(
            num_entries=self.index_bins,
            secret_key=self._secret_key,
            client_id=self._client_id,
        )
        self._chunk_client = OnionPirClientFFI(
            num_entries=self.chunk_bins,
            secret_key=self._secret_key,
            client_id=self._client_id,
        )

        # Register keys once — shared across all levels
        await self._register_keys(galois, gsw)
        self._keys_registered = True

        elapsed = time.time() - t0
        logger.info(f'OnionPIR initialized in {elapsed:.1f}s (single key registration)')

    async def _register_keys(self, galois_keys: bytes, gsw_keys: bytes) -> None:
        """Register FHE keys with the server (single registration)."""
        # Wire format: [4B len][1B=0x30][4B gk_len][gk][4B gsw_len][gsw]
        payload = bytearray()
        payload.append(REQ_REGISTER_KEYS)
        payload.extend(struct.pack('<I', len(galois_keys)))
        payload.extend(galois_keys)
        payload.extend(struct.pack('<I', len(gsw_keys)))
        payload.extend(gsw_keys)

        msg = struct.pack('<I', len(payload)) + bytes(payload)
        raw = await self._conn.send_request(msg)
        resp = raw[4:]
        if resp[0] != RESP_KEYS_ACK:
            raise ValueError(f'Key registration failed: 0x{resp[0]:02x}')

    async def query(self, script_hash: bytes) -> Optional[QueryResult]:
        results = await self.query_batch([script_hash])
        return results[0]

    async def query_batch(
        self,
        script_hashes: list[bytes],
        on_progress: Optional[Callable[[str, str], None]] = None,
    ) -> list[Optional[QueryResult]]:
        """Query multiple script hashes via OnionPIR."""
        if not self._keys_registered:
            raise RuntimeError('FHE keys not registered. Call initialize() first.')
        if not self.is_connected:
            raise ConnectionError('Not connected')

        N = len(script_hashes)
        progress = on_progress or (lambda s, d: None)
        index_k = self.index_k
        chunk_k = self.chunk_k

        # ── LEVEL 1: Index PIR ────────────────────────────────────────
        progress('Level 1', f'Planning {N} index queries...')
        tags = [compute_tag(self.tag_seed, sh) for sh in script_hashes]
        all_groups = [derive_buckets(sh) for sh in script_hashes]

        index_rounds = self._plan_pbc_rounds(all_groups, index_k)
        logger.info(f'Level 1: {N} queries -> {len(index_rounds)} round(s)')

        # IndexResult: {addr_idx: (entry_id, byte_offset, num_entries)}
        index_results: dict[int, tuple[int, int, int]] = {}
        total_index_rounds = 0
        rng_state = int(time.time() * 1e9) & MASK64

        for rnd in index_rounds:
            group_map = {group: addr_idx for addr_idx, group in rnd}

            # Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
            queries = []
            query_bins = []
            for g in range(index_k):
                for h in range(INDEX_CUCKOO_NUM_HASHES):
                    if g in group_map:
                        addr_idx = group_map[g]
                        key = derive_cuckoo_key(g, h)
                        bin_idx = cuckoo_hash(script_hashes[addr_idx], key, self.index_bins)
                    else:
                        rng_state = (rng_state + 0x9e3779b97f4a7c15) & MASK64
                        bin_idx = splitmix64(rng_state) % self.index_bins

                    queries.append(self._index_client.generate_query(bin_idx))
                    query_bins.append(bin_idx)

            # Send batch
            batch_msg = self._encode_batch_query(
                REQ_ONIONPIR_INDEX_QUERY, total_index_rounds, queries
            )
            raw = await self._conn.send_request(batch_msg)
            resp_payload = raw[4:]
            if resp_payload[0] != RESP_ONIONPIR_INDEX_RESULT:
                raise ValueError(f'Unexpected index response: 0x{resp_payload[0]:02x}')

            result_batch = self._decode_batch_result(resp_payload[1:])
            total_index_rounds += 1

            # Decrypt and scan for tags
            for addr_idx, group in rnd:
                if addr_idx in index_results:
                    continue
                for h in range(INDEX_CUCKOO_NUM_HASHES):
                    qi = group * INDEX_CUCKOO_NUM_HASHES + h
                    entry_bytes = self._index_client.decrypt_response(
                        query_bins[qi], result_batch[qi]
                    )
                    ir = self._scan_index_bin(entry_bytes, tags[addr_idx])
                    if ir is not None:
                        index_results[addr_idx] = ir
                        break

        found_count = len(index_results)
        whale_count = sum(1 for _, _, ne in index_results.values() if ne == 0)
        logger.info(f'Level 1: {found_count}/{N} found ({whale_count} whale)')

        # ── LEVEL 2: Chunk PIR ────────────────────────────────────────
        # Collect unique entry_ids
        unique_entry_ids = []
        entry_id_set = {}
        for addr_idx, (eid, byte_off, num_entries) in index_results.items():
            if num_entries == 0:
                continue  # whale
            for i in range(num_entries):
                e = eid + i
                if e not in entry_id_set:
                    entry_id_set[e] = len(unique_entry_ids)
                    unique_entry_ids.append(e)

        decrypted_entries: dict[int, bytes] = {}

        if unique_entry_ids:
            # Build reverse index for chunk cuckoo
            if self._reverse_index is None:
                logger.info(f'Building chunk reverse index ({self.total_packed_entries} entries)...')
                t0 = time.time()
                self._reverse_index = _build_chunk_reverse_index(self.total_packed_entries)
                logger.info(f'Reverse index built in {time.time()-t0:.1f}s')

            # PBC placement of entries into chunk groups
            entry_groups = [derive_chunk_buckets(eid) for eid in unique_entry_ids]
            chunk_rounds = self._plan_pbc_rounds(entry_groups, chunk_k)
            logger.info(f'Level 2: {len(unique_entry_ids)} entries -> {len(chunk_rounds)} round(s)')

            for ri, rnd in enumerate(chunk_rounds):
                group_to_entry = {}
                chunk_queries_info = []

                for ei, group in rnd:
                    eid = unique_entry_ids[ei]
                    # Build cuckoo table if not cached
                    if group not in self._cuckoo_cache:
                        self._cuckoo_cache[group] = _build_chunk_cuckoo_for_group(
                            group, self._reverse_index, self.chunk_bins
                        )

                    keys = [_chunk_derive_cuckoo_key(group, h) for h in range(CHUNK_CUCKOO_NUM_HASHES)]
                    bin_idx = _find_entry_in_cuckoo(
                        self._cuckoo_cache[group], eid, keys, self.chunk_bins
                    )
                    if bin_idx is None:
                        logger.error(f'entry_id {eid} not in cuckoo table for group {group}')
                        continue

                    group_to_entry[group] = (eid, bin_idx)
                    chunk_queries_info.append((eid, group, bin_idx))

                # Generate K_chunk queries
                queries = []
                for g in range(chunk_k):
                    if g in group_to_entry:
                        _, bin_idx = group_to_entry[g]
                    else:
                        rng_state = (rng_state + 0x9e3779b97f4a7c15) & MASK64
                        bin_idx = splitmix64(rng_state) % self.chunk_bins

                    queries.append(self._chunk_client.generate_query(bin_idx))

                batch_msg = self._encode_batch_query(
                    REQ_ONIONPIR_CHUNK_QUERY, ri, queries
                )
                raw = await self._conn.send_request(batch_msg)
                resp_payload = raw[4:]
                if resp_payload[0] != RESP_ONIONPIR_CHUNK_RESULT:
                    raise ValueError(f'Unexpected chunk response: 0x{resp_payload[0]:02x}')

                result_batch = self._decode_batch_result(resp_payload[1:])

                # Decrypt and store
                for eid, group, bin_idx in chunk_queries_info:
                    entry_bytes = self._chunk_client.decrypt_response(
                        bin_idx, result_batch[group]
                    )
                    decrypted_entries[eid] = entry_bytes[:PACKED_ENTRY_SIZE]

            logger.info(f'Level 2: {len(decrypted_entries)}/{len(unique_entry_ids)} entries recovered')

        # ── Reassemble ────────────────────────────────────────────────
        results: list[Optional[QueryResult]] = [None] * N
        for addr_idx in range(N):
            ir = index_results.get(addr_idx)
            if ir is None:
                continue

            entry_id, byte_offset, num_entries = ir
            if num_entries == 0:
                results[addr_idx] = QueryResult(is_whale=True)
                continue

            # Assemble data from entries
            full_data = bytearray()
            for i in range(num_entries):
                eid = entry_id + i
                entry = decrypted_entries.get(eid)
                if entry is None:
                    break
                if i == 0:
                    full_data.extend(entry[byte_offset:])
                else:
                    full_data.extend(entry)

            if not full_data:
                continue

            # Decode UTXOs using varint format
            entries, total_sats = self._decode_utxo_data(bytes(full_data))
            results[addr_idx] = QueryResult(
                entries=entries, total_sats=total_sats,
                start_chunk_id=entry_id, num_chunks=num_entries,
            )

        return results

    # ── Wire protocol helpers ─────────────────────────────────────────

    @staticmethod
    def _encode_batch_query(variant: int, round_id: int, queries: list[bytes]) -> bytes:
        """Encode OnionPIR batch query."""
        payload = bytearray()
        payload.append(variant)
        payload.extend(struct.pack('<H', round_id))
        payload.append(len(queries) & 0xFF)
        for q in queries:
            payload.extend(struct.pack('<I', len(q)))
            payload.extend(q)
        return struct.pack('<I', len(payload)) + bytes(payload)

    @staticmethod
    def _decode_batch_result(data: bytes) -> list[bytes]:
        """Decode OnionPIR batch result (after variant byte)."""
        if len(data) < 3:
            raise ValueError('Batch result too short')
        round_id = struct.unpack_from('<H', data, 0)[0]
        num_buckets = data[2]
        pos = 3
        results = []
        for _ in range(num_buckets):
            if pos + 4 > len(data):
                raise ValueError('Truncated batch result')
            rlen = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            results.append(data[pos:pos + rlen])
            pos += rlen
        return results

    def _scan_index_bin(self, entry_bytes: bytes, tag: int) -> Optional[tuple[int, int, int]]:
        """Scan decrypted index bin for matching tag.
        Returns (entry_id, byte_offset, num_entries) or None.
        """
        bucket_size = self.index_cuckoo_bucket_size
        slot_size = self.index_slot_size
        for slot in range(bucket_size):
            off = slot * slot_size
            if off + slot_size > len(entry_bytes):
                break
            slot_tag = struct.unpack_from('<Q', entry_bytes, off)[0]
            if slot_tag == tag and slot_tag != 0:
                entry_id = struct.unpack_from('<I', entry_bytes, off + 8)[0]
                byte_offset = struct.unpack_from('<H', entry_bytes, off + 12)[0]
                num_entries = entry_bytes[off + 14]
                return (entry_id, byte_offset, num_entries)
        return None

    @staticmethod
    def _decode_utxo_data(data: bytes) -> tuple[list[UtxoEntry], int]:
        """Decode varint-encoded UTXO data."""
        entries = []
        total_sats = 0
        pos = 0

        num_utxos, pos = _read_varint(data, pos)
        for _ in range(num_utxos):
            if pos + 32 > len(data):
                break
            txid = data[pos:pos + 32]
            pos += 32
            vout, pos = _read_varint(data, pos)
            amount, pos = _read_varint(data, pos)
            total_sats += amount
            entries.append(UtxoEntry(txid=txid, vout=vout, amount=amount))

        return entries, total_sats

    @staticmethod
    def _plan_pbc_rounds(
        candidate_groups: list,
        k: int,
    ) -> list[list[tuple[int, int]]]:
        """PBC cuckoo placement of items into groups."""
        remaining = list(range(len(candidate_groups)))
        rounds = []

        while remaining:
            round_cands = [candidate_groups[orig] for orig in remaining]
            buckets = [None] * k
            placed_indices = []

            for ri in range(len(round_cands)):
                if len(placed_indices) >= k:
                    break
                saved = buckets[:]
                if _pbc_cuckoo_place(round_cands, buckets, ri, 500):
                    placed_indices.append(ri)
                else:
                    buckets[:] = saved

            rnd = []
            for g in range(k):
                if buckets[g] is not None:
                    rnd.append((remaining[buckets[g]], g))

            if not rnd:
                logger.error(f'PBC placement failed for {len(remaining)} items')
                break

            placed_originals = {remaining[ri] for ri in placed_indices}
            remaining = [idx for idx in remaining if idx not in placed_originals]
            rounds.append(rnd)

        return rounds


def _pbc_cuckoo_place(
    cands: list, buckets: list, qi: int, max_kicks: int,
) -> bool:
    """Try to place item qi into buckets using cuckoo hashing."""
    for c in cands[qi]:
        if buckets[c] is None:
            buckets[c] = qi
            return True

    current_qi = qi
    current_bucket = cands[qi][0]

    for kick in range(max_kicks):
        evicted_qi = buckets[current_bucket]
        buckets[current_bucket] = current_qi

        for offset in range(NUM_HASHES):
            c = cands[evicted_qi][(kick + offset) % NUM_HASHES]
            if c == current_bucket:
                continue
            if buckets[c] is None:
                buckets[c] = evicted_qi
                return True

        next_bucket = cands[evicted_qi][0]
        for offset in range(NUM_HASHES):
            c = cands[evicted_qi][(kick + offset) % NUM_HASHES]
            if c != current_bucket:
                next_bucket = c
                break

        current_qi = evicted_qi
        current_bucket = next_bucket

    return False
