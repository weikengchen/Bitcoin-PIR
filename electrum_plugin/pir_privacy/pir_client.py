"""
Two-level Batch PIR client (DPF 2-server).

Supports true batching: multiple script hashes are packed into a single
batch of K=75 index buckets (Level 1) and K_CHUNK=80 chunk buckets
(Level 2) using cuckoo placement, minimizing round-trips.

Port of web/src/client.ts to Python.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable

from .pir_constants import (
    K, K_CHUNK, NUM_HASHES,
    INDEX_CUCKOO_NUM_HASHES,
    CHUNK_CUCKOO_NUM_HASHES,
    CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
    DPF_N, CHUNK_DPF_N,
)
from .pir_hash import (
    compute_tag,
    derive_buckets, derive_cuckoo_key, cuckoo_hash,
    derive_chunk_buckets, derive_chunk_cuckoo_key, cuckoo_hash_int,
)
from .pir_dpf import dpf_gen as _dpf_gen_raw
from .pir_protocol import (
    encode_get_info, encode_index_batch, encode_chunk_batch,
    decode_response, ServerInfo,
)
from .pir_ws_client import PirConnection
from .pir_common import (
    cuckoo_place, plan_rounds, read_varint, decode_utxo_data,
    find_entry_in_index_result, find_chunk_in_result, DummyRng,
)

import asyncio


def _dpf_gen_bytes(index: int, log_domain: int) -> tuple[bytes, bytes]:
    """Generate DPF keys and return as bytes."""
    k0, k1 = _dpf_gen_raw(index, log_domain)
    return k0.to_bytes(), k1.to_bytes()

logger = logging.getLogger(__name__)


# ── Types ──────────────────────────────────────────────────────────────────


@dataclass
class UtxoEntry:
    txid: bytes     # 32-byte raw TXID (internal byte order)
    vout: int
    amount: int     # satoshis


@dataclass
class QueryResult:
    entries: list[UtxoEntry] = field(default_factory=list)
    total_sats: int = 0
    start_chunk_id: int = 0
    num_chunks: int = 0
    num_rounds: int = 0
    is_whale: bool = False


# ── Client ─────────────────────────────────────────────────────────────────


class BatchPirClient:
    """Two-level Batch PIR client using DPF keys with two non-colluding servers."""

    def __init__(self, server0_url: str, server1_url: str):
        self.server0_url = server0_url
        self.server1_url = server1_url
        self._conn0 = PirConnection(server0_url)
        self._conn1 = PirConnection(server1_url)
        self._rng = DummyRng()

        # Server info (fetched on connect)
        self.index_bins = 0
        self.chunk_bins = 0
        self.tag_seed = 0

    async def connect(self) -> None:
        """Connect to both PIR servers and fetch server info."""
        await self._conn0.connect()
        await self._conn1.connect()
        logger.info('Connected to both PIR servers')
        await self._fetch_server_info()

    async def disconnect(self) -> None:
        """Disconnect from both servers."""
        await self._conn0.close()
        await self._conn1.close()

    @property
    def is_connected(self) -> bool:
        return self._conn0.is_connected and self._conn1.is_connected

    async def _fetch_server_info(self) -> None:
        """Fetch server parameters (bins, tag_seed)."""
        msg = encode_get_info()
        raw = await self._conn0.send_request(msg)
        resp = decode_response(raw[4:])  # strip 4-byte length prefix
        if resp['type'] != 'Info':
            raise ValueError(f"Unexpected response: {resp['type']}")
        info: ServerInfo = resp['info']
        self.index_bins = info.index_bins_per_table
        self.chunk_bins = info.chunk_bins_per_table
        self.tag_seed = info.tag_seed
        logger.info(
            f'Server info: index_bins={self.index_bins}, '
            f'chunk_bins={self.chunk_bins}, '
            f'tag_seed=0x{self.tag_seed:016x}'
        )
        # Also send GetInfo to server 1 (keeps protocol in sync)
        raw1 = await self._conn1.send_request(msg)
        decode_response(raw1[4:])

    # ── XOR utility ────────────────────────────────────────────────────────

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR two byte strings."""
        la, lb = len(a), len(b)
        length = max(la, lb)
        result = bytearray(length)
        for i in range(length):
            result[i] = (a[i] if i < la else 0) ^ (b[i] if i < lb else 0)
        return bytes(result)

    # Index/chunk result parsing, cuckoo placement, varint, and UTXO decoding
    # are provided by pir_common module.

    # ── Single query ───────────────────────────────────────────────────────

    async def query(self, script_hash: bytes) -> Optional[QueryResult]:
        """Query a single script hash. Returns QueryResult or None if not found."""
        results = await self.query_batch([script_hash])
        return results[0]

    # ═══════════════════════════════════════════════════════════════════════
    # TRUE BATCH QUERY — multiple script hashes in one batch
    # ═══════════════════════════════════════════════════════════════════════

    async def query_batch(
        self,
        script_hashes: list[bytes],
        on_progress: Optional[Callable[[str, str], None]] = None,
    ) -> list[Optional[QueryResult]]:
        """
        Query multiple script hashes in true batched mode.

        Level 1: Packs queries into K=75 index buckets using cuckoo placement.
        Level 2: Collects ALL chunk IDs and fetches in batched chunk rounds.

        Returns a list parallel to the input, with QueryResult or None.
        """
        if not self.is_connected:
            raise ConnectionError('Not connected')
        if self.index_bins == 0:
            raise RuntimeError('Server info not loaded')

        N = len(script_hashes)
        progress = on_progress or (lambda s, d: None)

        logger.info(f'=== Batch query: {N} script hashes ===')

        # ══════════════════════════════════════════════════════════════════
        # LEVEL 1: Index PIR (batched)
        # ══════════════════════════════════════════════════════════════════
        progress('Level 1', f'Planning index batch for {N} queries...')

        # Compute candidate index buckets for each query
        index_cand_buckets = [derive_buckets(sh) for sh in script_hashes]

        # Plan index rounds using cuckoo placement
        index_rounds = plan_rounds(index_cand_buckets, K, NUM_HASHES)
        logger.info(f'Level 1: {N} queries -> {len(index_rounds)} index round(s)')

        # Per-query results from Level 1
        index_results: dict[int, tuple[int, int]] = {}  # qi -> (start_chunk_id, num_chunks)

        for ir, rnd in enumerate(index_rounds):
            progress('Level 1', f'Index round {ir + 1}/{len(index_rounds)} ({len(rnd)} queries)...')

            # Build bucket -> query mapping
            bucket_to_query: dict[int, int] = {}
            for query_idx, bucket_id in rnd:
                bucket_to_query[bucket_id] = query_idx

            # Generate DPF keys for all K buckets
            progress('Level 1', f'Round {ir + 1}: generating DPF keys...')
            s0_keys: list[list[bytes]] = []
            s1_keys: list[list[bytes]] = []

            for b in range(K):
                qi = bucket_to_query.get(b)
                s0_bucket: list[bytes] = []
                s1_bucket: list[bytes] = []

                for h in range(INDEX_CUCKOO_NUM_HASHES):
                    if qi is not None:
                        sh = script_hashes[qi]
                        ck = derive_cuckoo_key(b, h)
                        alpha = cuckoo_hash(sh, ck, self.index_bins)
                    else:
                        alpha = self._rng.next_u64() % self.index_bins

                    k0, k1 = _dpf_gen_bytes(alpha, DPF_N)
                    s0_bucket.append(k0)
                    s1_bucket.append(k1)

                s0_keys.append(s0_bucket)
                s1_keys.append(s1_bucket)

            # Send to both servers in parallel
            progress('Level 1', f'Round {ir + 1}: querying servers...')
            req0 = encode_index_batch(ir, s0_keys)
            req1 = encode_index_batch(ir, s1_keys)

            raw0, raw1 = await asyncio.gather(
                self._conn0.send_request(req0),
                self._conn1.send_request(req1),
            )

            resp0 = decode_response(raw0[4:])
            resp1 = decode_response(raw1[4:])

            if resp0['type'] != 'IndexBatch' or resp1['type'] != 'IndexBatch':
                raise ValueError(f"Unexpected index response: {resp0['type']}, {resp1['type']}")

            # XOR and extract results
            for query_idx, bucket_id in rnd:
                r0 = resp0['result'].results[bucket_id]
                r1 = resp1['result'].results[bucket_id]

                found = None
                expected_tag = compute_tag(self.tag_seed, script_hashes[query_idx])
                for h in range(INDEX_CUCKOO_NUM_HASHES):
                    result = self._xor_bytes(r0[h], r1[h])
                    found = find_entry_in_index_result(result, expected_tag)
                    if found:
                        break

                if found:
                    index_results[query_idx] = found
                else:
                    logger.debug(f'Query {query_idx}: not found in index')

        logger.info(f'Level 1 complete: {len(index_results)}/{N} found')

        # ══════════════════════════════════════════════════════════════════
        # LEVEL 2: Chunk PIR (batched across ALL queries)
        # ══════════════════════════════════════════════════════════════════
        progress('Level 2', 'Collecting chunk IDs...')

        query_chunk_info: dict[int, tuple[int, int, int, int]] = {}
        # qi -> (start_chunk, num_units, start_chunk_id, num_chunks)
        all_chunk_ids_set: set[int] = set()
        whale_queries: set[int] = set()

        for qi, (start_chunk_id, num_chunks) in index_results.items():
            if num_chunks == 0:
                whale_queries.add(qi)
                logger.info(f'Query {qi}: whale address (excluded)')
                continue

            start_chunk = start_chunk_id
            num_units = -(-num_chunks // CHUNKS_PER_UNIT)  # ceil division
            for u in range(num_units):
                cid = start_chunk + u * CHUNKS_PER_UNIT
                all_chunk_ids_set.add(cid)
            query_chunk_info[qi] = (start_chunk, num_units, start_chunk_id, num_chunks)

        all_chunk_ids = sorted(all_chunk_ids_set)
        logger.info(f'Level 2: {len(all_chunk_ids)} unique chunks to fetch')

        # Plan chunk rounds
        chunk_cand_buckets = [derive_chunk_buckets(cid) for cid in all_chunk_ids]
        chunk_rounds = plan_rounds(chunk_cand_buckets, K_CHUNK, NUM_HASHES)
        logger.info(f'  {len(all_chunk_ids)} chunks -> {len(chunk_rounds)} chunk round(s)')

        # Execute chunk rounds
        recovered_chunks: dict[int, bytes] = {}

        for ri, round_plan in enumerate(chunk_rounds):
            progress('Level 2', f'Chunk round {ri + 1}/{len(chunk_rounds)} ({len(round_plan)} chunks)...')

            # Compute target locations
            bucket_targets: dict[int, list[int]] = {}
            for chunk_list_idx, bucket_id in round_plan:
                chunk_id = all_chunk_ids[chunk_list_idx]
                locs: list[int] = []
                for h in range(CHUNK_CUCKOO_NUM_HASHES):
                    ck = derive_chunk_cuckoo_key(bucket_id, h)
                    locs.append(cuckoo_hash_int(chunk_id, ck, self.chunk_bins))
                bucket_targets[bucket_id] = locs

            # Generate DPF keys
            s0_keys: list[list[bytes]] = []
            s1_keys: list[list[bytes]] = []

            for b in range(K_CHUNK):
                target = bucket_targets.get(b)
                s0_bucket: list[bytes] = []
                s1_bucket: list[bytes] = []

                for h in range(CHUNK_CUCKOO_NUM_HASHES):
                    alpha = target[h] if target else (self._rng.next_u64() % self.chunk_bins)
                    k0, k1 = _dpf_gen_bytes(alpha, CHUNK_DPF_N)
                    s0_bucket.append(k0)
                    s1_bucket.append(k1)

                s0_keys.append(s0_bucket)
                s1_keys.append(s1_bucket)

            # Send
            creq0 = encode_chunk_batch(ri, s0_keys)
            creq1 = encode_chunk_batch(ri, s1_keys)

            craw0, craw1 = await asyncio.gather(
                self._conn0.send_request(creq0),
                self._conn1.send_request(creq1),
            )

            cresp0 = decode_response(craw0[4:])
            cresp1 = decode_response(craw1[4:])

            if cresp0['type'] != 'ChunkBatch' or cresp1['type'] != 'ChunkBatch':
                raise ValueError(f"Unexpected chunk response: {cresp0['type']}, {cresp1['type']}")

            # XOR and extract
            for chunk_list_idx, bucket_id in round_plan:
                chunk_id = all_chunk_ids[chunk_list_idx]
                cr0 = cresp0['result'].results[bucket_id]
                cr1 = cresp1['result'].results[bucket_id]

                data = None
                for h in range(len(cr0)):
                    result = self._xor_bytes(cr0[h], cr1[h])
                    data = find_chunk_in_result(result, chunk_id)
                    if data:
                        break

                if data:
                    recovered_chunks[chunk_id] = data
                else:
                    logger.warning(f'Chunk {chunk_id} not found in round {ri} bucket {bucket_id}')

        logger.info(f'Level 2 complete: recovered {len(recovered_chunks)}/{len(all_chunk_ids)} chunks')

        # ══════════════════════════════════════════════════════════════════
        # Reassemble per-query results
        # ══════════════════════════════════════════════════════════════════
        progress('Decode', 'Reassembling UTXO data...')

        total_chunk_rounds = len(chunk_rounds)
        results: list[Optional[QueryResult]] = [None] * N

        for qi in range(N):
            if qi in whale_queries:
                results[qi] = QueryResult(is_whale=True)
                continue

            info = query_chunk_info.get(qi)
            if info is None:
                continue  # Not found in index

            start_chunk, num_units, start_chunk_id, num_chunks = info
            full_data = bytearray(num_units * UNIT_DATA_SIZE)
            missing = 0

            for u in range(num_units):
                cid = start_chunk + u * CHUNKS_PER_UNIT
                d = recovered_chunks.get(cid)
                if d:
                    full_data[u * UNIT_DATA_SIZE:(u + 1) * UNIT_DATA_SIZE] = d
                else:
                    missing += 1

            if missing > 0:
                logger.error(f'Query {qi}: {missing} chunks missing')

            entries, total_sats = decode_utxo_data(bytes(full_data))
            results[qi] = QueryResult(
                entries=entries,
                total_sats=total_sats,
                start_chunk_id=start_chunk_id,
                num_chunks=num_chunks,
                num_rounds=total_chunk_rounds,
            )

        found_count = sum(1 for r in results if r is not None)
        logger.info(f'=== Batch complete: {found_count}/{N} queries returned results ===')

        return results
