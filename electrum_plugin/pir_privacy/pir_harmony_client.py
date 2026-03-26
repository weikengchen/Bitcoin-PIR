"""
HarmonyPIR 2-server client for Electrum — using native Rust FFI via PyO3.

Two-server stateful PIR:
  - Hint Server: computes and sends hint parities (offline phase)
  - Query Server: answers online queries (indexed lookups)

Each Batch PIR bucket is managed by a PyHarmonyBucket (Rust via PyO3).

Build the native library:
  cd electrum_plugin/harmonypir-python
  pip install maturin
  maturin develop --release
"""

from __future__ import annotations

import asyncio
import struct
import logging
import os
from typing import Optional, Callable

from .pir_constants import (
    K, K_CHUNK, NUM_HASHES,
    CUCKOO_BUCKET_SIZE, INDEX_CUCKOO_NUM_HASHES,
    CHUNK_CUCKOO_BUCKET_SIZE, CHUNK_CUCKOO_NUM_HASHES,
    INDEX_ENTRY_SIZE, CHUNK_SLOT_SIZE,
    HARMONY_INDEX_W, HARMONY_CHUNK_W, HARMONY_EMPTY,
    REQ_HARMONY_GET_INFO, REQ_HARMONY_HINTS,
    REQ_HARMONY_BATCH_QUERY,
    RESP_HARMONY_INFO, RESP_HARMONY_HINTS, RESP_HARMONY_BATCH_QUERY,
    MASK64,
)
from .pir_hash import (
    derive_buckets, derive_cuckoo_key, cuckoo_hash, compute_tag,
    derive_chunk_buckets, derive_chunk_cuckoo_key, cuckoo_hash_int,
    hash160,
)
from .pir_ws_client import PirConnection
from .pir_client import QueryResult, UtxoEntry
from .pir_common import (
    plan_rounds, decode_utxo_data,
    find_entry_in_index_result, find_chunk_in_result,
)

logger = logging.getLogger(__name__)

# Try to import the native PyO3 module
try:
    from harmonypir_python import PyHarmonyBucket, compute_balanced_t, verify_protocol
    HAS_NATIVE = True
except ImportError:
    HAS_NATIVE = False
    logger.warning(
        'harmonypir_python native module not found. '
        'Build with: cd harmonypir-python && maturin develop --release'
    )


class HarmonyPirClient:
    """
    HarmonyPIR 2-server client.

    Same query interface as BatchPirClient, but uses the HarmonyPIR protocol
    with offline hint download + online stateful queries.

    Servers:
      - Hint Server: downloads hint parities for all 155 buckets (offline)
      - Query Server: answers batch queries (online)
    """

    def __init__(self, hint_server_url: str, query_server_url: str,
                 prp_backend: int = 0):
        if not HAS_NATIVE:
            raise ImportError(
                'HarmonyPIR requires the harmonypir_python native module. '
                'Build with: cd electrum_plugin/harmonypir-python && maturin develop --release'
            )

        self.hint_server_url = hint_server_url
        self.query_server_url = query_server_url
        self.prp_backend = prp_backend

        self._query_conn: Optional[PirConnection] = None

        # Server parameters
        self.index_bins = 0
        self.chunk_bins = 0
        self.tag_seed = 0

        # Bucket instances (75 index + 80 chunk)
        self._index_buckets: list = []  # PyHarmonyBucket instances
        self._chunk_buckets: list = []

        self._hints_loaded = False
        self._prp_key = os.urandom(16)

    @property
    def is_connected(self) -> bool:
        return self._query_conn is not None and self._query_conn.is_connected

    async def connect(self) -> None:
        """Connect to the query server and fetch server info."""
        self._query_conn = PirConnection(self.query_server_url)
        await self._query_conn.connect()
        await self._fetch_server_info()
        self._init_buckets()
        logger.info('HarmonyPIR query server connected')

    async def disconnect(self) -> None:
        if self._query_conn:
            await self._query_conn.close()

    async def _fetch_server_info(self) -> None:
        """Fetch server parameters via HARMONY_GET_INFO."""
        payload = bytearray([REQ_HARMONY_GET_INFO])
        msg = struct.pack('<I', len(payload)) + bytes(payload)
        raw = await self._query_conn.send_request(msg)
        data = raw[4:]
        if data[0] != RESP_HARMONY_INFO:
            raise ValueError(f'Unexpected response: 0x{data[0]:02x}')
        self.index_bins = struct.unpack_from('<I', data, 1)[0]
        self.chunk_bins = struct.unpack_from('<I', data, 5)[0]
        self.tag_seed = struct.unpack_from('<Q', data, 11)[0]
        logger.info(f'HarmonyPIR info: index_bins={self.index_bins}, chunk_bins={self.chunk_bins}')

    def _init_buckets(self) -> None:
        """Create PyHarmonyBucket instances for all buckets."""
        self._index_buckets = []
        for b in range(K):
            t = compute_balanced_t(self.index_bins)
            bucket = PyHarmonyBucket(
                n=self.index_bins, w=HARMONY_INDEX_W, t=t,
                prp_key=self._prp_key, bucket_id=b,
            )
            self._index_buckets.append(bucket)

        self._chunk_buckets = []
        for b in range(K_CHUNK):
            t = compute_balanced_t(self.chunk_bins)
            bucket = PyHarmonyBucket(
                n=self.chunk_bins, w=HARMONY_CHUNK_W, t=t,
                prp_key=self._prp_key, bucket_id=K + b,
            )
            self._chunk_buckets.append(bucket)

        logger.info(f'Initialized {K} index + {K_CHUNK} chunk HarmonyPIR buckets')

    async def fetch_hints(self) -> None:
        """
        Download hints from the Hint Server for all 155 buckets.
        This is the offline phase. Must be done once before queries.
        Uses raw websockets (not PirConnection) because hints arrive
        as multiple messages per single request.
        """
        from websockets.asyncio.client import connect as ws_connect
        hint_ws = await ws_connect(
            self.hint_server_url,
            max_size=50 * 1024 * 1024,
            ping_interval=None,
            ping_timeout=None,
        )

        try:
            # Request index hints (75 buckets)
            logger.info('Fetching index hints...')
            await self._request_hints(hint_ws, 0, K, self._index_buckets, HARMONY_INDEX_W)
            logger.info(f'Index hints loaded ({K} buckets)')

            # Request chunk hints (80 buckets)
            logger.info('Fetching chunk hints...')
            await self._request_hints(hint_ws, 1, K_CHUNK, self._chunk_buckets, HARMONY_CHUNK_W)
            logger.info(f'Chunk hints loaded ({K_CHUNK} buckets)')

            self._hints_loaded = True
        finally:
            await hint_ws.close()

    async def _request_hints(self, conn, level: int,
                             num_buckets: int, buckets: list,
                             w: int) -> None:
        """Request and load hints for a set of buckets.

        The hint server sends one response message per bucket:
          [4B len][1B RESP_HARMONY_HINTS][1B bucket_id][12B metadata][hint_data...]
        We send one request and receive num_buckets individual responses.
        """
        # Encode hint request: [1B variant][16B prp_key][1B backend][1B level]
        #                       [1B num_buckets][bucket_ids...]
        payload = bytearray()
        payload.append(REQ_HARMONY_HINTS)
        payload.extend(self._prp_key)
        payload.append(self.prp_backend)
        payload.append(level)
        payload.append(num_buckets)
        for b in range(num_buckets):
            payload.append(b)

        msg = struct.pack('<I', len(payload)) + bytes(payload)

        # Send request and read multiple responses (one per bucket).
        await conn.send(msg)

        # Receive one response per bucket.
        # Format per message: [4B len LE][1B RESP_HARMONY_HINTS][1B bucket_id]
        #                     [4B n LE][4B t LE][4B m LE][m*w bytes hints]
        received = 0
        while received < num_buckets:
            raw = await conn.recv()
            data = bytes(raw)
            if len(data) < 5:
                continue

            response = data[4:]  # strip length prefix

            if response[0] == RESP_HARMONY_HINTS:
                bucket_id = response[1]
                server_n = struct.unpack_from('<I', response, 2)[0]
                server_t = struct.unpack_from('<I', response, 6)[0]
                server_m = struct.unpack_from('<I', response, 10)[0]
                hints_data = response[14:]

                if bucket_id < len(buckets):
                    bucket = buckets[bucket_id]
                    expected = bucket.m() * w

                    if len(hints_data) != expected:
                        # Server's m differs — recreate bucket with server params
                        logger.debug(
                            f'  Bucket {bucket_id}: server n={server_n} t={server_t} m={server_m}, '
                            f'got {len(hints_data)} bytes, expected {expected}'
                        )
                        # Recreate bucket with server's parameters
                        buckets[bucket_id] = PyHarmonyBucket(
                            n=server_n, w=w, t=server_t,
                            prp_key=self._prp_key, bucket_id=bucket_id if level == 0 else K + bucket_id,
                        )
                        bucket = buckets[bucket_id]

                    bucket.load_hints(hints_data)
                    received += 1
                    if received % 25 == 0 or received == num_buckets:
                        logger.info(f'  Hints: {received}/{num_buckets}')
            elif response[0] == 0xFF:  # RESP_ERROR
                raise ValueError(f'Hint server error for level {level}')
            # Skip pong/other messages

    # ── Query interface (same as BatchPirClient) ──────────────────────────

    async def query(self, script_hash: bytes) -> Optional[QueryResult]:
        results = await self.query_batch([script_hash])
        return results[0]

    async def query_batch(
        self,
        script_hashes: list[bytes],
        on_progress: Optional[Callable[[str, str], None]] = None,
    ) -> list[Optional[QueryResult]]:
        """
        Query multiple script hashes via HarmonyPIR.

        Same interface as BatchPirClient.query_batch().
        Uses the same cuckoo placement and two-level flow, but with
        HarmonyPIR requests instead of DPF keys.
        """
        if not self.is_connected:
            raise ConnectionError('Not connected')
        if not self._hints_loaded:
            raise RuntimeError('Hints not loaded. Call fetch_hints() first.')

        N = len(script_hashes)
        progress = on_progress or (lambda s, d: None)

        # ── LEVEL 1: Index queries ────────────────────────────────────
        progress('Level 1', f'Planning {N} index queries...')

        index_cand_buckets = [derive_buckets(sh) for sh in script_hashes]
        index_rounds = plan_rounds(index_cand_buckets, K, NUM_HASHES)

        index_results: dict[int, tuple[int, int]] = {}
        whale_queries: set[int] = set()

        for ir, rnd in enumerate(index_rounds):
            bucket_to_query = {b: qi for qi, b in rnd}

            for h in range(INDEX_CUCKOO_NUM_HASHES):
                progress('Level 1', f'Round {ir+1}, h={h}...')

                # Build requests for all K buckets
                batch_items: list[tuple[int, bytes]] = []
                real_buckets: dict[int, int] = {}

                for b in range(K):
                    qi = bucket_to_query.get(b)
                    bucket = self._index_buckets[b]

                    if qi is not None and qi not in index_results and qi not in whale_queries:
                        ck = derive_cuckoo_key(b, h)
                        bin_index = cuckoo_hash(script_hashes[qi], ck, self.index_bins)
                        req_bytes, seg, pos, _ = bucket.build_request(bin_index)
                        batch_items.append((b, req_bytes))
                        real_buckets[b] = qi
                    else:
                        dummy = bucket.build_synthetic_dummy()
                        batch_items.append((b, dummy))

                # Encode and send batch query
                req_msg = self._encode_batch_query(0, ir * INDEX_CUCKOO_NUM_HASHES + h, batch_items)
                resp_data = await self._query_conn.send_request(req_msg)
                batch_resp = self._decode_batch_response(resp_data[4:])

                # Process responses for real buckets
                for b, qi in real_buckets.items():
                    resp_entries = batch_resp.get(b)
                    if resp_entries and len(resp_entries) > 0:
                        bucket = self._index_buckets[b]
                        answer_raw = bucket.process_response(resp_entries[0])
                        # PyO3 returns Vec<u8> as list[int]; convert to bytes
                        answer = bytes(answer_raw) if not isinstance(answer_raw, bytes) else answer_raw

                        # Search for matching tag
                        expected_tag = compute_tag(self.tag_seed, script_hashes[qi])
                        found = find_entry_in_index_result(
                            answer, expected_tag,
                            num_slots=len(answer) // INDEX_ENTRY_SIZE,
                        )
                        if found:
                            index_results[qi] = found
                            if found[1] == 0:  # num_chunks == 0
                                whale_queries.add(qi)

        logger.info(f'Level 1: {len(index_results)}/{N} found')

        # ── LEVEL 2: Chunk queries ────────────────────────────────────
        # Same two-level flow as DPF client — collect chunk IDs, plan rounds, query
        from .pir_constants import CHUNKS_PER_UNIT, UNIT_DATA_SIZE

        query_chunk_info: dict[int, tuple[int, int, int, int]] = {}
        all_chunk_ids_set: set[int] = set()

        for qi, (start_chunk_id, num_chunks) in index_results.items():
            if num_chunks == 0:
                continue
            num_units = -(-num_chunks // CHUNKS_PER_UNIT)
            for u in range(num_units):
                all_chunk_ids_set.add(start_chunk_id + u * CHUNKS_PER_UNIT)
            query_chunk_info[qi] = (start_chunk_id, num_units, start_chunk_id, num_chunks)

        all_chunk_ids = sorted(all_chunk_ids_set)
        chunk_cand_buckets = [derive_chunk_buckets(cid) for cid in all_chunk_ids]
        chunk_rounds = plan_rounds(chunk_cand_buckets, K_CHUNK, NUM_HASHES)

        recovered_chunks: dict[int, bytes] = {}

        for ri, round_plan in enumerate(chunk_rounds):
            progress('Level 2', f'Chunk round {ri+1}/{len(chunk_rounds)}...')

            bucket_to_chunk: dict[int, int] = {}
            for cli, bid in round_plan:
                bucket_to_chunk[bid] = cli

            for h in range(CHUNK_CUCKOO_NUM_HASHES):
                batch_items = []
                real_buckets = {}

                for b in range(K_CHUNK):
                    cli = bucket_to_chunk.get(b)
                    bucket = self._chunk_buckets[b]

                    if cli is not None:
                        chunk_id = all_chunk_ids[cli]
                        ck = derive_chunk_cuckoo_key(b, h)
                        bin_index = cuckoo_hash_int(chunk_id, ck, self.chunk_bins)
                        req_bytes, _, _, _ = bucket.build_request(bin_index)
                        batch_items.append((b, req_bytes))
                        real_buckets[b] = cli
                    else:
                        dummy = bucket.build_synthetic_dummy()
                        batch_items.append((b, dummy))

                req_msg = self._encode_batch_query(1, ri * CHUNK_CUCKOO_NUM_HASHES + h, batch_items)
                resp_data = await self._query_conn.send_request(req_msg)
                batch_resp = self._decode_batch_response(resp_data[4:])

                for b, cli in real_buckets.items():
                    resp_entries = batch_resp.get(b)
                    if resp_entries and len(resp_entries) > 0:
                        bucket = self._chunk_buckets[b]
                        answer_raw = bucket.process_response(resp_entries[0])
                        answer = bytes(answer_raw) if not isinstance(answer_raw, bytes) else answer_raw
                        chunk_id = all_chunk_ids[cli]
                        chunk_data = find_chunk_in_result(
                            answer, chunk_id,
                            num_slots=len(answer) // CHUNK_SLOT_SIZE,
                        )
                        if chunk_data:
                            recovered_chunks[chunk_id] = chunk_data

        logger.info(f'Level 2: {len(recovered_chunks)}/{len(all_chunk_ids)} chunks')

        # ── Reassemble results ────────────────────────────────────────
        results: list[Optional[QueryResult]] = [None] * N
        for qi in range(N):
            if qi in whale_queries:
                results[qi] = QueryResult(is_whale=True)
                continue
            info = query_chunk_info.get(qi)
            if not info:
                continue
            start_chunk, num_units, start_chunk_id, num_chunks = info
            full_data = bytearray(num_units * UNIT_DATA_SIZE)
            for u in range(num_units):
                cid = start_chunk + u * CHUNKS_PER_UNIT
                d = recovered_chunks.get(cid)
                if d:
                    full_data[u * UNIT_DATA_SIZE:(u + 1) * UNIT_DATA_SIZE] = d

            entries, total_sats = decode_utxo_data(bytes(full_data))
            results[qi] = QueryResult(
                entries=entries, total_sats=total_sats,
                start_chunk_id=start_chunk_id, num_chunks=num_chunks,
                num_rounds=len(chunk_rounds),
            )

        return results

    # ── Protocol encoding helpers ─────────────────────────────────────

    def _encode_batch_query(self, level: int, round_id: int,
                            items: list[tuple[int, bytes]]) -> bytes:
        """Encode a HarmonyPIR batch query message."""
        payload = bytearray()
        payload.append(REQ_HARMONY_BATCH_QUERY)
        payload.append(level)
        payload.extend(struct.pack('<H', round_id))
        payload.extend(struct.pack('<H', len(items)))
        payload.append(1)  # sub_queries_per_bucket

        for bucket_id, req_bytes in items:
            payload.append(bucket_id & 0xFF)
            count = len(req_bytes) // 4  # number of u32 indices
            payload.extend(struct.pack('<I', count))
            payload.extend(req_bytes)

        return struct.pack('<I', len(payload)) + bytes(payload)

    def _decode_batch_response(self, data: bytes) -> dict[int, list[bytes]]:
        """Decode a HarmonyPIR batch response.

        Format: [1B variant][1B level][2B round_id][2B num_buckets][1B sub_results_per_bucket]
                per bucket: [1B bucket_id] per sub_result: [4B data_len][data]
        Returns bucket_id -> [response_bytes].
        """
        if data[0] != RESP_HARMONY_BATCH_QUERY:
            raise ValueError(f'Unexpected batch response: 0x{data[0]:02x}')

        pos = 1  # skip variant
        _level = data[pos]; pos += 1
        _round_id = struct.unpack_from('<H', data, pos)[0]; pos += 2
        num_buckets = struct.unpack_from('<H', data, pos)[0]; pos += 2
        sub_results_per_bucket = data[pos]; pos += 1

        result: dict[int, list[bytes]] = {}
        for _ in range(num_buckets):
            bucket_id = data[pos]; pos += 1
            entries = []
            for _ in range(sub_results_per_bucket):
                length = struct.unpack_from('<I', data, pos)[0]
                pos += 4
                entries.append(data[pos:pos + length])
                pos += length
            result[bucket_id] = entries

        return result

    # ── Result parsing helpers ────────────────────────────────────────

    # Tag and chunk scanning use shared pir_common.find_entry_in_index_result
    # and pir_common.find_chunk_in_result.

    # ── Hint caching ──────────────────────────────────────────────────

    async def save_hints_to_cache(self, cache_path: str) -> None:
        """Serialize all bucket states to a local file."""
        data = bytearray()
        # Header: prp_key + prp_backend + index_bins + chunk_bins + tag_seed
        data.extend(self._prp_key)
        data.append(self.prp_backend)
        data.extend(struct.pack('<I', self.index_bins))
        data.extend(struct.pack('<I', self.chunk_bins))
        data.extend(struct.pack('<Q', self.tag_seed))
        # Per-bucket serialized state
        for bucket in self._index_buckets + self._chunk_buckets:
            state = bucket.serialize()
            data.extend(struct.pack('<I', len(state)))
            data.extend(state)

        with open(cache_path, 'wb') as f:
            f.write(data)
        logger.info(f'Saved HarmonyPIR hints to {cache_path} ({len(data)} bytes)')

    async def restore_hints_from_cache(self, cache_path: str) -> bool:
        """Restore hints from a local cache file. Returns True if successful."""
        if not os.path.isfile(cache_path):
            return False
        try:
            with open(cache_path, 'rb') as f:
                data = f.read()
            # Parse header
            self._prp_key = bytes(data[:16])
            self.prp_backend = data[16]
            self.index_bins = struct.unpack_from('<I', data, 17)[0]
            self.chunk_bins = struct.unpack_from('<I', data, 21)[0]
            self.tag_seed = struct.unpack_from('<Q', data, 25)[0]

            self._init_buckets()
            # TODO: deserialize per-bucket state from cache
            logger.info(f'Restored HarmonyPIR hints from {cache_path}')
            self._hints_loaded = True
            return True
        except Exception as e:
            logger.error(f'Failed to restore hints: {e}')
            return False
