"""
Binary protocol encoder/decoder for the Batch PIR system.

Matches web/src/protocol.ts and runtime/src/protocol.rs exactly:
  Messages are length-prefixed: [4B total_len LE][1B variant][payload...]
  Batch queries/results: [2B round_id][1B count][1B keys_per_bucket][per-bucket: [2B len][key]...]
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

from .pir_constants import (
    REQ_PING, REQ_GET_INFO, REQ_INDEX_BATCH, REQ_CHUNK_BATCH,
    RESP_PONG, RESP_INFO, RESP_INDEX_BATCH, RESP_CHUNK_BATCH, RESP_ERROR,
)


# ── Types ──────────────────────────────────────────────────────────────────


@dataclass
class ServerInfo:
    index_bins_per_table: int = 0
    chunk_bins_per_table: int = 0
    index_k: int = 0
    chunk_k: int = 0
    tag_seed: int = 0


@dataclass
class BatchResult:
    round_id: int = 0
    results: list[list[bytes]] = field(default_factory=list)
    # results[bucket_idx][hash_fn_idx] = result bytes


# ── Encoding ───────────────────────────────────────────────────────────────


def encode_ping() -> bytes:
    """Encode a Ping request."""
    payload = bytes([REQ_PING])
    return struct.pack('<I', len(payload)) + payload


def encode_get_info() -> bytes:
    """Encode a GetInfo request."""
    payload = bytes([REQ_GET_INFO])
    return struct.pack('<I', len(payload)) + payload


def _encode_batch_query(variant: int, round_id: int,
                        keys_by_bucket: list[list[bytes]]) -> bytes:
    """Encode a batch query (IndexBatch or ChunkBatch)."""
    parts = bytearray()
    parts.append(variant)

    # round_id: u16 LE
    parts.extend(struct.pack('<H', round_id))
    # count: u8 (number of buckets)
    num_buckets = len(keys_by_bucket)
    parts.append(num_buckets & 0xFF)
    # keys_per_bucket: u8
    keys_per_bucket = len(keys_by_bucket[0]) if num_buckets > 0 else 0
    parts.append(keys_per_bucket & 0xFF)

    for bucket_keys in keys_by_bucket:
        for key in bucket_keys:
            parts.extend(struct.pack('<H', len(key)))
            parts.extend(key)

    return struct.pack('<I', len(parts)) + bytes(parts)


def encode_index_batch(round_id: int,
                       keys_by_bucket: list[list[bytes]]) -> bytes:
    """Encode an IndexBatch request."""
    return _encode_batch_query(REQ_INDEX_BATCH, round_id, keys_by_bucket)


def encode_chunk_batch(round_id: int,
                       keys_by_bucket: list[list[bytes]]) -> bytes:
    """Encode a ChunkBatch request."""
    return _encode_batch_query(REQ_CHUNK_BATCH, round_id, keys_by_bucket)


# ── Decoding ───────────────────────────────────────────────────────────────


def _decode_batch_result(data: bytes, pos: int) -> tuple[BatchResult, int]:
    """Decode a batch result from binary data starting at pos."""
    round_id = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    count = data[pos]
    pos += 1
    results_per_bucket = data[pos]
    pos += 1

    results: list[list[bytes]] = []
    for _ in range(count):
        bucket_results: list[bytes] = []
        for _ in range(results_per_bucket):
            length = struct.unpack_from('<H', data, pos)[0]
            pos += 2
            r = data[pos:pos + length]
            pos += length
            bucket_results.append(r)
        results.append(bucket_results)

    return BatchResult(round_id=round_id, results=results), pos


def decode_response(data: bytes) -> dict:
    """
    Decode a response from the payload bytes (after stripping the 4-byte length prefix).

    Returns a dict with 'type' key and additional fields depending on type:
      - {'type': 'Pong'}
      - {'type': 'Info', 'info': ServerInfo}
      - {'type': 'IndexBatch', 'result': BatchResult}
      - {'type': 'ChunkBatch', 'result': BatchResult}
      - {'type': 'Error', 'message': str}
    """
    if len(data) == 0:
        raise ValueError('Empty response')

    variant = data[0]

    if variant == RESP_PONG:
        return {'type': 'Pong'}

    elif variant == RESP_INFO:
        if len(data) < 19:
            raise ValueError(f'Info response too short: {len(data)} bytes')
        index_bins = struct.unpack_from('<I', data, 1)[0]
        chunk_bins = struct.unpack_from('<I', data, 5)[0]
        index_k = data[9]
        chunk_k = data[10]
        tag_seed = struct.unpack_from('<Q', data, 11)[0]
        return {
            'type': 'Info',
            'info': ServerInfo(
                index_bins_per_table=index_bins,
                chunk_bins_per_table=chunk_bins,
                index_k=index_k,
                chunk_k=chunk_k,
                tag_seed=tag_seed,
            ),
        }

    elif variant == RESP_INDEX_BATCH:
        result, _ = _decode_batch_result(data, 1)
        return {'type': 'IndexBatch', 'result': result}

    elif variant == RESP_CHUNK_BATCH:
        result, _ = _decode_batch_result(data, 1)
        return {'type': 'ChunkBatch', 'result': result}

    elif variant == RESP_ERROR:
        msg_len = struct.unpack_from('<I', data, 1)[0]
        message = data[5:5 + msg_len].decode('utf-8', errors='replace')
        return {'type': 'Error', 'message': message}

    else:
        raise ValueError(f'Unknown response variant: 0x{variant:02x}')


def is_pong(raw_message: bytes) -> bool:
    """Check if a raw WebSocket message is a Pong response (to be silently discarded)."""
    if len(raw_message) >= 5:
        length = struct.unpack_from('<I', raw_message, 0)[0]
        if length == 1 and raw_message[4] == RESP_PONG:
            return True
    return False
