/**
 * HarmonyPIR-specific types.
 *
 * Shared between the HarmonyPIR adapter and any module that consumes
 * HarmonyPIR results (e.g. sync-merge). Kept in its own module so the
 * underlying implementation (TS client in the past, Rust-backed WASM
 * via HarmonyPirClientAdapter today) can be swapped without rippling
 * import-path changes through the codebase.
 */

// ─── Result shapes (different from DPF/OnionPIR — txid is a hex string
//     and the value is a number rather than a bigint amount). ────────────

export interface HarmonyUtxoEntry {
  txid: string;
  vout: number;
  value: number;
}

export interface HarmonyQueryResult {
  address: string;
  scriptHash: string;
  utxos: HarmonyUtxoEntry[];
  whale: boolean;
  /** Merkle verification result (undefined if not verified yet) */
  merkleVerified?: boolean;
  /** Merkle root hash hex (from server, for display) */
  merkleRootHex?: string;
  /** Raw chunk data (kept for Merkle verification) */
  rawChunkData?: Uint8Array;
  /** Script hash as bytes (for Merkle leaf hash) */
  scriptHashBytes?: Uint8Array;
  // ── Per-bucket bin Merkle ─────────────────────────────────────────
  /** PBC group index for the INDEX query (when found) */
  indexPbcGroup?: number;
  /** Cuckoo bin index within the INDEX group (when found) */
  indexBinIndex?: number;
  /** Raw INDEX bin content (slotsPerBin × slotSize bytes, when found) */
  indexBinContent?: Uint8Array;
  /**
   * All INDEX bins checked (for "not found" verification).
   * When a scripthash is NOT found, all cuckoo positions must be verified.
   */
  allIndexBins?: { pbcGroup: number; binIndex: number; binContent: Uint8Array }[];
  /** PBC group indices for each CHUNK query */
  chunkPbcGroups?: number[];
  /** Cuckoo bin indices for each CHUNK query */
  chunkBinIndices?: number[];
  /** Raw CHUNK bin contents */
  chunkBinContents?: Uint8Array[];
}

// ─── Query Inspector types ──────────────────────────────────────────────
// The UI's Query Inspector panel consumes these shapes. Post-Session-6
// the adapter populates the PBC/bin/whale fields from native inspector
// output; fields that exposed TS-side placement internals (segment/position,
// per-chunk segment/position, per-round timings) are no longer populated
// because the native Rust HarmonyClient does not surface them across the
// WASM boundary — they would have leaked implementation details that
// the server can already observe. Consumers should treat those fields as
// optional and render a fallback when absent.

export interface RoundTimingData {
  phase: 'index' | 'chunk';
  roundIdx: number;
  hashIdx: number;
  realCount: number;
  totalCount: number;
  buildMs: number;
  netMs: number;
  procMs: number;
  relocMs: number;
}

export interface QueryInspectorData {
  address: string;
  scriptPubKeyHex: string;
  scriptHashHex: string;
  candidateIndexGroups: number[];
  assignedIndexGroup: number;
  indexPlacementRound: number;
  // INDEX details
  indexBinIndex?: number;
  indexHashRound?: number;
  indexSegment?: number;
  indexPosition?: number;
  indexSegmentSize?: number;   // T (segment size parameter)
  tagHex?: string;
  startChunkId?: number;
  numChunks?: number;
  isWhale: boolean;
  // CHUNK details (per chunk)
  chunkDetails?: Array<{
    chunkId: number;
    groupId: number;
    segment?: number;
    position?: number;
  }>;
  // Timing (all rounds, shared across queries in same batch)
  roundTimings: RoundTimingData[];
  totalMs: number;
}
