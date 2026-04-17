/**
 * Shared DPF/OnionPIR result types.
 *
 * These live in their own module (rather than in `client.ts`) because multiple
 * clients and merge utilities import them — `onionpir_client.ts`,
 * `sync-merge.ts`, and `client.ts` itself. Keeping them in a neutral module
 * avoids the circular import hazard that arises when a non-DPF consumer
 * (OnionPIR) pulls from `client.ts`, and it lets `client.ts` eventually be
 * replaced by a WASM-backed adapter without rippling type renames through
 * every caller.
 *
 * HarmonyPIR has a structurally different result shape (`HarmonyQueryResult`,
 * `HarmonyUtxoEntry` with hex-string txids + `number` amounts) and lives in
 * `harmony-types.ts`.
 */

// ─── UTXO entry ─────────────────────────────────────────────────────────────

/**
 * One unspent transaction output. TXID is stored as raw 32-byte internal byte
 * order (matches what comes out of the PIR chunk decoder and what
 * `sync-merge.ts` keys dedup by).
 */
export interface UtxoEntry {
  /** 32-byte raw TXID (internal byte order) */
  txid: Uint8Array;
  vout: number;
  /** Amount in satoshis */
  amount: bigint;
}

// ─── Query result ───────────────────────────────────────────────────────────

/**
 * Result of a DPF/OnionPIR batch query for a single scripthash. The struct
 * carries both the decoded user-facing data (`entries`, `totalSats`) and
 * enough inspector state for follow-on Merkle verification
 * (`allIndexBins`, `chunkPbcGroups`, etc.).
 *
 * Fields fall into three layers:
 *   1. **User-facing data** (`entries`, `totalSats`, `isWhale`).
 *   2. **Sync / merge metadata** (`startChunkId`, `numChunks`, `numRounds`,
 *      `rawChunkData`, `scriptHash`, `merkleVerified`, `merkleRootHex`).
 *   3. **Per-bucket bin-Merkle inspector state** (everything from
 *      `indexPbcGroup` onwards). Populated at query time and consumed by
 *      `verifyMerkleBatch`; the UI also renders these for the audit panel.
 *
 * OnionPIR's "per-bin Merkle" branch uses the separate `merkleIndexRoot`,
 * `merkleDataRoot`, `indexBinHash`, etc. fields. They coexist with the DPF
 * per-bucket fields because the same client struct is reused; only one set is
 * populated per query, determined by the backend.
 */
export interface QueryResult {
  entries: UtxoEntry[];
  totalSats: bigint;
  startChunkId: number;
  numChunks: number;
  numRounds: number;
  /** True if this address was excluded from the database due to too many UTXOs */
  isWhale: boolean;
  /** Merkle verification result (undefined if not verified yet) */
  merkleVerified?: boolean;
  /** Merkle root hash hex (from server, for display) */
  merkleRootHex?: string;
  /** Raw chunk data (kept for Merkle verification) */
  rawChunkData?: Uint8Array;
  /** Script hash used for this query */
  scriptHash?: Uint8Array;
  // ── Per-bucket bin Merkle ─────────────────────────────────────────
  /** PBC group index for the INDEX query (when found) */
  indexPbcGroup?: number;
  /** Cuckoo bin index within the INDEX group (when found) */
  indexBinIndex?: number;
  /** Raw INDEX bin content (slotsPerBin × slotSize bytes, when found) */
  indexBinContent?: Uint8Array;
  /**
   * All INDEX bins checked (for "not found" verification).
   * When a scripthash is NOT found, we check multiple cuckoo positions.
   * All of them must be verified to prove the scripthash is truly absent.
   */
  allIndexBins?: { pbcGroup: number; binIndex: number; binContent: Uint8Array }[];
  /** PBC group indices for each CHUNK query */
  chunkPbcGroups?: number[];
  /** Cuckoo bin indices for each CHUNK query */
  chunkBinIndices?: number[];
  /** Raw CHUNK bin contents */
  chunkBinContents?: Uint8Array[];
  // ── Per-bin Merkle (OnionPIR) ─────────────────────────────────────
  /** INDEX-MERKLE root hex (OnionPIR per-bin) */
  merkleIndexRoot?: string;
  /** DATA-MERKLE root hex (OnionPIR per-bin) */
  merkleDataRoot?: string;
  /** SHA256 of the decrypted INDEX bin (per-bin Merkle leaf) */
  indexBinHash?: Uint8Array;
  /** Leaf position in INDEX-MERKLE tree */
  indexLeafPos?: number;
  /**
   * All INDEX bins checked for "not found" verification (OnionPIR).
   * Each entry has the bin hash and leaf position.
   */
  allIndexBinHashes?: { hash: Uint8Array; leafPos: number }[];
  /** SHA256 of each decrypted DATA bin (per-bin Merkle leaves) */
  dataBinHashes?: Uint8Array[];
  /** Leaf positions in DATA-MERKLE tree */
  dataLeafPositions?: number[];
}

// ─── Connection state ───────────────────────────────────────────────────────

/**
 * Connection lifecycle state reported by clients via `onConnectionStateChange`.
 * Shared across DPF, OnionPIR, and (indirectly through the adapter) HarmonyPIR.
 */
export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting';
