//! Core types for PIR SDK.
//!
//! These types are shared between server and client implementations.

use pir_core::params::TableParams;

/// A 20-byte script hash (HASH160 of the script).
pub type ScriptHash = [u8; 20];

/// A single UTXO entry returned from a PIR query.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UtxoEntry {
    /// Transaction ID (32 bytes, little-endian).
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount_sats: u64,
}

/// A reference to one cuckoo bin inspected during a PIR query.
///
/// Populated into [`QueryResult::index_bins`] / [`QueryResult::chunk_bins`]
/// by the inspector query path (e.g. `DpfClient::query_batch_with_inspector`)
/// so that per-bucket Merkle verification can run as a standalone second
/// pass against the same raw content that produced the user-facing result.
///
/// The `bin_content` is the XOR-reconstructed bin payload (all slots, not
/// just the matched slot) — i.e. exactly what the Merkle leaf hash is
/// computed over (`SHA256(bin_index_le || bin_content)`). Rebuilding a
/// `BucketMerkleItem` from this struct is a direct field copy.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BucketRef {
    /// PBC group this bin belongs to (0..k).
    pub pbc_group: u32,
    /// Cuckoo bin index within the group's flat table.
    pub bin_index: u32,
    /// XOR-reconstructed bin content (slots_per_bin × slot_size bytes).
    pub bin_content: Vec<u8>,
}

impl UtxoEntry {
    /// Create a new UTXO entry.
    pub fn new(txid: [u8; 32], vout: u32, amount_sats: u64) -> Self {
        Self { txid, vout, amount_sats }
    }

    /// Returns the outpoint as a 36-byte array (txid || vout_le).
    pub fn outpoint(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.txid);
        out[32..36].copy_from_slice(&self.vout.to_le_bytes());
        out
    }
}

/// Type of PIR database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DatabaseKind {
    /// Full UTXO set snapshot at a single height.
    Full,
    /// Delta (new + spent UTXOs) between two heights.
    Delta {
        /// Starting height of the delta.
        base_height: u32,
    },
}

impl DatabaseKind {
    /// Returns true if this is a full snapshot.
    pub fn is_full(&self) -> bool {
        matches!(self, DatabaseKind::Full)
    }

    /// Returns true if this is a delta.
    pub fn is_delta(&self) -> bool {
        matches!(self, DatabaseKind::Delta { .. })
    }

    /// Returns the base height for deltas, or 0 for full snapshots.
    pub fn base_height(&self) -> u32 {
        match self {
            DatabaseKind::Full => 0,
            DatabaseKind::Delta { base_height } => *base_height,
        }
    }
}

/// Information about a database available on the server.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DatabaseInfo {
    /// Database ID (index in the server's database list).
    pub db_id: u8,
    /// Whether this is a full snapshot or delta.
    pub kind: DatabaseKind,
    /// Human-readable name (e.g., "main", "delta_940611_944000").
    pub name: String,
    /// Tip height (snapshot height for full, end height for deltas).
    pub height: u32,
    /// INDEX-level bins per table.
    pub index_bins: u32,
    /// CHUNK-level bins per table.
    pub chunk_bins: u32,
    /// INDEX-level group count (K).
    pub index_k: u8,
    /// CHUNK-level group count (K).
    pub chunk_k: u8,
    /// Tag seed for INDEX-level fingerprints.
    pub tag_seed: u64,
    /// DPF domain exponent for INDEX level.
    pub dpf_n_index: u8,
    /// DPF domain exponent for CHUNK level.
    pub dpf_n_chunk: u8,
    /// Whether this database has per-bucket bin Merkle verification data.
    pub has_bucket_merkle: bool,
}

impl DatabaseInfo {
    /// Returns the base height (0 for full snapshots).
    pub fn base_height(&self) -> u32 {
        self.kind.base_height()
    }

    /// Build TableParams for the INDEX level.
    pub fn index_params(&self) -> TableParams {
        TableParams {
            k: self.index_k as usize,
            num_hashes: 3,
            master_seed: pir_core::params::INDEX_PARAMS.master_seed,
            slots_per_bin: 4,
            cuckoo_num_hashes: 2,
            slot_size: pir_core::params::INDEX_SLOT_SIZE,
            dpf_n: self.dpf_n_index,
            magic: pir_core::params::INDEX_PARAMS.magic,
            header_size: pir_core::params::INDEX_PARAMS.header_size,
            has_tag_seed: true,
        }
    }

    /// Build TableParams for the CHUNK level.
    pub fn chunk_params(&self) -> TableParams {
        TableParams {
            k: self.chunk_k as usize,
            num_hashes: 3,
            master_seed: pir_core::params::CHUNK_PARAMS.master_seed,
            slots_per_bin: 3,
            cuckoo_num_hashes: 2,
            slot_size: pir_core::params::CHUNK_SLOT_SIZE,
            dpf_n: self.dpf_n_chunk,
            magic: pir_core::params::CHUNK_PARAMS.magic,
            header_size: pir_core::params::CHUNK_PARAMS.header_size,
            has_tag_seed: false,
        }
    }
}

/// A catalog of all databases available on a server.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DatabaseCatalog {
    /// All available databases.
    pub databases: Vec<DatabaseInfo>,
}

impl DatabaseCatalog {
    /// Create an empty catalog.
    pub fn new() -> Self {
        Self { databases: Vec::new() }
    }

    /// Find a database by ID.
    pub fn get(&self, db_id: u8) -> Option<&DatabaseInfo> {
        self.databases.iter().find(|db| db.db_id == db_id)
    }

    /// Get all full snapshot databases.
    pub fn full_snapshots(&self) -> impl Iterator<Item = &DatabaseInfo> {
        self.databases.iter().filter(|db| db.kind.is_full())
    }

    /// Get all delta databases.
    pub fn deltas(&self) -> impl Iterator<Item = &DatabaseInfo> {
        self.databases.iter().filter(|db| db.kind.is_delta())
    }

    /// Find the best (highest height) full snapshot.
    pub fn best_full_snapshot(&self) -> Option<&DatabaseInfo> {
        self.full_snapshots().max_by_key(|db| db.height)
    }

    /// Get the latest tip height across all databases.
    pub fn latest_tip(&self) -> Option<u32> {
        self.databases.iter().map(|db| db.height).max()
    }

    /// Find deltas that start at the given base height.
    pub fn deltas_from(&self, base_height: u32) -> impl Iterator<Item = &DatabaseInfo> {
        self.databases
            .iter()
            .filter(move |db| db.kind.base_height() == base_height)
    }
}

/// Result of a single PIR query for one script hash.
///
/// # Merkle verification semantics
///
/// `merkle_verified` signals whether per-bucket Merkle proofs for this
/// query passed:
/// - `true`  — either proofs verified against the server-published root,
///             or the database does not publish Merkle commitments
///             (`DatabaseInfo::has_bucket_merkle == false`). "No failure
///             detected." Callers that *require* Merkle must also check
///             `has_bucket_merkle` on the source database.
/// - `false` — Merkle verification was attempted and FAILED. `entries`
///             is emptied and `is_whale` cleared; the result should be
///             treated as untrusted. This is the ONLY way a failed proof
///             is surfaced to callers (previously failures were coerced
///             to `None`, indistinguishable from genuine absence).
///
/// A `None` in `SyncResult::results` still means "not found" — if the
/// database has Merkle commitments, absence is proved by the symmetric
/// INDEX bin probes (`INDEX_CUCKOO_NUM_HASHES=2` per query, see
/// CLAUDE.md "Merkle INDEX Item-Count Symmetry").
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QueryResult {
    /// Decoded UTXO entries.
    pub entries: Vec<UtxoEntry>,
    /// Whether this address is a "whale" (too many UTXOs to fit in chunks).
    pub is_whale: bool,
    /// Whether the per-bucket Merkle proof verified (or N/A for databases
    /// without Merkle). See struct-level docs for full semantics.
    pub merkle_verified: bool,
    /// Raw chunk data for delta merging (only populated for delta queries).
    #[cfg_attr(feature = "serde", serde(skip))]
    pub raw_chunk_data: Option<Vec<u8>>,
    /// Inspector state: every INDEX cuckoo bin the client probed for this
    /// query. Populated only by the inspector path
    /// (e.g. `DpfClient::query_batch_with_inspector`); the main `sync` and
    /// `query_batch` paths leave this empty to keep the hot path lean.
    ///
    /// For not-found queries this always contains `INDEX_CUCKOO_NUM_HASHES=2`
    /// bins (the absence-proof invariant). For found queries it contains
    /// every position up to and including the matched one. See CLAUDE.md
    /// "Merkle INDEX Item-Count Symmetry" for why the wire count is always
    /// 2 — the observable invariant is enforced at the Merkle-item layer
    /// (`run_merkle_verification`), not here.
    #[cfg_attr(feature = "serde", serde(default))]
    pub index_bins: Vec<BucketRef>,
    /// Inspector state: every CHUNK cuckoo bin that backed a decoded UTXO.
    /// Empty for not-found, whale, and zero-chunk matches. Populated only
    /// by the inspector path.
    #[cfg_attr(feature = "serde", serde(default))]
    pub chunk_bins: Vec<BucketRef>,
    /// If this query resolved to a match, the index within
    /// [`index_bins`](Self::index_bins) of the matching bin. `None` for
    /// not-found / whale / inspector-free paths.
    #[cfg_attr(feature = "serde", serde(default))]
    pub matched_index_idx: Option<usize>,
}

impl Default for QueryResult {
    fn default() -> Self {
        Self::empty()
    }
}

impl QueryResult {
    /// Create an empty result.
    ///
    /// Defaults `merkle_verified` to `true` (no known failure). Callers
    /// that specifically want to represent a failed Merkle proof should
    /// set `merkle_verified = false` explicitly (or use
    /// [`merkle_failed`](Self::merkle_failed)).
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            is_whale: false,
            merkle_verified: true,
            raw_chunk_data: None,
            index_bins: Vec::new(),
            chunk_bins: Vec::new(),
            matched_index_idx: None,
        }
    }

    /// Create a result with entries.
    ///
    /// Defaults `merkle_verified` to `true` (no known failure).
    pub fn with_entries(entries: Vec<UtxoEntry>) -> Self {
        Self {
            entries,
            is_whale: false,
            merkle_verified: true,
            raw_chunk_data: None,
            index_bins: Vec::new(),
            chunk_bins: Vec::new(),
            matched_index_idx: None,
        }
    }

    /// Build a result representing a FAILED Merkle verification.
    ///
    /// Entries are empty and `merkle_verified` is `false`. Emitted by the
    /// per-backend `run_merkle_verification` paths when sibling proofs
    /// don't reconcile against the server-published root.
    pub fn merkle_failed() -> Self {
        Self {
            entries: Vec::new(),
            is_whale: false,
            merkle_verified: false,
            raw_chunk_data: None,
            index_bins: Vec::new(),
            chunk_bins: Vec::new(),
            matched_index_idx: None,
        }
    }

    /// Total balance in satoshis.
    pub fn total_balance(&self) -> u64 {
        self.entries.iter().map(|e| e.amount_sats).sum()
    }

    /// Number of UTXOs.
    pub fn utxo_count(&self) -> usize {
        self.entries.len()
    }
}

/// Result of a sync operation (potentially multiple steps).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncResult {
    /// Merged results for each queried script hash (in same order as input).
    pub results: Vec<Option<QueryResult>>,
    /// Final synced height.
    pub synced_height: u32,
    /// Whether this was a fresh sync (started from a full snapshot).
    pub was_fresh_sync: bool,
}

impl SyncResult {
    /// Get the result for a specific script hash by index.
    pub fn get(&self, index: usize) -> Option<&QueryResult> {
        self.results.get(index).and_then(|r| r.as_ref())
    }
}

/// PIR backend type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PirBackendType {
    /// DPF-PIR: Two-server, stateless, Distributed Point Functions.
    Dpf,
    /// HarmonyPIR: Two-server (hint + query), stateful per-group hints.
    Harmony,
    /// OnionPIR: Single-server, FHE-based.
    Onion,
}

impl PirBackendType {
    /// Returns the number of servers required for this backend.
    pub fn required_servers(&self) -> usize {
        match self {
            PirBackendType::Dpf => 2,
            PirBackendType::Harmony => 2,
            PirBackendType::Onion => 1,
        }
    }

    /// Returns true if this backend is stateful (requires setup phase).
    pub fn is_stateful(&self) -> bool {
        match self {
            PirBackendType::Dpf => false,
            PirBackendType::Harmony => true,
            PirBackendType::Onion => true,
        }
    }
}

/// Server role in a multi-server PIR setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ServerRole {
    /// Primary server (server 0 in DPF, hint server in HarmonyPIR).
    #[default]
    Primary,
    /// Secondary server (server 1 in DPF, query server in HarmonyPIR).
    Secondary,
    /// Standalone server (OnionPIR).
    Standalone,
}
