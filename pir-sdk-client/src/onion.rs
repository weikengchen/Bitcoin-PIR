//! OnionPIR client implementation.
//!
//! OnionPIR is a single-server PIR protocol based on fully homomorphic
//! encryption (BFV, Microsoft SEAL). The client encrypts its query under
//! its own secret key; the server operates on the ciphertexts and returns
//! an encrypted response that only the client can decrypt.
//!
//! ## Feature gating
//!
//! The real implementation is gated behind the `onion` cargo feature because
//! the upstream [`onionpir`](https://github.com/Bitcoin-PIR/OnionPIRv2-fork)
//! crate has a heavy native build: CMake + the Microsoft SEAL C++ library
//! (pulled in as a submodule) and Homebrew GCC on macOS. Most SDK consumers
//! don't need OnionPIR and shouldn't pay that cost.
//!
//! ```toml
//! [dependencies]
//! pir-sdk-client = { version = "0.1", features = ["onion"] }
//! ```
//!
//! Without the feature, `OnionClient` compiles but every query logs a
//! warning and returns `None` — so the rest of the SDK (DPF, HarmonyPIR)
//! stays usable on systems without a C++ toolchain.
//!
//! ## Protocol flow
//!
//! 1. Fetch JSON server info (`0x03`) — gives per-database OnionPIR params
//!    (index_bins, chunk_bins, index_k, chunk_k, tag_seed, total_packed,
//!    index_slots_per_bin, index_slot_size).
//! 2. Create a per-client `onionpir::Client`, generate Galois + GSW keys,
//!    export the secret key.
//! 3. Send `REQ_REGISTER_KEYS (0x50)` once per database — await
//!    `RESP_KEYS_ACK (0x50)`.
//! 4. For each INDEX round: send `REQ_ONIONPIR_INDEX_QUERY (0x51)` with K
//!    encrypted queries (2 × K because INDEX uses 2-hash cuckoo — one query
//!    per hash position per group). Decrypt, scan the 256-slot × 15-byte
//!    bin for a matching tag.
//! 5. For each CHUNK round: build a 6-hash cuckoo table client-side to find
//!    each entry's exact bin, send `REQ_ONIONPIR_CHUNK_QUERY (0x52)` with
//!    K_CHUNK encrypted queries. Decrypt PACKED_ENTRY_SIZE=3840 bytes per
//!    entry.
//! 6. Assemble entries into raw UTXO bytes and decode with varint.
//!
//! ## Privacy-critical padding
//!
//! Every INDEX round sends **exactly K queries** (padded with random-bin
//! dummies), every CHUNK round sends **exactly K_CHUNK queries**. This is
//! mandatory per `CLAUDE.md` and is implemented identically to the DPF
//! client — never "optimize" it away.

use crate::connection::WsConnection;
use async_trait::async_trait;
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, DatabaseCatalog, DatabaseInfo, DatabaseKind,
    PirBackendType, PirClient, PirError, PirResult, QueryResult, ScriptHash, SyncPlan, SyncResult,
    SyncStep,
};

// `UtxoEntry` is only constructed by the feature-gated decode path.
#[cfg(feature = "onion")]
use pir_sdk::UtxoEntry;

#[cfg(feature = "onion")]
use std::collections::{HashMap, HashSet};

// ─── Protocol wire codes ────────────────────────────────────────────────────

/// Request: fetch server info as JSON.
const REQ_GET_INFO_JSON: u8 = 0x03;
/// Response: JSON server info payload.
const RESP_GET_INFO_JSON: u8 = 0x03;
/// Request: fetch the DPF-format database catalog (reused for heights/names).
const REQ_GET_DB_CATALOG: u8 = 0x02;
/// Response: DPF-format database catalog.
const RESP_DB_CATALOG: u8 = 0x02;

/// Request: register FHE keys for a client.
#[cfg(feature = "onion")]
const REQ_REGISTER_KEYS: u8 = 0x50;
/// Response: FHE keys acknowledged.
#[cfg(feature = "onion")]
const RESP_KEYS_ACK: u8 = 0x50;
/// Request: batched encrypted INDEX queries.
#[cfg(feature = "onion")]
const REQ_ONIONPIR_INDEX_QUERY: u8 = 0x51;
/// Response: batched encrypted INDEX results.
#[cfg(feature = "onion")]
const RESP_ONIONPIR_INDEX_RESULT: u8 = 0x51;
/// Request: batched encrypted CHUNK queries.
#[cfg(feature = "onion")]
const REQ_ONIONPIR_CHUNK_QUERY: u8 = 0x52;
/// Response: batched encrypted CHUNK results.
#[cfg(feature = "onion")]
const RESP_ONIONPIR_CHUNK_RESULT: u8 = 0x52;

// ─── Layout constants ───────────────────────────────────────────────────────

/// Number of PBC hash functions (group assignment).
#[cfg(feature = "onion")]
const NUM_HASHES: usize = 3;

/// INDEX cuckoo hash functions (per-bin placement).
#[cfg(feature = "onion")]
const INDEX_CUCKOO_NUM_HASHES: usize = 2;

/// CHUNK cuckoo hash functions.
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_NUM_HASHES: usize = 6;

/// Max kicks before declaring a cuckoo-build failure.
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_MAX_KICKS: usize = 10000;

/// Master seed for CHUNK cuckoo derivation (must match server).
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_SEED: u64 = 0xa3f7c2d918e4b065;

/// Sentinel for empty cuckoo slots.
#[cfg(feature = "onion")]
const EMPTY: u32 = u32::MAX;

/// Size of one packed entry bin in the CHUNK table.
#[cfg(feature = "onion")]
const PACKED_ENTRY_SIZE: usize = 3840;

// ─── Per-DB OnionPIR parameters ─────────────────────────────────────────────

/// OnionPIR-specific parameters that aren't captured by [`DatabaseInfo`].
///
/// These come from the JSON `onionpir` sub-object in the server info
/// response. The SDK keeps a per-`db_id` table so the right numbers flow
/// into query generation when the client talks to deltas as well as the
/// main database.
///
/// The struct is always present (its values are parsed + stored regardless
/// of feature gate), but the fields are only *read* when the `onion` feature
/// is on. The `allow(dead_code)` silences the warning on default builds.
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "onion"), allow(dead_code))]
struct OnionDbParams {
    /// Total number of packed entries in the DB (for CHUNK reverse index).
    total_packed: usize,
    /// Number of slots in each decrypted INDEX bin (typically 256).
    index_slots_per_bin: usize,
    /// Byte size of each INDEX slot (typically 15).
    index_slot_size: usize,
}

// ─── Send + Sync wrapper around onionpir::Client ────────────────────────────
//
// `onionpir::Client` wraps an opaque C++ pointer via FFI and is `!Send + !Sync`
// by default.
//
// **Send is safe** because all mutating methods take `&mut self` and the
// upstream implementation has no global state touched by queries/decrypt.
// Moving an instance between threads (without sharing) is fine.
//
// **Sync is safe (with the same caveats as Send)** because the only `&self`
// methods on `onionpir::Client` are `export_secret_key` and `id`, both of
// which are read-only FFI calls over immutable C++ state. Any mutation goes
// through `&mut self`, which the Rust borrow checker forbids sharing across
// threads. So a `&SendClient` shared across threads can only invoke the
// read-only methods, which don't race. We still never intentionally call
// `generate_query`/`decrypt_response` concurrently on the same client — the
// SDK uses one client per (db_id, level) and serializes calls.
//
// The `PirClient` trait requires `Send + Sync`, which is why both impls are
// needed.

#[cfg(feature = "onion")]
struct SendClient(onionpir::Client);

#[cfg(feature = "onion")]
// Safety: `onionpir::Client` has no internal sharing, and all mutating FFI
// entry points take `&mut self`. Moving it between tasks is fine.
unsafe impl Send for SendClient {}

#[cfg(feature = "onion")]
// Safety: The only `&self` methods (`id`, `export_secret_key`) are read-only
// FFI calls. All mutation goes through `&mut self`, which Rust's aliasing
// rules prevent from being shared. So concurrent `&SendClient` access is
// race-free.
unsafe impl Sync for SendClient {}

// ─── FHE state (only when the `onion` feature is on) ────────────────────────

#[cfg(feature = "onion")]
struct FheState {
    /// Deterministic client ID (overridden from C++'s `rand()` default).
    client_id: u64,
    /// Exported secret key bytes; used to spawn per-level clients.
    secret_key: Vec<u8>,
    /// Serialized Galois key bytes; re-sent on server LRU eviction.
    galois_keys: Vec<u8>,
    /// Serialized GSW key bytes; re-sent on server LRU eviction.
    gsw_keys: Vec<u8>,
    /// Per-level clients, keyed by `(db_id, level)` where level 0=index, 1=chunk.
    ///
    /// Lazily populated on first query to each `(db_id, level)` combination.
    /// Keys are long-lived; per-level clients just adjust `num_entries` for
    /// query generation and response decryption.
    level_clients: HashMap<(u8, u8), SendClient>,
    /// Database IDs for which we've already registered keys on the server.
    registered: HashSet<u8>,
}

// ─── OnionClient ────────────────────────────────────────────────────────────

/// OnionPIR client for single-server FHE-based PIR queries.
///
/// Requires the `onion` cargo feature to perform real queries. Without the
/// feature, queries succeed as no-ops returning `None` — useful for builds
/// on systems without a C++ toolchain.
pub struct OnionClient {
    server_url: String,
    conn: Option<WsConnection>,
    catalog: Option<DatabaseCatalog>,
    /// Per-DB OnionPIR-specific parameters. Keyed by db_id.
    onion_params: std::collections::HashMap<u8, OnionDbParams>,
    /// Cached raw JSON info (so we can re-parse per-DB params on demand).
    info_json: Option<String>,
    #[cfg(feature = "onion")]
    fhe: Option<FheState>,
}

impl OnionClient {
    /// Create a new OnionPIR client.
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            conn: None,
            catalog: None,
            onion_params: std::collections::HashMap::new(),
            info_json: None,
            #[cfg(feature = "onion")]
            fhe: None,
        }
    }

    /// Fetch the JSON server info and (best-effort) the DPF-format catalog,
    /// merging into a unified [`DatabaseCatalog`] plus per-DB OnionPIR params.
    async fn fetch_server_info(&mut self) -> PirResult<()> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;

        // Request JSON info.
        let req = encode_request(REQ_GET_INFO_JSON, &[]);
        let response = conn.roundtrip(&req).await?;

        if response.is_empty() || response[0] != RESP_GET_INFO_JSON {
            return Err(PirError::Protocol(
                "expected 0x03 JSON info response".into(),
            ));
        }
        let json_bytes = &response[1..];
        let json = std::str::from_utf8(json_bytes)
            .map_err(|e| PirError::Protocol(format!("info JSON not UTF-8: {}", e)))?
            .to_string();

        self.onion_params = parse_onion_params_per_db(&json);
        if self.onion_params.is_empty() {
            return Err(PirError::Protocol(
                "server has no OnionPIR data — is this an OnionPIR-enabled server?".into(),
            ));
        }

        // Best-effort DPF catalog fetch for heights/names. If the server
        // doesn't support it, synthesize a single-DB catalog from JSON.
        let dpf_catalog = self.try_fetch_dpf_catalog().await.ok();

        let catalog = build_catalog(&json, &self.onion_params, dpf_catalog.as_ref());
        self.catalog = Some(catalog);
        self.info_json = Some(json);
        Ok(())
    }

    async fn try_fetch_dpf_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let req = encode_request(REQ_GET_DB_CATALOG, &[]);
        let response = conn.roundtrip(&req).await?;
        if response.is_empty() || response[0] != RESP_DB_CATALOG {
            return Err(PirError::Protocol("no DPF catalog available".into()));
        }
        decode_catalog(&response[1..])
    }

    /// Execute a single sync step for a batch of script hashes.
    #[cfg(feature = "onion")]
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        let params = self
            .onion_params
            .get(&db_info.db_id)
            .cloned()
            .ok_or_else(|| {
                PirError::InvalidState(format!(
                    "no OnionPIR params for db_id={}",
                    db_info.db_id
                ))
            })?;

        self.ensure_fhe_initialised()?;
        self.ensure_keys_registered(db_info).await?;

        log::info!(
            "[PIR-AUDIT] OnionPIR execute_step db_id={} ({}), {} scripthashes, K={}, K_CHUNK={}",
            db_info.db_id,
            db_info.name,
            script_hashes.len(),
            db_info.index_k,
            db_info.chunk_k
        );
        log::info!(
            "[PIR-AUDIT] OnionPIR padding: INDEX rounds send exactly K={} queries \
             (2*K cuckoo positions), CHUNK rounds send exactly K_CHUNK={} queries — \
             dummies fill empty groups.",
            db_info.index_k,
            db_info.chunk_k,
        );

        let index_results = self
            .query_index_level(script_hashes, db_info, &params)
            .await?;

        let chunk_data = self
            .query_chunk_level(script_hashes, &index_results, db_info, &params)
            .await?;

        // Decode per-scripthash UTXOs from assembled raw bytes.
        let mut results = Vec::with_capacity(script_hashes.len());
        for (idx, ir) in index_results.iter().enumerate() {
            let qr = match ir {
                None => {
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: NOT FOUND",
                        hex_short(&script_hashes[idx])
                    );
                    None
                }
                Some(ir) if ir.num_entries == 0 => {
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: WHALE (excluded)",
                        hex_short(&script_hashes[idx])
                    );
                    Some(QueryResult {
                        entries: Vec::new(),
                        is_whale: true,
                        raw_chunk_data: None,
                    })
                }
                Some(ir) => {
                    let raw = assemble_entry_bytes(ir, &chunk_data, db_info.db_id)?;
                    let entries = decode_utxo_entries(&raw);
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: FOUND {} UTXOs \
                         (entry_id={}, num_entries={}, byte_offset={})",
                        hex_short(&script_hashes[idx]),
                        entries.len(),
                        ir.entry_id,
                        ir.num_entries,
                        ir.byte_offset,
                    );
                    Some(QueryResult {
                        entries,
                        is_whale: false,
                        raw_chunk_data: if db_info.kind.is_delta() {
                            Some(raw)
                        } else {
                            None
                        },
                    })
                }
            };
            results.push(qr);
        }

        Ok(results)
    }

    /// Placeholder fallback when the `onion` feature is disabled.
    #[cfg(not(feature = "onion"))]
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        _db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        log::warn!(
            "OnionPIR query attempted without the `onion` cargo feature — \
             returning empty results for {} script hash(es). Enable the feature \
             (requires a C++ toolchain + cmake + SEAL) to run real OnionPIR queries.",
            script_hashes.len()
        );
        Ok(vec![None; script_hashes.len()])
    }

    // ─── FHE helpers (onion feature only) ───────────────────────────────────

    #[cfg(feature = "onion")]
    fn ensure_fhe_initialised(&mut self) -> PirResult<()> {
        if self.fhe.is_some() {
            return Ok(());
        }
        // Pick an arbitrary DB for key generation — keys are independent of
        // num_entries, so we just need something to instantiate the client.
        let any_db_id = *self
            .onion_params
            .keys()
            .next()
            .ok_or_else(|| PirError::InvalidState("no OnionPIR databases known".into()))?;
        let num_entries = self.num_entries_for_level(any_db_id, /* chunk */ false);

        // Override client_id with a cryptographic-quality random u64 — the
        // C++ default uses rand() which is non-crypto and can collide.
        let client_id: u64 = rand::random();

        // Allocate a temporary `Client` just for keygen + secret-key export,
        // then drop it. Per-level clients are created lazily from the exported
        // secret key as queries come in.
        let mut keygen = onionpir::Client::new_from_secret_key(
            num_entries as u64,
            client_id,
            &onionpir::Client::new(num_entries as u64).export_secret_key(),
        );
        // The above pattern (new + export + new_from_sk) is what the reference
        // onionpir_client does to decouple key ownership from num_entries.
        // We create one keygen client with our client_id bound to the newly
        // generated secret key, then pull keys + sk out of it.
        let galois_keys = keygen.generate_galois_keys();
        let gsw_keys = keygen.generate_gsw_keys();
        let secret_key = keygen.export_secret_key();

        self.fhe = Some(FheState {
            client_id,
            secret_key,
            galois_keys,
            gsw_keys,
            level_clients: HashMap::new(),
            registered: HashSet::new(),
        });
        log::info!("[PIR-AUDIT] OnionPIR generated FHE keys (client_id=0x{:016x})", client_id);
        Ok(())
    }

    /// Register keys for a given database if we haven't already. Server
    /// LRU-evicts at 100 clients, so this is also called lazily to retry.
    #[cfg(feature = "onion")]
    async fn ensure_keys_registered(&mut self, db_info: &DatabaseInfo) -> PirResult<()> {
        let already = self
            .fhe
            .as_ref()
            .map(|f| f.registered.contains(&db_info.db_id))
            .unwrap_or(false);
        if already {
            return Ok(());
        }
        self.register_keys(db_info.db_id).await
    }

    #[cfg(feature = "onion")]
    async fn register_keys(&mut self, db_id: u8) -> PirResult<()> {
        let (galois_keys, gsw_keys) = {
            let fhe = self
                .fhe
                .as_ref()
                .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;
            (fhe.galois_keys.clone(), fhe.gsw_keys.clone())
        };

        let payload = encode_register_keys(&galois_keys, &gsw_keys, db_id);
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(&payload).await?;

        if response.is_empty() || response[0] != RESP_KEYS_ACK {
            return Err(PirError::Protocol(
                "expected RESP_KEYS_ACK (0x50)".into(),
            ));
        }

        self.fhe
            .as_mut()
            .expect("fhe present")
            .registered
            .insert(db_id);
        log::info!(
            "[PIR-AUDIT] OnionPIR registered keys for db_id={}",
            db_id
        );
        Ok(())
    }

    /// Number of packed entries in a DB at a particular level (false=index, true=chunk).
    #[cfg(feature = "onion")]
    fn num_entries_for_level(&self, db_id: u8, chunk: bool) -> usize {
        let db = self.catalog.as_ref().and_then(|c| c.get(db_id));
        match db {
            Some(d) if chunk => d.chunk_bins as usize,
            Some(d) => d.index_bins as usize,
            None => 1,
        }
    }

    /// Get or create a per-level `onionpir::Client` for (db_id, level).
    #[cfg(feature = "onion")]
    fn get_level_client(&mut self, db_id: u8, chunk: bool) -> PirResult<&mut onionpir::Client> {
        let key = (db_id, if chunk { 1u8 } else { 0u8 });
        let num_entries = self.num_entries_for_level(db_id, chunk) as u64;
        let fhe = self
            .fhe
            .as_mut()
            .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;

        if !fhe.level_clients.contains_key(&key) {
            let client = onionpir::Client::new_from_secret_key(
                num_entries,
                fhe.client_id,
                &fhe.secret_key,
            );
            fhe.level_clients.insert(key, SendClient(client));
        }
        Ok(&mut fhe.level_clients.get_mut(&key).unwrap().0)
    }

    #[cfg(feature = "onion")]
    async fn query_index_level(
        &mut self,
        script_hashes: &[ScriptHash],
        db_info: &DatabaseInfo,
        params: &OnionDbParams,
    ) -> PirResult<Vec<Option<IndexResult>>> {
        let k = db_info.index_k as usize;
        let bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;
        let master_seed = pir_core::params::INDEX_PARAMS.master_seed;

        // Plan PBC rounds.
        let groups_per_sh: Vec<[usize; NUM_HASHES]> = script_hashes
            .iter()
            .map(|sh| pir_core::hash::derive_groups_3(sh, k))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(&groups_per_sh, k, NUM_HASHES, 500);

        let mut results: Vec<Option<IndexResult>> =
            (0..script_hashes.len()).map(|_| None).collect();
        let mut rng = SimpleRng::new();

        for (round_id, round) in rounds.iter().enumerate() {
            let mut group_to_sh: HashMap<usize, usize> = HashMap::new();
            for &(sh_idx, group) in round {
                group_to_sh.insert(group, sh_idx);
            }

            // Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
            let mut query_bins: Vec<u64> = Vec::with_capacity(2 * k);
            for g in 0..k {
                for h in 0..INDEX_CUCKOO_NUM_HASHES {
                    let bin = if let Some(&sh_idx) = group_to_sh.get(&g) {
                        let key = pir_core::hash::derive_cuckoo_key(master_seed, g, h);
                        pir_core::hash::cuckoo_hash(&script_hashes[sh_idx], key, bins) as u64
                    } else {
                        rng.next_u64() % bins as u64
                    };
                    query_bins.push(bin);
                }
            }

            // Encrypt queries.
            let index_client = self.get_level_client(db_info.db_id, false)?;
            let mut queries = Vec::with_capacity(2 * k);
            for &bin in &query_bins {
                queries.push(index_client.generate_query(bin));
            }

            // Send and receive.
            let msg = encode_onionpir_batch_query(
                REQ_ONIONPIR_INDEX_QUERY,
                round_id as u16,
                &queries,
                db_info.db_id,
            );
            let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
            let response = conn.roundtrip(&msg).await?;
            if response.is_empty() || response[0] != RESP_ONIONPIR_INDEX_RESULT {
                return Err(PirError::Protocol(
                    "expected RESP_ONIONPIR_INDEX_RESULT (0x51)".into(),
                ));
            }
            let batch = decode_onionpir_batch_result(&response[1..])?;

            // Decrypt the 2 responses per real-group and scan for tags.
            let index_client = self.get_level_client(db_info.db_id, false)?;
            for &(sh_idx, group) in round {
                let tag = pir_core::hash::compute_tag(tag_seed, &script_hashes[sh_idx]);
                for h in 0..INDEX_CUCKOO_NUM_HASHES {
                    let qi = group * INDEX_CUCKOO_NUM_HASHES + h;
                    if qi >= batch.len() {
                        return Err(PirError::Protocol(format!(
                            "result batch truncated: qi={} len={}",
                            qi,
                            batch.len()
                        )));
                    }
                    let bin = query_bins[qi];
                    let entry = index_client.decrypt_response(bin, &batch[qi]);
                    if let Some(ir) = scan_index_bin(
                        &entry,
                        tag,
                        params.index_slots_per_bin,
                        params.index_slot_size,
                    ) {
                        results[sh_idx] = Some(ir);
                        break;
                    }
                }
            }
        }

        Ok(results)
    }

    #[cfg(feature = "onion")]
    async fn query_chunk_level(
        &mut self,
        _script_hashes: &[ScriptHash],
        index_results: &[Option<IndexResult>],
        db_info: &DatabaseInfo,
        params: &OnionDbParams,
    ) -> PirResult<HashMap<u32, Vec<u8>>> {
        // Collect unique entry_ids to fetch.
        let mut unique: Vec<u32> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        for ir in index_results.iter().flatten() {
            if ir.num_entries == 0 {
                continue;
            }
            for i in 0..ir.num_entries as u32 {
                let eid = ir.entry_id + i;
                if seen.insert(eid) {
                    unique.push(eid);
                }
            }
        }

        let mut decrypted: HashMap<u32, Vec<u8>> = HashMap::new();
        if unique.is_empty() {
            return Ok(decrypted);
        }

        let chunk_k = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;

        // Build per-group reverse index once — scales with total entries.
        let reverse_index = build_chunk_reverse_index(params.total_packed, chunk_k);

        // Plan PBC rounds.
        let entry_groups: Vec<[usize; NUM_HASHES]> = unique
            .iter()
            .map(|&eid| pir_core::hash::derive_int_groups_3(eid, chunk_k))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(&entry_groups, chunk_k, NUM_HASHES, 500);

        let mut cuckoo_cache: HashMap<usize, Vec<u32>> = HashMap::new();
        let mut rng = SimpleRng::new();

        for (round_id, round) in rounds.iter().enumerate() {
            struct Q {
                entry_id: u32,
                group: usize,
                bin: usize,
            }
            let mut round_queries: Vec<Q> = Vec::new();
            let mut group_bin: HashMap<usize, usize> = HashMap::new();

            for &(ei, group) in round {
                let eid = unique[ei];
                cuckoo_cache
                    .entry(group)
                    .or_insert_with(|| {
                        build_chunk_cuckoo_for_group(group, &reverse_index, chunk_bins)
                    });

                let keys = chunk_derive_keys(group);
                let bin = find_in_chunk_cuckoo(
                    cuckoo_cache.get(&group).unwrap(),
                    eid,
                    &keys,
                    chunk_bins,
                )
                .ok_or_else(|| {
                    PirError::InvalidState(format!(
                        "entry_id {} not in chunk cuckoo for group {}",
                        eid, group
                    ))
                })?;

                round_queries.push(Q {
                    entry_id: eid,
                    group,
                    bin,
                });
                group_bin.insert(group, bin);
            }

            // Generate K_CHUNK queries with dummies in empty groups.
            let chunk_client = self.get_level_client(db_info.db_id, true)?;
            let mut queries = Vec::with_capacity(chunk_k);
            for g in 0..chunk_k {
                let bin = if let Some(&b) = group_bin.get(&g) {
                    b as u64
                } else {
                    rng.next_u64() % chunk_bins as u64
                };
                queries.push(chunk_client.generate_query(bin));
            }

            let msg = encode_onionpir_batch_query(
                REQ_ONIONPIR_CHUNK_QUERY,
                round_id as u16,
                &queries,
                db_info.db_id,
            );
            let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
            let response = conn.roundtrip(&msg).await?;
            if response.is_empty() || response[0] != RESP_ONIONPIR_CHUNK_RESULT {
                return Err(PirError::Protocol(
                    "expected RESP_ONIONPIR_CHUNK_RESULT (0x52)".into(),
                ));
            }
            let batch = decode_onionpir_batch_result(&response[1..])?;

            let chunk_client = self.get_level_client(db_info.db_id, true)?;
            for q in &round_queries {
                if q.group >= batch.len() {
                    return Err(PirError::Protocol(format!(
                        "chunk result truncated: group={} len={}",
                        q.group,
                        batch.len()
                    )));
                }
                let bytes = chunk_client.decrypt_response(q.bin as u64, &batch[q.group]);
                if bytes.len() < PACKED_ENTRY_SIZE {
                    return Err(PirError::Protocol(format!(
                        "decrypted chunk shorter than PACKED_ENTRY_SIZE: {} < {}",
                        bytes.len(),
                        PACKED_ENTRY_SIZE
                    )));
                }
                decrypted.insert(q.entry_id, bytes[..PACKED_ENTRY_SIZE].to_vec());
            }
        }

        Ok(decrypted)
    }
}

// ─── PirClient trait impl ───────────────────────────────────────────────────

#[async_trait]
impl PirClient for OnionClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Onion
    }

    async fn connect(&mut self) -> PirResult<()> {
        log::info!("Connecting to OnionPIR server: {}", self.server_url);
        let conn = WsConnection::connect(&self.server_url).await?;
        self.conn = Some(conn);
        #[cfg(not(feature = "onion"))]
        log::warn!(
            "OnionPIR client connected without the `onion` cargo feature — \
             queries will return empty results."
        );
        Ok(())
    }

    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.conn {
            let _ = conn.close().await;
        }
        self.conn = None;
        self.catalog = None;
        self.onion_params.clear();
        self.info_json = None;
        #[cfg(feature = "onion")]
        {
            self.fhe = None;
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        self.fetch_server_info().await?;
        Ok(self
            .catalog
            .clone()
            .expect("fetch_server_info populates catalog"))
    }

    fn cached_catalog(&self) -> Option<&DatabaseCatalog> {
        self.catalog.as_ref()
    }

    fn compute_sync_plan(
        &self,
        catalog: &DatabaseCatalog,
        last_height: Option<u32>,
    ) -> PirResult<SyncPlan> {
        compute_sync_plan(catalog, last_height)
    }

    async fn sync(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
    ) -> PirResult<SyncResult> {
        if !self.is_connected() {
            self.connect().await?;
        }
        let catalog = match &self.catalog {
            Some(c) => c.clone(),
            None => self.fetch_catalog().await?,
        };
        let plan = self.compute_sync_plan(&catalog, last_height)?;
        self.sync_with_plan(script_hashes, &plan, None).await
    }

    async fn sync_with_plan(
        &mut self,
        script_hashes: &[ScriptHash],
        plan: &SyncPlan,
        cached_results: Option<&[Option<QueryResult>]>,
    ) -> PirResult<SyncResult> {
        if plan.is_empty() {
            return Ok(SyncResult {
                results: cached_results
                    .map(|r| r.to_vec())
                    .unwrap_or_else(|| vec![None; script_hashes.len()]),
                synced_height: plan.target_height,
                was_fresh_sync: false,
            });
        }

        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let mut merged: Vec<Option<QueryResult>> = cached_results
            .map(|r| r.to_vec())
            .unwrap_or_else(|| vec![None; script_hashes.len()]);

        for (step_idx, step) in plan.steps.iter().enumerate() {
            log::info!(
                "[{}/{}] OnionPIR querying {} (db_id={}, height={})",
                step_idx + 1,
                plan.steps.len(),
                step.name,
                step.db_id,
                step.tip_height
            );

            let db_info = catalog
                .get(step.db_id)
                .ok_or(PirError::DatabaseNotFound(step.db_id))?
                .clone();

            let step_results = self.execute_step(script_hashes, step, &db_info).await?;

            if step.is_full() {
                merged = step_results;
            } else {
                merged = merge_delta_batch(&merged, &step_results)?;
            }
        }

        Ok(SyncResult {
            results: merged,
            synced_height: plan.target_height,
            was_fresh_sync: plan.is_fresh_sync,
        })
    }

    async fn query_batch(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let db_info = catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?
            .clone();
        let step = SyncStep::from_db_info(&db_info);
        self.execute_step(script_hashes, &step, &db_info).await
    }
}

// ─── INDEX-level scan result ────────────────────────────────────────────────

#[cfg(feature = "onion")]
#[derive(Clone, Debug)]
struct IndexResult {
    entry_id: u32,
    byte_offset: u16,
    num_entries: u8,
}

/// Scan a decrypted INDEX bin (slots_per_bin × slot_size bytes) for a tag.
/// OnionPIR slot layout: `tag(8) | entry_id(4) | byte_offset(2) | num_entries(1)`.
#[cfg(feature = "onion")]
fn scan_index_bin(
    entry_bytes: &[u8],
    tag: u64,
    slots_per_bin: usize,
    slot_size: usize,
) -> Option<IndexResult> {
    for slot in 0..slots_per_bin {
        let off = slot * slot_size;
        if off + slot_size > entry_bytes.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(entry_bytes[off..off + 8].try_into().ok()?);
        if slot_tag == tag && slot_tag != 0 {
            let entry_id =
                u32::from_le_bytes(entry_bytes[off + 8..off + 12].try_into().ok()?);
            let byte_offset =
                u16::from_le_bytes(entry_bytes[off + 12..off + 14].try_into().ok()?);
            let num_entries = entry_bytes[off + 14];
            return Some(IndexResult {
                entry_id,
                byte_offset,
                num_entries,
            });
        }
    }
    None
}

/// Stitch raw entry bytes into a single UTXO data blob starting at byte_offset.
#[cfg(feature = "onion")]
fn assemble_entry_bytes(
    ir: &IndexResult,
    chunk_data: &HashMap<u32, Vec<u8>>,
    db_id: u8,
) -> PirResult<Vec<u8>> {
    let mut out = Vec::with_capacity(ir.num_entries as usize * PACKED_ENTRY_SIZE);
    for i in 0..ir.num_entries as u32 {
        let eid = ir.entry_id + i;
        let entry = chunk_data.get(&eid).ok_or_else(|| {
            PirError::InvalidState(format!(
                "missing decrypted entry_id {} (db_id={})",
                eid, db_id
            ))
        })?;
        if i == 0 {
            let start = ir.byte_offset as usize;
            if start > entry.len() {
                return Err(PirError::Protocol(format!(
                    "byte_offset {} exceeds entry size {}",
                    start,
                    entry.len()
                )));
            }
            out.extend_from_slice(&entry[start..]);
        } else {
            out.extend_from_slice(entry);
        }
    }
    Ok(out)
}

/// Decode UTXO entries from assembled entry bytes (varint-encoded).
///
/// Layout: `varint(num_utxos) | [txid(32) | varint(vout) | varint(amount)] * N`.
#[cfg(feature = "onion")]
fn decode_utxo_entries(data: &[u8]) -> Vec<UtxoEntry> {
    let mut entries = Vec::new();
    if data.is_empty() {
        return entries;
    }
    let mut pos = 0;
    let (num_utxos, vr) = pir_core::codec::read_varint(&data[pos..]);
    pos += vr;

    for _ in 0..num_utxos {
        if pos + 32 > data.len() {
            break;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        if pos >= data.len() {
            break;
        }
        let (vout, vr) = pir_core::codec::read_varint(&data[pos..]);
        pos += vr;
        if pos >= data.len() {
            break;
        }
        let (amount, ar) = pir_core::codec::read_varint(&data[pos..]);
        pos += ar;

        entries.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount_sats: amount,
        });
    }

    entries
}

// ─── Client-side CHUNK cuckoo (6-hash, slots_per_bin=1) ─────────────────────

#[cfg(feature = "onion")]
fn chunk_derive_keys(group_id: usize) -> [u64; CHUNK_CUCKOO_NUM_HASHES] {
    let mut keys = [0u64; CHUNK_CUCKOO_NUM_HASHES];
    for (h, k) in keys.iter_mut().enumerate() {
        *k = pir_core::hash::splitmix64(
            CHUNK_CUCKOO_SEED
                .wrapping_add((group_id as u64).wrapping_mul(pir_core::hash::GOLDEN_RATIO))
                .wrapping_add((h as u64).wrapping_mul(pir_core::hash::CUCKOO_KEY_MIX)),
        );
    }
    keys
}

#[cfg(feature = "onion")]
#[inline]
fn chunk_cuckoo_hash(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (pir_core::hash::splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

#[cfg(feature = "onion")]
fn build_chunk_reverse_index(total_entries: usize, k_chunk: usize) -> Vec<Vec<u32>> {
    let mut index: Vec<Vec<u32>> = (0..k_chunk).map(|_| Vec::new()).collect();
    for eid in 0..total_entries as u32 {
        let groups = pir_core::hash::derive_int_groups_3(eid, k_chunk);
        for &g in &groups {
            index[g].push(eid);
        }
    }
    index
}

#[cfg(feature = "onion")]
fn build_chunk_cuckoo_for_group(
    group_id: usize,
    reverse_index: &[Vec<u32>],
    bins_per_table: usize,
) -> Vec<u32> {
    let entries = &reverse_index[group_id];
    let keys = chunk_derive_keys(group_id);
    let mut table = vec![EMPTY; bins_per_table];

    for &entry_id in entries {
        // Try primary placements.
        let mut placed = false;
        for &key in keys.iter() {
            let bin = chunk_cuckoo_hash(entry_id, key, bins_per_table);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed {
            continue;
        }

        // Kick loop — mirrors reference implementation exactly so bin
        // assignments match the server.
        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = chunk_cuckoo_hash(entry_id, keys[0], bins_per_table);
        let mut success = false;

        for kick in 0..CHUNK_CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % CHUNK_CUCKOO_NUM_HASHES;
                let bin = chunk_cuckoo_hash(evicted, keys[try_h], bins_per_table);
                if bin == current_bin {
                    continue;
                }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }

            let alt_h =
                (current_hash_fn + 1 + kick % (CHUNK_CUCKOO_NUM_HASHES - 1)) % CHUNK_CUCKOO_NUM_HASHES;
            let alt_bin = chunk_cuckoo_hash(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % CHUNK_CUCKOO_NUM_HASHES;
                chunk_cuckoo_hash(evicted, keys[h2], bins_per_table)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            // Don't panic — let the caller surface this as a protocol error.
            log::error!(
                "OnionPIR client-side cuckoo failed for entry_id={} group={}",
                entry_id,
                group_id
            );
        }
    }

    table
}

#[cfg(feature = "onion")]
fn find_in_chunk_cuckoo(
    table: &[u32],
    entry_id: u32,
    keys: &[u64; CHUNK_CUCKOO_NUM_HASHES],
    bins_per_table: usize,
) -> Option<usize> {
    for &key in keys.iter() {
        let bin = chunk_cuckoo_hash(entry_id, key, bins_per_table);
        if table[bin] == entry_id {
            return Some(bin);
        }
    }
    None
}

// ─── Wire encoding / decoding ──────────────────────────────────────────────

/// Encode a simple request `[4B len LE][1B variant][payload]`.
fn encode_request(variant: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(payload);
    buf
}

/// Encode a `RegisterKeysMsg`.
#[cfg(feature = "onion")]
fn encode_register_keys(galois: &[u8], gsw: &[u8], db_id: u8) -> Vec<u8> {
    let trailing = if db_id != 0 { 1 } else { 0 };
    let payload_len = 1 + 4 + galois.len() + 4 + gsw.len() + trailing;
    let mut buf = Vec::with_capacity(4 + payload_len);
    buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
    buf.push(REQ_REGISTER_KEYS);
    buf.extend_from_slice(&(galois.len() as u32).to_le_bytes());
    buf.extend_from_slice(galois);
    buf.extend_from_slice(&(gsw.len() as u32).to_le_bytes());
    buf.extend_from_slice(gsw);
    if db_id != 0 {
        buf.push(db_id);
    }
    buf
}

/// Encode an `OnionPirBatchQuery` for INDEX (0x51) or CHUNK (0x52) variants.
#[cfg(feature = "onion")]
fn encode_onionpir_batch_query(
    variant: u8,
    round_id: u16,
    queries: &[Vec<u8>],
    db_id: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(variant);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(queries.len() as u8);
    for q in queries {
        payload.extend_from_slice(&(q.len() as u32).to_le_bytes());
        payload.extend_from_slice(q);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let mut msg = Vec::with_capacity(4 + payload.len());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(&payload);
    msg
}

/// Decode an `OnionPirBatchResult` payload (after the variant byte).
///
/// Wire format: `[2B round_id][1B num_groups]({ [4B len][bytes] })*`.
#[cfg(feature = "onion")]
fn decode_onionpir_batch_result(data: &[u8]) -> PirResult<Vec<Vec<u8>>> {
    if data.len() < 3 {
        return Err(PirError::Decode("result batch too short".into()));
    }
    let mut pos = 2; // skip round_id
    let num_groups = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos + 4 > data.len() {
            return Err(PirError::Decode("truncated result len".into()));
        }
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + len > data.len() {
            return Err(PirError::Decode("truncated result bytes".into()));
        }
        results.push(data[pos..pos + len].to_vec());
        pos += len;
    }
    Ok(results)
}

/// Decode a DPF-format database catalog from response bytes (after variant byte).
///
/// This mirrors the layout produced by the unified server for `REQ_GET_DB_CATALOG`.
fn decode_catalog(data: &[u8]) -> PirResult<DatabaseCatalog> {
    if data.len() < 2 {
        return Err(PirError::Decode("catalog too short".into()));
    }
    let num_dbs = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    let mut pos = 2;
    let mut databases = Vec::with_capacity(num_dbs);

    for _ in 0..num_dbs {
        if pos + 3 > data.len() {
            return Err(PirError::Decode("truncated catalog entry header".into()));
        }
        let db_id = data[pos];
        pos += 1;
        let db_type = data[pos];
        pos += 1;
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(PirError::Decode("truncated catalog name".into()));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
        pos += name_len;

        if pos + 26 > data.len() {
            return Err(PirError::Decode("truncated catalog fields".into()));
        }
        let base_height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let chunk_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_k = data[pos];
        pos += 1;
        let chunk_k = data[pos];
        pos += 1;
        let tag_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let dpf_n_index = data[pos];
        pos += 1;
        let dpf_n_chunk = data[pos];
        pos += 1;
        let has_bucket_merkle = data[pos] != 0;
        pos += 1;

        let kind = if db_type == 1 {
            DatabaseKind::Delta { base_height }
        } else {
            DatabaseKind::Full
        };

        databases.push(DatabaseInfo {
            db_id,
            kind,
            name,
            height,
            index_bins,
            chunk_bins,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index,
            dpf_n_chunk,
            has_bucket_merkle,
        });
    }
    Ok(DatabaseCatalog { databases })
}

// ─── JSON parsing (minimal, no serde) ───────────────────────────────────────

/// Parse `"key":<number>` or `"key":"0xHEX"` out of a JSON string.
fn json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        let hex = &rest[..end];
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }
}

/// Find a JSON sub-object `"key":{ ... }` and return its inner slice.
fn extract_json_object<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)?;
    let brace = json[start..].find('{')? + start;
    let mut depth = 0;
    let mut end = brace;
    for (i, c) in json[brace..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = brace + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    Some(&json[brace..end])
}

/// Parse per-DB OnionPIR params from the JSON info response.
///
/// Looks at the top-level `"onionpir"` (main DB, db_id=0) and each entry in
/// `"databases":[ ... ]` with a nested `"onionpir"` object.
fn parse_onion_params_per_db(json: &str) -> std::collections::HashMap<u8, OnionDbParams> {
    let mut out = std::collections::HashMap::new();

    // Main DB (db_id=0) — only if top-level has an onionpir sub-object.
    if let Some(opi) = extract_json_object(json, "onionpir") {
        if let Some(p) = parse_onion_params_from_opi(opi) {
            out.insert(0u8, p);
        }
    }

    // Per-DB entries. The regex-free path: scan "databases":[...] and find
    // each { db_id:.., onionpir:{...} } block.
    if let Some(dbs) = extract_json_object_array(json, "databases") {
        for entry in dbs {
            let id = match json_u64(entry, "db_id") {
                Some(v) => v as u8,
                None => continue,
            };
            if let Some(opi) = extract_json_object(entry, "onionpir") {
                if let Some(p) = parse_onion_params_from_opi(opi) {
                    out.insert(id, p);
                }
            }
        }
    }

    out
}

fn parse_onion_params_from_opi(opi: &str) -> Option<OnionDbParams> {
    Some(OnionDbParams {
        total_packed: json_u64(opi, "total_packed_entries")? as usize,
        index_slots_per_bin: json_u64(opi, "index_slots_per_bin")? as usize,
        index_slot_size: json_u64(opi, "index_slot_size")? as usize,
    })
}

/// Extract array elements of a top-level `"key":[{...},{...},...]` JSON field.
/// Returns each object (including braces) as a `&str`.
fn extract_json_object_array<'a>(json: &'a str, key: &str) -> Option<Vec<&'a str>> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix('[')?;
    let arr_start = json.len() - rest.len();

    let mut depth = 0i32;
    let mut objs = Vec::new();
    let mut current_start: Option<usize> = None;
    for (i, c) in rest.char_indices() {
        let abs = arr_start + i;
        match c {
            '{' => {
                if depth == 0 {
                    current_start = Some(abs);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = current_start.take() {
                        objs.push(&json[s..abs + 1]);
                    }
                }
            }
            ']' if depth == 0 => return Some(objs),
            _ => {}
        }
    }
    Some(objs)
}

/// Build a [`DatabaseCatalog`] from JSON info + optional DPF catalog.
///
/// Prefers DPF catalog data when present (gives real names and heights);
/// otherwise synthesizes a single full-snapshot entry per OnionPIR DB.
fn build_catalog(
    json: &str,
    onion_params: &std::collections::HashMap<u8, OnionDbParams>,
    dpf: Option<&DatabaseCatalog>,
) -> DatabaseCatalog {
    // Index OnionPIR-level params (index_bins, chunk_bins, index_k, chunk_k,
    // tag_seed) by db_id. Falls back to top-level fields if per-DB missing.
    let top_index_bins = json_u64(json, "index_bins_per_table").unwrap_or(0) as u32;
    let top_chunk_bins = json_u64(json, "chunk_bins_per_table").unwrap_or(0) as u32;
    let top_index_k = json_u64(json, "index_k").unwrap_or(75) as u8;
    let top_chunk_k = json_u64(json, "chunk_k").unwrap_or(80) as u8;
    let top_tag_seed = json_u64(json, "tag_seed").unwrap_or(0);
    let top_opi = extract_json_object(json, "onionpir");

    // Prefer DPF-catalog heights when available.
    if let Some(dc) = dpf {
        let mut dbs = Vec::with_capacity(dc.databases.len());
        for d in &dc.databases {
            if !onion_params.contains_key(&d.db_id) {
                // Skip DBs that don't have OnionPIR data on this server.
                continue;
            }
            // Override index/chunk bins with OnionPIR-specific values if present.
            let (opi_bins_idx, opi_bins_chunk, opi_index_k, opi_chunk_k, opi_tag_seed) =
                onion_level_params(json, d.db_id, top_index_bins, top_chunk_bins, top_index_k, top_chunk_k, top_tag_seed);
            dbs.push(DatabaseInfo {
                db_id: d.db_id,
                kind: d.kind,
                name: d.name.clone(),
                height: d.height,
                index_bins: opi_bins_idx,
                chunk_bins: opi_bins_chunk,
                index_k: opi_index_k,
                chunk_k: opi_chunk_k,
                tag_seed: opi_tag_seed,
                dpf_n_index: pir_core::params::compute_dpf_n(opi_bins_idx as usize),
                dpf_n_chunk: pir_core::params::compute_dpf_n(opi_bins_chunk as usize),
                has_bucket_merkle: false,
            });
        }
        if !dbs.is_empty() {
            return DatabaseCatalog { databases: dbs };
        }
    }

    // Fallback: synthesize from OnionPIR JSON alone.
    let mut dbs = Vec::new();
    let mut ids: Vec<u8> = onion_params.keys().copied().collect();
    ids.sort();
    for id in ids {
        let (bins_idx, bins_chunk, index_k, chunk_k, tag_seed) = onion_level_params(
            json, id, top_index_bins, top_chunk_bins, top_index_k, top_chunk_k, top_tag_seed,
        );
        dbs.push(DatabaseInfo {
            db_id: id,
            kind: DatabaseKind::Full,
            name: if id == 0 {
                "main".into()
            } else {
                format!("db{}", id)
            },
            height: 0,
            index_bins: bins_idx,
            chunk_bins: bins_chunk,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index: pir_core::params::compute_dpf_n(bins_idx as usize),
            dpf_n_chunk: pir_core::params::compute_dpf_n(bins_chunk as usize),
            has_bucket_merkle: false,
        });
    }

    // Silence unused-warning when DPF branch didn't run but we built from JSON only.
    let _ = top_opi;

    DatabaseCatalog { databases: dbs }
}

/// Pick OnionPIR level params for a db_id, falling back to top-level defaults.
fn onion_level_params(
    json: &str,
    db_id: u8,
    fallback_index_bins: u32,
    fallback_chunk_bins: u32,
    fallback_index_k: u8,
    fallback_chunk_k: u8,
    fallback_tag_seed: u64,
) -> (u32, u32, u8, u8, u64) {
    let opi_section = if db_id == 0 {
        extract_json_object(json, "onionpir")
    } else {
        // Look for the matching entry in the databases array.
        extract_json_object_array(json, "databases")
            .and_then(|entries| {
                entries
                    .into_iter()
                    .find(|e| json_u64(e, "db_id") == Some(db_id as u64))
            })
            .and_then(|e| extract_json_object(e, "onionpir"))
    };
    if let Some(opi) = opi_section {
        let ib = json_u64(opi, "index_bins_per_table").unwrap_or(fallback_index_bins as u64) as u32;
        let cb = json_u64(opi, "chunk_bins_per_table").unwrap_or(fallback_chunk_bins as u64) as u32;
        let ik = json_u64(opi, "index_k").unwrap_or(fallback_index_k as u64) as u8;
        let ck = json_u64(opi, "chunk_k").unwrap_or(fallback_chunk_k as u64) as u8;
        let ts = json_u64(opi, "tag_seed").unwrap_or(fallback_tag_seed);
        (ib, cb, ik, ck, ts)
    } else {
        (
            fallback_index_bins,
            fallback_chunk_bins,
            fallback_index_k,
            fallback_chunk_k,
            fallback_tag_seed,
        )
    }
}

// ─── Misc helpers ──────────────────────────────────────────────────────────

/// First 8 hex chars of a script hash — for concise audit logs.
#[cfg(feature = "onion")]
fn hex_short(sh: &[u8]) -> String {
    let mut s = String::with_capacity(16 + 3);
    for b in sh.iter().take(8) {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('.');
    s.push('.');
    s.push('.');
    s
}

/// Tiny deterministic PRNG (seeded from wall clock) for dummy query bins.
#[cfg(feature = "onion")]
struct SimpleRng {
    state: u64,
}

#[cfg(feature = "onion")]
impl SimpleRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xcafebabedeadbeef);
        Self {
            state: pir_core::hash::splitmix64(seed),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(pir_core::hash::GOLDEN_RATIO);
        pir_core::hash::splitmix64(self.state)
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_request_simple() {
        let buf = encode_request(0x03, &[]);
        assert_eq!(buf, vec![1, 0, 0, 0, 0x03]);
    }

    #[test]
    fn test_json_u64_decimal() {
        assert_eq!(json_u64(r#"{"k":42,"x":0}"#, "k"), Some(42));
        assert_eq!(json_u64(r#"{"foo":null,"k":7}"#, "k"), Some(7));
    }

    #[test]
    fn test_json_u64_hex() {
        assert_eq!(
            json_u64(r#"{"tag_seed":"0x71a2ef38b4c90d15"}"#, "tag_seed"),
            Some(0x71a2ef38b4c90d15),
        );
    }

    #[test]
    fn test_extract_json_object_nested() {
        let j = r#"{"outer":{"inner":{"a":1}},"x":2}"#;
        assert_eq!(extract_json_object(j, "outer"), Some(r#"{"inner":{"a":1}}"#));
        assert_eq!(extract_json_object(j, "inner"), Some(r#"{"a":1}"#));
    }

    #[test]
    fn test_parse_onion_params_main_only() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_bins_per_table":100,"chunk_bins_per_table":200,"tag_seed":"0x1","index_k":75,"chunk_k":80,"index_slots_per_bin":256,"index_slot_size":15,"chunk_slots_per_bin":1,"chunk_slot_size":3840}}"#;
        let params = parse_onion_params_per_db(j);
        assert_eq!(params.len(), 1);
        let p = params.get(&0).unwrap();
        assert_eq!(p.total_packed, 1000);
        assert_eq!(p.index_slots_per_bin, 256);
        assert_eq!(p.index_slot_size, 15);
    }

    #[test]
    fn test_parse_onion_params_multi_db() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_slots_per_bin":256,"index_slot_size":15},"databases":[{"db_id":0,"onionpir":{"total_packed_entries":1000,"index_slots_per_bin":256,"index_slot_size":15}},{"db_id":1,"onionpir":{"total_packed_entries":50,"index_slots_per_bin":128,"index_slot_size":15}}]}"#;
        let params = parse_onion_params_per_db(j);
        assert_eq!(params.len(), 2);
        assert_eq!(params.get(&0).unwrap().total_packed, 1000);
        assert_eq!(params.get(&1).unwrap().total_packed, 50);
        assert_eq!(params.get(&1).unwrap().index_slots_per_bin, 128);
    }

    #[test]
    fn test_parse_onion_params_no_onionpir() {
        let j = r#"{"index_bins_per_table":100,"chunk_bins_per_table":200}"#;
        assert!(parse_onion_params_per_db(j).is_empty());
    }

    #[test]
    fn test_build_catalog_from_json_only() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_bins_per_table":100,"chunk_bins_per_table":200,"tag_seed":"0xdeadbeef","index_k":75,"chunk_k":80,"index_slots_per_bin":256,"index_slot_size":15,"chunk_slots_per_bin":1,"chunk_slot_size":3840}}"#;
        let params = parse_onion_params_per_db(j);
        let catalog = build_catalog(j, &params, None);
        assert_eq!(catalog.databases.len(), 1);
        let db = &catalog.databases[0];
        assert_eq!(db.db_id, 0);
        assert_eq!(db.index_bins, 100);
        assert_eq!(db.chunk_bins, 200);
        assert_eq!(db.tag_seed, 0xdeadbeef);
        assert!(matches!(db.kind, DatabaseKind::Full));
    }

    #[test]
    fn test_onion_client_new_uninitialised() {
        let c = OnionClient::new("ws://localhost:8091");
        assert_eq!(c.backend_type(), PirBackendType::Onion);
        assert!(!c.is_connected());
        assert!(c.cached_catalog().is_none());
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_register_keys_no_db_id() {
        let buf = encode_register_keys(&[1, 2, 3], &[9, 8], 0);
        // 4B len, variant, 4B galois_len=3, galois=[1,2,3], 4B gsw_len=2, gsw=[9,8]
        // payload_len = 1 + 4 + 3 + 4 + 2 = 14
        assert_eq!(&buf[0..4], &14u32.to_le_bytes());
        assert_eq!(buf[4], REQ_REGISTER_KEYS);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_register_keys_with_db_id() {
        let buf = encode_register_keys(&[1], &[2], 3);
        // payload_len = 1 + 4 + 1 + 4 + 1 + 1 = 12 (trailing db_id byte)
        assert_eq!(&buf[0..4], &12u32.to_le_bytes());
        assert_eq!(*buf.last().unwrap(), 3);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_onionpir_batch_query() {
        let qs = vec![vec![0xaau8, 0xbb], vec![0xcc]];
        let buf = encode_onionpir_batch_query(REQ_ONIONPIR_INDEX_QUERY, 7, &qs, 0);
        // payload: variant(1) + round_id(2) + num_groups(1) + [len(4)+bytes]*
        let expected_payload_len = 1 + 2 + 1 + (4 + 2) + (4 + 1);
        assert_eq!(&buf[0..4], &(expected_payload_len as u32).to_le_bytes());
        assert_eq!(buf[4], REQ_ONIONPIR_INDEX_QUERY);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_decode_onionpir_batch_result_roundtrip() {
        let qs = vec![vec![0x11, 0x22], vec![0x33]];
        let buf = encode_onionpir_batch_query(RESP_ONIONPIR_INDEX_RESULT, 0, &qs, 0);
        // Skip length prefix + variant byte.
        let decoded = decode_onionpir_batch_result(&buf[5..]).unwrap();
        assert_eq!(decoded, qs);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_scan_index_bin_hit() {
        // Single slot: tag=0x42, entry_id=7, byte_offset=100, num_entries=3
        let mut entry = vec![0u8; 15];
        entry[0..8].copy_from_slice(&0x42u64.to_le_bytes());
        entry[8..12].copy_from_slice(&7u32.to_le_bytes());
        entry[12..14].copy_from_slice(&100u16.to_le_bytes());
        entry[14] = 3;
        let ir = scan_index_bin(&entry, 0x42, 1, 15).expect("should find");
        assert_eq!(ir.entry_id, 7);
        assert_eq!(ir.byte_offset, 100);
        assert_eq!(ir.num_entries, 3);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_scan_index_bin_miss() {
        let entry = vec![0u8; 15];
        assert!(scan_index_bin(&entry, 0x42, 1, 15).is_none());
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_chunk_cuckoo_roundtrip() {
        // Build a reverse index and cuckoo table, then verify every assigned
        // entry is findable. Load factor must be comfortably below 1.0 for
        // cuckoo to succeed — with total=200 and k_chunk=10 each group gets
        // ~60 entries (3 PBC hashes), so 256 bins gives ~23% load.
        let total = 200usize;
        let k_chunk = 10usize;
        let bins = 256usize;
        let rev = build_chunk_reverse_index(total, k_chunk);
        // Check all non-empty groups, not just the first — catches
        // regressions that only show up at higher loads.
        for (group, entries) in rev.iter().enumerate() {
            if entries.is_empty() {
                continue;
            }
            let table = build_chunk_cuckoo_for_group(group, &rev, bins);
            let keys = chunk_derive_keys(group);
            for &eid in entries {
                let bin = find_in_chunk_cuckoo(&table, eid, &keys, bins);
                assert!(
                    bin.is_some(),
                    "entry_id {} not found in group {} ({} entries, {} bins)",
                    eid,
                    group,
                    entries.len(),
                    bins
                );
            }
        }
    }
}
