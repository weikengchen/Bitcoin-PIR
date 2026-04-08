//! Unified PIR WebSocket server — serves all 3 protocols from one process.
//!
//! Roles:
//!   --role primary   (default): DPF + OnionPIR + HarmonyPIR (hint + query)
//!   --role secondary:           DPF only (2nd server for 2-server DPF protocol)
//!
//! Uses pir-core's MappedDatabase for table loading instead of legacy CuckooTablePair.
//!
//! Usage:
//!   unified_server --port 8091 [--data-dir /path/to/checkpoint] [--role primary|secondary] [--warmup]
//!     [--checkpoint /path/to/checkpoint <height>]...
//!     [--delta /path/to/delta <base_height> <tip_height>]...

use runtime::eval::{self, GroupTiming};
use runtime::protocol::*;
use runtime::onionpir::*;
use runtime::config::ServerConfig;
use runtime::table::{MappedDatabase, MappedSubTable, DatabaseDescriptor, DatabaseType, ServerState};
use runtime::warmup::{self, MmapRegion};

use futures_util::{SinkExt, StreamExt};
use libdpf::DpfKey;
use pir_core::params::{self, INDEX_PARAMS, CHUNK_PARAMS};
use rayon::prelude::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// HarmonyPIR imports
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;

// OnionPIR imports
use memmap2::Mmap;
use onionpir::{self, Server as PirServer, KeyStore};

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum ServerRole {
    Primary,
    Secondary,
}

struct CliArgs {
    port: u16,
    data_dir: PathBuf,
    role: ServerRole,
    warmup: bool,
    /// Path to databases.toml config file (overrides --checkpoint/--delta).
    config_path: Option<PathBuf>,
    /// Checkpoint databases: (path, height).
    checkpoints: Vec<(PathBuf, u32)>,
    /// Delta databases: (path, base_height, tip_height).
    deltas: Vec<(PathBuf, u32, u32)>,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8091u16;
    let mut data_dir = PathBuf::from("/Volumes/Bitcoin/data/checkpoints/940611");
    let mut role = ServerRole::Primary;
    let mut warmup = false;
    let mut config_path: Option<PathBuf> = None;
    let mut checkpoints: Vec<(PathBuf, u32)> = Vec::new();
    let mut deltas: Vec<(PathBuf, u32, u32)> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(8091);
                i += 1;
            }
            "--data-dir" | "-d" => {
                if let Some(dir) = args.get(i + 1) {
                    data_dir = PathBuf::from(dir);
                }
                i += 1;
            }
            "--role" | "-r" => {
                if let Some(r) = args.get(i + 1) {
                    role = match r.as_str() {
                        "secondary" | "s" | "2" => ServerRole::Secondary,
                        _ => ServerRole::Primary,
                    };
                }
                i += 1;
            }
            "--warmup" | "-w" => {
                warmup = true;
            }
            "--config" | "-c" => {
                if let Some(path) = args.get(i + 1) {
                    config_path = Some(PathBuf::from(path));
                }
                i += 1;
            }
            "--checkpoint" => {
                // --checkpoint <path> <height>
                if let (Some(path), Some(height)) = (
                    args.get(i + 1),
                    args.get(i + 2).and_then(|s| s.parse::<u32>().ok()),
                ) {
                    checkpoints.push((PathBuf::from(path), height));
                    i += 2;
                }
            }
            "--delta" => {
                // --delta <path> <base_height> <tip_height>
                if let (Some(path), Some(base), Some(tip)) = (
                    args.get(i + 1),
                    args.get(i + 2).and_then(|s| s.parse::<u32>().ok()),
                    args.get(i + 3).and_then(|s| s.parse::<u32>().ok()),
                ) {
                    deltas.push((PathBuf::from(path), base, tip));
                    i += 3;
                }
            }
            _ => {}
        }
        i += 1;
    }

    CliArgs { port, data_dir, role, warmup, config_path, checkpoints, deltas }
}

// ─── OnionPIR worker thread ─────────────────────────────────────────────────

enum PirCommand {
    RegisterKeys {
        client_id: u64,
        galois_keys: Vec<u8>,
        gsw_keys: Vec<u8>,
        reply: oneshot::Sender<()>,
    },
    AnswerBatch {
        client_id: u64,
        level: u8,
        round_id: u16,
        queries: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

// ─── OnionPIR file paths + headers ──────────────────────────────────────────

const ONION_NTT_FILE: &str = "onion_shared_ntt.bin";
const ONION_CHUNK_CUCKOO_FILE: &str = "onion_chunk_cuckoo.bin";
const ONION_INDEX_PIR_DIR: &str = "onion_index_pir";
const ONION_INDEX_META_FILE: &str = "onion_index_meta.bin";

const ONION_CHUNK_MAGIC: u64 = 0xBA7C_0010_0000_0001;
const ONION_INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;

struct OnionChunkHeader {
    k_chunk: usize,
    bins_per_table: usize,
    num_packed_entries: usize,
}

fn read_onion_chunk_header(data: &[u8]) -> OnionChunkHeader {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, ONION_CHUNK_MAGIC, "Bad onion chunk cuckoo magic");
    OnionChunkHeader {
        k_chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        num_packed_entries: u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize,
    }
}

struct OnionIndexMeta {
    k: usize,
    bins_per_table: usize,
    slots_per_bin: usize,
    tag_seed: u64,
    slot_size: usize,
}

fn read_onion_index_meta(data: &[u8]) -> OnionIndexMeta {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, ONION_INDEX_META_MAGIC, "Bad onion index meta magic");
    OnionIndexMeta {
        k: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize,
        slots_per_bin: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        tag_seed: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        slot_size: u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize,
    }
}

// ─── HarmonyPIR hint computation ────────────────────────────────────────────

fn derive_group_key(master_key: &[u8; 16], group_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = group_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

fn xor_into_hint(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

fn compute_hints_for_group(
    db: &MappedDatabase,
    prp_key: &[u8; 16],
    prp_backend: u8,
    level: u8,
    group_id: u8,
) -> (u8, u32, u32, u32, Vec<u8>) {
    // Level mapping:
    //   0 = INDEX, 1 = CHUNK
    //   10..10+N = bucket Merkle INDEX sibling L0, L1, ...
    //   20..20+N = bucket Merkle CHUNK sibling L0, L1, ...
    let (sub_table, entry_size, k_offset) = if level == 0 {
        (&db.index, db.index.params.bin_size(), 0u32)
    } else if level == 1 {
        (&db.chunk, db.chunk.params.bin_size(), db.index.params.k as u32)
    } else if level >= 10 && level < 20 {
        let sib_level = (level - 10) as usize;
        if sib_level >= db.bucket_merkle_index_siblings.len() {
            panic!("invalid bucket merkle index sibling level {}", sib_level);
        }
        let sib = &db.bucket_merkle_index_siblings[sib_level];
        // k_offset: after INDEX (75) + CHUNK (80) = 155, plus level offset
        let offset = (db.index.params.k + db.chunk.params.k) as u32 + sib_level as u32 * db.index.params.k as u32;
        (sib, sib.params.bin_size(), offset)
    } else if level >= 20 && level < 30 {
        let sib_level = (level - 20) as usize;
        if sib_level >= db.bucket_merkle_chunk_siblings.len() {
            panic!("invalid bucket merkle chunk sibling level {}", sib_level);
        }
        let sib = &db.bucket_merkle_chunk_siblings[sib_level];
        let index_sib_levels = db.bucket_merkle_index_siblings.len();
        let offset = (db.index.params.k + db.chunk.params.k) as u32
            + (index_sib_levels * db.index.params.k + sib_level * db.chunk.params.k) as u32;
        (sib, sib.params.bin_size(), offset)
    } else {
        panic!("invalid hint level {}", level);
    };

    let real_n = sub_table.bins_per_table;
    let w = entry_size;

    let t_raw = harmonypir_wasm::find_best_t(real_n as u32);
    let (padded_n, t_val) = harmonypir_wasm::pad_n_for_t(real_n as u32, t_raw);
    let pn = padded_n as usize;
    let t = t_val as usize;

    let params = Params::new(pn, w, t).expect("valid params");
    let m = params.m;

    let derived_key = derive_group_key(prp_key, k_offset + group_id as u32);
    let domain = 2 * pn;
    let r = harmonypir_wasm::compute_rounds(padded_n);

    use harmonypir::prp::BatchPrp;
    use harmonypir::prp::fast::FastPrpWrapper;
    use harmonypir::prp::alf::AlfPrp;
    let cell_of: Vec<usize> = match prp_backend {
        harmonypir_wasm::PRP_FASTPRP => {
            let prp = FastPrpWrapper::new(&derived_key, domain);
            prp.batch_forward()
        }
        harmonypir_wasm::PRP_ALF => {
            let prp = AlfPrp::new(&derived_key, domain, &derived_key, 0x4250_4952);
            prp.batch_forward()
        }
        _ => {
            let prp = HoangPrp::new(domain, r, &derived_key);
            prp.batch_forward()
        }
    };

    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();
    let table_bytes = sub_table.group_bytes(group_id as usize);
    for k in 0..pn {
        let segment = cell_of[k] / t;
        if k < real_n {
            let entry = &table_bytes[k * entry_size..(k + 1) * entry_size];
            xor_into_hint(&mut hints[segment], entry);
        }
    }

    let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();
    (group_id, padded_n, t_val as u32, m as u32, flat)
}

// ─── Server state ───────────────────────────────────────────────────────────

struct UnifiedServerData {
    state: ServerState,
    role: ServerRole,
    /// OnionPIR worker channels indexed by db_id.
    /// Each entry is `None` if that DB has no OnionPIR data (or if secondary role).
    /// Length matches `state.databases.len()`.
    onionpir_txs: Vec<Option<Arc<mpsc::Sender<PirCommand>>>>,
    /// Per-DB OnionPIR parameters (None if that DB has no OnionPIR data).
    /// Length matches `state.databases.len()`.
    onionpir_infos: Vec<Option<OnionPirInfo>>,
    /// OnionPIR Merkle sibling info for the main DB (if available).
    /// Per-DB Merkle is intentionally not yet supported — only db_id=0.
    onionpir_merkle: Option<OnionPirMerkleInfo>,
    /// All mmap'd regions for residency monitoring.
    mmap_regions: Vec<MmapRegion>,
}

impl UnifiedServerData {
    /// Main UTXO database (db_id=0). Always present.
    fn main_db(&self) -> &MappedDatabase {
        self.state.get_db(0).expect("main database must be loaded")
    }

    /// Whether ANY database has OnionPIR data loaded (used as a request guard).
    fn has_any_onionpir(&self) -> bool {
        self.onionpir_txs.iter().any(|t| t.is_some())
    }

    /// Look up the OnionPIR worker channel for a specific db_id.
    /// Returns `None` if the db_id is out of range or if that DB has no OnionPIR data.
    fn onionpir_tx_for(&self, db_id: u8) -> Option<&Arc<mpsc::Sender<PirCommand>>> {
        self.onionpir_txs.get(db_id as usize).and_then(|o| o.as_ref())
    }
}

#[derive(Clone)]
struct OnionPirMerkleLevelInfo {
    k: usize,
    bins_per_table: usize,
    num_groups: usize,
}

/// Per-bin Merkle sub-tree info (INDEX or DATA).
#[derive(Clone)]
struct OnionPirMerkleSubTree {
    levels: Vec<OnionPirMerkleLevelInfo>,
    root_hex: String,
    tree_top: Vec<u8>,
}

/// Two per-bin Merkle trees: INDEX-MERKLE and DATA-MERKLE.
#[derive(Clone)]
struct OnionPirMerkleInfo {
    arity: usize,
    index_tree: OnionPirMerkleSubTree,
    data_tree: OnionPirMerkleSubTree,
}

#[derive(Clone)]
struct OnionPirInfo {
    total_packed_entries: u32,
    index_bins_per_table: u32,
    chunk_bins_per_table: u32,
    index_k: u8,
    chunk_k: u8,
    tag_seed: u64,
    index_slots_per_bin: u16,
    index_slot_size: u8,
}

impl UnifiedServerData {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            index_bins_per_table: self.main_db().index.bins_per_table as u32,
            chunk_bins_per_table: self.main_db().chunk.bins_per_table as u32,
            index_k: self.main_db().index.params.k as u8,
            chunk_k: self.main_db().chunk.params.k as u8,
            tag_seed: self.main_db().index.tag_seed,
        }
    }


    /// Build a JSON server info string covering all protocols.
    fn server_info_json(&self) -> String {
        let mut json = format!(
            r#"{{"index_bins_per_table":{},"chunk_bins_per_table":{},"index_k":{},"chunk_k":{},"tag_seed":"0x{:016x}","index_dpf_n":{},"chunk_dpf_n":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":{},"chunk_slot_size":{},"role":"{}""#,
            self.main_db().index.bins_per_table,
            self.main_db().chunk.bins_per_table,
            self.main_db().index.params.k,
            self.main_db().chunk.params.k,
            self.main_db().index.tag_seed,
            params::compute_dpf_n(self.main_db().index.bins_per_table),
            params::compute_dpf_n(self.main_db().chunk.bins_per_table),
            self.main_db().index.params.slots_per_bin,
            self.main_db().index.params.slot_size,
            self.main_db().chunk.params.slots_per_bin,
            self.main_db().chunk.params.slot_size,
            match self.role { ServerRole::Primary => "primary", ServerRole::Secondary => "secondary" },
        );

        if let Some(Some(ref opi)) = self.onionpir_infos.get(0) {
            json.push_str(&format!(
                r#","onionpir":{{"total_packed_entries":{},"index_bins_per_table":{},"chunk_bins_per_table":{},"tag_seed":"0x{:016x}","index_k":{},"chunk_k":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":1,"chunk_slot_size":{}}}"#,
                opi.total_packed_entries, opi.index_bins_per_table, opi.chunk_bins_per_table,
                opi.tag_seed, opi.index_k, opi.chunk_k,
                opi.index_slots_per_bin, opi.index_slot_size,
                3840, // PACKED_ENTRY_SIZE = 3.75KB fixed bin size for OnionPIR chunks
            ));
        }

        if let Some(ref om) = self.onionpir_merkle {
            // Per-bin Merkle with two sub-trees: index and data
            json.push_str(&format!(r#","onionpir_merkle":{{"arity":{}"#, om.arity));

            // INDEX sub-tree
            let it = &om.index_tree;
            json.push_str(&format!(r#","index":{{"sibling_levels":{},"levels":["#, it.levels.len()));
            for (i, lv) in it.levels.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(r#"{{"k":{},"bins_per_table":{},"num_groups":{}}}"#,
                    lv.k, lv.bins_per_table, lv.num_groups));
            }
            json.push_str("]");
            json.push_str(&format!(r#","root":"{}""#, it.root_hex));
            let top_hash = pir_core::merkle::sha256(&it.tree_top);
            json.push_str(&format!(r#","tree_top_hash":"{}""#,
                top_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
            json.push_str(&format!(r#","tree_top_size":{}}}"#, it.tree_top.len()));

            // DATA sub-tree
            let dt = &om.data_tree;
            json.push_str(&format!(r#","data":{{"sibling_levels":{},"levels":["#, dt.levels.len()));
            for (i, lv) in dt.levels.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(r#"{{"k":{},"bins_per_table":{},"num_groups":{}}}"#,
                    lv.k, lv.bins_per_table, lv.num_groups));
            }
            json.push_str("]");
            json.push_str(&format!(r#","root":"{}""#, dt.root_hex));
            let top_hash = pir_core::merkle::sha256(&dt.tree_top);
            json.push_str(&format!(r#","tree_top_hash":"{}""#,
                top_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
            json.push_str(&format!(r#","tree_top_size":{}}}"#, dt.tree_top.len()));

            json.push('}');
        }

        if self.main_db().has_merkle() {
            let arity = self.main_db().merkle_arity;
            let num_levels = self.main_db().merkle_siblings.len();
            json.push_str(&format!(
                r#","merkle":{{"arity":{},"sibling_levels":{},"sibling_k":{},"sibling_bucket_size":{},"sibling_slot_size":{},"levels":["#,
                arity, num_levels,
                75, // K for sibling tables
                4,  // slots_per_bin
                pir_core::merkle::merkle_sibling_slot_size(arity),
            ));
            for (i, sib) in self.main_db().merkle_siblings.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(
                    r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                    params::compute_dpf_n(sib.bins_per_table),
                    sib.bins_per_table,
                ));
            }
            json.push_str("]");
            // Root hash as hex
            if let Some(ref root) = self.main_db().merkle_root {
                json.push_str(&format!(r#","root":"{}""#,
                    root.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
            }
            // Tree-top: send SHA256 hash of the cache blob (32 bytes hex) for compact verification.
            // Client fetches the full cache separately if needed (or trusts the hash).
            if let Some(ref top) = self.main_db().merkle_tree_top {
                let top_hash = pir_core::merkle::sha256(top);
                json.push_str(&format!(r#","tree_top_hash":"{}""#,
                    top_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
                json.push_str(&format!(r#","tree_top_size":{}"#, top.len()));
            }
            json.push('}');
        }

        // Per-bucket bin Merkle info
        if self.main_db().has_bucket_merkle() {
            json.push_str(r#","merkle_bucket":{"arity":8,"#);

            // INDEX sibling levels
            json.push_str(r#""index_levels":["#);
            for (i, sib) in self.main_db().bucket_merkle_index_siblings.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(
                    r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                    params::compute_dpf_n(sib.bins_per_table),
                    sib.bins_per_table,
                ));
            }
            json.push_str("],");

            // CHUNK sibling levels
            json.push_str(r#""chunk_levels":["#);
            for (i, sib) in self.main_db().bucket_merkle_chunk_siblings.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(
                    r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                    params::compute_dpf_n(sib.bins_per_table),
                    sib.bins_per_table,
                ));
            }
            json.push_str("],");

            // Per-group roots as hex arrays
            if let Some(ref roots_data) = self.main_db().bucket_merkle_roots {
                let index_k = self.main_db().index.params.k;
                let chunk_k = self.main_db().chunk.params.k;

                json.push_str(r#""index_roots":["#);
                for g in 0..index_k {
                    if g > 0 { json.push(','); }
                    let root = &roots_data[g * 32..(g + 1) * 32];
                    json.push('"');
                    for b in root { json.push_str(&format!("{:02x}", b)); }
                    json.push('"');
                }
                json.push_str("],");

                json.push_str(r#""chunk_roots":["#);
                for g in 0..chunk_k {
                    if g > 0 { json.push(','); }
                    let root = &roots_data[(index_k + g) * 32..(index_k + g + 1) * 32];
                    json.push('"');
                    for b in root { json.push_str(&format!("{:02x}", b)); }
                    json.push('"');
                }
                json.push_str("],");
            }

            // Super-root
            if let Some(ref sr) = self.main_db().bucket_merkle_root {
                json.push_str(&format!(r#""super_root":"{}","#,
                    sr.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
            }

            // Tree-tops hash and size
            if let Some(ref tops) = self.main_db().bucket_merkle_tree_tops {
                let tops_hash = pir_core::merkle::sha256(tops);
                json.push_str(&format!(r#""tree_tops_hash":"{}","tree_tops_size":{}"#,
                    tops_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                    tops.len()));
            }

            json.push('}');
        }

        // Per-database info array (Merkle availability + params for each DB)
        if self.state.databases.len() > 1 || self.state.databases.iter().any(|db| db.has_bucket_merkle()) {
            json.push_str(r#","databases":["#);
            for (i, db) in self.state.databases.iter().enumerate() {
                if i > 0 { json.push(','); }
                json.push_str(&format!(r#"{{"db_id":{},"has_bucket_merkle":{}"#,
                    i, db.has_bucket_merkle()));

                if db.has_bucket_merkle() {
                    json.push_str(r#","merkle_bucket":{"arity":8,"#);

                    // INDEX sibling levels
                    json.push_str(r#""index_levels":["#);
                    for (li, sib) in db.bucket_merkle_index_siblings.iter().enumerate() {
                        if li > 0 { json.push(','); }
                        json.push_str(&format!(
                            r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                            params::compute_dpf_n(sib.bins_per_table),
                            sib.bins_per_table,
                        ));
                    }
                    json.push_str("],");

                    // CHUNK sibling levels
                    json.push_str(r#""chunk_levels":["#);
                    for (li, sib) in db.bucket_merkle_chunk_siblings.iter().enumerate() {
                        if li > 0 { json.push(','); }
                        json.push_str(&format!(
                            r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                            params::compute_dpf_n(sib.bins_per_table),
                            sib.bins_per_table,
                        ));
                    }
                    json.push_str("],");

                    // Per-group roots
                    if let Some(ref roots_data) = db.bucket_merkle_roots {
                        let index_k = db.index.params.k;
                        let chunk_k = db.chunk.params.k;

                        json.push_str(r#""index_roots":["#);
                        for g in 0..index_k {
                            if g > 0 { json.push(','); }
                            let root = &roots_data[g * 32..(g + 1) * 32];
                            json.push('"');
                            for b in root { json.push_str(&format!("{:02x}", b)); }
                            json.push('"');
                        }
                        json.push_str("],");

                        json.push_str(r#""chunk_roots":["#);
                        for g in 0..chunk_k {
                            if g > 0 { json.push(','); }
                            let root = &roots_data[(index_k + g) * 32..(index_k + g + 1) * 32];
                            json.push('"');
                            for b in root { json.push_str(&format!("{:02x}", b)); }
                            json.push('"');
                        }
                        json.push_str("],");
                    }

                    if let Some(ref sr) = db.bucket_merkle_root {
                        json.push_str(&format!(r#""super_root":"{}","#,
                            sr.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
                    }

                    if let Some(ref tops) = db.bucket_merkle_tree_tops {
                        let tops_hash = pir_core::merkle::sha256(tops);
                        json.push_str(&format!(r#""tree_tops_hash":"{}","tree_tops_size":{}"#,
                            tops_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                            tops.len()));
                    }

                    json.push('}'); // close merkle_bucket
                }

                json.push('}'); // close database entry
            }
            json.push(']'); // close databases array
        }

        json.push('}');
        json
    }

    /// Encode a JSON info response as a length-prefixed binary message.
    fn encode_info_json_response(&self, variant: u8) -> Vec<u8> {
        let json = self.server_info_json();
        let json_bytes = json.as_bytes();
        // Wire: [4B length LE][1B variant][json bytes]
        let payload_len = 1 + json_bytes.len();
        let mut msg = Vec::with_capacity(4 + payload_len);
        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
        msg.push(variant);
        msg.extend_from_slice(json_bytes);
        msg
    }

    fn build_catalog(&self) -> DatabaseCatalog {
        DatabaseCatalog {
            databases: self.state.databases.iter().enumerate().map(|(i, db)| {
                DatabaseCatalogEntry {
                    db_id: i as u8,
                    db_type: match db.descriptor.db_type {
                        DatabaseType::Full => 0,
                        DatabaseType::Delta => 1,
                    },
                    name: db.descriptor.name.clone(),
                    base_height: db.descriptor.base_height,
                    height: db.descriptor.height,
                    index_bins_per_table: db.index.bins_per_table as u32,
                    chunk_bins_per_table: db.chunk.bins_per_table as u32,
                    index_k: db.index.params.k as u8,
                    chunk_k: db.chunk.params.k as u8,
                    tag_seed: db.index.tag_seed,
                    dpf_n_index: params::compute_dpf_n(db.index.bins_per_table),
                    dpf_n_chunk: params::compute_dpf_n(db.chunk.bins_per_table),
                    has_bucket_merkle: db.has_bucket_merkle(),
                }
            }).collect(),
        }
    }

    fn process_index_batch(&self, query: &BatchQuery, db: &MappedDatabase) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = db.index.params.k;
        let num_groups = query.keys.len().min(k);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.index.group_bytes(b);
                let (r0, r1, timing) = eval::process_index_group(
                    &key_refs[0], &key_refs[1],
                    table_bytes,
                    db.index.bins_per_table,
                );
                (vec![r0, r1], timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (BatchResult { level: 0, round_id: 0, results }, total_dpf, total_fetch)
    }

    fn process_chunk_batch(&self, query: &BatchQuery, db: &MappedDatabase) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = db.chunk.params.k;
        let num_groups = query.keys.len().min(k);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.chunk.group_bytes(b);
                let (r, timing) = eval::process_chunk_group(
                    &key_refs,
                    table_bytes,
                    db.chunk.bins_per_table,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (BatchResult { level: 1, round_id: query.round_id, results }, total_dpf, total_fetch)
    }

    fn process_merkle_sibling_batch(&self, query: &BatchQuery, db: &MappedDatabase) -> (BatchResult, std::time::Duration, std::time::Duration) {
        // round_id encoding: `level * 100 + pbc_round_index`
        // The server only cares about the sibling level (which table to query).
        // The PBC round index is just echoed back for client-side correlation.
        let level = (query.round_id as usize) / 100;
        let sib_table = &db.merkle_siblings[level];
        let k = sib_table.params.k;
        let result_size = sib_table.params.bin_size(); // slots_per_bin × slot_size
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = sib_table.group_bytes(b);
                let (r, timing) = eval::process_merkle_sibling_group(
                    &key_refs,
                    table_bytes,
                    sib_table.bins_per_table,
                    result_size,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (BatchResult { level: 2, round_id: query.round_id, results }, total_dpf, total_fetch)
    }

    /// Generic DPF batch evaluation against any MappedSubTable.
    fn process_generic_batch(&self, query: &BatchQuery, table: &MappedSubTable)
        -> (BatchResult, std::time::Duration, std::time::Duration)
    {
        let k = table.params.k;
        let result_size = table.params.bin_size();
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = table.group_bytes(b);
                let (r, timing) = eval::process_merkle_sibling_group(
                    &key_refs,
                    table_bytes,
                    table.bins_per_table,
                    result_size,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (BatchResult { level: query.level, round_id: query.round_id, results }, total_dpf, total_fetch)
    }

    fn handle_harmony_query(&self, query: &HarmonyQuery) -> Response {
        let (sub_table, entry_size) = match query.level {
            0 => (&self.main_db().index, self.main_db().index.params.bin_size()),
            1 => (&self.main_db().chunk, self.main_db().chunk.params.bin_size()),
            _ => return Response::Error("invalid level".into()),
        };

        let group_id = query.group_id as usize;
        let table_bytes = sub_table.group_bytes(group_id);

        let mut data = Vec::with_capacity(query.indices.len() * entry_size);
        for &idx in &query.indices {
            let idx_usize = idx as usize;
            if idx_usize >= sub_table.bins_per_table {
                return Response::Error(format!("index {} out of range", idx));
            }
            let offset = idx_usize * entry_size;
            data.extend_from_slice(&table_bytes[offset..offset + entry_size]);
        }

        Response::HarmonyQueryResult(HarmonyQueryResult {
            group_id: query.group_id,
            round_id: query.round_id,
            data,
        })
    }

    fn handle_harmony_batch_query(&self, query: &HarmonyBatchQuery) -> Response {
        // Level mapping (same as hint levels):
        //   0 = INDEX, 1 = CHUNK
        //   10..10+N = bucket Merkle INDEX sibling L0, L1, ...
        //   20..20+N = bucket Merkle CHUNK sibling L0, L1, ...
        let (sub_table, entry_size) = if query.level == 0 {
            (&self.main_db().index, self.main_db().index.params.bin_size())
        } else if query.level == 1 {
            (&self.main_db().chunk, self.main_db().chunk.params.bin_size())
        } else if query.level >= 10 && query.level < 20 {
            let sib_level = (query.level - 10) as usize;
            if sib_level >= self.main_db().bucket_merkle_index_siblings.len() {
                return Response::Error(format!("invalid bucket merkle index sib level {}", sib_level));
            }
            let sib = &self.main_db().bucket_merkle_index_siblings[sib_level];
            (sib, sib.params.bin_size())
        } else if query.level >= 20 && query.level < 30 {
            let sib_level = (query.level - 20) as usize;
            if sib_level >= self.main_db().bucket_merkle_chunk_siblings.len() {
                return Response::Error(format!("invalid bucket merkle chunk sib level {}", sib_level));
            }
            let sib = &self.main_db().bucket_merkle_chunk_siblings[sib_level];
            (sib, sib.params.bin_size())
        } else {
            return Response::Error(format!("invalid level {}", query.level));
        };

        let result_items: Vec<HarmonyBatchResultItem> = query.items
            .par_iter()
            .map(|item| {
                let table_bytes = sub_table.group_bytes(item.group_id as usize);
                let sub_results: Vec<Vec<u8>> = item.sub_queries.iter().map(|indices| {
                    let mut data = Vec::with_capacity(indices.len() * entry_size);
                    for &idx in indices {
                        let idx_usize = idx as usize;
                        if idx_usize < sub_table.bins_per_table {
                            let off = idx_usize * entry_size;
                            data.extend_from_slice(&table_bytes[off..off + entry_size]);
                        } else {
                            data.extend(std::iter::repeat(0u8).take(entry_size));
                        }
                    }
                    data
                }).collect();
                HarmonyBatchResultItem { group_id: item.group_id, sub_results }
            })
            .collect();

        Response::HarmonyBatchResult(HarmonyBatchResult {
            level: query.level,
            round_id: query.round_id,
            sub_results_per_group: query.sub_queries_per_group,
            items: result_items,
        })
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    let role_name = match args.role {
        ServerRole::Primary => "primary",
        ServerRole::Secondary => "secondary",
    };

    println!("=== Unified PIR Server ({}) ===", role_name);
    println!("  Port:     {}", args.port);
    if let Some(ref config_path) = args.config_path {
        println!("  Config:   {}", config_path.display());
    } else {
        println!("  Data dir: {}", args.data_dir.display());
        for (path, height) in &args.checkpoints {
            println!("  Checkpoint: {} (height={})", path.display(), height);
        }
        for (path, base, tip) in &args.deltas {
            println!("  Delta:      {} ({}→{})", path.display(), base, tip);
        }
    }
    println!();

    let total_start = Instant::now();

    // ── Load databases ─────────────────────────────────────────────────
    let mut all_databases: Vec<MappedDatabase> = Vec::new();
    let mut mmap_regions: Vec<MmapRegion> = Vec::new();
    // Per-DB source directories for OnionPIR loading (db_id, label, path).
    // Populated alongside `all_databases` so OnionPIR setup can iterate over
    // every loaded DB and look for its OnionPIR files.
    let mut db_paths: Vec<(u8, String, PathBuf)> = Vec::new();

    // The data_dir for OnionPIR / Merkle files = first database's directory.
    let main_data_dir: PathBuf;

    if let Some(ref config_path) = args.config_path {
        let config = ServerConfig::load(config_path);
        println!("[config] Loaded {} databases from {}", config.databases.len(), config_path.display());

        for (i, db_cfg) in config.databases.iter().enumerate() {
            let db_type = match db_cfg.db_type.as_str() {
                "delta" => DatabaseType::Delta,
                _ => DatabaseType::Full,
            };
            let db_path = config.db_path(i);
            let db = MappedDatabase::load(&db_path, DatabaseDescriptor {
                name: db_cfg.name.clone(),
                db_type,
                base_height: db_cfg.base_height,
                height: db_cfg.height,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            });
            let type_label = if db_type == DatabaseType::Delta {
                format!("Delta:{}→{}", db_cfg.base_height, db_cfg.height)
            } else {
                format!("Full:{}", db_cfg.height)
            };
            println!("[{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}, priority={}",
                type_label, db.index.bins_per_table, db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table),
                db_cfg.priority);
            mmap_regions.push(MmapRegion {
                name: format!("{}/batch_pir_cuckoo.bin", db_cfg.name),
                ptr: db.index.mmap.as_ptr(), len: db.index.mmap.len(), priority: db_cfg.priority,
            });
            mmap_regions.push(MmapRegion {
                name: format!("{}/chunk_pir_cuckoo.bin", db_cfg.name),
                ptr: db.chunk.mmap.as_ptr(), len: db.chunk.mmap.len(), priority: db_cfg.priority,
            });
            db_paths.push((i as u8, db_cfg.name.clone(), db_path));
            all_databases.push(db);
        }

        // First database's directory is used for OnionPIR / Merkle files.
        main_data_dir = config.db_path(0);
    } else {
        // Legacy CLI mode: --data-dir + --checkpoint + --delta

        let main_db = MappedDatabase::load(&args.data_dir, DatabaseDescriptor {
            name: "main".to_string(),
            db_type: DatabaseType::Full,
            base_height: 0,
            height: 0,
            index_params: INDEX_PARAMS,
            chunk_params: CHUNK_PARAMS,
        });

        mmap_regions.push(MmapRegion { name: "batch_pir_cuckoo.bin".into(), ptr: main_db.index.mmap.as_ptr(), len: main_db.index.mmap.len(), priority: 1 });
        mmap_regions.push(MmapRegion { name: "chunk_pir_cuckoo.bin".into(), ptr: main_db.chunk.mmap.as_ptr(), len: main_db.chunk.mmap.len(), priority: 1 });
        db_paths.push((0u8, "main".to_string(), args.data_dir.clone()));
        all_databases.push(main_db);

        for (path, height) in &args.checkpoints {
            let name = format!("checkpoint_{}", height);
            let db = MappedDatabase::load(path, DatabaseDescriptor {
                name: name.clone(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: *height,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            });
            println!("[Checkpoint:{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                height, db.index.bins_per_table, db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table));
            mmap_regions.push(MmapRegion {
                name: format!("{}/batch_pir_cuckoo.bin", name),
                ptr: db.index.mmap.as_ptr(), len: db.index.mmap.len(), priority: 5,
            });
            mmap_regions.push(MmapRegion {
                name: format!("{}/chunk_pir_cuckoo.bin", name),
                ptr: db.chunk.mmap.as_ptr(), len: db.chunk.mmap.len(), priority: 5,
            });
            db_paths.push((all_databases.len() as u8, name, path.clone()));
            all_databases.push(db);
        }

        for (path, base, tip) in &args.deltas {
            let name = format!("delta_{}_{}", base, tip);
            let db = MappedDatabase::load(path, DatabaseDescriptor {
                name: name.clone(),
                db_type: DatabaseType::Delta,
                base_height: *base,
                height: *tip,
                index_params: INDEX_PARAMS,
                chunk_params: CHUNK_PARAMS,
            });
            println!("[Delta:{}→{}] INDEX bins={}, CHUNK bins={}, dpf_n_index={}, dpf_n_chunk={}",
                base, tip, db.index.bins_per_table, db.chunk.bins_per_table,
                params::compute_dpf_n(db.index.bins_per_table),
                params::compute_dpf_n(db.chunk.bins_per_table));
            mmap_regions.push(MmapRegion {
                name: format!("{}/batch_pir_cuckoo.bin", name),
                ptr: db.index.mmap.as_ptr(), len: db.index.mmap.len(), priority: 10,
            });
            mmap_regions.push(MmapRegion {
                name: format!("{}/chunk_pir_cuckoo.bin", name),
                ptr: db.chunk.mmap.as_ptr(), len: db.chunk.mmap.len(), priority: 10,
            });
            db_paths.push((all_databases.len() as u8, name, path.clone()));
            all_databases.push(db);
        }

        main_data_dir = args.data_dir.clone();
    }

    let main_db = &all_databases[0];
    let index_k = main_db.index.params.k;
    let chunk_k = main_db.chunk.params.k;

    // ── Set up OnionPIR per-DB (primary only, if data available) ──────────
    //
    // Each database can have its own OnionPIR data. Loading is per-DB:
    //   onionpir_txs[db_id]    = Some(channel) if db has OnionPIR data
    //   onionpir_infos[db_id]  = Some(info)    if db has OnionPIR data
    //   onionpir_merkle        = main DB only (db_id=0)
    //
    // db_paths was already populated alongside `all_databases` above; it's
    // a list of (db_id, label, source_dir) for every loaded database.

    let num_total_dbs = db_paths.len();
    let mut onionpir_txs: Vec<Option<Arc<mpsc::Sender<PirCommand>>>> = vec![None; num_total_dbs];
    let mut onionpir_infos: Vec<Option<OnionPirInfo>> = (0..num_total_dbs).map(|_| None).collect();

    // Per-bin Merkle: two sub-trees (INDEX-MERKLE and DATA-MERKLE) — main DB only
    let mut index_merkle_sib_infos: Vec<OnionPirMerkleLevelInfo> = Vec::new();
    let mut data_merkle_sib_infos: Vec<OnionPirMerkleLevelInfo> = Vec::new();
    let mut index_merkle_root: Option<Vec<u8>> = None;
    let mut data_merkle_root: Option<Vec<u8>> = None;
    let mut index_merkle_tree_top: Option<Vec<u8>> = None;
    let mut data_merkle_tree_top: Option<Vec<u8>> = None;
    let mut num_index_sibling_levels: usize = 0;
    let mut num_data_sibling_levels: usize = 0;

    // Per-bin Merkle sibling DBs are only ever loaded for the main DB.
    struct SiblingLevelData {
        k: usize,
        bins_per_table: usize,
        num_groups: usize,
        cuckoo_tables: Vec<Vec<u32>>,
        ntt_mmap: Mmap,
    }

    fn load_merkle_sib_levels(
        data_dir: &std::path::Path,
        prefix: &str,
        mmap_regions: &mut Vec<MmapRegion>,
    ) -> Vec<SiblingLevelData> {
        let mut levels: Vec<SiblingLevelData> = Vec::new();
        for level in 0..10 {
            let ntt_path = data_dir.join(format!("merkle_onion_{}_sib_L{}_ntt.bin", prefix, level));
            let cuckoo_path = data_dir.join(format!("merkle_onion_{}_sib_L{}_cuckoo.bin", prefix, level));
            if !ntt_path.exists() || !cuckoo_path.exists() { break; }

            let cuckoo_data = std::fs::read(&cuckoo_path).expect("read sibling cuckoo");
            let k = u32::from_le_bytes(cuckoo_data[8..12].try_into().unwrap()) as usize;
            let bins_per_table = u32::from_le_bytes(cuckoo_data[16..20].try_into().unwrap()) as usize;
            let num_groups = u32::from_le_bytes(cuckoo_data[28..32].try_into().unwrap()) as usize;

            let header_size = 36;
            let mut tables: Vec<Vec<u32>> = Vec::with_capacity(k);
            for g in 0..k {
                let offset = header_size + g * bins_per_table * 4;
                let mut table = Vec::with_capacity(bins_per_table);
                for b in 0..bins_per_table {
                    let pos = offset + b * 4;
                    let eid = u32::from_le_bytes(cuckoo_data[pos..pos + 4].try_into().unwrap());
                    table.push(eid);
                }
                tables.push(table);
            }

            let ntt_file = std::fs::File::open(&ntt_path).expect("open sibling NTT");
            let ntt_mm = unsafe { Mmap::map(&ntt_file) }.expect("mmap sibling NTT");

            println!("  {} Sibling L{}: K={}, bins={}, groups={}, NTT={:.2} GB",
                prefix, level, k, bins_per_table, num_groups, ntt_mm.len() as f64 / 1e9);
            mmap_regions.push(MmapRegion {
                name: format!("merkle_onion_{}_sib_L{}_ntt.bin", prefix, level),
                ptr: ntt_mm.as_ptr(),
                len: ntt_mm.len(),
                priority: 2,
            });

            levels.push(SiblingLevelData { k, bins_per_table, num_groups, cuckoo_tables: tables, ntt_mmap: ntt_mm });
        }
        levels
    }

    if args.role == ServerRole::Primary {
        for (db_id, db_label, db_dir) in &db_paths {
            let ntt_path = db_dir.join(ONION_NTT_FILE);
            if !ntt_path.exists() {
                println!("[OnionPIR:{}] Not available (no {} in {})", db_label, ONION_NTT_FILE, db_dir.display());
                continue;
            }
            println!("[OnionPIR:{}] Loading data...", db_label);

            let chunk_cuckoo_path = db_dir.join(ONION_CHUNK_CUCKOO_FILE);
            let index_pir_dir = db_dir.join(ONION_INDEX_PIR_DIR);
            let index_meta_path = db_dir.join(ONION_INDEX_META_FILE);

            // Read OnionPIR-specific headers
            let cuckoo_data = std::fs::read(&chunk_cuckoo_path).expect("read onion chunk cuckoo");
            let ch = read_onion_chunk_header(&cuckoo_data);
            let meta_data = std::fs::read(&index_meta_path).expect("read onion index meta");
            let im = read_onion_index_meta(&meta_data);

            println!("  Chunk: K={}, bins={}, packed={}", ch.k_chunk, ch.bins_per_table, ch.num_packed_entries);
            println!("  Index: K={}, bins={}, slots_per_bin={}", im.k, im.bins_per_table, im.slots_per_bin);

            onionpir_infos[*db_id as usize] = Some(OnionPirInfo {
                total_packed_entries: ch.num_packed_entries as u32,
                index_bins_per_table: im.bins_per_table as u32,
                chunk_bins_per_table: ch.bins_per_table as u32,
                index_k: im.k as u8,
                chunk_k: ch.k_chunk as u8,
                tag_seed: im.tag_seed,
                index_slots_per_bin: im.slots_per_bin as u16,
                index_slot_size: im.slot_size as u8,
            });

            // Parse chunk cuckoo tables
            let header_size = 36;
            let mut chunk_tables: Vec<Vec<u32>> = Vec::with_capacity(ch.k_chunk);
            for g in 0..ch.k_chunk {
                let offset = header_size + g * ch.bins_per_table * 4;
                let mut table = Vec::with_capacity(ch.bins_per_table);
                for b in 0..ch.bins_per_table {
                    let pos = offset + b * 4;
                    let eid = u32::from_le_bytes(cuckoo_data[pos..pos + 4].try_into().unwrap());
                    table.push(eid);
                }
                chunk_tables.push(table);
            }

            // Load NTT store
            let ntt_file = std::fs::File::open(&ntt_path).expect("open NTT store");
            let ntt_mmap = unsafe { Mmap::map(&ntt_file) }.expect("mmap NTT store");
            println!("  NTT store: {:.2} GB", ntt_mmap.len() as f64 / 1e9);
            mmap_regions.push(MmapRegion {
                name: format!("{}/{}", db_label, ONION_NTT_FILE),
                ptr: ntt_mmap.as_ptr(),
                len: ntt_mmap.len(),
                priority: 1,
            });

            // Only load Merkle sibling levels for the main DB (db_id=0).
            // Per-DB OnionPIR Merkle is intentionally out of scope right now.
            let (index_sibling_levels, data_sibling_levels) = if *db_id == 0 {
                (
                    load_merkle_sib_levels(db_dir, "index", &mut mmap_regions),
                    load_merkle_sib_levels(db_dir, "data", &mut mmap_regions),
                )
            } else {
                (Vec::new(), Vec::new())
            };

            if *db_id == 0 {
                // Load Merkle roots and tree-top caches (main DB only)
                let root_path = db_dir.join("merkle_onion_index_root.bin");
                if root_path.exists() {
                    index_merkle_root = Some(std::fs::read(&root_path).expect("read index merkle root"));
                }
                let root_path = db_dir.join("merkle_onion_data_root.bin");
                if root_path.exists() {
                    data_merkle_root = Some(std::fs::read(&root_path).expect("read data merkle root"));
                }
                let top_path = db_dir.join("merkle_onion_index_tree_top.bin");
                if top_path.exists() {
                    index_merkle_tree_top = Some(std::fs::read(&top_path).expect("read index merkle tree-top"));
                }
                let top_path = db_dir.join("merkle_onion_data_tree_top.bin");
                if top_path.exists() {
                    data_merkle_tree_top = Some(std::fs::read(&top_path).expect("read data merkle tree-top"));
                }

                num_index_sibling_levels = index_sibling_levels.len();
                num_data_sibling_levels = data_sibling_levels.len();

                index_merkle_sib_infos = index_sibling_levels.iter().map(|s| {
                    OnionPirMerkleLevelInfo { k: s.k, bins_per_table: s.bins_per_table, num_groups: s.num_groups }
                }).collect();
                data_merkle_sib_infos = data_sibling_levels.iter().map(|s| {
                    OnionPirMerkleLevelInfo { k: s.k, bins_per_table: s.bins_per_table, num_groups: s.num_groups }
                }).collect();
            }

            // Combine sibling levels for the PIR worker:
            // levels 10..10+N_index = index sibling, levels 20..20+N_data = data sibling
            let mut sibling_levels: Vec<SiblingLevelData> = Vec::new();
            sibling_levels.extend(index_sibling_levels);
            sibling_levels.extend(data_sibling_levels);

            let k_index = im.k;
            let k_chunk = ch.k_chunk;
            let index_bins = im.bins_per_table;
            let chunk_bins = ch.bins_per_table;
            let index_pir_dir_clone = index_pir_dir.clone();
            let worker_label = db_label.clone();

            let (tx, mut pir_rx) = mpsc::channel::<PirCommand>(64);
            onionpir_txs[*db_id as usize] = Some(Arc::new(tx));

            // Spawn PIR worker thread (one per DB)
            std::thread::spawn(move || {
                let mut key_store = Box::new(KeyStore::new(0));

                // Set up chunk servers
                let p_chunk = onionpir::params_info(chunk_bins as u64);
                let padded_chunk = p_chunk.num_entries as usize;
                let ntt_u64_ptr = ntt_mmap.as_ptr() as *const u64;

                let mut chunk_index_tables: Vec<Vec<u32>> = Vec::with_capacity(k_chunk);
                let mut chunk_servers: Vec<PirServer> = Vec::with_capacity(k_chunk);
                for g in 0..k_chunk {
                    let mut server = PirServer::new(chunk_bins as u64);
                    let mut index_table = vec![0u32; padded_chunk];
                    for bin in 0..chunk_bins {
                        let eid = chunk_tables[g][bin];
                        if eid != u32::MAX {
                            index_table[bin] = eid;
                        }
                    }
                    unsafe {
                        server.set_shared_database(ntt_u64_ptr, ch.num_packed_entries, &index_table);
                        server.set_key_store(&key_store);
                    }
                    chunk_index_tables.push(index_table);
                    chunk_servers.push(server);
                }
                println!("  [OnionPIR:{}] {} chunk servers ready", worker_label, k_chunk);

                // Set up index servers
                let mut index_servers: Vec<PirServer> = Vec::with_capacity(k_index);
                for b in 0..k_index {
                    let path = index_pir_dir_clone.join(format!("group_{}.bin", b));
                    let mut server = PirServer::new(index_bins as u64);
                    assert!(server.load_db(path.to_str().unwrap()), "Failed to load {:?}", path);
                    unsafe { server.set_key_store(&key_store); }
                    index_servers.push(server);
                }
                println!("  [OnionPIR:{}] {} index servers ready", worker_label, k_index);

                // Set up sibling servers (per level, per PBC group) — main DB only
                let mut sibling_all_index_tables: Vec<Vec<Vec<u32>>> = Vec::new();
                let mut sibling_all_servers: Vec<Vec<PirServer>> = Vec::new();

                for (li, sib) in sibling_levels.iter().enumerate() {
                    let p_sib = onionpir::params_info(sib.bins_per_table as u64);
                    let padded = p_sib.num_entries as usize;
                    let sib_ntt_ptr = sib.ntt_mmap.as_ptr() as *const u64;

                    let mut level_index_tables: Vec<Vec<u32>> = Vec::with_capacity(sib.k);
                    let mut level_servers: Vec<PirServer> = Vec::with_capacity(sib.k);

                    for g in 0..sib.k {
                        let mut server = PirServer::new(sib.bins_per_table as u64);
                        let mut index_table = vec![0u32; padded];
                        for bin in 0..sib.bins_per_table {
                            let eid = sib.cuckoo_tables[g][bin];
                            if eid != u32::MAX {
                                index_table[bin] = eid;
                            }
                        }
                        unsafe {
                            server.set_shared_database(sib_ntt_ptr, sib.num_groups, &index_table);
                            server.set_key_store(&key_store);
                        }
                        level_index_tables.push(index_table);
                        level_servers.push(server);
                    }
                    println!("  [OnionPIR:{}] sibling L{}: {} servers ready (bins={})", worker_label, li, sib.k, sib.bins_per_table);
                    sibling_all_index_tables.push(level_index_tables);
                    sibling_all_servers.push(level_servers);
                }

                // Event loop
                while let Some(cmd) = pir_rx.blocking_recv() {
                    match cmd {
                        PirCommand::RegisterKeys { client_id, galois_keys, gsw_keys, reply } => {
                            let t = Instant::now();
                            key_store.set_galois_key(client_id, &galois_keys);
                            key_store.set_gsw_key(client_id, &gsw_keys);
                            println!("  [OnionPIR:{}] client {} keys registered in {:.2?}", worker_label, client_id, t.elapsed());
                            let _ = reply.send(());
                        }
                        PirCommand::AnswerBatch { client_id, level, round_id, queries, reply } => {
                            let t = Instant::now();
                            let (name, results): (&str, Vec<Vec<u8>>) = if level == 0 {
                                let results = queries.iter().enumerate().map(|(i, q)| {
                                    let g = i / 2;
                                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        index_servers[g].answer_query(client_id, q)
                                    })) {
                                        Ok(r) => r,
                                        Err(e) => { eprintln!("[OnionPIR:{}] panic in index group {}: {:?}", worker_label, g, e); Vec::new() }
                                    }
                                }).collect();
                                ("index", results)
                            } else if level == 1 {
                                let results = queries.iter().enumerate().map(|(b, q)| {
                                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        chunk_servers[b].answer_query(client_id, q)
                                    })) {
                                        Ok(r) => r,
                                        Err(e) => { eprintln!("[OnionPIR:{}] panic in chunk group {}: {:?}", worker_label, b, e); Vec::new() }
                                    }
                                }).collect();
                                ("chunk", results)
                            } else if level >= 10 && (level as usize - 10) < sibling_all_servers.len() {
                                let sib_level = level as usize - 10;
                                let servers = &mut sibling_all_servers[sib_level];
                                let results = queries.iter().enumerate().map(|(b, q)| {
                                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        servers[b].answer_query(client_id, q)
                                    })) {
                                        Ok(r) => r,
                                        Err(e) => { eprintln!("[OnionPIR:{}] panic in sibling L{} group {}: {:?}", worker_label, sib_level, b, e); Vec::new() }
                                    }
                                }).collect();
                                ("sibling", results)
                            } else {
                                eprintln!("[OnionPIR:{}] unknown level {}", worker_label, level);
                                ("unknown", Vec::new())
                            };
                            println!("  [OnionPIR:{}] {} r{} {} queries in {:.2?}", worker_label, name, round_id, queries.len(), t.elapsed());
                            let _ = reply.send(results);
                        }
                    }
                }
            });
        }
    }

    // ── Build server state ──────────────────────────────────────────────

    // Build OnionPIR per-bin Merkle info if any sibling levels were loaded
    let onionpir_merkle_data = if num_index_sibling_levels > 0 || num_data_sibling_levels > 0
        || index_merkle_root.is_some() || data_merkle_root.is_some()
    {
        let index_root_hex = index_merkle_root.as_ref()
            .map(|r| r.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            .unwrap_or_default();
        let data_root_hex = data_merkle_root.as_ref()
            .map(|r| r.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            .unwrap_or_default();
        Some(OnionPirMerkleInfo {
            arity: 120,
            index_tree: OnionPirMerkleSubTree {
                levels: index_merkle_sib_infos,
                root_hex: index_root_hex,
                tree_top: index_merkle_tree_top.unwrap_or_default(),
            },
            data_tree: OnionPirMerkleSubTree {
                levels: data_merkle_sib_infos,
                root_hex: data_root_hex,
                tree_top: data_merkle_tree_top.unwrap_or_default(),
            },
        })
    } else {
        None
    };

    println!();
    println!("Data loaded in {:.2?}", total_start.elapsed());
    println!();

    // ── Residency report & optional warmup ─────────────────────────────

    warmup::report_residency(&mmap_regions);
    if args.warmup {
        warmup::warmup_regions(&mut mmap_regions);
        warmup::report_residency(&mmap_regions);
    }
    println!();

    // ── Assemble ServerState ────────────────────────────────────────────
    let num_databases = all_databases.len();
    let state = ServerState { databases: all_databases };

    let server = Arc::new(UnifiedServerData {
        state,
        role: args.role,
        onionpir_txs,
        onionpir_infos,
        onionpir_merkle: onionpir_merkle_data,
        mmap_regions,
    });

    // ── Accept WebSocket connections ────────────────────────────────────

    let addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Role: {}", role_name);
    println!("  Index: K={}, bins_per_table={}", index_k, server.main_db().index.bins_per_table);
    println!("  Chunk: K={}, bins_per_table={}", chunk_k, server.main_db().chunk.bins_per_table);
    println!("  Databases: {}", num_databases);
    println!("  OnionPIR: {}", if server.has_any_onionpir() { "enabled" } else { "disabled" });
    match args.role {
        ServerRole::Primary => println!("  HarmonyPIR: query server"),
        ServerRole::Secondary => println!("  HarmonyPIR: hint server"),
    }
    if server.main_db().has_merkle() { println!("  Merkle: available"); }
    println!();

    let client_counter = std::sync::atomic::AtomicU64::new(1);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => { eprintln!("Accept error: {}", e); continue; }
        };

        let client_id = client_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let server = Arc::clone(&server);

        tokio::spawn(async move {
            let ws = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => { eprintln!("[{}] Handshake failed: {}", peer, e); return; }
            };
            println!("[{}] Connected (id={})", peer, client_id);
            let (mut sink, mut ws_stream) = ws.split();

            while let Some(msg) = ws_stream.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => { eprintln!("[{}] Read error: {}", peer, e); break; }
                };

                let bin = match msg {
                    Message::Binary(b) => b,
                    Message::Ping(p) => { let _ = sink.send(Message::Pong(p)).await; continue; }
                    Message::Close(_) => break,
                    _ => continue,
                };

                if bin.len() < 5 { continue; }
                let payload = &bin[4..];
                let variant = payload[0];
                let body = &payload[1..];

                // Route by variant byte
                match variant {
                    // ── Shared: info / ping ──────────────────────────────
                    REQ_PING => {
                        let _ = sink.send(Message::Binary(Response::Pong.encode().into())).await;
                    }
                    REQ_GET_INFO => {
                        let _ = sink.send(Message::Binary(Response::Info(server.server_info()).encode().into())).await;
                    }
                    0x03 /* REQ_GET_INFO_JSON */ => {
                        let _ = sink.send(Message::Binary(server.encode_info_json_response(0x03).into())).await;
                    }
                    // 0x33 was REQ_ONIONPIR_GET_INFO (binary ServerInfoV2), now removed.
                    // All clients should use 0x03 (JSON) instead.
                    REQ_GET_DB_CATALOG => {
                        let _ = sink.send(Message::Binary(Response::DbCatalog(server.build_catalog()).encode().into())).await;
                    }
                    REQ_RESIDENCY => {
                        let json = warmup::residency_json(&server.mmap_regions);
                        let json_bytes = json.as_bytes();
                        let payload_len = 1 + json_bytes.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_RESIDENCY);
                        msg.extend_from_slice(json_bytes);
                        let _ = sink.send(Message::Binary(msg.into())).await;
                    }

                    // ── DPF batch queries (both roles) ──────────────────
                    REQ_INDEX_BATCH => {
                        if let Ok(Request::IndexBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) => db,
                                    None => return Response::Error(format!("unknown db_id {}", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                let (batch, dpf_sum, fetch_sum) = s.process_index_batch(&q, db);
                                let wall = t.elapsed();
                                println!("[index] db={} {} groups {:.2?} | dpf {:.2?} fetch+xor {:.2?}", q.db_id, n, wall, dpf_sum, fetch_sum);
                                Response::IndexBatch(batch)
                            }).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }
                    REQ_CHUNK_BATCH => {
                        if let Ok(Request::ChunkBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) => db,
                                    None => return Response::Error(format!("unknown db_id {}", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                let round = q.round_id;
                                let (batch, dpf_sum, fetch_sum) = s.process_chunk_batch(&q, db);
                                let wall = t.elapsed();
                                println!("[chunk] db={} r{} {} groups {:.2?} | dpf {:.2?} fetch+xor {:.2?}", q.db_id, round, n, wall, dpf_sum, fetch_sum);
                                Response::ChunkBatch(batch)
                            }).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }

                    // ── Merkle sibling batch queries ──────────────────────
                    REQ_MERKLE_SIBLING_BATCH => {
                        if let Ok(Request::MerkleSiblingBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) if db.has_merkle() => db,
                                    _ => return Response::Error(format!("db {} has no merkle siblings", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                // round_id = level * 100 + pbc_round_index
                                let level = q.round_id / 100;
                                let pbc_round = q.round_id % 100;
                                let (batch, dpf_sum, fetch_sum) = s.process_merkle_sibling_batch(&q, db);
                                let wall = t.elapsed();
                                println!("[merkle-sib] db={} L{} r{} {} groups {:.2?} | dpf {:.2?} fetch+xor {:.2?}",
                                    q.db_id, level, pbc_round, n, wall, dpf_sum, fetch_sum);
                                Response::MerkleSiblingBatch(batch)
                            }).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }

                    // ── Merkle tree-top cache fetch ──────────────────────
                    REQ_MERKLE_TREE_TOP => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let db = server.state.get_db(db_id);
                        let top = db.and_then(|d| d.merkle_tree_top.as_ref());
                        if let Some(top) = top {
                            // Send: [4B len][1B RESP_MERKLE_TREE_TOP][tree_top_bytes...]
                            let payload_len = 1 + top.len();
                            let mut msg = Vec::with_capacity(4 + payload_len);
                            msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                            msg.push(RESP_MERKLE_TREE_TOP);
                            msg.extend_from_slice(top);
                            let _ = sink.send(Message::Binary(msg.into())).await;
                            println!("[merkle-top] db={} sent {} bytes", db_id, top.len());
                        } else {
                            let err = Response::Error(format!("db {} has no merkle tree-top", db_id));
                            let _ = sink.send(Message::Binary(err.encode().into())).await;
                        }
                    }

                    // ── Per-bucket bin Merkle sibling batch queries ──────
                    REQ_BUCKET_MERKLE_SIB_BATCH => {
                        if let Ok(Request::BucketMerkleSibBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let db = match s.state.get_db(q.db_id) {
                                    Some(db) if db.has_bucket_merkle() => db,
                                    _ => return Response::Error(format!("db {} has no bucket merkle", q.db_id)),
                                };
                                let t = Instant::now();
                                let n = q.keys.len();
                                // round_id encodes: table_type * 100 + level
                                let table_type = q.round_id / 100;
                                let level = (q.round_id % 100) as usize;
                                let sib_tables = if table_type == 0 {
                                    &db.bucket_merkle_index_siblings
                                } else {
                                    &db.bucket_merkle_chunk_siblings
                                };
                                if level >= sib_tables.len() {
                                    return Response::Error(format!("bucket merkle: invalid level {}", level));
                                }
                                let sib = &sib_tables[level];
                                let (batch, dpf_sum, fetch_sum) = s.process_generic_batch(&q, sib);
                                let wall = t.elapsed();
                                println!("[bkt-merkle-sib] db={} T{} L{} {} groups {:.2?} | dpf {:.2?} fetch {:.2?}",
                                    q.db_id, table_type, level, n, wall, dpf_sum, fetch_sum);
                                Response::BucketMerkleSibBatch(batch)
                            }).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }

                    // ── Per-bucket Merkle tree-tops fetch ────────────────
                    REQ_BUCKET_MERKLE_TREE_TOPS => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let db = server.state.get_db(db_id);
                        let tops = db.and_then(|d| d.bucket_merkle_tree_tops.as_ref());
                        if let Some(tops) = tops {
                            let payload_len = 1 + tops.len();
                            let mut msg = Vec::with_capacity(4 + payload_len);
                            msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                            msg.push(RESP_BUCKET_MERKLE_TREE_TOPS);
                            msg.extend_from_slice(tops);
                            let _ = sink.send(Message::Binary(msg.into())).await;
                            println!("[bkt-merkle-tops] db={} sent {} bytes", db_id, tops.len());
                        } else {
                            let err = Response::Error(format!("db {} has no bucket merkle tree-tops", db_id));
                            let _ = sink.send(Message::Binary(err.encode().into())).await;
                        }
                    }

                    // ── HarmonyPIR ────────────────────────────────────────
                    // Primary  = query server (REQ_HARMONY_QUERY, REQ_HARMONY_BATCH_QUERY)
                    // Secondary = hint server (REQ_HARMONY_HINTS)
                    // Both respond to REQ_HARMONY_GET_INFO
                    REQ_HARMONY_GET_INFO => {
                        let _ = sink.send(Message::Binary(
                            Response::HarmonyInfo(server.server_info()).encode().into()
                        )).await;
                    }
                    REQ_HARMONY_HINTS if server.role == ServerRole::Secondary => {
                        if let Ok(Request::HarmonyHints(hint_req)) = Request::decode(payload) {
                            let t_start = Instant::now();
                            let level = hint_req.level;
                            let num = hint_req.group_ids.len();
                            let prp_key: [u8; 16] = hint_req.prp_key;
                            let prp_backend = hint_req.prp_backend;
                            let group_ids = hint_req.group_ids.clone();
                            let s = Arc::clone(&server);

                            let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(4);
                            tokio::task::spawn_blocking(move || {
                                group_ids.par_iter().for_each_with(tx, |tx, &bid| {
                                    let result = compute_hints_for_group(s.main_db(), &prp_key, prp_backend, level, bid);
                                    let _ = tx.blocking_send(result);
                                });
                            });

                            let mut sent = 0;
                            while let Some((group_id, n, t, m, flat_hints)) = rx.recv().await {
                                let hint_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                                let mut resp = Vec::with_capacity(4 + hint_len);
                                resp.extend_from_slice(&(hint_len as u32).to_le_bytes());
                                resp.push(RESP_HARMONY_HINTS);
                                resp.push(group_id);
                                resp.extend_from_slice(&n.to_le_bytes());
                                resp.extend_from_slice(&t.to_le_bytes());
                                resp.extend_from_slice(&m.to_le_bytes());
                                resp.extend_from_slice(&flat_hints);
                                if let Err(e) = sink.send(Message::Binary(resp.into())).await {
                                    eprintln!("[{}] Send error: {}", peer, e);
                                    break;
                                }
                                sent += 1;
                            }
                            println!("[harmony-hint] L{} {}/{} groups in {:.2?}", level, sent, num, t_start.elapsed());
                        }
                    }
                    REQ_HARMONY_QUERY if server.role == ServerRole::Primary => {
                        if let Ok(Request::HarmonyQuery(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_query(&q)).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }
                    REQ_HARMONY_BATCH_QUERY if server.role == ServerRole::Primary => {
                        if let Ok(Request::HarmonyBatchQuery(q)) = Request::decode(payload) {
                            let t = Instant::now();
                            let n = q.items.len();
                            let level = q.level;
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_batch_query(&q)).await.unwrap();
                            println!("[harmony-batch] L{} {} groups in {:.2?}", level, n, t.elapsed());
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }

                    // ── OnionPIR (primary only, if available) ────────────
                    REQ_REGISTER_KEYS if server.has_any_onionpir() => {
                        if let Ok(keys_msg) = RegisterKeysMsg::decode(body) {
                            let db_id = keys_msg.db_id;
                            let tx = match server.onionpir_tx_for(db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", db_id));
                                    let _ = sink.send(Message::Binary(resp.encode().into())).await;
                                    continue;
                                }
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::RegisterKeys {
                                client_id,
                                galois_keys: keys_msg.galois_keys,
                                gsw_keys: keys_msg.gsw_keys,
                                reply: reply_tx,
                            }).await;
                            let _ = reply_rx.await;
                            let mut resp = Vec::with_capacity(5);
                            resp.extend_from_slice(&1u32.to_le_bytes());
                            resp.push(RESP_KEYS_ACK);
                            let _ = sink.send(Message::Binary(resp.into())).await;
                        }
                    }
                    REQ_ONIONPIR_INDEX_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = sink.send(Message::Binary(resp.encode().into())).await;
                                    continue;
                                }
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 0,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_INDEX_RESULT).into())).await;
                        }
                    }
                    REQ_ONIONPIR_CHUNK_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = sink.send(Message::Binary(resp.encode().into())).await;
                                    continue;
                                }
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 1,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_CHUNK_RESULT).into())).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP if server.onionpir_merkle.is_some() => {
                        let om = server.onionpir_merkle.as_ref().unwrap();
                        let top = &om.index_tree.tree_top;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = sink.send(Message::Binary(msg.into())).await;
                        println!("[onion-merkle-index-top] sent {} bytes", top.len());
                    }
                    REQ_ONIONPIR_MERKLE_DATA_TREE_TOP if server.onionpir_merkle.is_some() => {
                        let om = server.onionpir_merkle.as_ref().unwrap();
                        let top = &om.data_tree.tree_top;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_DATA_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = sink.send(Message::Binary(msg.into())).await;
                        println!("[onion-merkle-data-top] sent {} bytes", top.len());
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_SIBLING if server.has_any_onionpir() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Per-DB OnionPIR Merkle is intentionally out of scope — only db_id=0.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if batch.db_id != 0 {
                                let resp = Response::Error("OnionPIR Merkle is only supported for db_id=0".to_string());
                                let _ = sink.send(Message::Binary(resp.encode().into())).await;
                                continue;
                            }
                            let sibling_level = (batch.round_id / 100) as u8;
                            let tx = match server.onionpir_tx_for(0) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 10 + sibling_level, // worker: 10..10+N_index = index siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_MERKLE_INDEX_SIBLING).into())).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_DATA_SIBLING if server.has_any_onionpir() && server.onionpir_merkle.is_some() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Data siblings start after index siblings in the worker's server array.
                        // Per-DB OnionPIR Merkle is intentionally out of scope — only db_id=0.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if batch.db_id != 0 {
                                let resp = Response::Error("OnionPIR Merkle is only supported for db_id=0".to_string());
                                let _ = sink.send(Message::Binary(resp.encode().into())).await;
                                continue;
                            }
                            let sibling_level = (batch.round_id / 100) as u8;
                            let om = server.onionpir_merkle.as_ref().unwrap();
                            let index_sib_count = om.index_tree.levels.len() as u8;
                            let tx = match server.onionpir_tx_for(0) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 10 + index_sib_count + sibling_level, // worker: offset past index siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_MERKLE_DATA_SIBLING).into())).await;
                        }
                    }

                    // ── Unsupported ──────────────────────────────────────
                    _ => {
                        let resp = Response::Error(format!("unsupported request 0x{:02x} for {} role", variant, role_name));
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                    }
                }
            }

            println!("[{}] Disconnected (id={})", peer, client_id);
        });
    }
}
