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
use runtime::hint_pool;
use runtime::protocol::*;
use runtime::onionpir::*;
use runtime::config::ServerConfig;
use runtime::table::{MappedDatabase, MappedSubTable, DatabaseDescriptor, DatabaseType, ServerState};
use runtime::warmup::{self, MmapRegion};

use futures_util::{SinkExt, StreamExt};
use libdpf::DpfKey;
use pir_core::params::{self, INDEX_PARAMS, CHUNK_PARAMS};
use rayon::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Loosely-coupled flag controlling **only OnionPIR loading** at startup.
///
/// History: `Primary` and `Secondary` originally bundled three
/// independent decisions — OnionPIR loading, HarmonyPIR query
/// dispatch, HarmonyPIR hint dispatch. That bundling pinned operators
/// into "primary host = full stack, secondary host = hint-only" which
/// made it awkward to allocate workload to where the hardware fits.
///
/// Today the role flag controls only one thing: whether to attempt
/// loading OnionPIR data files at startup. Both roles handle every
/// DPF and HarmonyPIR opcode (hint, query, batch query, info). The
/// CLIENT chooses which endpoint to send hint vs query requests to —
/// the two-server non-collusion property of HarmonyPIR comes from
/// picking independent operators/hardware, not from server-side
/// dispatch gating.
///
/// `--disable-onion` overrides the OnionPIR-loading default for a
/// primary-role instance that doesn't have the data files (e.g., the
/// VPSBG host, which is OnionPIR-free by design).
///
/// (The variant names are kept for back-compat with existing systemd
/// units and CLI invocations; semantically they could just as well be
/// `WithOnion`/`NoOnion`.)
#[derive(Clone, Copy, PartialEq)]
enum ServerRole {
    /// Tries to load OnionPIR data at startup unless `--disable-onion`
    /// is set. Both Hetzner (which has OnionPIR data) and VPSBG (which
    /// doesn't, hence `--disable-onion`) can run as Primary safely;
    /// the loader gracefully skips on missing files.
    Primary,
    /// Skips OnionPIR loading entirely. Useful when the operator
    /// wants to be explicit about "this server is intentionally
    /// OnionPIR-free" without relying on file-presence detection.
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
    /// Hex-encoded ed25519 admin pubkey (64 chars). When set, REQ_ADMIN_*
    /// requests are accepted and gated by challenge/response auth against
    /// this key. When unset, all REQ_ADMIN_* requests return an error
    /// envelope.
    admin_pubkey_hex: Option<String>,
    /// Skip OnionPIR loading even if files are present and this is a
    /// primary-role instance. Used on hosts that are intentionally
    /// OnionPIR-free (e.g., the VPSBG non-collusion partner where
    /// OnionPIR data is not synced from Hetzner). Primary role
    /// otherwise auto-loads OnionPIR if files exist.
    disable_onion: bool,
    /// Directory containing the AMD VCEK chain PEMs. Expected files:
    ///   - cert_chain.pem  (ASK + ARK concatenated, as AMD KDS returns)
    ///   - vcek.pem        (the per-chip VCEK for the current TCB)
    /// If unset (or files missing), the AttestResult ships empty cert
    /// fields and the browser-side verifier falls back to V2-binding-
    /// only mode. Operator's responsibility to refresh after TCB
    /// changes (kernel update, microcode update) — see
    /// docs/PHASE3_ROADMAP.md.
    vcek_dir: Option<PathBuf>,
    /// HarmonyPIR V2 hint pool size (0 = pool disabled, use V1 on-demand).
    pool_size: usize,
    /// Directory for pool file persistence.
    pool_dir: Option<PathBuf>,
    /// Require ARC credential presentation before serving PIR queries.
    require_arc: bool,
    require_cashu: bool,
    cashu_keysets: Vec<(String, String)>,
    /// Whether this server accepts HarmonyPIR hint requests
    /// (`REQ_HARMONY_HINTS` / `REQ_HARMONY_HINTS_V2`). Default `false`;
    /// must be explicitly enabled via `--serve-hints`. Combined with
    /// `--serve-queries` to pin the role: pir1 (Hetzner, no-SEV) runs
    /// `--serve-hints --serve-queries` (HarmonyPIR hint pool + DPF
    /// server-0 + OnionPIR); pir2 (VPSBG, SEV-SNP Tier 3) runs
    /// `--serve-queries` only (DPF server-1 + HarmonyPIR query phase).
    /// Misconfiguration (client hits the wrong role) becomes a
    /// wire-level rejection instead of silently falling through to
    /// the legacy V1-on-demand path or producing confusing errors.
    serve_hints: bool,
    /// Whether this server accepts PIR query requests (DPF batches,
    /// OnionPIR queries, HarmonyPIR query phase, Merkle siblings,
    /// tree-tops). Default `false`; must be explicitly enabled via
    /// `--serve-queries`. See `serve_hints` for the deployment
    /// topology rationale.
    serve_queries: bool,
    /// Path to the server's long-lived Ed25519 identity key (raw 32-byte
    /// seed). Combined with `--identity-cert-path` to build the
    /// REQ_ANNOUNCE bundle. If either is missing or fails to load,
    /// REQ_ANNOUNCE is disabled but the rest of the protocol runs
    /// normally. Generate one with `bpir-admin generate-identity`.
    identity_key_path: Option<PathBuf>,
    /// Path to the operator-signed IdentityCert (raw bytes produced by
    /// `bpir-admin sign-identity`, encoded per
    /// `pir_identity::IdentityCert::encode`).
    identity_cert_path: Option<PathBuf>,
    /// Human-readable server identifier (e.g. "pir1", "pir2"). Bound
    /// into the announcement bundle; cross-checked against the cert
    /// loaded from `--identity-cert-path`. Required if either of the
    /// identity flags is set.
    identity_server_id: Option<String>,
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
    let mut admin_pubkey_hex: Option<String> = None;
    let mut disable_onion = false;
    let mut vcek_dir: Option<PathBuf> = None;
    let mut pool_size: usize = 0; // 0 = pool disabled
    let mut pool_dir: Option<PathBuf> = None;
    let mut require_arc = false;
    let mut require_cashu = false;
    let mut cashu_keysets: Vec<(String, String)> = Vec::new();
    let mut serve_hints = false;
    let mut serve_queries = false;
    let mut identity_key_path: Option<PathBuf> = None;
    let mut identity_cert_path: Option<PathBuf> = None;
    let mut identity_server_id: Option<String> = None;

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
            "--admin-pubkey-hex" => {
                if let Some(hex) = args.get(i + 1) {
                    admin_pubkey_hex = Some(hex.clone());
                }
                i += 1;
            }
            "--disable-onion" => {
                disable_onion = true;
            }
            "--vcek-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    vcek_dir = Some(PathBuf::from(dir));
                }
                i += 1;
            }
            "--pool-size" => {
                pool_size = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                i += 1;
            }
            "--pool-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    pool_dir = Some(PathBuf::from(dir));
                }
                i += 1;
            }
            "--require-arc" => {
                require_arc = true;
            }
            "--require-cashu" => {
                require_cashu = true;
            }
            "--cashu-keyset" => {
                // Format: --cashu-keyset <id>:<hex_secret_key>
                // Can be repeated for multiple keysets.
                if let Some(kv) = args.get(i + 1) {
                    if let Some((id, sk_hex)) = kv.split_once(':') {
                        cashu_keysets.push((id.to_string(), sk_hex.to_string()));
                    }
                }
                i += 1;
            }
            "--serve-hints" => {
                serve_hints = true;
            }
            "--serve-queries" => {
                serve_queries = true;
            }
            "--identity-key-path" => {
                if let Some(p) = args.get(i + 1) {
                    identity_key_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--identity-cert-path" => {
                if let Some(p) = args.get(i + 1) {
                    identity_cert_path = Some(PathBuf::from(p));
                }
                i += 1;
            }
            "--identity-server-id" => {
                if let Some(s) = args.get(i + 1) {
                    identity_server_id = Some(s.clone());
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    CliArgs { port, data_dir, role, warmup, config_path, checkpoints, deltas, admin_pubkey_hex, disable_onion, vcek_dir, pool_size, pool_dir, require_arc, require_cashu, cashu_keysets, serve_hints, serve_queries, identity_key_path, identity_cert_path, identity_server_id }
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
// Consolidated INDEX file produced by gen_3_onion. Replaces the legacy
// onion_index_pir/group_{0..K-1}.bin directory layout. Layout:
//   [master header 32B: magic u64 | K u64 | per_group_bytes u64 | reserved u64]
//   [group_0: per_group_bytes] [group_1: per_group_bytes] ... [group_{K-1}]
// Each per-group slice is exactly what OnionPIR's save_db_to_file produced
// (standard preproc header + NTT-form data) and is passed into
// PirServer::load_db_from_bytes — zero-copy via one outer mmap.
const ONION_INDEX_ALL_FILE: &str = "onion_index_all.bin";
const ONION_INDEX_META_FILE: &str = "onion_index_meta.bin";

const ONION_CHUNK_MAGIC: u64 = 0xBA7C_0010_0000_0001;
const ONION_INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;
const ONION_INDEX_ALL_MAGIC: u64 = 0xBA7C_0010_0000_0003;
const ONION_INDEX_ALL_HEADER_BYTES: usize = 32;

/// XOR markers re-used from pir-core::cuckoo so v1 (legacy, no anchor)
/// vs v2 (snapshot/delta anchor appended) are discriminated by the
/// same bit pattern across all BitcoinPIR file formats.
const ONION_MAGIC_SNAPSHOT_XOR: u64 = pir_core::cuckoo::ANCHOR_MAGIC_SNAPSHOT_XOR;
const ONION_MAGIC_DELTA_XOR: u64 = pir_core::cuckoo::ANCHOR_MAGIC_DELTA_XOR;

/// Recognise legacy + v2 magics for an onion file header. Returns the
/// matched legacy magic (for downstream offset parsing) on success.
/// `Err` if the magic is unrecognised.
fn check_onion_magic(magic: u64, legacy: u64, file_label: &str) -> u64 {
    let snap = legacy ^ ONION_MAGIC_SNAPSHOT_XOR;
    let delta = legacy ^ ONION_MAGIC_DELTA_XOR;
    if magic == legacy || magic == snap || magic == delta {
        legacy
    } else {
        panic!(
            "Bad {} magic: expected 0x{:016x} (legacy), 0x{:016x} (v2 snapshot), or 0x{:016x} (v2 delta); got 0x{:016x}",
            file_label, legacy, snap, delta, magic
        );
    }
}

/// Parse the chain anchor appended after an onion file's `header_size`-byte
/// legacy header, when the magic indicates a v2 (snapshot/delta) layout.
/// `None` for a legacy (pre-anchor) file.
fn parse_onion_anchor(
    data: &[u8],
    legacy_magic: u64,
    header_size: usize,
) -> Option<pir_core::cuckoo::HeaderAnchor> {
    use pir_core::seeds::{ChainAnchor, DeltaAnchor, CHAIN_ANCHOR_BYTES, DELTA_ANCHOR_BYTES};
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    if magic == legacy_magic ^ ONION_MAGIC_SNAPSHOT_XOR {
        let end = header_size + CHAIN_ANCHOR_BYTES;
        ChainAnchor::from_bytes(data.get(header_size..end)?)
            .ok()
            .map(pir_core::cuckoo::HeaderAnchor::Snapshot)
    } else if magic == legacy_magic ^ ONION_MAGIC_DELTA_XOR {
        let end = header_size + DELTA_ANCHOR_BYTES;
        DeltaAnchor::from_bytes(data.get(header_size..end)?)
            .ok()
            .map(pir_core::cuckoo::HeaderAnchor::Delta)
    } else {
        None
    }
}

/// Self-verify that the onion INDEX/CHUNK seeds were honestly derived
/// from the embedded chain anchor. Panics (refuse-to-serve) on mismatch;
/// no-op for a legacy (anchor-less) onion DB. Mirrors the DPF/HarmonyPIR
/// `MappedSubTable::verify_anchor_consistency` defense-in-depth check.
fn verify_onion_anchor_seeds(
    anchor: &pir_core::cuckoo::HeaderAnchor,
    im_master: u64,
    im_tag: u64,
    ch_master: u64,
    label: &str,
) {
    fn check<C: pir_core::seeds::SeedContext>(
        a: &C,
        im_master: u64,
        im_tag: u64,
        ch_master: u64,
        label: &str,
    ) {
        use pir_core::seeds::{derive_seed_u64, domain};
        let dm = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, a);
        assert_eq!(
            dm, im_master,
            "[anchor] {} onion INDEX master_seed mismatch: derived 0x{:016x} vs header 0x{:016x} — refusing to serve",
            label, dm, im_master
        );
        let dt = derive_seed_u64(domain::INDEX_TAG_FINGERPRINT, a);
        assert_eq!(
            dt, im_tag,
            "[anchor] {} onion INDEX tag_seed mismatch — refusing to serve",
            label
        );
        let dc = derive_seed_u64(domain::CHUNK_CUCKOO_MASTER, a);
        assert_eq!(
            dc, ch_master,
            "[anchor] {} onion CHUNK master_seed mismatch — refusing to serve",
            label
        );
    }
    match anchor {
        pir_core::cuckoo::HeaderAnchor::Snapshot(a) => check(a, im_master, im_tag, ch_master, label),
        pir_core::cuckoo::HeaderAnchor::Delta(a) => check(a, im_master, im_tag, ch_master, label),
    }
}

struct OnionChunkHeader {
    k_chunk: usize,
    bins_per_table: usize,
    num_packed_entries: usize,
    /// CHUNK cuckoo master seed (chain-derived for v2 DBs). Layout:
    /// magic(8) k_chunk(4) cuckoo_hashes(4) bins(4) master_seed(8) ...
    master_seed: u64,
    /// Byte offset where the per-group bin→entry-id tables begin. For a
    /// v2 (chain-anchored) file the anchor is written BETWEEN the 36-byte
    /// header and the tables (same convention as the DPF cuckoo files),
    /// so the tables shift by the anchor length. The table reader MUST use
    /// this — a hardcoded 36 reads the anchor bytes as entry-ids, which
    /// then index out-of-bounds into the NTT store and segfault the query.
    data_offset: usize,
}

/// Legacy onion chunk-cuckoo header size (before any v2 anchor).
const ONION_CHUNK_HEADER_BYTES: usize = 36;

fn read_onion_chunk_header(data: &[u8]) -> OnionChunkHeader {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let _ = check_onion_magic(magic, ONION_CHUNK_MAGIC, "onion chunk cuckoo");
    // The v2 anchor (if any) sits between the legacy header and the
    // per-group tables — so the table data offset must skip it too.
    let anchor_len = if magic == ONION_CHUNK_MAGIC ^ ONION_MAGIC_SNAPSHOT_XOR {
        pir_core::seeds::CHAIN_ANCHOR_BYTES
    } else if magic == ONION_CHUNK_MAGIC ^ ONION_MAGIC_DELTA_XOR {
        pir_core::seeds::DELTA_ANCHOR_BYTES
    } else {
        0
    };
    OnionChunkHeader {
        k_chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[20..28].try_into().unwrap()),
        num_packed_entries: u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize,
        data_offset: ONION_CHUNK_HEADER_BYTES + anchor_len,
    }
}

struct OnionIndexMeta {
    k: usize,
    bins_per_table: usize,
    slots_per_bin: usize,
    tag_seed: u64,
    slot_size: usize,
    /// INDEX cuckoo master seed (chain-derived for v2 DBs). Layout:
    /// magic(8) k(4) cuckoo_hashes(4) slots_per_bin(4) bins(4) master_seed(8) tag_seed(8) slot_size(4)
    master_seed: u64,
    /// Chain anchor appended after the 44-byte legacy header in v2 files.
    anchor: Option<pir_core::cuckoo::HeaderAnchor>,
}

/// Legacy (pre-anchor) byte size of the onion index meta header.
const ONION_INDEX_META_HEADER_BYTES: usize = 44;

fn read_onion_index_meta(data: &[u8]) -> OnionIndexMeta {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let _ = check_onion_magic(magic, ONION_INDEX_META_MAGIC, "onion index meta");
    OnionIndexMeta {
        k: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize,
        slots_per_bin: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        tag_seed: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        slot_size: u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize,
        anchor: parse_onion_anchor(data, ONION_INDEX_META_MAGIC, ONION_INDEX_META_HEADER_BYTES),
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
    } else if (10..20).contains(&level) {
        let sib_level = (level - 10) as usize;
        if sib_level >= db.bucket_merkle_index_siblings.len() {
            panic!("invalid bucket merkle index sibling level {}", sib_level);
        }
        let sib = &db.bucket_merkle_index_siblings[sib_level];
        // k_offset: after INDEX (75) + CHUNK (80) = 155, plus level offset
        let offset = (db.index.params.k + db.chunk.params.k) as u32 + sib_level as u32 * db.index.params.k as u32;
        (sib, sib.params.bin_size(), offset)
    } else if (20..30).contains(&level) {
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
    // PRP_ALF (= 2) was removed 2026-05-12 — see harmonypir-wasm/src/lib.rs:36
    // and pir-sdk-client/src/harmony.rs:81 for the rationale (panic on
    // domain<65536 crashed pir-vpsbg in a tight loop).
    let cell_of: Vec<usize> = match prp_backend {
        harmonypir_wasm::PRP_FASTPRP => {
            let prp = FastPrpWrapper::new(&derived_key, domain);
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
    (group_id, padded_n, t_val, m as u32, flat)
}

// ─── Server state ───────────────────────────────────────────────────────────

/// A pool entry that has been "claimed" by one half of a V2-half session
/// and is waiting for the matching second half. Stored under the
/// client-supplied 16-byte `session_token` in
/// [`UnifiedServerData::v2_half_pending`].
///
/// The entry is held shared (`Arc`) because the half-stream serve loop
/// only reads from it; once both halves have been served, the entry is
/// simply dropped (the pool refills lazily).
struct V2HalfPending {
    /// The pool entry feeding both halves of this session. Shared so
    /// the second half's serve loop can read its frames without
    /// having to coordinate with the first half's lifetime.
    entry: Arc<hint_pool::PoolEntry>,
    /// Bitmask of sides already served (bit 0 = side 0 / INDEX,
    /// bit 1 = side 1 / CHUNK). Used to reject duplicate requests
    /// for the same side on the same token, and to determine when
    /// the entry can be evicted.
    sides_served: u8,
    /// When this token was first seen. Used by the cleanup task to
    /// expire lone entries.
    created_at: Instant,
}

/// TTL for a lone V2-half pending entry. Generous enough to absorb a
/// straggling second-half request from a flaky client, short enough
/// that orphaned entries don't deplete the pool. The pool fills at a
/// rate roughly determined by `--pool-size` × the generator's hint
/// computation throughput (a few entries / sec on the i7-8700), so
/// 30 s × that rate ≈ 100 entries is a safe steady-state bound on
/// the pending map.
const V2_HALF_PENDING_TTL_SECS: u64 = 30;

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
    /// OnionPIR per-bin Merkle info indexed by db_id.
    /// Each entry is `None` if that DB has no OnionPIR Merkle data (no
    /// `merkle_onion_*` sibling / root / tree-top files on disk).
    /// Length matches `state.databases.len()`.
    onionpir_merkle: Vec<Option<OnionPirMerkleInfo>>,
    /// All mmap'd regions for residency monitoring.
    mmap_regions: Vec<MmapRegion>,
    /// Admin auth config — `Some` when the operator started the server with
    /// `--admin-pubkey-hex <hex>`. `None` means REQ_ADMIN_* requests fail.
    admin_config: Option<pir_runtime_core::admin::AdminConfig>,
    /// Data root for admin DB uploads: the directory `databases.toml`
    /// lives in (or `data_dir` for legacy invocations). Staging dirs
    /// land at `<data_root>/.staging/<name>/` and ACTIVATE renames into
    /// `<data_root>/<target_path>/`.
    data_root: PathBuf,
    /// Long-lived X25519 keypair for the inner encrypted channel
    /// (cloudflared-blind WSS frames). Generated inside the SEV-SNP
    /// guest at startup; the public half is committed to REPORT_DATA
    /// via `pir_core::attest::build_report_data` (V2). The secret half
    /// is consumed by per-connection handshakes via
    /// `channel_keypair.new_handshake()` in the dispatch loop's
    /// REQ_HANDSHAKE branch.
    channel_keypair: pir_runtime_core::channel::ChannelKeypair,
    /// Pre-computed HarmonyPIR V2 hint pool (None if pool_size=0).
    hint_pool: Option<hint_pool::HintPool>,
    /// Pending half-stream pool entries, keyed by client-supplied
    /// session token. The first arriving half of a logical V2-half
    /// session allocates a pool entry into this map; the second
    /// arriving half consumes the matching slot and clears the entry.
    /// Lone entries (one half arrives, the other never does) are
    /// garbage-collected by a background tokio task after 30 s.
    ///
    /// Wrapped in `tokio::sync::Mutex` because both the per-connection
    /// dispatch loop (under `tokio::main`) and the cleanup task touch
    /// it. The map itself is small (typically <16 pending entries at
    /// any moment), so lock contention is negligible vs the network
    /// IO it gates.
    v2_half_pending: Arc<tokio::sync::Mutex<HashMap<[u8; 16], V2HalfPending>>>,
    /// ARC presentation verifier + seen-tag set. Wrapped in a Mutex because
    /// `verify()` mutates the per-context tag set. `None` if ARC is disabled
    /// (server started without --require-arc).
    arc_verifier: Option<std::sync::Mutex<pir_runtime_core::arc_verifier::ArcVerifier>>,
    /// Whether ARC credential presentation is required for PIR queries.
    require_arc: bool,
    /// Cashu blind auth verifier.
    cashu_verifier: Option<std::sync::Mutex<pir_runtime_core::cashu_verifier::CashuVerifier>>,
    /// Whether Cashu BAT presentation is required for PIR queries.
    require_cashu: bool,
    /// Whether this server accepts `REQ_HARMONY_HINTS` /
    /// `REQ_HARMONY_HINTS_V2` opcodes (set via `--serve-hints`).
    /// Mirrors `CliArgs::serve_hints`. Gated in the dispatch loop.
    serve_hints: bool,
    /// Whether this server accepts PIR query opcodes (DPF + OnionPIR +
    /// HarmonyPIR query phase). Mirrors `CliArgs::serve_queries`.
    serve_queries: bool,
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

    /// Look up the OnionPIR per-bin Merkle info for a specific db_id.
    /// Returns `None` if the db_id is out of range or if that DB has no Merkle data.
    fn onionpir_merkle_for(&self, db_id: u8) -> Option<&OnionPirMerkleInfo> {
        self.onionpir_merkle.get(db_id as usize).and_then(|o| o.as_ref())
    }

    /// Whether ANY database has OnionPIR Merkle data loaded.
    fn has_any_onionpir_merkle(&self) -> bool {
        self.onionpir_merkle.iter().any(|m| m.is_some())
    }
}

/// Per-group OnionPIR Merkle metadata for one DB (Phase 3 per-group
/// redesign). The 155-tree tree-top blob `merkle_onion_tree_tops.bin`
/// is served whole to clients on either TREE_TOP request; the per-group
/// sibling FHE-PIR DBs (one OnionPIR `Server` per group) live in the
/// OnionPIR worker thread.
#[derive(Clone)]
struct OnionPirMerkleInfo {
    arity: usize,
    /// SHA256 of the concatenated 155 per-group roots — the §2f trust anchor.
    super_root_hex: String,
    /// `merkle_onion_tree_tops.bin` verbatim (75 INDEX + 80 DATA per-group
    /// tree-tops); served whole on either INDEX/DATA TREE_TOP request.
    tree_tops: Vec<u8>,
    /// Number of INDEX per-group sibling trees (= INDEX PBC group count).
    index_k: usize,
    /// Plaintexts in each INDEX per-group sibling DB.
    index_num_pt: usize,
    /// Number of DATA per-group sibling trees (= CHUNK PBC group count).
    data_k: usize,
    /// Plaintexts in each DATA per-group sibling DB.
    data_num_pt: usize,
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
    /// INDEX/CHUNK cuckoo master seeds (chain-derived for v2 DBs),
    /// delivered to the standalone OnionPIR TS client so it computes
    /// placements with the server's seed instead of a hardcoded const.
    index_master_seed: u64,
    chunk_master_seed: u64,
}

impl UnifiedServerData {
    /// Append a single `OnionPirMerkleInfo` object to `json` preceded by
    /// `prefix`. Per-group schema (Phase 3): `arity`, `super_root`, the
    /// shared 155-tree tree-top blob's hash/size, and per-kind `{k,num_pt}`
    /// for the INDEX and DATA per-group sibling DBs.
    fn append_onionpir_merkle_json(json: &mut String, prefix: &str, om: &OnionPirMerkleInfo) {
        json.push_str(prefix);
        let top_hash = pir_core::merkle::sha256(&om.tree_tops);
        json.push_str(&format!(
            r#"{{"arity":{},"super_root":"{}","tree_tops_hash":"{}","tree_tops_size":{}"#,
            om.arity,
            om.super_root_hex,
            top_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            om.tree_tops.len(),
        ));
        json.push_str(&format!(
            r#","index":{{"k":{},"num_pt":{}}},"data":{{"k":{},"num_pt":{}}}}}"#,
            om.index_k, om.index_num_pt, om.data_k, om.data_num_pt,
        ));
    }

    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            index_bins_per_table: self.main_db().index.bins_per_table as u32,
            chunk_bins_per_table: self.main_db().chunk.bins_per_table as u32,
            index_k: self.main_db().index.params.k as u8,
            chunk_k: self.main_db().chunk.params.k as u8,
            tag_seed: self.main_db().index.tag_seed,
            index_master_seed: self.main_db().index.master_seed,
            chunk_master_seed: self.main_db().chunk.master_seed,
            anchor: self.main_db().index.anchor,
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

        if let Some(Some(ref opi)) = self.onionpir_infos.first() {
            json.push_str(&format!(
                r#","onionpir":{{"total_packed_entries":{},"index_bins_per_table":{},"chunk_bins_per_table":{},"tag_seed":"0x{:016x}","index_master_seed":"0x{:016x}","chunk_master_seed":"0x{:016x}","index_k":{},"chunk_k":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":1,"chunk_slot_size":{}}}"#,
                opi.total_packed_entries, opi.index_bins_per_table, opi.chunk_bins_per_table,
                opi.tag_seed, opi.index_master_seed, opi.chunk_master_seed,
                opi.index_k, opi.chunk_k,
                opi.index_slots_per_bin, opi.index_slot_size,
                3840, // PACKED_ENTRY_SIZE = 3.75KB fixed bin size for OnionPIR chunks
            ));
        }

        // Top-level `onionpir_merkle` reflects the main DB (db_id=0) for
        // backward compatibility with clients that only look at the main
        // entry. Per-DB Merkle is also emitted under `databases[]` below.
        if let Some(om) = self.onionpir_merkle_for(0) {
            Self::append_onionpir_merkle_json(&mut json, ",\"onionpir_merkle\":", om);
        }

        // Legacy global N-ary tree Merkle ("merkle":{…}) removed — the
        // per-bucket bin Merkle below ("merkle_bucket":{…}) is the active
        // scheme. No DB carries N-ary Merkle data anymore.

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
        if self.state.databases.len() > 1
            || self.state.databases.iter().any(|db| db.has_bucket_merkle())
            || self.has_any_onionpir_merkle()
        {
            json.push_str(r#","databases":["#);
            for (i, db) in self.state.databases.iter().enumerate() {
                if i > 0 { json.push(','); }
                let has_onionpir_merkle = self.onionpir_merkle_for(i as u8).is_some();
                let has_onionpir = self.onionpir_txs.get(i).map(|o| o.is_some()).unwrap_or(false);
                json.push_str(&format!(
                    r#"{{"db_id":{},"has_bucket_merkle":{},"has_onionpir":{},"has_onionpir_merkle":{}"#,
                    i, db.has_bucket_merkle(), has_onionpir, has_onionpir_merkle
                ));

                // Per-DB OnionPIR parameters (so the web client can switch BFV
                // params when querying a delta with different bins_per_table).
                if let Some(Some(ref opi)) = self.onionpir_infos.get(i) {
                    json.push_str(&format!(
                        r#","onionpir":{{"total_packed_entries":{},"index_bins_per_table":{},"chunk_bins_per_table":{},"tag_seed":"0x{:016x}","index_k":{},"chunk_k":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":1,"chunk_slot_size":{}}}"#,
                        opi.total_packed_entries, opi.index_bins_per_table, opi.chunk_bins_per_table,
                        opi.tag_seed, opi.index_k, opi.chunk_k,
                        opi.index_slots_per_bin, opi.index_slot_size,
                        3840, // PACKED_ENTRY_SIZE
                    ));
                }

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

                // Per-DB OnionPIR per-bin Merkle, when this DB has it
                if let Some(om) = self.onionpir_merkle_for(i as u8) {
                    Self::append_onionpir_merkle_json(&mut json, ",\"onionpir_merkle\":", om);
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
                    index_master_seed: db.index.master_seed,
                    chunk_master_seed: db.chunk.master_seed,
                    anchor: db.index.anchor,
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
                    key_refs[0], key_refs[1],
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
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        let (sub_table, entry_size) = match query.level {
            0 => (&db.index, db.index.params.bin_size()),
            1 => (&db.chunk, db.chunk.params.bin_size()),
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
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        // Level mapping (same as hint levels):
        //   0 = INDEX, 1 = CHUNK
        //   10..10+N = bucket Merkle INDEX sibling L0, L1, ...
        //   20..20+N = bucket Merkle CHUNK sibling L0, L1, ...
        let (sub_table, entry_size) = if query.level == 0 {
            (&db.index, db.index.params.bin_size())
        } else if query.level == 1 {
            (&db.chunk, db.chunk.params.bin_size())
        } else if query.level >= 10 && query.level < 20 {
            let sib_level = (query.level - 10) as usize;
            if sib_level >= db.bucket_merkle_index_siblings.len() {
                return Response::Error(format!("invalid bucket merkle index sib level {}", sib_level));
            }
            let sib = &db.bucket_merkle_index_siblings[sib_level];
            (sib, sib.params.bin_size())
        } else if query.level >= 20 && query.level < 30 {
            let sib_level = (query.level - 20) as usize;
            if sib_level >= db.bucket_merkle_chunk_siblings.len() {
                return Response::Error(format!("invalid bucket merkle chunk sib level {}", sib_level));
            }
            let sib = &db.bucket_merkle_chunk_siblings[sib_level];
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
                            data.extend(std::iter::repeat_n(0u8, entry_size));
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

// ─── AMD VCEK chain loader ─────────────────────────────────────────────────
//
// Reads two PEM files from `--vcek-dir`:
//   - cert_chain.pem  — ASK + ARK as concatenated PEMs (the format AMD
//                       KDS returns from /vcek/v1/{Family}/cert_chain).
//                       ASK comes first, ARK second.
//   - vcek.pem        — the per-chip VCEK for the current TCB (fetched
//                       from /vcek/v1/{Family}/{ChipID}?TCB-params).
//
// Splits cert_chain.pem on the BEGIN/END boundaries so the AttestResult
// fields end up with separate `ark_pem` and `ask_pem`. (Splitting here
// rather than at the verifier matches the operator workflow: one curl
// per file from AMD KDS, then one cp into --vcek-dir.)
//
// Returns (ark, ask, vcek). Empty Vecs on any I/O or parse failure;
// caller logs and continues — AttestResult ships empty cert fields and
// the browser falls back to V2-binding-only mode.
fn load_vcek_chain(dir: &PathBuf) -> std::io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let chain_path = dir.join("cert_chain.pem");
    let vcek_path = dir.join("vcek.pem");
    let chain_bytes = std::fs::read(&chain_path)?;
    let vcek_bytes = std::fs::read(&vcek_path)?;

    let (ask, ark) = split_cert_chain_ask_then_ark(&chain_bytes).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "cert_chain.pem at {} did not contain two PEM blocks (expected ASK then ARK)",
                chain_path.display()
            ),
        )
    })?;
    Ok((ark, ask, vcek_bytes))
}

/// Split a concatenated PEM blob into (first_block, second_block) by
/// looking for `-----BEGIN` / `-----END` boundaries. AMD KDS returns
/// the chain endpoint as ASK + ARK (in that order); callers swap to
/// (ark, ask) at the call site.
fn split_cert_chain_ask_then_ark(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let s = std::str::from_utf8(bytes).ok()?;
    // Find the END of the first block, including its line.
    let first_end = s.find("-----END")?;
    let after_first_end = first_end + s[first_end..].find('\n')? + 1;
    let first_block = s[..after_first_end].as_bytes().to_vec();
    // The remainder should start with the second BEGIN line.
    let rest = &s[after_first_end..];
    let second_begin = rest.find("-----BEGIN")?;
    let second_block = rest[second_begin..].as_bytes().to_vec();
    if second_block.is_empty() {
        return None;
    }
    Some((first_block, second_block))
}

// ─── REQ_ANNOUNCE response builder ──────────────────────────────────────────
//
// Maps the startup-built `ServerState.announcement_bundle` to the wire
// reply: `Some` → `RESP_ANNOUNCE` carrying the operator-signed bundle
// verbatim; `None` → `RESP_ERROR` (the server was started without a
// consistent identity key + operator cert). Extracted so the REQ_ANNOUNCE
// dispatch arm and its unit test share one implementation — booting the
// full binary needs a multi-GB checkpoint, so this is the closest seam
// the production code path can be exercised at in-process.
fn build_announce_response(announcement_bundle: &Option<Vec<u8>>) -> Response {
    match announcement_bundle {
        Some(bytes) => Response::Announce(bytes.clone()),
        None => Response::Error(
            "announce not configured: server lacks identity key or operator cert".into(),
        ),
    }
}

// ─── Encrypted-channel send helper ─────────────────────────────────────────
//
// Wraps the raw `sink.send(Message::Binary(...))` pattern so that, if a
// session is established for this connection, the outgoing payload gets
// AEAD-sealed via pir_channel before going on the wire. Cleartext callers
// pass `None` and the function is a thin pass-through.
//
// `payload` is the full outgoing wire blob: `[4B len LE][1B variant][body]`.
// When sealing, we strip the 4-byte length, seal the rest, then re-frame
// with a fresh outer length around the sealed bytes. The result still
// satisfies the WS receiver's `[4B len][payload]` expectation; the
// payload's first byte is now `pir_channel::ENCRYPTED_FRAME_MAGIC` (0xfe)
// instead of the raw variant byte.
//
// Errors from sealing (sequence-counter exhaustion, AEAD backend failure)
// are surfaced as `tungstenite::Error::Io(..)` so the caller can use the
// same `if let Err(e) = ...` shape it already uses for raw send errors.
async fn send_resp<S>(
    sink: &mut S,
    session: Option<&mut pir_runtime_core::channel::Session>,
    payload: Vec<u8>,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::SinkExt<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    let to_send = match session {
        Some(s) => {
            if payload.len() < 4 {
                // Defensive: malformed (no length prefix). Pass through —
                // the WS receiver will see a too-short frame and ignore it,
                // matching pre-Slice-B.2 behaviour.
                payload
            } else {
                let inner = &payload[4..];
                let sealed = s
                    .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                    .map_err(|e| {
                        TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                    })?;
                let mut framed = Vec::with_capacity(4 + sealed.len());
                framed.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                framed.extend_from_slice(&sealed);
                framed
            }
        }
        None => payload,
    };
    sink.send(Message::Binary(to_send)).await
}

// `feed_resp` (a per-frame `sink.feed()` variant of `send_resp`) was
// removed when the V2 / V2-half hint paths switched from one
// `Message::Binary` per group to a coalesced ~768 KB batch — see
// `HINT_BATCH_BYTES` below. The coalesced path uses `send_resp_batch`,
// which seals each record individually (preserving per-record framing
// the client demuxes) and emits the concatenated buffer as one
// `Sink::send`-flushed Binary message per batch.

/// Send a batch of `[4B len][body]` records as ONE WebSocket Binary
/// message. Each record retains its own `[4B len][body_or_sealed]`
/// framing inside the buffer so the client's transport layer can demux
/// them one-by-one via [`WsConnection::recv`] (which peels one record
/// per call, buffering any tail).
///
/// When the channel session is active, each record is sealed
/// individually with a fresh sequence number — the seal pattern is
/// byte-identical to N back-to-back `send_resp` calls, just emitted as
/// one WS Binary message instead of N.
///
/// Used by the HarmonyPIR hint paths (V1, V2, V2-half) to coalesce the
/// per-group hint records into ~`HINT_BATCH_BYTES`-sized batches; see
/// the call sites for the surrounding loops.
async fn send_resp_batch<S>(
    sink: &mut S,
    mut session: Option<&mut pir_runtime_core::channel::Session>,
    records: Vec<Vec<u8>>,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::SinkExt<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    if records.is_empty() {
        return Ok(());
    }
    // Pre-size the output buffer. For the no-channel case we know the
    // exact size; for the channel case each sealed body is
    // `body.len() + 1 (magic) + 8 (seq) + 16 (tag) = body.len() + 25`,
    // so a tight upper-bound stays correct without re-allocating.
    let total_estimate: usize = records
        .iter()
        .map(|r| if r.len() < 4 { r.len() } else { 4 + (r.len() - 4) + 25 })
        .sum();
    let mut buf: Vec<u8> = Vec::with_capacity(total_estimate);
    for payload in records {
        match session.as_deref_mut() {
            Some(s) => {
                if payload.len() < 4 {
                    // Defensive: malformed (no length prefix). Pass
                    // through — matches `send_resp` behaviour.
                    buf.extend_from_slice(&payload);
                } else {
                    let inner = &payload[4..];
                    let sealed = s
                        .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                        .map_err(|e| {
                            TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                        })?;
                    buf.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&sealed);
                }
            }
            None => {
                buf.extend_from_slice(&payload);
            }
        }
    }
    sink.send(Message::Binary(buf)).await
}

// ─── Transport-level message chunking (Cloudflare large-message workaround) ──
//
// Cloudflare's WebSocket proxy silently corrupts single messages above
// ~1 MB (a 3.1 MB OnionPIR RegisterKeys upload arrives truncated — see
// docs/PIR1_REGISTER_KEYS_TRUNCATION.md). Messages over CHUNK_SIZE are
// split into `[4B len][CHUNK_MAGIC][seq:u16][total:u16][piece]` frames;
// the peer reassembles. These constants MUST stay in sync with
// `pir-sdk-client/src/connection.rs` (CHUNK_MAGIC / CHUNK_SIZE) and
// `web/src/onionpir_client.ts`.
const CHUNK_MAGIC: u8 = 0xc7;
const CHUNK_SIZE: usize = 256 * 1024;
const CHUNK_HDR: usize = 1 + 2 + 2; // magic + seq + total
const MAX_REASSEMBLED: usize = 64 * 1024 * 1024;

/// Target accumulation size before flushing a coalesced HarmonyPIR hint
/// batch as one WebSocket Binary message. Per-group hint records
/// (~74 KB each on the public deployment) are concatenated into a buffer
/// until the threshold is crossed, then flushed.
///
/// Wire-format inside the buffer is unchanged — each record is still the
/// pre-existing `[4B len][RESP_HARMONY_HINTS][group_id][n][t][m][hints]`
/// frame. Only WS message boundaries are reduced (a HarmonyPIR query that
/// previously emitted ~622 RX HARMONY_HINTS frames across two sockets now
/// emits ~32).
///
/// Sized below 1 MiB so the message survives the Cloudflare WebSocket
/// proxy (~1 MB ceiling — see docs/PIR1_REGISTER_KEYS_TRUNCATION.md).
/// Mirrors `HINT_BATCH_BYTES` in
/// `runtime/src/bin/harmonypir_hint_server.rs`.
const HINT_BATCH_BYTES: usize = 768 * 1024;

/// Like [`send_resp`], but when `allow_chunk` is set and the framed
/// message exceeds `CHUNK_SIZE`, splits it into chunk frames the client
/// reassembles. Used for the large OnionPIR result messages
/// (INDEX/CHUNK batches ~1–2 MB, Merkle tree-tops ~1 MB) sent to
/// chunk-capable clients. `allow_chunk` is the per-connection
/// `client_supports_chunks` flag — false for legacy / WASM DPF/Harmony
/// clients, which never receive a large enough OnionPIR message anyway.
async fn send_resp_chunked<S>(
    sink: &mut S,
    session: Option<&mut pir_runtime_core::channel::Session>,
    payload: Vec<u8>,
    allow_chunk: bool,
) -> tokio_tungstenite::tungstenite::Result<()>
where
    S: futures_util::SinkExt<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    use tokio_tungstenite::tungstenite::{Error as TungError, Message};
    // Frame (and optionally seal) exactly like send_resp.
    let to_send = match session {
        Some(s) => {
            if payload.len() < 4 {
                payload
            } else {
                let inner = &payload[4..];
                let sealed = s
                    .seal(pir_runtime_core::channel::Direction::ServerToClient, inner)
                    .map_err(|e| {
                        TungError::Io(std::io::Error::other(format!("channel seal: {}", e)))
                    })?;
                let mut framed = Vec::with_capacity(4 + sealed.len());
                framed.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                framed.extend_from_slice(&sealed);
                framed
            }
        }
        None => payload,
    };
    if !allow_chunk || to_send.len() <= CHUNK_SIZE {
        return sink.send(Message::Binary(to_send)).await;
    }
    let total = to_send.len().div_ceil(CHUNK_SIZE);
    if total > u16::MAX as usize {
        return Err(TungError::Io(std::io::Error::other(format!(
            "response too large to chunk: {} bytes",
            to_send.len()
        ))));
    }
    for seq in 0..total {
        let start = seq * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(to_send.len());
        let piece = &to_send[start..end];
        let mut frame = Vec::with_capacity(4 + CHUNK_HDR + piece.len());
        frame.extend_from_slice(&((CHUNK_HDR + piece.len()) as u32).to_le_bytes());
        frame.push(CHUNK_MAGIC);
        frame.extend_from_slice(&(seq as u16).to_le_bytes());
        frame.extend_from_slice(&(total as u16).to_le_bytes());
        frame.extend_from_slice(piece);
        sink.send(Message::Binary(frame)).await?;
    }
    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    let role_name = match args.role {
        ServerRole::Primary => "primary",
        ServerRole::Secondary => "secondary",
    };

    // ── Mode validation ────────────────────────────────────────────────
    // The server's accepted-opcode set is gated by two independent flags:
    //   --serve-hints   → REQ_HARMONY_HINTS / REQ_HARMONY_HINTS_V2
    //   --serve-queries → all PIR query opcodes (DPF batches, OnionPIR
    //                      queries, HarmonyPIR query phase, Merkle siblings,
    //                      tree-tops, batched index/chunk)
    // At least one must be enabled, else the server has no useful role.
    // Run-mode logged below; configure on each unit file (see
    // `deploy/systemd/pir-primary.service` and
    // `deploy/systemd/pir-secondary.service`).
    if !args.serve_hints && !args.serve_queries {
        eprintln!(
            "ERROR: must enable at least one of --serve-hints / --serve-queries.\n  \
             Hint-only deployment (HarmonyPIR V2 pool):  --serve-hints --pool-size N\n  \
             Query-only deployment (DPF / OnionPIR / HarmonyPIR query): --serve-queries\n  \
             Both (legacy single-host or pir1 Hetzner topology):       --serve-hints --serve-queries"
        );
        std::process::exit(2);
    }

    println!("=== Unified PIR Server ({}) ===", role_name);
    println!("  Port:     {}", args.port);
    println!(
        "  Mode:     hints={}, queries={}",
        if args.serve_hints { "yes" } else { "no" },
        if args.serve_queries { "yes" } else { "no" },
    );
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
    //   onionpir_merkle[db_id] = Some(info)    if db has OnionPIR Merkle data
    //
    // db_paths was already populated alongside `all_databases` above; it's
    // a list of (db_id, label, source_dir) for every loaded database.

    let num_total_dbs = db_paths.len();
    let mut onionpir_txs: Vec<Option<Arc<mpsc::Sender<PirCommand>>>> = vec![None; num_total_dbs];
    let mut onionpir_infos: Vec<Option<OnionPirInfo>> = (0..num_total_dbs).map(|_| None).collect();
    let mut onionpir_merkle_per_db: Vec<Option<OnionPirMerkleInfo>> =
        (0..num_total_dbs).map(|_| None).collect();

    // Per-group OnionPIR Merkle (Phase 3): one consolidated sibling file
    // per kind, loaded per-DB alongside the OnionPIR worker setup.
    struct OnionSibFile {
        /// Number of per-group sibling DBs (= PBC group count).
        k: usize,
        /// Plaintexts per per-group sibling DB.
        num_pt: usize,
        /// Byte length of one per-group `save_db` blob.
        blob_len: usize,
        /// `merkle_onion_sib_{index,data}.bin` mmap: `[24B header][K blobs]`.
        mmap: Mmap,
    }

    /// Load one consolidated per-group sibling file (Phase 3). Returns
    /// `None` if the file is absent (DB has no per-group OnionPIR Merkle).
    fn load_onion_sib_file(
        data_dir: &std::path::Path,
        db_label: &str,
        tree_kind: &str,
        mmap_regions: &mut Vec<MmapRegion>,
    ) -> Option<OnionSibFile> {
        let path = data_dir.join(format!("merkle_onion_sib_{}.bin", tree_kind));
        if !path.exists() {
            return None;
        }
        let file = std::fs::File::open(&path).expect("open onion sibling file");
        let mmap = unsafe { Mmap::map(&file) }.expect("mmap onion sibling file");
        assert!(
            mmap.len() >= 24,
            "{}: too small ({} B) for the 24-byte header",
            path.display(),
            mmap.len(),
        );
        // Header: [8B magic][4B K][4B arity][4B num_pt][4B blob_len].
        let k = u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as usize;
        let num_pt = u32::from_le_bytes(mmap[16..20].try_into().unwrap()) as usize;
        let blob_len = u32::from_le_bytes(mmap[20..24].try_into().unwrap()) as usize;
        let expected = 24 + k * blob_len;
        assert_eq!(
            mmap.len(),
            expected,
            "{}: size mismatch (header K={} blob_len={} → {} B, file is {} B)",
            path.display(),
            k,
            blob_len,
            expected,
            mmap.len(),
        );
        println!(
            "  [{}] onion sibling '{}': K={}, num_pt={}, blob={:.2} MB, total={:.2} MB",
            db_label,
            tree_kind,
            k,
            num_pt,
            blob_len as f64 / 1e6,
            mmap.len() as f64 / 1e6,
        );
        mmap_regions.push(MmapRegion {
            name: format!("{}/merkle_onion_sib_{}.bin", db_label, tree_kind),
            ptr: mmap.as_ptr(),
            len: mmap.len(),
            priority: 2,
        });
        Some(OnionSibFile { k, num_pt, blob_len, mmap })
    }

    if args.role == ServerRole::Primary && !args.disable_onion {
        for (db_id, db_label, db_dir) in &db_paths {
            let ntt_path = db_dir.join(ONION_NTT_FILE);
            if !ntt_path.exists() {
                println!("[OnionPIR:{}] Not available (no {} in {})", db_label, ONION_NTT_FILE, db_dir.display());
                continue;
            }
            println!("[OnionPIR:{}] Loading data...", db_label);

            let chunk_cuckoo_path = db_dir.join(ONION_CHUNK_CUCKOO_FILE);
            let index_all_path = db_dir.join(ONION_INDEX_ALL_FILE);
            let index_meta_path = db_dir.join(ONION_INDEX_META_FILE);

            if !index_all_path.exists() {
                println!(
                    "[OnionPIR:{}] Skipping — {} missing in {}. Re-run scripts/build_delta_onion.sh (or gen_3_onion) to regenerate the consolidated INDEX layout.",
                    db_label, ONION_INDEX_ALL_FILE, db_dir.display(),
                );
                continue;
            }

            // Read OnionPIR-specific headers
            let cuckoo_data = std::fs::read(&chunk_cuckoo_path).expect("read onion chunk cuckoo");
            let ch = read_onion_chunk_header(&cuckoo_data);
            let meta_data = std::fs::read(&index_meta_path).expect("read onion index meta");
            let im = read_onion_index_meta(&meta_data);

            println!("  Chunk: K={}, bins={}, packed={}", ch.k_chunk, ch.bins_per_table, ch.num_packed_entries);
            println!("  Index: K={}, bins={}, slots_per_bin={}", im.k, im.bins_per_table, im.slots_per_bin);

            // Phase: self-verify onion seeds against the chain anchor embedded
            // in onion_index_meta.bin (v2 header). No-op for legacy onion DBs.
            if let Some(anchor) = im.anchor {
                verify_onion_anchor_seeds(&anchor, im.master_seed, im.tag_seed, ch.master_seed, db_label);
                println!("  anchor verified: onion INDEX/CHUNK seeds match chain-derived values");
            }

            onionpir_infos[*db_id as usize] = Some(OnionPirInfo {
                total_packed_entries: ch.num_packed_entries as u32,
                index_bins_per_table: im.bins_per_table as u32,
                chunk_bins_per_table: ch.bins_per_table as u32,
                index_k: im.k as u8,
                chunk_k: ch.k_chunk as u8,
                tag_seed: im.tag_seed,
                index_slots_per_bin: im.slots_per_bin as u16,
                index_slot_size: im.slot_size as u8,
                index_master_seed: im.master_seed,
                chunk_master_seed: ch.master_seed,
            });

            // Parse chunk cuckoo tables. ch.data_offset accounts for the v2
            // chain-anchor that sits between the header and the tables —
            // hardcoding 36 here read the anchor bytes as entry-ids and
            // segfaulted the onion query path (see OnionChunkHeader).
            let header_size = ch.data_offset;
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

            // Load consolidated INDEX file (onion_index_all.bin). Single mmap;
            // we parse the 32-byte master header here and hand per-group slices
            // to the PIR worker thread, which in turn feeds each slice into
            // `PirServer::load_db_from_bytes` (zero-copy aliased pointer).
            let index_all_file = std::fs::File::open(&index_all_path)
                .unwrap_or_else(|e| panic!("open {}: {}", index_all_path.display(), e));
            let index_all_mmap = unsafe { Mmap::map(&index_all_file) }
                .expect("mmap onion_index_all.bin");
            {
                if index_all_mmap.len() < ONION_INDEX_ALL_HEADER_BYTES {
                    panic!(
                        "{}: file too small ({} bytes) for index_all master header",
                        index_all_path.display(), index_all_mmap.len(),
                    );
                }
                let magic = u64::from_le_bytes(index_all_mmap[0..8].try_into().unwrap());
                let file_k = u64::from_le_bytes(index_all_mmap[8..16].try_into().unwrap()) as usize;
                let file_per_group = u64::from_le_bytes(index_all_mmap[16..24].try_into().unwrap()) as usize;
                // Accept legacy + v2 (anchor trailer) magic.
                let _ = check_onion_magic(magic, ONION_INDEX_ALL_MAGIC, "onion index-all master");
                assert_eq!(
                    file_k, im.k,
                    "{}: K mismatch (file says {}, meta says {})",
                    index_all_path.display(), file_k, im.k,
                );
                // The K per-group payloads occupy [HEADER .. HEADER + K*per_group);
                // a v2 file then appends the chain anchor as a trailer.
                let data_len = ONION_INDEX_ALL_HEADER_BYTES + file_k * file_per_group;
                let all_anchor =
                    parse_onion_anchor(&index_all_mmap, ONION_INDEX_ALL_MAGIC, data_len);
                let expected_len = data_len
                    + match all_anchor {
                        None => 0,
                        Some(pir_core::cuckoo::HeaderAnchor::Snapshot(_)) => {
                            pir_core::seeds::CHAIN_ANCHOR_BYTES
                        }
                        Some(pir_core::cuckoo::HeaderAnchor::Delta(_)) => {
                            pir_core::seeds::DELTA_ANCHOR_BYTES
                        }
                    };
                assert_eq!(
                    index_all_mmap.len(), expected_len,
                    "{}: total size mismatch (expected {}, got {})",
                    index_all_path.display(), expected_len, index_all_mmap.len(),
                );
                // Cross-file consistency: onion_index_all's trailer anchor must
                // match the one embedded in onion_index_meta.bin — catches a
                // mixed build where the two files came from different anchors.
                if let (Some(a), Some(m)) = (all_anchor, im.anchor) {
                    assert_eq!(
                        a, m,
                        "{}: index-all anchor disagrees with index-meta anchor — mixed build, refusing to serve",
                        index_all_path.display(),
                    );
                }
                println!(
                    "  Index-all: K={}, per_group={:.2} MB, total={:.2} MB",
                    file_k,
                    file_per_group as f64 / 1e6,
                    index_all_mmap.len() as f64 / 1e6,
                );
            }
            mmap_regions.push(MmapRegion {
                name: format!("{}/{}", db_label, ONION_INDEX_ALL_FILE),
                ptr: index_all_mmap.as_ptr(),
                len: index_all_mmap.len(),
                priority: 1,
            });
            let index_all_per_group =
                u64::from_le_bytes(index_all_mmap[16..24].try_into().unwrap()) as usize;

            // Load the per-group OnionPIR Merkle sidecars (Phase 3
            // per-group redesign). A DB ships these only if
            // `gen_4_build_merkle_onion` has been run for it.
            let index_sib_file =
                load_onion_sib_file(db_dir, db_label, "index", &mut mmap_regions);
            let data_sib_file =
                load_onion_sib_file(db_dir, db_label, "data", &mut mmap_regions);

            let merkle_tree_tops: Option<Vec<u8>> = {
                let p = db_dir.join("merkle_onion_tree_tops.bin");
                if p.exists() {
                    Some(std::fs::read(&p).expect("read merkle_onion_tree_tops.bin"))
                } else {
                    None
                }
            };
            let merkle_super_root: Option<Vec<u8>> = {
                let p = db_dir.join("merkle_onion_root.bin");
                if p.exists() {
                    Some(std::fs::read(&p).expect("read merkle_onion_root.bin"))
                } else {
                    None
                }
            };

            // A DB has OnionPIR Merkle iff the full per-group set is on
            // disk: both consolidated sibling files plus the tree-top blob.
            let has_merkle_data = index_sib_file.is_some()
                && data_sib_file.is_some()
                && merkle_tree_tops.is_some();
            if has_merkle_data {
                let idx = index_sib_file.as_ref().unwrap();
                let dat = data_sib_file.as_ref().unwrap();
                let arity = onionpir::params_info(0).entry_size as usize / 32;
                let super_root_hex = merkle_super_root
                    .as_ref()
                    .map(|r| r.iter().map(|b| format!("{:02x}", b)).collect::<String>())
                    .unwrap_or_default();
                onionpir_merkle_per_db[*db_id as usize] = Some(OnionPirMerkleInfo {
                    arity,
                    super_root_hex,
                    tree_tops: merkle_tree_tops.unwrap_or_default(),
                    index_k: idx.k,
                    index_num_pt: idx.num_pt,
                    data_k: dat.k,
                    data_num_pt: dat.num_pt,
                });
            }

            let k_index = im.k;
            let k_chunk = ch.k_chunk;
            let index_bins = im.bins_per_table;
            let chunk_bins = ch.bins_per_table;
            let index_all_per_group_for_worker = index_all_per_group;
            let worker_label = db_label.clone();

            let (tx, mut pir_rx) = mpsc::channel::<PirCommand>(64);
            onionpir_txs[*db_id as usize] = Some(Arc::new(tx));

            // Spawn PIR worker thread (one per DB)
            std::thread::spawn(move || {
                // OnionPIRv2 port: KeyStore::new() takes no args now.
                let key_store = Box::new(KeyStore::new());

                // Set up chunk servers.
                //
                // OnionPIRv2 port (commit 6 / runtime-num_pt update): post the
                // upstream `target_num_pt` refactor (`fb14f4e447b...`),
                // `params_info(chunk_bins)` returns the LOCAL per-instance
                // shape (small server sized for `chunk_bins` ~37K plaintexts).
                // That's what each chunk worker's PirServer needs.
                let p_chunk = onionpir::params_info(chunk_bins as u64);
                let padded_chunk = p_chunk.num_entries as usize;
                // OnionPIRv2 port: `set_shared_database` now takes
                // `&[u64]` rather than a raw `*const u64` + count. The
                // unsafe slice construction below is sound for the same
                // reason the old raw-pointer call was: `ntt_mmap` is
                // captured by-move into this worker-thread closure and
                // outlives every `PirServer` we attach to it.
                //
                // SAFETY: `ntt_mmap` is a `&[u8]` with `len() % 8 == 0`
                // (preprocessed_db.bin payload is u64-aligned by build).
                let ntt_u64_slice: &[u64] = unsafe {
                    std::slice::from_raw_parts(
                        ntt_mmap.as_ptr() as *const u64,
                        ntt_mmap.len() / 8,
                    )
                };

                // Shared store's `num_pt` — what gen_2_onion's builder
                // `PirServer::new(num_packed_entries)` was created with,
                // which is what `set_shared_database`'s `shared_num_entries`
                // argument wants. Pre-`fb14f4e` we passed
                // `p_chunk.num_plaintexts` (the local per-instance value);
                // post-refactor those are different numbers and the local
                // one is wrong here. Derive from the NTT store file size
                // instead — `len() / 8 / coeff_val_cnt` is the count of
                // plaintext slots the builder saved.
                let coeff_val_cnt =
                    onionpir::params_info(0).coeff_val_cnt as usize;
                assert!(
                    coeff_val_cnt > 0
                        && ntt_u64_slice.len().is_multiple_of(coeff_val_cnt),
                    "chunk NTT store len ({} u64s) not divisible by \
                     coeff_val_cnt ({}); file is the wrong shape",
                    ntt_u64_slice.len(),
                    coeff_val_cnt,
                );
                let chunk_shared_num_entries =
                    (ntt_u64_slice.len() / coeff_val_cnt) as u64;

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
                        // OnionPIRv2 port: `set_shared_database` returns
                        // bool now (false on validation failure). Wrap in
                        // assert! so silent failures don't ship.
                        // OnionPIRv2 port (commit 3a): pass
                        // `num_plaintexts` (compile-time DB shape) as
                        // `shared_num_entries`, not the pre-port
                        // `num_packed_entries` (dataset size). The NTT
                        // store from gen_2_onion's post-port save_db
                        // payload is sized for the full num_plaintexts
                        // slot count; passing the smaller
                        // num_packed_entries would lie about the layout.
                        // Cuckoo placement only assigns to
                        // [0, num_packed_entries) so empty slots beyond
                        // that range are never queried.
                        assert!(
                            server.set_shared_database(
                                ntt_u64_slice,
                                chunk_shared_num_entries,
                                &index_table,
                            ),
                            "set_shared_database failed (chunk worker {} \
                             group {}; chunk_shared_num_entries={}, \
                             index_table.len={}, local_num_pt={})",
                            worker_label,
                            g,
                            chunk_shared_num_entries,
                            index_table.len(),
                            p_chunk.num_plaintexts,
                        );
                        // OnionPIRv2 port: `set_key_store` takes Option now.
                        server.set_key_store(Some(&key_store));
                    }
                    chunk_index_tables.push(index_table);
                    chunk_servers.push(server);
                }
                println!("  [OnionPIR:{}] {} chunk servers ready", worker_label, k_chunk);

                // Set up index servers — each slices into the consolidated
                // onion_index_all.bin mmap via load_db_from_bytes (zero-copy).
                // The mmap handle must outlive every PirServer that aliases
                // it, which is satisfied by moving `index_all_mmap` into this
                // worker thread closure — the mmap drops only when the
                // thread exits, which happens on process shutdown.
                let mut index_servers: Vec<PirServer> = Vec::with_capacity(k_index);
                for b in 0..k_index {
                    let off = ONION_INDEX_ALL_HEADER_BYTES + b * index_all_per_group_for_worker;
                    let end = off + index_all_per_group_for_worker;
                    let slice = &index_all_mmap[off..end];
                    let mut server = PirServer::new(index_bins as u64);
                    // SAFETY: `index_all_mmap` is owned by this worker thread
                    // and lives as long as `server`. The PirServer will NOT
                    // munmap the borrowed buffer on drop (fd = -1 path inside
                    // load_db_from_borrowed).
                    assert!(
                        unsafe { server.load_db_from_borrowed(slice) },
                        "Failed to load index group {} from consolidated index_all (offset {}, len {})",
                        b, off, slice.len(),
                    );
                    // OnionPIRv2 port: `set_key_store` takes Option now.
                    unsafe { server.set_key_store(Some(&key_store)); }
                    index_servers.push(server);
                }
                println!("  [OnionPIR:{}] {} index servers ready (via onion_index_all.bin mmap)", worker_label, k_index);

                // Set up per-group OnionPIR Merkle sibling servers — one
                // PirServer per group, each zero-copy aliasing its
                // 24-byte-header sub-slice of merkle_onion_sib_*.bin.
                // Mirrors the index_servers block above.
                let build_sib_servers = |sib: &OnionSibFile, kind: &str| -> Vec<PirServer> {
                    let mut servers = Vec::with_capacity(sib.k);
                    for g in 0..sib.k {
                        let off = 24 + g * sib.blob_len;
                        let slice = &sib.mmap[off..off + sib.blob_len];
                        let mut server = PirServer::new(sib.num_pt as u64);
                        // SAFETY: `sib.mmap` is owned by this worker thread
                        // (moved into the closure) and outlives `server`.
                        assert!(
                            unsafe { server.load_db_from_borrowed(slice) },
                            "[OnionPIR:{}] load_db_from_borrowed failed for {} \
                             sibling group {} (offset {}, len {})",
                            worker_label, kind, g, off, slice.len(),
                        );
                        // OnionPIRv2 port: `set_key_store` takes Option now.
                        unsafe { server.set_key_store(Some(&key_store)); }
                        servers.push(server);
                    }
                    println!(
                        "  [OnionPIR:{}] {} sibling servers ready ({} groups, num_pt={})",
                        worker_label, kind, sib.k, sib.num_pt,
                    );
                    servers
                };
                let mut index_sib_servers: Vec<PirServer> = match &index_sib_file {
                    Some(sib) => build_sib_servers(sib, "index"),
                    None => Vec::new(),
                };
                let mut data_sib_servers: Vec<PirServer> = match &data_sib_file {
                    Some(sib) => build_sib_servers(sib, "data"),
                    None => Vec::new(),
                };

                // Event loop
                while let Some(cmd) = pir_rx.blocking_recv() {
                    match cmd {
                        PirCommand::RegisterKeys { client_id, galois_keys, gsw_keys, reply } => {
                            let t = Instant::now();
                            key_store.set_galois_keys(client_id, &galois_keys);
                            key_store.set_gsw_key(client_id, &gsw_keys);
                            println!("  [OnionPIR:{}] client {} keys registered in {:.2?}", worker_label, client_id, t.elapsed());
                            let _ = reply.send(());
                        }
                        PirCommand::AnswerBatch { client_id, level, round_id, queries, reply } => {
                            let t = Instant::now();
                            // OnionPIRv2 port (2402b16): rayon-parallel `answer_query`
                            // across the per-group PirServer Vec. Safe after upstream
                            // 2402b16 made g_scratch / NTT cache / TimerLogger
                            // thread_local + added a mutex to SharedKeyStore. Each
                            // rayon worker gets one exclusive `&mut PirServer`
                            // (Send-but-not-Sync), so per-server state is single-
                            // threaded; the shared SharedKeyStore is mutex-guarded.
                            //
                            // The bd1a2928 attempt to ship this was reverted after a
                            // pir1 deploy showed 60 s registrations + empty
                            // answer_query. That turned out NOT to be a 2402b16 bug —
                            // it was a contaminated incremental libonionpir.a build
                            // from flipping the onionpir git rev repeatedly without a
                            // clean rebuild (see docs/PIR1_REGISTER_KEYS_TRUNCATION.md).
                            // With a clean build, 2402b16 registers keys in ~1 ms and
                            // the parallel path is sound.
                            //
                            // Wall-time projection (i7-8700, 6 cores):
                            //   INDEX 142 s → ~25 s ; CHUNK 157 s → ~25 s. Total batch
                            //   ≈ 60 s — under Cloudflare's ~100 s WS idle timeout.
                            let worker_label = &worker_label;
                            let queries_ref = &queries;
                            let (name, results): (&str, Vec<Vec<u8>>) = if level == 0 {
                                let results: Vec<Vec<u8>> = index_servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .flat_map_iter(|(g, server)| {
                                        let q0 = &queries_ref[2 * g];
                                        let q1 = &queries_ref[2 * g + 1];
                                        let r0 = match std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| server.answer_query(client_id, q0)),
                                        ) {
                                            Ok(r) => r,
                                            Err(e) => { eprintln!("[OnionPIR:{}] panic in index group {} q0: {:?}", worker_label, g, e); Vec::new() }
                                        };
                                        let r1 = match std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| server.answer_query(client_id, q1)),
                                        ) {
                                            Ok(r) => r,
                                            Err(e) => { eprintln!("[OnionPIR:{}] panic in index group {} q1: {:?}", worker_label, g, e); Vec::new() }
                                        };
                                        std::iter::once(r0).chain(std::iter::once(r1))
                                    })
                                    .collect();
                                ("index", results)
                            } else if level == 1 {
                                let results: Vec<Vec<u8>> = chunk_servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .map(|(b, server)| {
                                        match std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| server.answer_query(client_id, &queries_ref[b])),
                                        ) {
                                            Ok(r) => r,
                                            Err(e) => { eprintln!("[OnionPIR:{}] panic in chunk group {}: {:?}", worker_label, b, e); Vec::new() }
                                        }
                                    })
                                    .collect();
                                ("chunk", results)
                            } else if level == 10 || level == 11 {
                                // Per-group OnionPIR Merkle siblings:
                                // level 10 = INDEX trees, level 11 = DATA trees.
                                let (servers, kind): (&mut Vec<PirServer>, &str) = if level == 10 {
                                    (&mut index_sib_servers, "index-sibling")
                                } else {
                                    (&mut data_sib_servers, "data-sibling")
                                };
                                let results: Vec<Vec<u8>> = servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .map(|(b, server)| {
                                        match std::panic::catch_unwind(
                                            std::panic::AssertUnwindSafe(|| server.answer_query(client_id, &queries_ref[b])),
                                        ) {
                                            Ok(r) => r,
                                            Err(e) => { eprintln!("[OnionPIR:{}] panic in {} group {}: {:?}", worker_label, kind, b, e); Vec::new() }
                                        }
                                    })
                                    .collect();
                                (kind, results)
                            } else {
                                eprintln!("[OnionPIR:{}] unknown level {}", worker_label, level);
                                ("unknown", Vec::new())
                            };
                            // OnionPIRv2 port: report empty/nonempty result split
                            // alongside the existing wall-clock log so a future
                            // "all-empty batch" client-side report (see
                            // `pir-sdk-client/src/onion.rs::batch_looks_evicted`)
                            // can be triaged from server logs alone — either the
                            // C++ answer_query catch fired (empty=N/N, fast wall
                            // time → keystore drift or query malformed) or the
                            // matmul completed (empty=0/N, full wall time →
                            // client decode / decryption-noise bug).
                            let empty_count = results.iter().filter(|r| r.is_empty()).count();
                            let nonempty_bytes: usize = results.iter().filter(|r| !r.is_empty()).map(|r| r.len()).sum();
                            let first_resp_len = results.iter().find(|r| !r.is_empty()).map(|r| r.len()).unwrap_or(0);
                            println!(
                                "  [OnionPIR:{}] {} r{} {} queries in {:.2?} (empty={}/{}, nonempty_total={}B, resp_len={}B, client_id={})",
                                worker_label, name, round_id, queries.len(), t.elapsed(),
                                empty_count, results.len(), nonempty_bytes, first_resp_len, client_id,
                            );
                            let _ = reply.send(results);
                        }
                    }
                }
            });
        }
    }

    // ── Build server state ──────────────────────────────────────────────
    // (OnionPIR per-bin Merkle info was built per-DB inside the loading
    // loop above; it's stored in `onionpir_merkle_per_db`.)

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

    // ── Generate the long-lived channel keypair ─────────────────────────
    // This is the X25519 key the future encrypted channel handshakes
    // ECDH against. We generate it inside the SEV-SNP guest at startup
    // (before any client traffic), commit the pubkey to REPORT_DATA via
    // build_report_data's V2 layout, and stash both halves on the
    // server. The secret never touches disk; on reboot a new key is
    // generated, which automatically bumps MEASUREMENT (because the
    // pubkey-in-cmdline path doesn't apply yet — see Slice B).
    //
    // Why on a non-SEV host (Hetzner) too? The channel layer is hosted
    // identically; only the attestation backing differs. Clients still
    // get an encrypted channel against pir1; they just don't get the
    // chip-signed binding.
    let channel_keypair = pir_runtime_core::channel::ChannelKeypair::generate();
    let channel_pubkey = channel_keypair.public_bytes();
    println!(
        "  Channel pubkey: {}",
        channel_pubkey.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );

    // ── Load AMD VCEK chain (optional) ───────────────────────────────────
    // Operator places ARK + ASK + VCEK PEMs at --vcek-dir; server reads
    // once at startup and ships them in every AttestResult so the
    // browser can chain-validate the SNP report's signature back to
    // AMD's known root without talking to kdsintf.amd.com directly
    // (CORS-blocked from the browser).
    let (ark_pem, ask_pem, vcek_pem) = match args.vcek_dir.as_ref() {
        Some(dir) => match load_vcek_chain(dir) {
            Ok((ark, ask, vcek)) => {
                println!(
                    "  VCEK chain: loaded from {} (ark={}B ask={}B vcek={}B)",
                    dir.display(),
                    ark.len(),
                    ask.len(),
                    vcek.len(),
                );
                (ark, ask, vcek)
            }
            Err(e) => {
                eprintln!(
                    "  VCEK chain: failed to load from {}: {} — AttestResult will ship empty cert fields, browser falls back to V2-binding-only verification",
                    dir.display(),
                    e
                );
                (Vec::new(), Vec::new(), Vec::new())
            }
        },
        None => {
            println!("  VCEK chain: not configured (--vcek-dir unset) — AttestResult ships empty cert fields");
            (Vec::new(), Vec::new(), Vec::new())
        }
    };

    // ── Build the operator-signed announcement bundle, if configured ─
    // [HUMAN-decided 2026-05-21] When either file is missing or the
    // cert / key disagree, log a warning and serve without announce
    // (REQ_ANNOUNCE returns RESP_ERROR). Existing attest / handshake
    // / query paths are unaffected.
    let announcement_bundle: Option<Vec<u8>> = match (
        args.identity_key_path.as_ref(),
        args.identity_cert_path.as_ref(),
        args.identity_server_id.as_deref(),
    ) {
        (Some(key_path), Some(cert_path), Some(server_id)) => {
            match pir_runtime_core::identity::load_identity_key(key_path)
                .and_then(|sk| {
                    pir_runtime_core::identity::load_identity_cert(cert_path)
                        .map(|cert| (sk, cert))
                })
            {
                Ok((sk, cert)) => {
                    // Manifest roots in db_id order — same as the V2
                    // attest layout, so the bundle and the SEV report
                    // commit to the same set.
                    let manifest_roots: Vec<[u8; 32]> = all_databases
                        .iter()
                        .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
                        .collect();
                    let binary_sha256 = pir_runtime_core::attest::self_exe_sha256();
                    let git_rev = pir_runtime_core::attest::GIT_REV;
                    let issued_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    match pir_runtime_core::identity::build_announcement_bundle(
                        &sk,
                        cert,
                        server_id,
                        channel_pubkey,
                        binary_sha256,
                        git_rev,
                        manifest_roots,
                        issued_at,
                    ) {
                        Ok(id) => {
                            let id_short: String = id
                                .cert
                                .identity_pubkey[..8]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect();
                            println!(
                                "  Identity announce: enabled (server_id={}, identity_pub={}…, issued_at={})",
                                server_id, id_short, issued_at
                            );
                            Some(id.encoded_bundle)
                        }
                        Err(e) => {
                            eprintln!(
                                "  Identity announce: DISABLED — failed to build bundle: {}. REQ_ANNOUNCE will return RESP_ERROR; attest/handshake/queries still serve normally.",
                                e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  Identity announce: DISABLED — {}. REQ_ANNOUNCE will return RESP_ERROR; attest/handshake/queries still serve normally.",
                        e
                    );
                    None
                }
            }
        }
        (None, None, None) => {
            println!(
                "  Identity announce: not configured (--identity-key-path / --identity-cert-path / --identity-server-id unset)"
            );
            None
        }
        _ => {
            eprintln!(
                "  Identity announce: DISABLED — all three of --identity-key-path, --identity-cert-path, --identity-server-id must be set together (or none of them)."
            );
            None
        }
    };

    // ── Assemble ServerState ────────────────────────────────────────────
    let num_databases = all_databases.len();
    let state = ServerState {
        databases: all_databases,
        server_static_pub: channel_pubkey,
        ark_pem,
        ask_pem,
        vcek_pem,
        announcement_bundle,
    };

    let admin_config = match args.admin_pubkey_hex.as_deref() {
        None => None,
        Some(hex) => match pir_runtime_core::admin::AdminConfig::from_hex(hex) {
            Ok(c) => {
                println!("  Admin auth: enabled (pubkey={})", &hex[..16]);
                Some(c)
            }
            Err(e) => panic!("invalid --admin-pubkey-hex: {}", e),
        },
    };

    // data_root = directory of databases.toml (where DB subdirs live)
    // when --config is given; otherwise fall back to --data-dir.
    let data_root = match args.config_path.as_ref() {
        Some(p) => p.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".")),
        None => args.data_dir.clone(),
    };
    println!("  Data root: {}", data_root.display());

    // ── Initialize HarmonyPIR V2 hint pool (if enabled) ──────────────────
    let (arc_verifier, require_arc) = if args.require_arc {
        let verifier = pir_runtime_core::arc_verifier::ArcVerifier::generate();
        println!("  ARC: enabled — credential verification required");
        (Some(std::sync::Mutex::new(verifier)), true)
    } else {
        println!("  ARC: disabled (use --require-arc to enable)");
        (None, false)
    };

    let (cashu_verifier, require_cashu) = if args.require_cashu {
        if args.cashu_keysets.is_empty() {
            panic!("--require-cashu requires at least one --cashu-keyset <id>:<hex_sk>");
        }
        let verifier = pir_runtime_core::cashu_verifier::CashuVerifier::from_keys(&args.cashu_keysets)
            .expect("valid Cashu keysets");
        println!("  Cashu: enabled — {} keyset(s) loaded", verifier.keyset_count());
        (Some(std::sync::Mutex::new(verifier)), true)
    } else {
        println!("  Cashu: disabled (use --require-cashu to enable)");
        (None, false)
    };

    let hint_pool = if args.pool_size > 0 {
        let pool_config = hint_pool::HintPoolConfig {
            pool_size: args.pool_size,
            // Default to PRP_FASTPRP (large-domain SAFE; main hints have
            // domain >= 2^20 easily). Was PRP_ALF before 2026-05-12 but
            // ALF panicked on small (sibling) domains, crashing the server.
            prp_backend: harmonypir_wasm::PRP_FASTPRP,
            pool_dir: args.pool_dir.clone(),
        };
        let main_db = state.get_db(0).expect("main database must be loaded");
        if let Some(ref dir) = pool_config.pool_dir {
            let _ = std::fs::create_dir_all(dir);
        }
        let backend_name = match pool_config.prp_backend {
            harmonypir_wasm::PRP_HMR12 => "HMR12",
            harmonypir_wasm::PRP_FASTPRP => "FastPRP",
            _ => "unknown",
        };
        println!(
            "  HarmonyPIR V2 hint pool: size={}, backend={}, dir={}",
            pool_config.pool_size,
            backend_name,
            pool_config.pool_dir.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "memory-only".into())
        );
        Some(hint_pool::HintPool::new(pool_config, main_db))
    } else {
        println!("  HarmonyPIR V2 hint pool: disabled (use --pool-size to enable)");
        None
    };

    let server = Arc::new(UnifiedServerData {
        state,
        role: args.role,
        onionpir_txs,
        onionpir_infos,
        onionpir_merkle: onionpir_merkle_per_db,
        mmap_regions,
        admin_config,
        data_root,
        channel_keypair,
        hint_pool,
        v2_half_pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        arc_verifier,
        require_arc,
        cashu_verifier,
        require_cashu,
        serve_hints: args.serve_hints,
        serve_queries: args.serve_queries,
    });

    // Background task: garbage-collect V2-half pending entries whose
    // matching second half never arrived. Runs every 10 s; entries
    // older than `V2_HALF_PENDING_TTL_SECS` are evicted (their pool
    // entry is dropped — the pool generator will refill).
    {
        let pending = Arc::clone(&server.v2_half_pending);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let cutoff = Instant::now()
                    .checked_sub(Duration::from_secs(V2_HALF_PENDING_TTL_SECS));
                let Some(cutoff) = cutoff else { continue };
                let mut map = pending.lock().await;
                let before = map.len();
                map.retain(|_token, pend| pend.created_at >= cutoff);
                let evicted = before.saturating_sub(map.len());
                if evicted > 0 {
                    println!(
                        "[v2-half-pending] evicted {} stale entr(ies), {} remaining",
                        evicted,
                        map.len()
                    );
                }
            }
        });
    }

    // ── Accept WebSocket connections ────────────────────────────────────

    // Bind dual-stack: `[::]:port` accepts both IPv6 connections AND IPv4
    // connections (via v4-mapped addresses) on Linux when the system default
    // `IPV6_V6ONLY=0` is in effect (true by default on Ubuntu). This matters
    // for cloudflared and similar reverse-proxies that resolve `localhost`
    // to `::1` first per RFC 6724 happy-eyeballs — binding only `0.0.0.0`
    // would silently refuse those connections.
    let addr: SocketAddr = format!("[::]:{}", args.port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Role: {}", role_name);
    println!("  Index: K={}, bins_per_table={}", index_k, server.main_db().index.bins_per_table);
    println!("  Chunk: K={}, bins_per_table={}", chunk_k, server.main_db().chunk.bins_per_table);
    println!("  Databases: {}", num_databases);
    println!(
        "  OnionPIR: {}",
        if server.has_any_onionpir() {
            "enabled"
        } else if args.disable_onion {
            "disabled (--disable-onion)"
        } else if args.role == ServerRole::Secondary {
            "disabled (secondary role never loads OnionPIR)"
        } else {
            "disabled (no onion_*.bin files in any DB dir)"
        }
    );
    match args.role {
        ServerRole::Primary => println!("  HarmonyPIR: query server"),
        ServerRole::Secondary => println!("  HarmonyPIR: hint server"),
    }
    if server.main_db().has_bucket_merkle() { println!("  Merkle: available (per-bucket)"); }
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

            // Per-connection admin auth state. Lives until the connection
            // drops; disconnecting is logging out.
            let mut admin_state = pir_runtime_core::admin::AdminConnectionState::default();

            // Per-connection encrypted-channel session. `None` until the
            // client sends REQ_HANDSHAKE; `Some` after we've derived the
            // session key. While Some, every outgoing response is sealed
            // (via send_resp below), and incoming frames whose first byte
            // is `pir_channel::ENCRYPTED_FRAME_MAGIC` are decrypted at the
            // top of the dispatch loop.
            //
            // We KEEP cleartext support per-frame even after the session
            // is established — a client can mix cleartext probes (e.g.
            // REQ_PING) with encrypted PIR queries on the same socket.
            // Privacy-conscious clients (the browser SDK) wrap every
            // application frame; legacy clients keep working.
            let mut channel_session: Option<pir_runtime_core::channel::Session> = None;

            // Per-connection ARC state: set to true after the first valid
            // REQ_CREDENTIAL_PRESENT. The presentation_context for this
            // connection is the client-supplied bytes (typically a random
            // session nonce). Tags are scoped to this context.
            let mut arc_ok: bool = false;
            let mut arc_pres_ctx: Option<Vec<u8>> = None;
            let mut cashu_ok: bool = false;

            // Per-connection transport-level chunk reassembly state. A
            // client that sends a multi-MB message (OnionPIR RegisterKeys
            // / query batches) splits it into CHUNK_MAGIC frames; we
            // reassemble before dispatch. `client_supports_chunks` flips
            // true on the first chunk frame seen and gates whether the
            // server chunks its (large) responses back.
            let mut chunk_acc: Vec<u8> = Vec::new();
            let mut chunk_expected: u16 = 0;
            let mut chunk_total: u16 = 0;
            let mut client_supports_chunks = false;

            while let Some(msg) = ws_stream.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => { eprintln!("[{}] Read error: {}", peer, e); break; }
                };

                let raw_bin = match msg {
                    Message::Binary(b) => b,
                    Message::Ping(p) => { let _ = sink.send(Message::Pong(p)).await; continue; }
                    Message::Close(_) => break,
                    _ => continue,
                };

                // Transport-level chunk reassembly. A chunk frame is
                // `[4B len][CHUNK_MAGIC][seq:u16][total:u16][piece]`; a
                // normal message never carries CHUNK_MAGIC at offset 4.
                let bin: Vec<u8> = if raw_bin.len() >= 4 + CHUNK_HDR && raw_bin[4] == CHUNK_MAGIC {
                    client_supports_chunks = true;
                    let seq = u16::from_le_bytes([raw_bin[5], raw_bin[6]]);
                    let total = u16::from_le_bytes([raw_bin[7], raw_bin[8]]);
                    if total == 0 || seq != chunk_expected {
                        eprintln!("[{}] bad chunk frame (seq={} total={} expected={}) — resetting", peer, seq, total, chunk_expected);
                        chunk_acc.clear();
                        chunk_expected = 0;
                        continue;
                    }
                    if seq == 0 {
                        chunk_total = total;
                        chunk_acc.clear();
                    } else if total != chunk_total {
                        eprintln!("[{}] chunk total changed mid-stream — resetting", peer);
                        chunk_acc.clear();
                        chunk_expected = 0;
                        continue;
                    }
                    let piece = &raw_bin[4 + CHUNK_HDR..];
                    if chunk_acc.len() + piece.len() > MAX_REASSEMBLED {
                        eprintln!("[{}] reassembled message exceeds cap — resetting", peer);
                        chunk_acc.clear();
                        chunk_expected = 0;
                        continue;
                    }
                    chunk_acc.extend_from_slice(piece);
                    chunk_expected += 1;
                    if chunk_expected < chunk_total {
                        continue; // wait for the next chunk frame
                    }
                    chunk_expected = 0;
                    std::mem::take(&mut chunk_acc)
                } else {
                    raw_bin.to_vec()
                };

                if bin.len() < 5 { continue; }
                let outer_payload = &bin[4..];

                // Encrypted-frame demux. If the first byte is the channel
                // magic AND we have an established session, open the frame
                // and dispatch the inner request as if it were cleartext.
                // If the magic appears but no session is established, that's
                // a protocol error (clients must REQ_HANDSHAKE first).
                let decrypted: Vec<u8>;
                let payload: &[u8] = if outer_payload.first() == Some(&pir_runtime_core::channel::ENCRYPTED_FRAME_MAGIC) {
                    match channel_session.as_mut() {
                        Some(s) => {
                            match s.open(pir_runtime_core::channel::Direction::ClientToServer, outer_payload) {
                                Ok(buf) => {
                                    decrypted = buf;
                                    decrypted.as_slice()
                                }
                                Err(e) => {
                                    eprintln!("[{}] channel open failed: {}", peer, e);
                                    let err = Response::Error(format!("channel open failed: {}", e));
                                    let _ = send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                                    continue;
                                }
                            }
                        }
                        None => {
                            eprintln!("[{}] received encrypted frame without established session", peer);
                            let err = Response::Error("encrypted frame received but no session established (run REQ_HANDSHAKE first)".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                            continue;
                        }
                    }
                } else {
                    outer_payload
                };

                if payload.is_empty() { continue; }
                let variant = payload[0];
                let body = &payload[1..];

                // ARC gate: if --require-arc is set and no valid credential
                // presented yet, reject PIR-bearing request variants. Whitelisted
                // variants (info, ping, auth, attest, handshake, hints, and the
                // credential presentation itself) pass through.
                if (server.require_arc || server.require_cashu) && !arc_ok && !cashu_ok {
                    match variant {
                        REQ_INDEX_BATCH
                        | REQ_CHUNK_BATCH
                        | REQ_BUCKET_MERKLE_SIB_BATCH
                        | REQ_BUCKET_MERKLE_TREE_TOPS
                        | REQ_HARMONY_QUERY
                        | REQ_HARMONY_BATCH_QUERY
                        | REQ_REGISTER_KEYS
                        | REQ_ONIONPIR_INDEX_QUERY
                        | REQ_ONIONPIR_CHUNK_QUERY
                        | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
                        | REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP
                        | REQ_ONIONPIR_MERKLE_DATA_SIBLING
                        | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP => {
                            let resp = Response::Error(
                                "ARC credential required — send REQ_CREDENTIAL_PRESENT first".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        _ => {}
                    }
                }

                // Mode gate: reject hint or query requests this server isn't
                // configured for (`--serve-hints` / `--serve-queries` flags).
                // Whitelisted opcodes (info / ping / attest / handshake /
                // residency / credential / admin / db-catalog) always pass —
                // they don't expose hint or query content, only metadata
                // needed for clients to discover the server's capabilities.
                if !server.serve_hints {
                    match variant {
                        REQ_HARMONY_HINTS | REQ_HARMONY_HINTS_V2 | REQ_HARMONY_HINTS_V2_HALF => {
                            let resp = Response::Error(
                                "server not configured to serve hints — start with --serve-hints (see deploy/systemd/*.service)".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        _ => {}
                    }
                }
                if !server.serve_queries {
                    match variant {
                        REQ_INDEX_BATCH
                        | REQ_CHUNK_BATCH
                        | REQ_BUCKET_MERKLE_SIB_BATCH
                        | REQ_BUCKET_MERKLE_TREE_TOPS
                        | REQ_HARMONY_QUERY
                        | REQ_HARMONY_BATCH_QUERY
                        | REQ_REGISTER_KEYS
                        | REQ_ONIONPIR_INDEX_QUERY
                        | REQ_ONIONPIR_CHUNK_QUERY
                        | REQ_ONIONPIR_MERKLE_INDEX_SIBLING
                        | REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP
                        | REQ_ONIONPIR_MERKLE_DATA_SIBLING
                        | REQ_ONIONPIR_MERKLE_DATA_TREE_TOP => {
                            let resp = Response::Error(
                                "server not configured to answer queries — start with --serve-queries (see deploy/systemd/*.service)".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        _ => {}
                    }
                }

                // Route by variant byte
                match variant {
                    // ── Shared: info / ping ──────────────────────────────
                    REQ_PING => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::Pong.encode()).await;
                    }
                    REQ_GET_INFO => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::Info(server.server_info()).encode()).await;
                    }
                    0x03 /* REQ_GET_INFO_JSON */ => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), server.encode_info_json_response(0x03)).await;
                    }
                    // 0x33 was REQ_ONIONPIR_GET_INFO (binary ServerInfoV2), now removed.
                    // All clients should use 0x03 (JSON) instead.
                    REQ_GET_DB_CATALOG => {
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::DbCatalog(server.build_catalog()).encode()).await;
                    }
                    REQ_CREDENTIAL_PRESENT => {
                        // Wire format:
                        //   [1B variant=0x08]
                        //   [1B request_context_len][request_context]
                        //   [1B presentation_context_len][presentation_context]
                        //   [8B presentation_limit LE]
                        //   [presentation_bytes...]
                        if body.len() < 11 {
                            let resp = Response::Error("malformed REQ_CREDENTIAL_PRESENT: too short".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let req_ctx_len = body[0] as usize;
                        if body.len() < 1 + req_ctx_len + 1 {
                            let resp = Response::Error("malformed REQ_CREDENTIAL_PRESENT: truncated".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let req_ctx = &body[1..1 + req_ctx_len];
                        let off = 1 + req_ctx_len;
                        let pres_ctx_len = body[off] as usize;
                        if body.len() < off + 1 + pres_ctx_len + 8 {
                            let resp = Response::Error("malformed REQ_CREDENTIAL_PRESENT: truncated".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let pres_ctx = &body[off + 1..off + 1 + pres_ctx_len];
                        let limit_off = off + 1 + pres_ctx_len;
                        let limit = u64::from_le_bytes(
                            body[limit_off..limit_off + 8].try_into().unwrap()
                        );
                        let pres_bytes = &body[limit_off + 8..];

                        let result = match &server.arc_verifier {
                            None => Err(pir_runtime_core::arc_verifier::ArcVerifyError::InvalidProof(
                                "ARC disabled on this server".into()
                            )),
                            Some(verifier) => {
                                let mut v = verifier.lock().unwrap();
                                v.verify(req_ctx, pres_ctx, pres_bytes, limit)
                            }
                        };

                        match result {
                            Ok(()) => {
                                arc_ok = true;
                                arc_pres_ctx = Some(pres_ctx.to_vec());
                                let resp = Response::ArcCredentialOk;
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Err(e) => {
                                arc_ok = false;
                                let resp = Response::Error(format!("ARC: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }
                    REQ_CASHU_BAT_PRESENT => {
                        // Wire format: [1B variant=0x09][bat_base64url bytes...]
                        let bat_str = match std::str::from_utf8(body) {
                            Ok(s) => s,
                            Err(_) => {
                                let resp = Response::Error("invalid UTF-8 in Cashu BAT".into());
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let result = match &server.cashu_verifier {
                            None => Err(pir_runtime_core::cashu_verifier::CashuVerifyError::InvalidFormat(
                                "Cashu disabled on this server".into(),
                            )),
                            Some(v) => v.lock().unwrap().verify(bat_str),
                        };
                        match result {
                            Ok(()) => {
                                cashu_ok = true;
                                let resp = Response::CashuBatOk;
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Err(e) => {
                                cashu_ok = false;
                                let resp = Response::Error(format!("Cashu: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }
                    REQ_ADMIN_AUTH_CHALLENGE => {
                        match server.admin_config {
                            None => {
                                let resp = Response::Error("admin auth disabled (server started without --admin-pubkey-hex)".into());
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                            Some(_) => {
                                let nonce = admin_state.issue_challenge();
                                let resp = Response::AdminAuthChallenge(
                                    pir_runtime_core::protocol::AdminAuthChallenge { nonce },
                                );
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            }
                        }
                    }
                    REQ_ADMIN_AUTH_RESPONSE => {
                        let cfg = match server.admin_config.as_ref() {
                            Some(c) => c,
                            None => {
                                let resp = Response::Error("admin auth disabled".into());
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let signature = if let Ok(Request::AdminAuthResponse { signature }) = Request::decode(payload) {
                            signature
                        } else {
                            let resp = Response::Error("malformed REQ_ADMIN_AUTH_RESPONSE".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        };
                        let result = match admin_state.verify_response(&signature, cfg) {
                            Ok(()) => {
                                println!("[{}] admin authenticated", peer);
                                pir_runtime_core::protocol::AdminAuthResult { ok: true, msg: "ok".into() }
                            }
                            Err(e) => {
                                eprintln!("[{}] admin auth failed: {}", peer, e);
                                pir_runtime_core::protocol::AdminAuthResult { ok: false, msg: e.to_string() }
                            }
                        };
                        let _ = send_resp(&mut sink, channel_session.as_mut(), Response::AdminAuthResponse(result).encode()).await;
                    }
                    REQ_ADMIN_DB_UPLOAD_BEGIN | REQ_ADMIN_DB_UPLOAD_CHUNK
                    | REQ_ADMIN_DB_UPLOAD_FINALIZE | REQ_ADMIN_DB_ACTIVATE => {
                        if !admin_state.authenticated {
                            let resp = Response::Error("not authenticated; complete REQ_ADMIN_AUTH_* first".into());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }
                        let req = match Request::decode(payload) {
                            Ok(r) => r,
                            Err(e) => {
                                let resp = Response::Error(format!("decode admin request: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let resp = match req {
                            Request::AdminDbUploadBegin { name, manifest_toml } => {
                                let r = match admin_state.begin_upload(name.clone(), manifest_toml, &server.data_root) {
                                    Ok(()) => {
                                        println!("[{}] admin upload BEGIN {:?}", peer, name);
                                        pir_runtime_core::protocol::AdminAck { ok: true, msg: "ok".into() }
                                    }
                                    Err(e) => {
                                        eprintln!("[{}] admin upload BEGIN failed: {}", peer, e);
                                        pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() }
                                    }
                                };
                                Response::AdminDbUploadBegin(r)
                            }
                            Request::AdminDbUploadChunk { name, file_path, offset, data } => {
                                let r = match admin_state.write_chunk(&name, &file_path, offset, &data) {
                                    Ok(()) => pir_runtime_core::protocol::AdminAck { ok: true, msg: "ok".into() },
                                    Err(e) => pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() },
                                };
                                Response::AdminDbUploadChunk(r)
                            }
                            Request::AdminDbUploadFinalize { name } => {
                                let r = match admin_state.finalize_upload(&name) {
                                    Ok(root) => pir_runtime_core::protocol::AdminFinalizeResult {
                                        ok: true,
                                        msg: "verified".into(),
                                        manifest_root: root,
                                    },
                                    Err(e) => pir_runtime_core::protocol::AdminFinalizeResult {
                                        ok: false,
                                        msg: e.to_string(),
                                        manifest_root: [0u8; 32],
                                    },
                                };
                                Response::AdminDbUploadFinalize(r)
                            }
                            Request::AdminDbActivate { name, target_path } => {
                                let r = match admin_state.activate(&name, &target_path, &server.data_root) {
                                    Ok(()) => {
                                        println!("[{}] admin ACTIVATE {:?} → {:?} (restart server to load)", peer, name, target_path);
                                        pir_runtime_core::protocol::AdminAck {
                                            ok: true,
                                            msg: "activated; restart server to load".into(),
                                        }
                                    }
                                    Err(e) => pir_runtime_core::protocol::AdminAck { ok: false, msg: e.to_string() },
                                };
                                Response::AdminDbActivate(r)
                            }
                            _ => unreachable!("variant byte already filtered"),
                        };
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_ATTEST => {
                        if let Ok(Request::Attest { nonce }) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                use pir_runtime_core::attest;
                                let manifest_roots: Vec<[u8; 32]> = s.state.databases.iter()
                                    .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
                                    .collect();
                                let binary_sha256 = attest::self_exe_sha256();
                                let server_static_pub = s.state.server_static_pub;
                                let git_rev = attest::GIT_REV;
                                let report_data = attest::build_report_data(
                                    nonce,
                                    &manifest_roots,
                                    binary_sha256,
                                    server_static_pub,
                                    git_rev,
                                );
                                let sev_snp_report = attest::fetch_report(report_data)
                                    .ok().flatten().unwrap_or_default();
                                Response::Attest(pir_runtime_core::protocol::AttestResult {
                                    sev_snp_report,
                                    manifest_roots,
                                    binary_sha256,
                                    server_static_pub,
                                    git_rev: git_rev.to_string(),
                                    ark_pem: s.state.ark_pem.clone(),
                                    ask_pem: s.state.ask_pem.clone(),
                                    vcek_pem: s.state.vcek_pem.clone(),
                                })
                            }).await.unwrap();
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_ANNOUNCE => {
                        // Operator-signed identity bundle, built at startup
                        // into `ServerState.announcement_bundle` when the
                        // --identity-* flags are set. `None` means the server
                        // lacks an identity key / operator cert.
                        let resp = build_announce_response(&server.state.announcement_bundle);
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                    REQ_HANDSHAKE => {
                        // Encrypted-channel handshake. The reply MUST go out
                        // in cleartext — the client doesn't have the session
                        // key until it processes RESP_HANDSHAKE. So we mint
                        // the Session AFTER the send, and the next inbound
                        // frame the client sends will be encrypted.
                        if let Ok(Request::Handshake { client_eph_pub, nonce }) = Request::decode(payload) {
                            let server_hs = server.channel_keypair.new_handshake();
                            let server_eph_pub = server_hs.server_eph_pub();
                            let new_session = server_hs.complete_handshake(&client_eph_pub, &nonce);
                            let resp = Response::Handshake(
                                pir_runtime_core::protocol::HandshakeResult { server_eph_pub },
                            );
                            // Cleartext send (force `None` so send_resp doesn't seal).
                            let _ = send_resp(&mut sink, None, resp.encode()).await;
                            // Now switch the connection into encrypted mode for
                            // all subsequent client→server and server→client
                            // frames.
                            channel_session = Some(new_session);
                        } else {
                            let err = Response::Error(
                                "malformed REQ_HANDSHAKE (expected client_eph_pub:32 + nonce:32)".into(),
                            );
                            let _ = send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                        }
                    }
                    REQ_RESIDENCY => {
                        let json = warmup::residency_json(&server.mmap_regions);
                        let json_bytes = json.as_bytes();
                        let payload_len = 1 + json_bytes.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_RESIDENCY);
                        msg.extend_from_slice(json_bytes);
                        let _ = send_resp(&mut sink, channel_session.as_mut(), msg).await;
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
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
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
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }

                    // (0x31 REQ_MERKLE_SIBLING_BATCH / 0x32 REQ_MERKLE_TREE_TOP
                    //  retired — legacy global N-ary tree Merkle. The per-bucket
                    //  bin Merkle arms below are the active scheme.)

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
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
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
                            let _ = send_resp(&mut sink, channel_session.as_mut(), msg).await;
                            println!("[bkt-merkle-tops] db={} sent {} bytes", db_id, tops.len());
                        } else {
                            let err = Response::Error(format!("db {} has no bucket merkle tree-tops", db_id));
                            let _ = send_resp(&mut sink, channel_session.as_mut(), err.encode()).await;
                        }
                    }

                    // ── HarmonyPIR ────────────────────────────────────────
                    // Both roles respond to ALL HarmonyPIR ops. The
                    // role flag controls only OnionPIR loading at startup
                    // (and `--disable-onion` overrides even that). The
                    // CLIENT decides which server to send hint requests
                    // vs query requests to — the protocol's two-server
                    // non-collusion guarantee comes from picking
                    // independent endpoints, not from server-side dispatch
                    // gating. This decoupling lets operators allocate
                    // workload (hint is ~6× CPU of query per Hetzner
                    // production stats) to whichever endpoint has the
                    // matching hardware capacity, without re-rolling the
                    // role flag and the systemd unit.
                    REQ_HARMONY_GET_INFO => {
                        let _ = send_resp(
                            &mut sink,
                            channel_session.as_mut(),
                            Response::HarmonyInfo(server.server_info()).encode(),
                        ).await;
                    }
                    REQ_HARMONY_HINTS => {
                        if let Ok(Request::HarmonyHints(hint_req)) = Request::decode(payload) {
                            let t_start = Instant::now();
                            let level = hint_req.level;
                            let num = hint_req.group_ids.len();
                            let prp_key: [u8; 16] = hint_req.prp_key;
                            let prp_backend = hint_req.prp_backend;
                            let group_ids = hint_req.group_ids.clone();
                            let db_id = hint_req.db_id;
                            // Validate db_id before spawning blocking work.
                            if server.state.get_db(db_id).is_none() {
                                let resp = Response::Error(format!("unknown db_id {}", db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let s = Arc::clone(&server);

                            let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(4);
                            tokio::task::spawn_blocking(move || {
                                let db = s.state.get_db(db_id).expect("db_id checked before spawn");
                                group_ids.par_iter().for_each_with(tx, |tx, &bid| {
                                    let result = compute_hints_for_group(db, &prp_key, prp_backend, level, bid);
                                    let _ = tx.blocking_send(result);
                                });
                            });

                            // Coalesce per-group records into ~HINT_BATCH_BYTES
                            // WS messages so the browser sees ~30 onmessage
                            // events instead of `num` (~155). Each record
                            // retains its per-record `[4B len][body]`
                            // framing inside the buffer (sealed
                            // individually if the channel is active) so
                            // the client's existing one-record-per-recv()
                            // contract holds — see `send_resp_batch` and
                            // `WsConnection::recv` for the demux.
                            let mut sent = 0;
                            let mut batches = 0usize;
                            let mut pending: Vec<Vec<u8>> = Vec::new();
                            let mut pending_bytes = 0usize;
                            while let Some((group_id, n, t, m, flat_hints)) = rx.recv().await {
                                let hint_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                                let mut record = Vec::with_capacity(4 + hint_len);
                                record.extend_from_slice(&(hint_len as u32).to_le_bytes());
                                record.push(RESP_HARMONY_HINTS);
                                record.push(group_id);
                                record.extend_from_slice(&n.to_le_bytes());
                                record.extend_from_slice(&t.to_le_bytes());
                                record.extend_from_slice(&m.to_le_bytes());
                                record.extend_from_slice(&flat_hints);
                                pending_bytes += record.len();
                                pending.push(record);
                                if pending_bytes >= HINT_BATCH_BYTES {
                                    let batch = std::mem::take(&mut pending);
                                    pending_bytes = 0;
                                    if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), batch).await {
                                        eprintln!("[{}] Send error: {}", peer, e);
                                        break;
                                    }
                                    batches += 1;
                                }
                                sent += 1;
                            }
                            if !pending.is_empty() {
                                if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), pending).await {
                                    eprintln!("[{}] Final-batch send error: {}", peer, e);
                                } else {
                                    batches += 1;
                                }
                            }
                            println!("[harmony-hint] db={} L{} {}/{} groups in {:.2?} ({} WS batches)",
                                db_id, level, sent, num, t_start.elapsed(), batches);
                        }
                    }
                    REQ_HARMONY_HINTS_V2 => {
                        // V2: server generates PRP key, serves pre-computed frames from pool.
                        let t_start = Instant::now();
                        let v2_req = match Request::decode(payload) {
                            Ok(Request::HarmonyHintsV2(h)) => h,
                            Ok(other) => {
                                let resp = Response::Error(format!("unexpected request type for V2 hints: {:?}", other));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            Err(e) => {
                                let resp = Response::Error(format!("V2 hint request decode error: {}", e));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let db_id = v2_req.db_id;
                        if server.state.get_db(db_id).is_none() {
                            let resp = Response::Error(format!("unknown db_id {}", db_id));
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }

                        let pool = match &server.hint_pool {
                            Some(p) => p,
                            None => {
                                let resp = Response::Error(
                                    "V2 hints not available: start server with --pool-size to enable".into()
                                );
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };

                        let entry = match pool.take() {
                            Some(e) => e,
                            None => {
                                let resp = Response::Error("server shutting down".into());
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };

                        // 1. Send key preamble as its own (small) WS Binary
                        //    message — keeps the existing wire shape for the
                        //    preamble + makes the client's first recv()
                        //    return just the preamble. (The client picks the
                        //    PRP key out of it before building HarmonyGroup
                        //    instances.)
                        if let Err(e) = send_resp(&mut sink, channel_session.as_mut(), entry.key_preamble.clone()).await {
                            eprintln!("[{}] V2 preamble send error: {}", peer, e);
                            continue;
                        }

                        // 2. Coalesce INDEX + CHUNK frames into
                        //    ~HINT_BATCH_BYTES WS messages. Each record
                        //    retains its per-record `[4B len][body]`
                        //    framing (sealed individually if the channel
                        //    is on) so the client's
                        //    one-record-per-recv() contract holds — see
                        //    `send_resp_batch` + `WsConnection::recv`
                        //    for the demux. A typical pool entry's ~155
                        //    frames now flush as ~10 WS messages
                        //    instead of 155.
                        let mut sent = 0usize;
                        let mut batches = 0usize;
                        let mut pending: Vec<Vec<u8>> = Vec::new();
                        let mut pending_bytes = 0usize;
                        let frame_iter = entry.index_frames.iter().chain(entry.chunk_frames.iter());
                        for frame in frame_iter {
                            pending_bytes += frame.len();
                            pending.push(frame.clone());
                            if pending_bytes >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut pending);
                                pending_bytes = 0;
                                if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), batch).await {
                                    eprintln!("[{}] V2 frame batch send error: {}", peer, e);
                                    break;
                                }
                                batches += 1;
                            }
                            sent += 1;
                        }
                        if !pending.is_empty() {
                            if let Err(e) = send_resp_batch(&mut sink, channel_session.as_mut(), pending).await {
                                eprintln!("[{}] V2 final-batch send error: {}", peer, e);
                            } else {
                                batches += 1;
                            }
                        }

                        // 3. Terminal sentinel: group_id=0xFF signals
                        //    end-of-stream. Sent as its own (small) message
                        //    so the client's last recv() returns just the
                        //    sentinel, matching the legacy unbatched shape.
                        let terminal_len: u32 = 1 + 1; // variant + group_id
                        let mut terminal = Vec::with_capacity(4 + terminal_len as usize);
                        terminal.extend_from_slice(&terminal_len.to_le_bytes());
                        terminal.push(RESP_HARMONY_HINTS);
                        terminal.push(0xFFu8);
                        let _ = send_resp(&mut sink, channel_session.as_mut(), terminal).await;

                        let elapsed = t_start.elapsed();
                        println!(
                            "[harmony-hint-v2] db={} {} groups served from pool ({} WS batches, prp_key={:02x?}...) in {:.2?}",
                            db_id,
                            sent,
                            batches,
                            &entry.prp_key[..4],
                            elapsed,
                        );
                    }
                    REQ_HARMONY_HINTS_V2_HALF => {
                        // Half-stream V2: serve INDEX (side=0) or CHUNK
                        // (side=1) frames from a pool entry shared with
                        // a matching session_token request.
                        let t_start = Instant::now();
                        let v2half_req = match Request::decode(payload) {
                            Ok(Request::HarmonyHintsV2Half(h)) => h,
                            Ok(other) => {
                                let resp = Response::Error(format!(
                                    "unexpected request type for V2 half hints: {:?}",
                                    other
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            Err(e) => {
                                let resp = Response::Error(format!(
                                    "V2 half hint request decode error: {}",
                                    e
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        let db_id = v2half_req.db_id;
                        if server.state.get_db(db_id).is_none() {
                            let resp =
                                Response::Error(format!("unknown db_id {}", db_id));
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                            continue;
                        }

                        let pool = match &server.hint_pool {
                            Some(p) => p,
                            None => {
                                let resp = Response::Error(
                                    "V2 half hints not available: start server with --pool-size to enable"
                                        .into(),
                                );
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };

                        let token = v2half_req.session_token;
                        let side = v2half_req.side;
                        let side_bit: u8 = 1 << side;

                        // Look up (or allocate) the pending entry for
                        // this token. Held under one short critical
                        // section — we drop the lock before serving
                        // frames because send/feed yield the task.
                        let entry_arc: Arc<hint_pool::PoolEntry> = {
                            let mut map = server.v2_half_pending.lock().await;
                            match map.get_mut(&token) {
                                Some(pend) => {
                                    if pend.sides_served & side_bit != 0 {
                                        // Same side already served on
                                        // this token — protocol error.
                                        drop(map);
                                        let resp = Response::Error(format!(
                                            "V2 half: side {} already served for this token",
                                            side
                                        ));
                                        let _ = send_resp(
                                            &mut sink,
                                            channel_session.as_mut(),
                                            resp.encode(),
                                        )
                                        .await;
                                        continue;
                                    }
                                    let arc = Arc::clone(&pend.entry);
                                    pend.sides_served |= side_bit;
                                    // If both sides now served, the
                                    // entry is no longer pending — drop
                                    // it from the map (the Arc keeps
                                    // the data alive in our local
                                    // `entry_arc` for the remainder of
                                    // this serve loop).
                                    if pend.sides_served == 0b11 {
                                        map.remove(&token);
                                    }
                                    arc
                                }
                                None => {
                                    // First half to arrive — allocate a
                                    // fresh pool entry.
                                    let entry = match pool.take() {
                                        Some(e) => e,
                                        None => {
                                            drop(map);
                                            let resp = Response::Error(
                                                "server shutting down".into(),
                                            );
                                            let _ = send_resp(
                                                &mut sink,
                                                channel_session.as_mut(),
                                                resp.encode(),
                                            )
                                            .await;
                                            continue;
                                        }
                                    };
                                    let arc = Arc::new(entry);
                                    map.insert(
                                        token,
                                        V2HalfPending {
                                            entry: Arc::clone(&arc),
                                            sides_served: side_bit,
                                            created_at: Instant::now(),
                                        },
                                    );
                                    arc
                                }
                            }
                        };

                        // 1. Send key preamble (same for both halves
                        //    since they share the entry). Kept as its own
                        //    small WS Binary message so the client's first
                        //    recv() returns just the preamble.
                        if let Err(e) = send_resp(
                            &mut sink,
                            channel_session.as_mut(),
                            entry_arc.key_preamble.clone(),
                        )
                        .await
                        {
                            eprintln!(
                                "[{}] V2-half preamble send error: {}",
                                peer, e
                            );
                            continue;
                        }

                        // 2. Coalesce the selected half's frames into
                        //    ~HINT_BATCH_BYTES WS messages. Each record
                        //    retains its per-record `[4B len][body]`
                        //    framing (sealed individually if the
                        //    channel is on) so the client's
                        //    one-record-per-recv() contract holds. A
                        //    typical half (~78 INDEX or ~77 CHUNK
                        //    frames @ ~74 KB) now flushes as ~5 WS
                        //    messages instead of ~78.
                        let frames: &[Vec<u8>] = if side == 0 {
                            &entry_arc.index_frames
                        } else {
                            &entry_arc.chunk_frames
                        };
                        let mut sent = 0usize;
                        let mut batches = 0usize;
                        let mut pending: Vec<Vec<u8>> = Vec::new();
                        let mut pending_bytes = 0usize;
                        for frame in frames {
                            pending_bytes += frame.len();
                            pending.push(frame.clone());
                            if pending_bytes >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut pending);
                                pending_bytes = 0;
                                if let Err(e) = send_resp_batch(
                                    &mut sink,
                                    channel_session.as_mut(),
                                    batch,
                                )
                                .await
                                {
                                    eprintln!(
                                        "[{}] V2-half frame batch send error (side={}, group={}): {}",
                                        peer, side, sent, e
                                    );
                                    break;
                                }
                                batches += 1;
                            }
                            sent += 1;
                        }
                        if !pending.is_empty() {
                            if let Err(e) = send_resp_batch(
                                &mut sink,
                                channel_session.as_mut(),
                                pending,
                            )
                            .await
                            {
                                eprintln!(
                                    "[{}] V2-half final-batch send error (side={}): {}",
                                    peer, side, e
                                );
                            } else {
                                batches += 1;
                            }
                        }

                        // 3. Send terminal sentinel.
                        let terminal_len: u32 = 1 + 1;
                        let mut terminal = Vec::with_capacity(4 + terminal_len as usize);
                        terminal.extend_from_slice(&terminal_len.to_le_bytes());
                        terminal.push(RESP_HARMONY_HINTS);
                        terminal.push(0xFFu8);
                        let _ = send_resp(
                            &mut sink,
                            channel_session.as_mut(),
                            terminal,
                        )
                        .await;

                        let elapsed = t_start.elapsed();
                        let side_name = if side == 0 { "INDEX" } else { "CHUNK" };
                        println!(
                            "[harmony-hint-v2-half] db={} side={} {} groups served from pool ({} WS batches, prp_key={:02x?}..., token={:02x?}...) in {:.2?}",
                            db_id,
                            side_name,
                            sent,
                            batches,
                            &entry_arc.prp_key[..4],
                            &token[..4],
                            elapsed,
                        );
                    }
                    REQ_HARMONY_QUERY => {
                        if let Ok(Request::HarmonyQuery(q)) = Request::decode(payload) {
                            // Validate db_id before dispatching to a worker.
                            if server.state.get_db(q.db_id).is_none() {
                                let resp = Response::Error(format!("unknown db_id {}", q.db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_query(&q)).await.unwrap();
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                        }
                    }
                    REQ_HARMONY_BATCH_QUERY => {
                        if let Ok(Request::HarmonyBatchQuery(q)) = Request::decode(payload) {
                            // Validate db_id before dispatching to a worker.
                            if server.state.get_db(q.db_id).is_none() {
                                let resp = Response::Error(format!("unknown db_id {}", q.db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let t = Instant::now();
                            let n = q.items.len();
                            let level = q.level;
                            let db_id = q.db_id;
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_batch_query(&q)).await.unwrap();
                            println!("[harmony-batch] db={} L{} {} groups in {:.2?}", db_id, level, n, t.elapsed());
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
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
                                    let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
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
                            let _ = send_resp(&mut sink, channel_session.as_mut(), resp).await;
                        }
                    }
                    REQ_ONIONPIR_INDEX_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
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
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_INDEX_RESULT), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_CHUNK_QUERY if server.has_any_onionpir() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => {
                                    let resp = Response::Error(format!("OnionPIR not available for db_id={}", batch.db_id));
                                    let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
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
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_CHUNK_RESULT), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP if server.has_any_onionpir_merkle() => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let om = match server.onionpir_merkle_for(db_id) {
                            Some(om) => om,
                            None => {
                                let resp = Response::Error(format!("OnionPIR Merkle not available for db_id={}", db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        // Per-group redesign: one consolidated 155-tree
                        // tree-top blob, served whole on either request.
                        let top = &om.tree_tops;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), msg, client_supports_chunks).await;
                        println!("[onion-merkle-tree-tops] db={} (index req) sent {} bytes", db_id, top.len());
                    }
                    REQ_ONIONPIR_MERKLE_DATA_TREE_TOP if server.has_any_onionpir_merkle() => {
                        // Optional db_id byte: payload[1] if present, else 0.
                        let db_id = if payload.len() > 1 { payload[1] } else { 0 };
                        let om = match server.onionpir_merkle_for(db_id) {
                            Some(om) => om,
                            None => {
                                let resp = Response::Error(format!("OnionPIR Merkle not available for db_id={}", db_id));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                        };
                        // Per-group redesign: one consolidated 155-tree
                        // tree-top blob, served whole on either request.
                        let top = &om.tree_tops;
                        let payload_len = 1 + top.len();
                        let mut msg = Vec::with_capacity(4 + payload_len);
                        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
                        msg.push(RESP_ONIONPIR_MERKLE_DATA_TREE_TOP);
                        msg.extend_from_slice(top);
                        let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), msg, client_supports_chunks).await;
                        println!("[onion-merkle-tree-tops] db={} (data req) sent {} bytes", db_id, top.len());
                    }
                    REQ_ONIONPIR_MERKLE_INDEX_SIBLING if server.has_any_onionpir() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Per-DB: the db_id trailer in the batch message selects the
                        // OnionPIR worker and its per-bin Merkle sibling levels.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if server.onionpir_merkle_for(batch.db_id).is_none() {
                                let resp = Response::Error(format!(
                                    "OnionPIR Merkle not available for db_id={}",
                                    batch.db_id
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 10, // worker: INDEX per-group siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_MERKLE_INDEX_SIBLING), client_supports_chunks).await;
                        }
                    }
                    REQ_ONIONPIR_MERKLE_DATA_SIBLING if server.has_any_onionpir() && server.has_any_onionpir_merkle() => {
                        // round_id encoding: sibling_level * 100 + pbc_round_index
                        // Data siblings start after index siblings in the worker's server array.
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            if server.onionpir_merkle_for(batch.db_id).is_none() {
                                let resp = Response::Error(format!(
                                    "OnionPIR Merkle not available for db_id={}",
                                    batch.db_id
                                ));
                                let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                                continue;
                            }
                            let tx = match server.onionpir_tx_for(batch.db_id) {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id,
                                level: 11, // worker: DATA per-group siblings
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = send_resp_chunked(&mut sink, channel_session.as_mut(), result_msg.encode(RESP_ONIONPIR_MERKLE_DATA_SIBLING), client_supports_chunks).await;
                        }
                    }

                    // ── Unsupported ──────────────────────────────────────
                    _ => {
                        let resp = Response::Error(format!("unsupported request 0x{:02x} for {} role", variant, role_name));
                        let _ = send_resp(&mut sink, channel_session.as_mut(), resp.encode()).await;
                    }
                }
            }

            // ARC cleanup: remove the seen-tag set for this connection's
            // presentation context so memory doesn't grow unboundedly.
            if let (Some(ctx), Some(verifier)) = (arc_pres_ctx, &server.arc_verifier) {
                verifier.lock().unwrap().remove_context(&ctx);
            }

            println!("[{}] Disconnected (id={})", peer, client_id);
        });
    }
}

#[cfg(test)]
mod announce_dispatch_tests {
    //! Tests for the REQ_ANNOUNCE response builder used by the
    //! production dispatch loop. The full per-connection match lives
    //! inline in `main` and needs a multi-GB checkpoint to boot, so we
    //! exercise the shared `build_announce_response` seam directly.
    //! Routing (opcode 0x07 reaching this arm rather than the catch-all
    //! "unsupported request" arm) is verified live by the operator-
    //! identity end-to-end check, since it can only be observed against
    //! a running binary.
    use super::*;

    #[test]
    fn announce_response_configured_returns_bundle_verbatim() {
        let bundle = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x07];
        match build_announce_response(&Some(bundle.clone())) {
            Response::Announce(b) => assert_eq!(b, bundle),
            other => panic!("expected Announce, got {:?}", other),
        }
    }

    #[test]
    fn announce_response_configured_wire_roundtrips_to_same_bundle() {
        // The arm sends `resp.encode()` on the wire; a client decodes it
        // back to identical bundle bytes — proving the dispatch arm emits
        // a well-formed RESP_ANNOUNCE frame the SDK `announce()` parses.
        let bundle = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let wire = build_announce_response(&Some(bundle.clone())).encode();
        // Wire layout: [u32 LE outer len][RESP_ANNOUNCE][u32 LE blen][bundle];
        // `Response::decode` consumes everything after the outer length.
        match Response::decode(&wire[4..]).expect("decode RESP_ANNOUNCE") {
            Response::Announce(b) => assert_eq!(b, bundle),
            other => panic!("expected Announce after round-trip, got {:?}", other),
        }
    }

    #[test]
    fn announce_response_unconfigured_returns_error() {
        // None (server started without --identity-* flags, or with an
        // inconsistent key/cert pair) must surface as RESP_ERROR carrying
        // the documented "announce not configured" message — the client's
        // `announce()` maps this to PirError::ServerError.
        match build_announce_response(&None) {
            Response::Error(msg) => assert!(
                msg.contains("announce not configured"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Error, got {:?}", other),
        }
    }
}
