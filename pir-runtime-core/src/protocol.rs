//! Simple binary protocol for two-level Batch PIR.
//!
//! All integers are little-endian. Messages are length-prefixed:
//!   [4B total_len][1B variant][payload...]
//!
//! The outer 4-byte length includes the variant byte.

use std::io;

// ─── Request variants ───────────────────────────────────────────────────────

pub const REQ_PING: u8 = 0x00;
pub const REQ_GET_INFO: u8 = 0x01;
pub const REQ_INDEX_BATCH: u8 = 0x11;
pub const REQ_CHUNK_BATCH: u8 = 0x21;
pub const REQ_MERKLE_SIBLING_BATCH: u8 = 0x31;
pub const REQ_MERKLE_TREE_TOP: u8 = 0x32;
pub const REQ_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
pub const REQ_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;

// ─── HarmonyPIR request variants ────────────────────────────────────────────

pub const REQ_HARMONY_GET_INFO: u8 = 0x40;
pub const REQ_HARMONY_HINTS: u8 = 0x41;
pub const REQ_HARMONY_QUERY: u8 = 0x42;
pub const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;
/// V2 hint request: server generates the PRP key (client does not send one).
pub const REQ_HARMONY_HINTS_V2: u8 = 0x44;
/// HarmonyPIR V2 half-stream hint request.
///
/// Lets a client split the V2 main hint download across two TCP sockets:
/// one fetches the INDEX half, the other fetches the CHUNK half. Both
/// halves share the same PRP key — the server pairs the two requests
/// by `session_token` and serves both halves from the same pool entry.
/// This breaks the single-stream bandwidth-delay-product cap on the
/// ~20 MB V2 stream without changing per-half wire shape: each half
/// is structurally identical to the corresponding portion of the
/// existing `REQ_HARMONY_HINTS_V2` response.
///
/// Wire: [16B session_token][1B side: 0=INDEX 1=CHUNK]
///       [optional trailing 1B db_id, only when non-zero —
///        backward compatible]
pub const REQ_HARMONY_HINTS_V2_HALF: u8 = 0x46;

// ─── Extended request variants (multi-database) ────────────────────────────

pub const REQ_GET_DB_CATALOG: u8 = 0x02;

// ─── Monitoring ────────────────────────────────────────────────────────────

pub const REQ_RESIDENCY: u8 = 0x04;

// ─── Attestation ───────────────────────────────────────────────────────────
//
// Slice 2 of the attestation work. Client sends a 32-byte nonce; server
// returns the SEV-SNP attestation report (if available), the per-DB
// manifest roots from MANIFEST.toml verification, the SHA-256 of the
// running binary, and the build's git rev. The client recomputes the
// REPORT_DATA preimage and matches it against the field embedded in the
// signed report.

pub const REQ_ATTEST: u8 = 0x05;

// ─── Anonymous credential (ARC) ────────────────────────────────────────────

/// Client presents an ARC credential before a PIR query batch.
/// Server verifies it and responds 0x00 (valid) or an error code.
pub const REQ_CREDENTIAL_PRESENT: u8 = 0x08;
/// Response: ARC credential presentation accepted.
pub const RESP_CREDENTIAL_OK: u8 = 0x08;

/// Client presents a Cashu Blind Auth Token (BAT) before a PIR query batch.
/// Server verifies the BDHKE signature and checks the spent-set.
pub const REQ_CASHU_BAT_PRESENT: u8 = 0x09;
/// Response: Cashu BAT accepted.
pub const RESP_CASHU_BAT_OK: u8 = 0x09;

// ─── Encrypted channel handshake (Slice B) ─────────────────────────────────
//
// One-round X25519 handshake before any traffic-bearing requests on a
// connection. After the handshake completes, every subsequent frame is
// AEAD-wrapped per `pir_channel::Session::seal` — the wire layout starts
// with `pir_channel::ENCRYPTED_FRAME_MAGIC` (= 0xfe), a sequence number,
// and a ChaCha20-Poly1305 ciphertext of the inner request/response.
//
// Sequence:
//   client → server:  REQ_HANDSHAKE { client_eph_pub: [u8;32], nonce: [u8;32] }
//   server → client:  RESP_HANDSHAKE { server_eph_pub: [u8;32] }
//
// The client must already know the server's long-lived static pubkey
// (via REQ_ATTEST + verifying REPORT_DATA — the V2 layout binds the
// pubkey to the chip-signed attestation). With both pubkeys + the
// nonce, both sides derive a session key via HKDF-SHA256.
//
// Cleartext requests (PING, GET_INFO, ATTEST, the handshake itself)
// remain available pre-handshake. Once the server processes a
// REQ_HANDSHAKE, the connection enters encrypted mode and any
// cleartext frame after that is a protocol error.
pub const REQ_HANDSHAKE: u8 = 0x06;

// ─── Admin auth (Slice 3a) ─────────────────────────────────────────────────
//
// Challenge/response with ed25519. The server holds the admin's public
// key (loaded once at startup from a CLI flag or env var, eventually
// from the UKI cmdline in tier 3). The client holds the matching
// private key on the operator's laptop.
//
//   client → server:  REQ_ADMIN_AUTH_CHALLENGE
//   server → client:  RESP_ADMIN_AUTH_CHALLENGE { nonce: [u8; 32] }
//   client signs `b"BPIR-ADMIN-AUTH-V1" || nonce` with their ed25519 sk
//   client → server:  REQ_ADMIN_AUTH_RESPONSE { signature: [u8; 64] }
//   server verifies → marks the connection authenticated.
//
// Auth state lives per-WebSocket-connection on the server. Disconnecting
// is logging out. Nothing in the wire protocol persists auth across
// connections.

pub const REQ_ADMIN_AUTH_CHALLENGE: u8 = 0x80;
pub const REQ_ADMIN_AUTH_RESPONSE: u8 = 0x81;

/// Domain-separation tag for admin-auth signatures. Must match between
/// client and server.
pub const ADMIN_AUTH_DOMAIN_TAG: &[u8] = b"BPIR-ADMIN-AUTH-V1";

// ─── Admin DB upload (Slice 3b) ────────────────────────────────────────────
//
// Streaming DB upload over the authenticated admin channel. After
// `REQ_ADMIN_AUTH_RESPONSE` succeeds, the client runs:
//
//   BEGIN { name, manifest_toml }     - server creates /data/.staging/<name>/
//                                        and writes MANIFEST.toml
//   CHUNK { name, file_path, offset,  - server appends bytes to the staged
//           data } × N                  file (one per file × chunk)
//   FINALIZE { name }                 - server verifies all files against
//                                        the manifest hashes; returns the
//                                        manifest_root (sha256 of MANIFEST)
//   ACTIVATE { name, target_path }    - server atomically renames
//                                        .staging/<name>/ → <target_path>/
//                                        (relative to data_root). The
//                                        operator restarts unified_server
//                                        to load the new DB (no hot-reload
//                                        in this slice).
//
// All operations require the connection to be authenticated; otherwise
// the server returns a RESP_ERROR envelope.

pub const REQ_ADMIN_DB_UPLOAD_BEGIN: u8 = 0x82;
pub const REQ_ADMIN_DB_UPLOAD_CHUNK: u8 = 0x83;
pub const REQ_ADMIN_DB_UPLOAD_FINALIZE: u8 = 0x84;
pub const REQ_ADMIN_DB_ACTIVATE: u8 = 0x85;

// ─── Response variants ──────────────────────────────────────────────────────

pub const RESP_PONG: u8 = 0x00;
pub const RESP_INFO: u8 = 0x01;
pub const RESP_DB_CATALOG: u8 = 0x02;
pub const RESP_ATTEST: u8 = 0x05;
pub const RESP_HANDSHAKE: u8 = 0x06;
pub const RESP_ADMIN_AUTH_CHALLENGE: u8 = 0x80;
pub const RESP_ADMIN_AUTH_RESPONSE: u8 = 0x81;
pub const RESP_ADMIN_DB_UPLOAD_BEGIN: u8 = 0x82;
pub const RESP_ADMIN_DB_UPLOAD_CHUNK: u8 = 0x83;
pub const RESP_ADMIN_DB_UPLOAD_FINALIZE: u8 = 0x84;
pub const RESP_ADMIN_DB_ACTIVATE: u8 = 0x85;
pub const RESP_INDEX_BATCH: u8 = 0x11;
pub const RESP_CHUNK_BATCH: u8 = 0x21;
pub const RESP_MERKLE_SIBLING_BATCH: u8 = 0x31;
pub const RESP_MERKLE_TREE_TOP: u8 = 0x32;
pub const RESP_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
pub const RESP_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;
pub const RESP_RESIDENCY: u8 = 0x04;
pub const RESP_ERROR: u8 = 0xFF;

// ─── HarmonyPIR response variants ──────────────────────────────────────────

pub const RESP_HARMONY_INFO: u8 = 0x40;
pub const RESP_HARMONY_HINTS: u8 = 0x41;
pub const RESP_HARMONY_QUERY: u8 = 0x42;
pub const RESP_HARMONY_BATCH_QUERY: u8 = 0x43;
/// Key preamble sent before per-group hint frames in V2 protocol.
pub const RESP_HARMONY_HINTS_KEY: u8 = 0x44;

// ─── Request types ──────────────────────────────────────────────────────────

/// A batch of DPF keys for one level.
/// Each group has N DPF keys (one per cuckoo hash function).
#[derive(Clone, Debug)]
pub struct BatchQuery {
    /// 0 for index, 1 for chunk
    pub level: u8,
    /// Round ID (only meaningful for chunk level; 0 for index)
    pub round_id: u16,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
    /// Per-group: list of DPF keys. Length = K (75) or K_CHUNK (80).
    /// Inner Vec length = number of cuckoo hash functions (2 for index, 3 for chunks).
    pub keys: Vec<Vec<Vec<u8>>>,
}

/// HarmonyPIR hint request: client asks Hint Server to compute hints.
///
/// Wire: [16B prp_key][1B prp_backend][1B level][1B num_groups][per group: 1B id]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyHintRequest {
    pub prp_key: [u8; 16],
    pub prp_backend: u8,
    pub level: u8,
    pub group_ids: Vec<u8>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

/// HarmonyPIR V2 hint request: server generates the PRP key.
///
/// Wire: [1B level_sentinel=0xFF][1B reserved=0x00]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
///
/// The server always returns ALL groups for both INDEX and CHUNK levels.
/// The level sentinel 0xFF signals "both levels."
#[derive(Clone, Debug)]
pub struct HarmonyHintRequestV2 {
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    pub db_id: u8,
}

/// HarmonyPIR V2 half-stream hint request.
///
/// Pairs with [`HarmonyHintRequestV2`] but only emits one of the two
/// trees (INDEX = side 0, CHUNK = side 1). The server matches two
/// requests carrying the same `session_token` against the same pool
/// entry — both halves therefore expose the same PRP key in their
/// preambles.
///
/// Wire: [16B session_token][1B side: 0=INDEX, 1=CHUNK]
///       [optional trailing 1B db_id, only when non-zero —
///        backward compatible]
///
/// Response wire shape per side is identical to the corresponding
/// portion of a [`HarmonyHintRequestV2`] response:
///   `[KEY_PREAMBLE] + [INDEX or CHUNK frames] + [SENTINEL]`
///
/// The server's pending-pool map keeps a token-to-entry mapping with
/// a short TTL (~30 s). The first arriving half allocates a fresh
/// pool entry; the second matching half consumes its other side
/// from the same entry. Lone tokens (one half arrives, the other
/// never does) expire and release their pool entries to be re-used.
#[derive(Clone, Debug)]
pub struct HarmonyHintRequestV2Half {
    /// 16-byte client-generated random token. Both halves of a logical
    /// session carry the same token; the server uses it as the key
    /// into its pending pool entry map.
    pub session_token: [u8; 16],
    /// Which half this request is for: 0 = INDEX, 1 = CHUNK.
    pub side: u8,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    pub db_id: u8,
}

/// HarmonyPIR query: client sends T indices for one group to Query Server.
///
/// Wire: [1B level][1B group_id][2B round_id][4B count][count × 4B u32 LE indices]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyQuery {
    pub level: u8,
    pub group_id: u8,
    pub round_id: u16,
    pub indices: Vec<u32>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

/// HarmonyPIR query result: server returns T entries for one group.
#[derive(Clone, Debug)]
pub struct HarmonyQueryResult {
    pub group_id: u8,
    pub round_id: u16,
    pub data: Vec<u8>,
}

/// HarmonyPIR batch query: client sends queries for multiple groups in one message.
///
/// Wire format:
///   [1B level][2B round_id LE][2B num_groups LE][1B sub_queries_per_group]
///   per group:
///     [1B group_id]
///     per sub_query (× sub_queries_per_group):
///       [4B count LE][count × 4B u32 LE indices]
///   [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyBatchQuery {
    pub level: u8,
    pub round_id: u16,
    pub sub_queries_per_group: u8,
    /// Per-group items.  Each item has `sub_queries_per_group` sub-queries.
    pub items: Vec<HarmonyBatchItem>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

#[derive(Clone, Debug)]
pub struct HarmonyBatchItem {
    pub group_id: u8,
    /// Each sub-query is a Vec of sorted u32 indices.
    pub sub_queries: Vec<Vec<u32>>,
}

/// HarmonyPIR batch result.
///
/// Wire format:
///   [1B level][2B round_id LE][2B num_groups LE][1B sub_results_per_group]
///   per group:
///     [1B group_id]
///     per sub_result (× sub_results_per_group):
///       [4B data_len LE][data_len bytes]
#[derive(Clone, Debug)]
pub struct HarmonyBatchResult {
    pub level: u8,
    pub round_id: u16,
    pub sub_results_per_group: u8,
    pub items: Vec<HarmonyBatchResultItem>,
}

#[derive(Clone, Debug)]
pub struct HarmonyBatchResultItem {
    pub group_id: u8,
    pub sub_results: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum Request {
    Ping,
    GetInfo,
    GetDbCatalog,
    /// Attestation request — 32-byte client-supplied nonce gets folded
    /// into REPORT_DATA so the response is anti-replay.
    Attest { nonce: [u8; 32] },
    /// Encrypted-channel handshake — sent in cleartext as the first
    /// channel-establishing message. After the server replies with its
    /// `server_eph_pub`, both sides derive a session key per
    /// `pir_channel`'s ECDH+HKDF construction. Subsequent client→server
    /// frames are AEAD-wrapped with `pir_channel::ENCRYPTED_FRAME_MAGIC`
    /// as the leading byte.
    Handshake {
        /// Client's per-session X25519 ephemeral pubkey.
        client_eph_pub: [u8; 32],
        /// Random 32-byte salt for HKDF-SHA256 session-key derivation.
        nonce: [u8; 32],
    },
    /// Admin auth step 1 — client asks the server for a challenge nonce.
    AdminAuthChallenge,
    /// Admin auth step 2 — client returns ed25519 signature over
    /// `ADMIN_AUTH_DOMAIN_TAG || nonce`.
    AdminAuthResponse { signature: [u8; 64] },
    /// Start a new DB upload — server creates `data_root/.staging/<name>/`
    /// and writes `MANIFEST.toml` from `manifest_toml`.
    AdminDbUploadBegin {
        name: String,
        manifest_toml: Vec<u8>,
    },
    /// Append `data` to `staging/<name>/<file_path>` at byte `offset`.
    AdminDbUploadChunk {
        name: String,
        file_path: String,
        offset: u64,
        data: Vec<u8>,
    },
    /// Verify the staged dir against its manifest. Returns the manifest root.
    AdminDbUploadFinalize {
        name: String,
    },
    /// Atomic-rename `staging/<name>/` → `data_root/<target_path>/`.
    /// Operator restarts unified_server to load the new DB.
    AdminDbActivate {
        name: String,
        target_path: String,
    },
    IndexBatch(BatchQuery),
    ChunkBatch(BatchQuery),
    MerkleSiblingBatch(BatchQuery),
    BucketMerkleSibBatch(BatchQuery),
    HarmonyGetInfo,
    HarmonyHints(HarmonyHintRequest),
    HarmonyHintsV2(HarmonyHintRequestV2),
    HarmonyHintsV2Half(HarmonyHintRequestV2Half),
    HarmonyQuery(HarmonyQuery),
    HarmonyBatchQuery(HarmonyBatchQuery),
}

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub index_k: u8,
    pub chunk_k: u8,
    pub tag_seed: u64,
}

/// Info about a single database in the server's catalog.
#[derive(Clone, Debug)]
pub struct DatabaseCatalogEntry {
    /// Database ID (index into the server's database list).
    pub db_id: u8,
    /// 0 = full UTXO snapshot, 1 = delta between two heights.
    pub db_type: u8,
    /// Human-readable name (e.g. "main", "delta_940611_944000").
    pub name: String,
    /// Base height (0 for full snapshots, start height for deltas).
    pub base_height: u32,
    /// Tip height (snapshot height for full, end height for deltas).
    pub height: u32,
    /// INDEX-level bins_per_table.
    pub index_bins_per_table: u32,
    /// CHUNK-level bins_per_table.
    pub chunk_bins_per_table: u32,
    /// INDEX-level group count.
    pub index_k: u8,
    /// CHUNK-level group count.
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

/// Server's database catalog listing all available databases.
#[derive(Clone, Debug)]
pub struct DatabaseCatalog {
    pub databases: Vec<DatabaseCatalogEntry>,
}

/// Server response to a `REQ_ADMIN_AUTH_CHALLENGE`. The 32-byte
/// `nonce` is what the client must sign (prefixed by
/// `ADMIN_AUTH_DOMAIN_TAG`) and return as a `REQ_ADMIN_AUTH_RESPONSE`.
#[derive(Clone, Debug)]
pub struct AdminAuthChallenge {
    pub nonce: [u8; 32],
}

/// Server response to a `REQ_ADMIN_AUTH_RESPONSE`. `ok = true` means
/// the connection is now authenticated; subsequent admin requests on
/// the same connection are accepted. `msg` is a short status string
/// (e.g. "ok", "no challenge issued", "bad signature").
#[derive(Clone, Debug)]
pub struct AdminAuthResult {
    pub ok: bool,
    pub msg: String,
}

/// Generic ack used by BEGIN, CHUNK, ACTIVATE.
#[derive(Clone, Debug)]
pub struct AdminAck {
    pub ok: bool,
    pub msg: String,
}

/// Reply to `REQ_ADMIN_DB_UPLOAD_FINALIZE`. On success, `manifest_root`
/// is the SHA-256 of the staged `MANIFEST.toml` — the same value
/// `MappedDatabase::load()` would expose if the staging dir were
/// activated and the server reloaded.
#[derive(Clone, Debug)]
pub struct AdminFinalizeResult {
    pub ok: bool,
    pub msg: String,
    pub manifest_root: [u8; 32],
}

/// Result of an attestation request.
///
/// Wire format (encoded after the `RESP_ATTEST` variant byte):
///
///   [4B sev_report_len LE][sev_report_bytes]   (len=0 if not on SEV-SNP)
///   [1B num_manifest_roots][num × 32B]          (per-DB roots in db_id order)
///   [32B binary_sha256]
///   [2B git_rev_len LE][git_rev_bytes UTF-8]
///
/// Per-DB manifest roots are zero (`[0u8; 32]`) for DBs that don't have
/// a `MANIFEST.toml` (back-compat with legacy DBs).
/// Server's response to a `REQ_HANDSHAKE`. Carries the per-session
/// X25519 ephemeral public key. The client combines this with the
/// server's long-lived static pubkey (verified via attestation) and
/// its own ephemeral secret to derive the session key — see
/// `pir_channel::ClientHandshake::complete_handshake`.
///
/// Wire format (after the `RESP_HANDSHAKE` variant byte):
/// `[u8; 32] server_eph_pub`
#[derive(Clone, Debug)]
pub struct HandshakeResult {
    /// Per-session X25519 ephemeral pubkey. Different for every
    /// handshake even within the same boot of the server (provides
    /// forward secrecy).
    pub server_eph_pub: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AttestResult {
    /// Raw signed SEV-SNP attestation report bytes (~1184 for v5).
    /// Empty if /dev/sev-guest unavailable on the host.
    pub sev_snp_report: Vec<u8>,
    /// Per-DB manifest roots in db_id order. Length matches catalog.
    pub manifest_roots: Vec<[u8; 32]>,
    /// SHA-256 of `/proc/self/exe` captured at server startup.
    pub binary_sha256: [u8; 32],
    /// Long-lived X25519 public key the server generated inside the
    /// SEV-SNP guest at boot. Bound into REPORT_DATA via
    /// `pir_core::attest::build_report_data` (V2 layout) so a chip-
    /// signed report authenticates this exact key. Used by clients
    /// to establish an end-to-end encrypted channel that cloudflared
    /// (and Cloudflare's edge) can't read. All-zero on servers that
    /// don't yet have a channel key (transitional).
    pub server_static_pub: [u8; 32],
    /// Git commit baked in at build time (40-char SHA, optionally
    /// suffixed with `-dirty`, or "unknown" for non-git builds).
    pub git_rev: String,
    /// PEM-encoded AMD ARK (Root Key) certificate. Empty if the server
    /// doesn't have the cert chain loaded (operator hasn't run the
    /// fetch-vcek-chain step). The browser's pir-attest-verify uses
    /// it (combined with `ask_pem` + `vcek_pem`) to chain-validate
    /// the SEV-SNP report's signature back to AMD's known root.
    pub ark_pem: Vec<u8>,
    /// PEM-encoded AMD ASK (SEV Signing Key) certificate, per
    /// SoC family (Milan / Genoa / Turin). Empty if not loaded.
    pub ask_pem: Vec<u8>,
    /// PEM-encoded VCEK (Versioned Chip Endorsement Key) certificate
    /// for THIS chip + TCB. Empty if not loaded. The chip ID + TCB
    /// in the SNP report determine the AMD KDS URL the operator
    /// fetched this from.
    pub vcek_pem: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BatchResult {
    pub level: u8,
    pub round_id: u16,
    /// Per-group: list of results. Same structure as request keys.
    pub results: Vec<Vec<Vec<u8>>>,
}

#[derive(Clone, Debug)]
pub enum Response {
    Pong,
    Info(ServerInfo),
    DbCatalog(DatabaseCatalog),
    Attest(AttestResult),
    /// Server's reply to `Request::Handshake`. Carries the per-session
    /// X25519 ephemeral pubkey. After this exchange both sides have the
    /// same session key derived via `pir_channel`'s ECDH+HKDF.
    Handshake(HandshakeResult),
    AdminAuthChallenge(AdminAuthChallenge),
    AdminAuthResponse(AdminAuthResult),
    AdminDbUploadBegin(AdminAck),
    AdminDbUploadChunk(AdminAck),
    AdminDbUploadFinalize(AdminFinalizeResult),
    AdminDbActivate(AdminAck),
    IndexBatch(BatchResult),
    ChunkBatch(BatchResult),
    MerkleSiblingBatch(BatchResult),
    BucketMerkleSibBatch(BatchResult),
    Error(String),
    HarmonyInfo(ServerInfo),
    HarmonyQueryResult(HarmonyQueryResult),
    HarmonyBatchResult(HarmonyBatchResult),
    /// ARC credential presentation verified (status=0x00).
    ArcCredentialOk,
    /// Cashu BAT presentation verified.
    CashuBatOk,
}

// ─── Encoding ───────────────────────────────────────────────────────────────

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Request::Ping => {
                payload.push(REQ_PING);
            }
            Request::GetInfo => {
                payload.push(REQ_GET_INFO);
            }
            Request::GetDbCatalog => {
                payload.push(REQ_GET_DB_CATALOG);
            }
            Request::Attest { nonce } => {
                payload.push(REQ_ATTEST);
                payload.extend_from_slice(nonce);
            }
            Request::Handshake { client_eph_pub, nonce } => {
                payload.push(REQ_HANDSHAKE);
                payload.extend_from_slice(client_eph_pub);
                payload.extend_from_slice(nonce);
            }
            Request::AdminAuthChallenge => {
                payload.push(REQ_ADMIN_AUTH_CHALLENGE);
            }
            Request::AdminAuthResponse { signature } => {
                payload.push(REQ_ADMIN_AUTH_RESPONSE);
                payload.extend_from_slice(signature);
            }
            Request::AdminDbUploadBegin { name, manifest_toml } => {
                payload.push(REQ_ADMIN_DB_UPLOAD_BEGIN);
                encode_lp_string(&mut payload, name);
                payload.extend_from_slice(&(manifest_toml.len() as u32).to_le_bytes());
                payload.extend_from_slice(manifest_toml);
            }
            Request::AdminDbUploadChunk { name, file_path, offset, data } => {
                payload.push(REQ_ADMIN_DB_UPLOAD_CHUNK);
                encode_lp_string(&mut payload, name);
                encode_lp_string(&mut payload, file_path);
                payload.extend_from_slice(&offset.to_le_bytes());
                payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
                payload.extend_from_slice(data);
            }
            Request::AdminDbUploadFinalize { name } => {
                payload.push(REQ_ADMIN_DB_UPLOAD_FINALIZE);
                encode_lp_string(&mut payload, name);
            }
            Request::AdminDbActivate { name, target_path } => {
                payload.push(REQ_ADMIN_DB_ACTIVATE);
                encode_lp_string(&mut payload, name);
                encode_lp_string(&mut payload, target_path);
            }
            Request::IndexBatch(q) => {
                payload.push(REQ_INDEX_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::ChunkBatch(q) => {
                payload.push(REQ_CHUNK_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::MerkleSiblingBatch(q) => {
                payload.push(REQ_MERKLE_SIBLING_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::BucketMerkleSibBatch(q) => {
                payload.push(REQ_BUCKET_MERKLE_SIB_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::HarmonyGetInfo => {
                payload.push(REQ_HARMONY_GET_INFO);
            }
            Request::HarmonyHints(h) => {
                payload.push(REQ_HARMONY_HINTS);
                payload.extend_from_slice(&h.prp_key);
                payload.push(h.prp_backend);
                payload.push(h.level);
                payload.push(h.group_ids.len() as u8);
                payload.extend_from_slice(&h.group_ids);
                // Trailing db_id byte: only appended when non-zero for backward compatibility.
                if h.db_id != 0 {
                    payload.push(h.db_id);
                }
            }
            Request::HarmonyHintsV2(h) => {
                payload.push(REQ_HARMONY_HINTS_V2);
                payload.push(0xFFu8); // level_sentinel: all levels
                payload.push(0x00u8); // reserved
                if h.db_id != 0 {
                    payload.push(h.db_id);
                }
            }
            Request::HarmonyHintsV2Half(h) => {
                payload.push(REQ_HARMONY_HINTS_V2_HALF);
                payload.extend_from_slice(&h.session_token);
                payload.push(h.side);
                if h.db_id != 0 {
                    payload.push(h.db_id);
                }
            }
            Request::HarmonyQuery(q) => {
                payload.push(REQ_HARMONY_QUERY);
                payload.push(q.level);
                payload.push(q.group_id);
                payload.extend_from_slice(&q.round_id.to_le_bytes());
                payload.extend_from_slice(&(q.indices.len() as u32).to_le_bytes());
                for idx in &q.indices {
                    payload.extend_from_slice(&idx.to_le_bytes());
                }
                // Trailing db_id byte: only appended when non-zero for backward compatibility.
                if q.db_id != 0 {
                    payload.push(q.db_id);
                }
            }
            Request::HarmonyBatchQuery(q) => {
                payload.push(REQ_HARMONY_BATCH_QUERY);
                encode_harmony_batch_query(&mut payload, q);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty request"));
        }
        match data[0] {
            REQ_PING => Ok(Request::Ping),
            REQ_GET_INFO => Ok(Request::GetInfo),
            REQ_GET_DB_CATALOG => Ok(Request::GetDbCatalog),
            REQ_ATTEST => {
                if data.len() < 1 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "attest request must carry a 32-byte nonce",
                    ));
                }
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&data[1..33]);
                Ok(Request::Attest { nonce })
            }
            REQ_HANDSHAKE => {
                // Wire layout: [variant:1][client_eph_pub:32][nonce:32]
                if data.len() < 1 + 32 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "handshake request must carry 32-byte client_eph_pub + 32-byte nonce",
                    ));
                }
                let mut client_eph_pub = [0u8; 32];
                client_eph_pub.copy_from_slice(&data[1..33]);
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&data[33..65]);
                Ok(Request::Handshake { client_eph_pub, nonce })
            }
            REQ_ADMIN_AUTH_CHALLENGE => Ok(Request::AdminAuthChallenge),
            REQ_ADMIN_AUTH_RESPONSE => {
                if data.len() < 1 + 64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "admin auth response must carry a 64-byte signature",
                    ));
                }
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&data[1..65]);
                Ok(Request::AdminAuthResponse { signature })
            }
            REQ_ADMIN_DB_UPLOAD_BEGIN => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                if pos + 4 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "missing manifest len"));
                }
                let mlen = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
                pos += 4;
                if pos + mlen > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated manifest_toml"));
                }
                let manifest_toml = data[pos..pos+mlen].to_vec();
                Ok(Request::AdminDbUploadBegin { name, manifest_toml })
            }
            REQ_ADMIN_DB_UPLOAD_CHUNK => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                let file_path = decode_lp_string(data, &mut pos)?;
                if pos + 8 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "missing offset"));
                }
                let offset = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
                pos += 8;
                if pos + 4 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "missing data len"));
                }
                let dlen = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
                pos += 4;
                if pos + dlen > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated chunk data"));
                }
                let data_bytes = data[pos..pos+dlen].to_vec();
                Ok(Request::AdminDbUploadChunk { name, file_path, offset, data: data_bytes })
            }
            REQ_ADMIN_DB_UPLOAD_FINALIZE => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                Ok(Request::AdminDbUploadFinalize { name })
            }
            REQ_ADMIN_DB_ACTIVATE => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                let target_path = decode_lp_string(data, &mut pos)?;
                Ok(Request::AdminDbActivate { name, target_path })
            }
            REQ_INDEX_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::IndexBatch(q))
            }
            REQ_CHUNK_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::ChunkBatch(q))
            }
            REQ_MERKLE_SIBLING_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::MerkleSiblingBatch(q))
            }
            REQ_BUCKET_MERKLE_SIB_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::BucketMerkleSibBatch(q))
            }
            REQ_HARMONY_GET_INFO => Ok(Request::HarmonyGetInfo),
            REQ_HARMONY_HINTS => {
                let h = decode_harmony_hint_request(&data[1..])?;
                Ok(Request::HarmonyHints(h))
            }
            REQ_HARMONY_HINTS_V2 => {
                let h = decode_harmony_hint_request_v2(&data[1..])?;
                Ok(Request::HarmonyHintsV2(h))
            }
            REQ_HARMONY_HINTS_V2_HALF => {
                let h = decode_harmony_hint_request_v2_half(&data[1..])?;
                Ok(Request::HarmonyHintsV2Half(h))
            }
            REQ_HARMONY_QUERY => {
                let q = decode_harmony_query(&data[1..])?;
                Ok(Request::HarmonyQuery(q))
            }
            REQ_HARMONY_BATCH_QUERY => {
                let q = decode_harmony_batch_query(&data[1..])?;
                Ok(Request::HarmonyBatchQuery(q))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown request variant: 0x{:02x}", v),
            )),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Response::Pong => {
                payload.push(RESP_PONG);
            }
            Response::Info(info) => {
                payload.push(RESP_INFO);
                payload.extend_from_slice(&info.index_bins_per_table.to_le_bytes());
                payload.extend_from_slice(&info.chunk_bins_per_table.to_le_bytes());
                payload.push(info.index_k);
                payload.push(info.chunk_k);
                payload.extend_from_slice(&info.tag_seed.to_le_bytes());
            }
            Response::DbCatalog(cat) => {
                payload.push(RESP_DB_CATALOG);
                encode_db_catalog(&mut payload, cat);
            }
            Response::Attest(r) => {
                payload.push(RESP_ATTEST);
                encode_attest_result(&mut payload, r);
            }
            Response::Handshake(r) => {
                payload.push(RESP_HANDSHAKE);
                payload.extend_from_slice(&r.server_eph_pub);
            }
            Response::AdminAuthChallenge(c) => {
                payload.push(RESP_ADMIN_AUTH_CHALLENGE);
                payload.extend_from_slice(&c.nonce);
            }
            Response::AdminAuthResponse(r) => {
                payload.push(RESP_ADMIN_AUTH_RESPONSE);
                encode_admin_ack_payload(&mut payload, r.ok, &r.msg);
            }
            Response::AdminDbUploadBegin(a) => {
                payload.push(RESP_ADMIN_DB_UPLOAD_BEGIN);
                encode_admin_ack_payload(&mut payload, a.ok, &a.msg);
            }
            Response::AdminDbUploadChunk(a) => {
                payload.push(RESP_ADMIN_DB_UPLOAD_CHUNK);
                encode_admin_ack_payload(&mut payload, a.ok, &a.msg);
            }
            Response::AdminDbUploadFinalize(r) => {
                payload.push(RESP_ADMIN_DB_UPLOAD_FINALIZE);
                payload.push(if r.ok { 1 } else { 0 });
                let mb = r.msg.as_bytes();
                payload.extend_from_slice(&(mb.len() as u16).to_le_bytes());
                payload.extend_from_slice(mb);
                payload.extend_from_slice(&r.manifest_root);
            }
            Response::AdminDbActivate(a) => {
                payload.push(RESP_ADMIN_DB_ACTIVATE);
                encode_admin_ack_payload(&mut payload, a.ok, &a.msg);
            }
            Response::IndexBatch(r) => {
                payload.push(RESP_INDEX_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::ChunkBatch(r) => {
                payload.push(RESP_CHUNK_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::MerkleSiblingBatch(r) => {
                payload.push(RESP_MERKLE_SIBLING_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::BucketMerkleSibBatch(r) => {
                payload.push(RESP_BUCKET_MERKLE_SIB_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::Error(msg) => {
                payload.push(RESP_ERROR);
                let bytes = msg.as_bytes();
                payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bytes);
            }
            Response::HarmonyInfo(info) => {
                payload.push(RESP_HARMONY_INFO);
                payload.extend_from_slice(&info.index_bins_per_table.to_le_bytes());
                payload.extend_from_slice(&info.chunk_bins_per_table.to_le_bytes());
                payload.push(info.index_k);
                payload.push(info.chunk_k);
                payload.extend_from_slice(&info.tag_seed.to_le_bytes());
            }
            Response::HarmonyQueryResult(r) => {
                payload.push(RESP_HARMONY_QUERY);
                payload.push(r.group_id);
                payload.extend_from_slice(&r.round_id.to_le_bytes());
                payload.extend_from_slice(&r.data);
            }
            Response::HarmonyBatchResult(r) => {
                payload.push(RESP_HARMONY_BATCH_QUERY);
                encode_harmony_batch_result(&mut payload, r);
            }
            Response::ArcCredentialOk => {
                payload.push(RESP_CREDENTIAL_OK);
                payload.push(0x00u8); // status = valid
            }
            Response::CashuBatOk => {
                payload.push(RESP_CASHU_BAT_OK);
                payload.push(0x00u8);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty response"));
        }
        match data[0] {
            RESP_PONG => Ok(Response::Pong),
            RESP_INFO => {
                if data.len() < 19 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "info too short"));
                }
                Ok(Response::Info(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                    tag_seed: u64::from_le_bytes(data[11..19].try_into().unwrap()),
                }))
            }
            RESP_DB_CATALOG => {
                let cat = decode_db_catalog(&data[1..])?;
                Ok(Response::DbCatalog(cat))
            }
            RESP_ATTEST => {
                let r = decode_attest_result(&data[1..])?;
                Ok(Response::Attest(r))
            }
            RESP_HANDSHAKE => {
                if data.len() < 1 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "handshake response missing 32-byte server_eph_pub",
                    ));
                }
                let mut server_eph_pub = [0u8; 32];
                server_eph_pub.copy_from_slice(&data[1..33]);
                Ok(Response::Handshake(HandshakeResult { server_eph_pub }))
            }
            RESP_ADMIN_AUTH_CHALLENGE => {
                if data.len() < 1 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "admin auth challenge response missing nonce",
                    ));
                }
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&data[1..33]);
                Ok(Response::AdminAuthChallenge(AdminAuthChallenge { nonce }))
            }
            RESP_ADMIN_AUTH_RESPONSE => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminAuthResponse(AdminAuthResult { ok, msg }))
            }
            RESP_ADMIN_DB_UPLOAD_BEGIN => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminDbUploadBegin(AdminAck { ok, msg }))
            }
            RESP_ADMIN_DB_UPLOAD_CHUNK => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminDbUploadChunk(AdminAck { ok, msg }))
            }
            RESP_ADMIN_DB_UPLOAD_FINALIZE => {
                if data.len() < 1 + 1 + 2 + 32 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "finalize result too short"));
                }
                let ok = data[1] != 0;
                let msg_len = u16::from_le_bytes(data[2..4].try_into().unwrap()) as usize;
                if 4 + msg_len + 32 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "finalize result truncated"));
                }
                let msg = String::from_utf8_lossy(&data[4..4 + msg_len]).to_string();
                let mut manifest_root = [0u8; 32];
                manifest_root.copy_from_slice(&data[4 + msg_len..4 + msg_len + 32]);
                Ok(Response::AdminDbUploadFinalize(AdminFinalizeResult { ok, msg, manifest_root }))
            }
            RESP_ADMIN_DB_ACTIVATE => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminDbActivate(AdminAck { ok, msg }))
            }
            RESP_INDEX_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::IndexBatch(r))
            }
            RESP_CHUNK_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::ChunkBatch(r))
            }
            RESP_MERKLE_SIBLING_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::MerkleSiblingBatch(r))
            }
            RESP_BUCKET_MERKLE_SIB_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::BucketMerkleSibBatch(r))
            }
            RESP_ERROR => {
                let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
                let msg = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                Ok(Response::Error(msg))
            }
            RESP_HARMONY_INFO => {
                if data.len() < 19 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony info too short"));
                }
                Ok(Response::HarmonyInfo(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                    tag_seed: u64::from_le_bytes(data[11..19].try_into().unwrap()),
                }))
            }
            RESP_HARMONY_QUERY => {
                if data.len() < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony query result too short"));
                }
                Ok(Response::HarmonyQueryResult(HarmonyQueryResult {
                    group_id: data[1],
                    round_id: u16::from_le_bytes(data[2..4].try_into().unwrap()),
                    data: data[4..].to_vec(),
                }))
            }
            RESP_HARMONY_BATCH_QUERY => {
                let r = decode_harmony_batch_result(&data[1..])?;
                Ok(Response::HarmonyBatchResult(r))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown response variant: 0x{:02x}", v),
            )),
        }
    }
}

// ─── Batch encoding helpers ─────────────────────────────────────────────────

/// Wire format:
///   [2B round_id][1B num_groups][1B keys_per_group]
///   For each group:
///     For each key (keys_per_group times):
///       [2B key_len][key_data]
fn encode_batch_query(buf: &mut Vec<u8>, q: &BatchQuery) {
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.push(q.keys.len() as u8);
    let keys_per_group = q.keys.first().map_or(0, |k| k.len()) as u8;
    buf.push(keys_per_group);
    for group_keys in &q.keys {
        for k in group_keys {
            buf.extend_from_slice(&(k.len() as u16).to_le_bytes());
            buf.extend_from_slice(k);
        }
    }
    // Trailing db_id byte: only appended when non-zero for backward compatibility.
    if q.db_id != 0 {
        buf.push(q.db_id);
    }
}

fn decode_batch_query(data: &[u8]) -> io::Result<BatchQuery> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch query too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let keys_per_group = data[pos] as usize;
    pos += 1;
    let mut keys = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let mut group_keys = Vec::with_capacity(keys_per_group);
        for _ in 0..keys_per_group {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key data"));
            }
            group_keys.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        keys.push(group_keys);
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(BatchQuery {
        level: 0,
        round_id,
        db_id,
        keys,
    })
}

fn encode_batch_result(buf: &mut Vec<u8>, r: &BatchResult) {
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.push(r.results.len() as u8);
    let results_per_group = r.results.first().map_or(0, |r| r.len()) as u8;
    buf.push(results_per_group);
    for group_results in &r.results {
        for res in group_results {
            buf.extend_from_slice(&(res.len() as u16).to_le_bytes());
            buf.extend_from_slice(res);
        }
    }
}

fn decode_batch_result(data: &[u8]) -> io::Result<BatchResult> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch result too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let results_per_group = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let mut group_results = Vec::with_capacity(results_per_group);
        for _ in 0..results_per_group {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result data"));
            }
            group_results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        results.push(group_results);
    }
    Ok(BatchResult {
        level: 0,
        round_id,
        results,
    })
}

// ─── HarmonyPIR encoding helpers ────────────────────────────────────────────

fn decode_harmony_hint_request(data: &[u8]) -> io::Result<HarmonyHintRequest> {
    // [16B prp_key][1B prp_backend][1B level][1B num_groups][per group: 1B id]
    // [optional trailing 1B db_id, only when non-zero — backward compatible]
    if data.len() < 19 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony hint request too short"));
    }
    let mut prp_key = [0u8; 16];
    prp_key.copy_from_slice(&data[0..16]);
    let prp_backend = data[16];
    let level = data[17];
    let num_groups = data[18] as usize;
    let pos = 19 + num_groups;
    if data.len() < pos {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated group list"));
    }
    let group_ids = data[19..pos].to_vec();
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(HarmonyHintRequest {
        prp_key,
        prp_backend,
        level,
        group_ids,
        db_id,
    })
}

/// V2 hint request wire format:
/// [1B level_sentinel=0xFF][1B reserved=0x00]
/// [optional trailing 1B db_id]
fn decode_harmony_hint_request_v2(data: &[u8]) -> io::Result<HarmonyHintRequestV2> {
    // Minimum: level_sentinel (1) + reserved (1)
    if data.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "V2 hint request too short",
        ));
    }
    let level_sentinel = data[0];
    if level_sentinel != 0xFF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("V2 hint request expected level_sentinel 0xFF, got 0x{:02x}", level_sentinel),
        ));
    }
    // data[1] is reserved, ignored.
    let db_id = if data.len() > 2 { data[2] } else { 0 };
    Ok(HarmonyHintRequestV2 { db_id })
}

/// V2 half-stream hint request wire format:
/// [16B session_token][1B side: 0=INDEX, 1=CHUNK]
/// [optional trailing 1B db_id]
fn decode_harmony_hint_request_v2_half(data: &[u8]) -> io::Result<HarmonyHintRequestV2Half> {
    // Minimum: session_token (16) + side (1)
    if data.len() < 17 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "V2 half hint request too short",
        ));
    }
    let mut session_token = [0u8; 16];
    session_token.copy_from_slice(&data[..16]);
    let side = data[16];
    if side != 0 && side != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("V2 half hint request side must be 0 or 1, got {}", side),
        ));
    }
    let db_id = if data.len() > 17 { data[17] } else { 0 };
    Ok(HarmonyHintRequestV2Half {
        session_token,
        side,
        db_id,
    })
}

// ─── HarmonyPIR batch encoding helpers ─────────────────────────────────────

/// Encode a `HarmonyBatchQuery` *payload* (no [4B length][1B opcode]
/// envelope — the envelope is owned by `Request::encode`). Exposed as
/// `pub` so out-of-crate callers (notably the WASM wire-explorer
/// decoder in `pir-sdk-wasm`) have a single source-of-truth encoder
/// to test their mirrored decoder against.
pub fn encode_harmony_batch_query(buf: &mut Vec<u8>, q: &HarmonyBatchQuery) {
    buf.push(q.level);
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.extend_from_slice(&(q.items.len() as u16).to_le_bytes());
    buf.push(q.sub_queries_per_group);
    for item in &q.items {
        buf.push(item.group_id);
        for sq in &item.sub_queries {
            buf.extend_from_slice(&(sq.len() as u32).to_le_bytes());
            for &idx in sq {
                buf.extend_from_slice(&idx.to_le_bytes());
            }
        }
    }
    // Trailing db_id byte: only appended when non-zero for backward compatibility.
    if q.db_id != 0 {
        buf.push(q.db_id);
    }
}

/// Decode a `HarmonyBatchQuery` *payload* (no [4B length][1B opcode]
/// envelope — pass `&data[1..]` from a `[opcode][payload]` frame, or
/// just `&payload` from a stripped frame). Exposed as `pub` so
/// out-of-crate callers (the WASM wire-explorer in `pir-sdk-wasm`)
/// share one parser definition with the server side.
pub fn decode_harmony_batch_query(data: &[u8]) -> io::Result<HarmonyBatchQuery> {
    if data.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony batch query too short"));
    }
    let level = data[0];
    let round_id = u16::from_le_bytes(data[1..3].try_into().unwrap());
    let num_groups = u16::from_le_bytes(data[3..5].try_into().unwrap()) as usize;
    let sub_queries_per_group = data[5];
    let mut pos = 6;
    let mut items = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch group"));
        }
        let group_id = data[pos];
        pos += 1;
        let mut sub_queries = Vec::with_capacity(sub_queries_per_group as usize);
        for _ in 0..sub_queries_per_group {
            if pos + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch sub-query count"));
            }
            let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + count * 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch indices"));
            }
            let mut indices = Vec::with_capacity(count);
            for i in 0..count {
                let off = pos + i * 4;
                indices.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
            }
            pos += count * 4;
            sub_queries.push(indices);
        }
        items.push(HarmonyBatchItem { group_id, sub_queries });
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(HarmonyBatchQuery { level, round_id, sub_queries_per_group, items, db_id })
}

fn encode_harmony_batch_result(buf: &mut Vec<u8>, r: &HarmonyBatchResult) {
    buf.push(r.level);
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.extend_from_slice(&(r.items.len() as u16).to_le_bytes());
    buf.push(r.sub_results_per_group);
    for item in &r.items {
        buf.push(item.group_id);
        for sr in &item.sub_results {
            buf.extend_from_slice(&(sr.len() as u32).to_le_bytes());
            buf.extend_from_slice(sr);
        }
    }
}

fn decode_harmony_batch_result(data: &[u8]) -> io::Result<HarmonyBatchResult> {
    if data.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony batch result too short"));
    }
    let level = data[0];
    let round_id = u16::from_le_bytes(data[1..3].try_into().unwrap());
    let num_groups = u16::from_le_bytes(data[3..5].try_into().unwrap()) as usize;
    let sub_results_per_group = data[5];
    let mut pos = 6;
    let mut items = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result group"));
        }
        let group_id = data[pos];
        pos += 1;
        let mut sub_results = Vec::with_capacity(sub_results_per_group as usize);
        for _ in 0..sub_results_per_group {
            if pos + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result len"));
            }
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result data"));
            }
            sub_results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        items.push(HarmonyBatchResultItem { group_id, sub_results });
    }
    Ok(HarmonyBatchResult { level, round_id, sub_results_per_group, items })
}

// ─── Database catalog encoding helpers ─────────────────────────────────────

/// Wire format:
///   [1B num_databases]
///   Per database:
///     [1B db_id][1B name_len][name bytes][4B height]
///     [4B index_bins][4B chunk_bins][1B index_k][1B chunk_k]
///     [8B tag_seed][1B dpf_n_index][1B dpf_n_chunk]
fn encode_db_catalog(buf: &mut Vec<u8>, cat: &DatabaseCatalog) {
    buf.push(cat.databases.len() as u8);
    for entry in &cat.databases {
        buf.push(entry.db_id);
        buf.push(entry.db_type);
        let name_bytes = entry.name.as_bytes();
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&entry.base_height.to_le_bytes());
        buf.extend_from_slice(&entry.height.to_le_bytes());
        buf.extend_from_slice(&entry.index_bins_per_table.to_le_bytes());
        buf.extend_from_slice(&entry.chunk_bins_per_table.to_le_bytes());
        buf.push(entry.index_k);
        buf.push(entry.chunk_k);
        buf.extend_from_slice(&entry.tag_seed.to_le_bytes());
        buf.push(entry.dpf_n_index);
        buf.push(entry.dpf_n_chunk);
        buf.push(if entry.has_bucket_merkle { 1 } else { 0 });
    }
}

fn decode_db_catalog(data: &[u8]) -> io::Result<DatabaseCatalog> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "catalog too short"));
    }
    let num_dbs = data[0] as usize;
    let mut pos = 1;
    let mut databases = Vec::with_capacity(num_dbs);
    for _ in 0..num_dbs {
        if pos + 3 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog entry"));
        }
        let db_id = data[pos];
        pos += 1;
        let db_type = data[pos];
        pos += 1;
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog name"));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;
        // base_height(4) + height(4) + index_bins(4) + chunk_bins(4) + index_k(1) + chunk_k(1) + tag_seed(8) + dpf_n_index(1) + dpf_n_chunk(1) = 28
        // + has_bucket_merkle(1) = 29 (optional for backward compat)
        if pos + 28 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog fields"));
        }
        let base_height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_bins_per_table = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let chunk_bins_per_table = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
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
        // has_bucket_merkle: always present in current wire format (1 byte, 0 or 1)
        let has_bucket_merkle = if pos < data.len() {
            let v = data[pos] != 0;
            pos += 1;
            v
        } else {
            false
        };
        databases.push(DatabaseCatalogEntry {
            db_id,
            db_type,
            name,
            base_height,
            height,
            index_bins_per_table,
            chunk_bins_per_table,
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

// ─── Attestation encoding helpers ──────────────────────────────────────────

fn encode_attest_result(buf: &mut Vec<u8>, r: &AttestResult) {
    buf.extend_from_slice(&(r.sev_snp_report.len() as u32).to_le_bytes());
    buf.extend_from_slice(&r.sev_snp_report);
    // Manifest-roots count fits in u8 because db_id is u8 (≤255 DBs).
    let n = r.manifest_roots.len();
    debug_assert!(n <= u8::MAX as usize, "too many manifest roots");
    buf.push(n as u8);
    for root in &r.manifest_roots {
        buf.extend_from_slice(root);
    }
    buf.extend_from_slice(&r.binary_sha256);
    // V2 wire layout: server_static_pub immediately after binary_sha256.
    // Bumped together with REPORT_DATA's BPIR-ATTEST-V2 tag.
    buf.extend_from_slice(&r.server_static_pub);
    let git_bytes = r.git_rev.as_bytes();
    debug_assert!(git_bytes.len() <= u16::MAX as usize, "git_rev too long");
    buf.extend_from_slice(&(git_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(git_bytes);
    // V3 cert chain extension: ARK + ASK + VCEK PEMs. Each prefixed
    // with a u32 LE length (PEMs are ~2 KB each — well below 2 GiB).
    // Empty if the operator hasn't loaded the cert chain on the
    // server; the verifier falls back to V2-binding-only mode in
    // that case.
    encode_lp_bytes_u32(buf, &r.ark_pem);
    encode_lp_bytes_u32(buf, &r.ask_pem);
    encode_lp_bytes_u32(buf, &r.vcek_pem);
}

/// Length-prefixed bytes write helper (u32 LE length + body). Mirrors
/// the existing `encode_lp_string` but without the UTF-8 assumption,
/// for binary blobs like PEM bytes.
fn encode_lp_bytes_u32(buf: &mut Vec<u8>, body: &[u8]) {
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(body);
}

fn decode_attest_result(data: &[u8]) -> io::Result<AttestResult> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attest result missing sev_report length",
        ));
    }
    let sev_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if pos + sev_len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated sev_snp_report",
        ));
    }
    let sev_snp_report = data[pos..pos + sev_len].to_vec();
    pos += sev_len;

    if pos >= data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attest result missing manifest count",
        ));
    }
    let n_roots = data[pos] as usize;
    pos += 1;
    if pos + n_roots * 32 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated manifest roots",
        ));
    }
    let mut manifest_roots = Vec::with_capacity(n_roots);
    for _ in 0..n_roots {
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[pos..pos + 32]);
        manifest_roots.push(root);
        pos += 32;
    }

    if pos + 32 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated binary_sha256",
        ));
    }
    let mut binary_sha256 = [0u8; 32];
    binary_sha256.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // V2 wire layout: server_static_pub right after binary_sha256.
    if pos + 32 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated server_static_pub (V2 wire layout)",
        ));
    }
    let mut server_static_pub = [0u8; 32];
    server_static_pub.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    if pos + 2 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated git_rev length",
        ));
    }
    let git_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    if pos + git_len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated git_rev bytes",
        ));
    }
    let git_rev = String::from_utf8_lossy(&data[pos..pos + git_len]).to_string();
    pos += git_len;

    // V3 cert chain extension. Trailing empty for back-compat with
    // V2-only servers (which stop emitting after git_rev — those
    // verifiers fall back to V2-binding-only mode).
    let ark_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("ark_pem: {}", e)))?;
    let ask_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("ask_pem: {}", e)))?;
    let vcek_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("vcek_pem: {}", e)))?;

    Ok(AttestResult {
        sev_snp_report,
        manifest_roots,
        binary_sha256,
        server_static_pub,
        git_rev,
        ark_pem,
        ask_pem,
        vcek_pem,
    })
}

/// Read a length-prefixed binary blob. If `pos` is at end-of-buffer
/// returns empty (back-compat with older servers that don't emit the
/// trailing fields). If `pos` is mid-buffer but the length prefix is
/// truncated or the body would overrun, returns an error.
fn decode_lp_bytes_u32_or_empty(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    if *pos == data.len() {
        return Ok(Vec::new());
    }
    if *pos + 4 > data.len() {
        return Err(format!(
            "truncated u32 length prefix at pos {} (len={})",
            *pos,
            data.len()
        ));
    }
    let n = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + n > data.len() {
        return Err(format!("body truncated: claimed {} bytes, have {}", n, data.len() - *pos));
    }
    let body = data[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(body)
}

// ─── Admin upload encoding helpers ─────────────────────────────────────────

/// Encode a length-prefixed UTF-8 string with a 4-byte LE length.
fn encode_lp_string(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

/// Decode a `[4B len LE][bytes]` UTF-8 string starting at `*pos`,
/// advancing `*pos` past it. Lossy UTF-8 conversion.
fn decode_lp_string(data: &[u8], pos: &mut usize) -> io::Result<String> {
    if *pos + 4 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing length-prefixed string len",
        ));
    }
    let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated length-prefixed string body",
        ));
    }
    let s = String::from_utf8_lossy(&data[*pos..*pos + len]).to_string();
    *pos += len;
    Ok(s)
}

/// Common AdminAck wire body: `[1B ok][2B msg_len LE][msg_bytes]`.
fn encode_admin_ack_payload(buf: &mut Vec<u8>, ok: bool, msg: &str) {
    buf.push(if ok { 1 } else { 0 });
    let mb = msg.as_bytes();
    buf.extend_from_slice(&(mb.len() as u16).to_le_bytes());
    buf.extend_from_slice(mb);
}

fn decode_admin_ack_payload(data: &[u8]) -> io::Result<(bool, String)> {
    if data.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "admin ack too short"));
    }
    let ok = data[0] != 0;
    let msg_len = u16::from_le_bytes(data[1..3].try_into().unwrap()) as usize;
    if 3 + msg_len > data.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "admin ack truncated msg"));
    }
    Ok((ok, String::from_utf8_lossy(&data[3..3 + msg_len]).to_string()))
}

fn decode_harmony_query(data: &[u8]) -> io::Result<HarmonyQuery> {
    // [1B level][1B group_id][2B round_id][4B count][count × 4B u32 LE]
    // [optional trailing 1B db_id, only when non-zero — backward compatible]
    if data.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony query too short"));
    }
    let level = data[0];
    let group_id = data[1];
    let round_id = u16::from_le_bytes(data[2..4].try_into().unwrap());
    let count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let expected = 8 + count * 4;
    if data.len() < expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated harmony query indices"));
    }
    let mut indices = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 4;
        indices.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if expected < data.len() { data[expected] } else { 0 };
    Ok(HarmonyQuery {
        level,
        group_id,
        round_id,
        indices,
        db_id,
    })
}

#[cfg(test)]
mod attest_wire_tests {
    use super::*;

    #[test]
    fn attest_request_roundtrip() {
        let nonce = [0xAAu8; 32];
        let req = Request::Attest { nonce };
        let encoded = req.encode();
        // [4B len LE][1B variant][32B nonce] = 4 + 33
        assert_eq!(encoded.len(), 4 + 33);
        let payload_len = u32::from_le_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert_eq!(payload_len, 33);
        // skip the 4B length prefix when decoding the payload
        let decoded = Request::decode(&encoded[4..]).unwrap();
        match decoded {
            Request::Attest { nonce: n } => assert_eq!(n, nonce),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_request_truncated_nonce_fails() {
        // Missing the last byte of the nonce.
        let mut bad = vec![REQ_ATTEST];
        bad.extend_from_slice(&[0u8; 31]);
        let err = Request::decode(&bad).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn attest_response_roundtrip_with_sev_report() {
        let r = AttestResult {
            sev_snp_report: vec![0xCDu8; 1184],
            manifest_roots: vec![[0x11u8; 32], [0x22u8; 32]],
            binary_sha256: [0x33u8; 32],
            server_static_pub: [0x44u8; 32],
            git_rev: "deadbeef".to_string(),
            ark_pem: b"-----BEGIN ARK-----\nfakebytes\n-----END ARK-----\n".to_vec(),
            ask_pem: b"-----BEGIN ASK-----\nfakebytes\n-----END ASK-----\n".to_vec(),
            vcek_pem: b"-----BEGIN VCEK-----\nfakebytes\n-----END VCEK-----\n".to_vec(),
        };
        let encoded = Response::Attest(r.clone()).encode();
        let decoded = Response::decode(&encoded[4..]).unwrap();
        match decoded {
            Response::Attest(r2) => {
                assert_eq!(r2.sev_snp_report, r.sev_snp_report);
                assert_eq!(r2.manifest_roots, r.manifest_roots);
                assert_eq!(r2.binary_sha256, r.binary_sha256);
                assert_eq!(r2.server_static_pub, r.server_static_pub);
                assert_eq!(r2.git_rev, r.git_rev);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_roundtrip_no_sev_report() {
        // Hetzner case: empty sev_snp_report, still has the rest.
        let r = AttestResult {
            sev_snp_report: vec![],
            manifest_roots: vec![[0u8; 32]],
            binary_sha256: [0xFFu8; 32],
            server_static_pub: [0u8; 32], // no channel key on this server yet
            git_rev: "unknown".to_string(),
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let encoded = Response::Attest(r.clone()).encode();
        let decoded = Response::decode(&encoded[4..]).unwrap();
        match decoded {
            Response::Attest(r2) => {
                assert!(r2.sev_snp_report.is_empty());
                assert_eq!(r2.manifest_roots.len(), 1);
                assert_eq!(r2.server_static_pub, [0u8; 32]);
                assert_eq!(r2.git_rev, "unknown");
                assert!(r2.ark_pem.is_empty());
                assert!(r2.ask_pem.is_empty());
                assert!(r2.vcek_pem.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_zero_dbs() {
        let r = AttestResult {
            sev_snp_report: vec![0u8; 50],
            manifest_roots: vec![],
            binary_sha256: [0xAAu8; 32],
            server_static_pub: [0xBBu8; 32],
            git_rev: "abc".into(),
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: vec![0xCCu8; 1500], // simulate ~1.5 KB VCEK PEM
        };
        let encoded = Response::Attest(r.clone()).encode();
        let decoded = Response::decode(&encoded[4..]).unwrap();
        match decoded {
            Response::Attest(r2) => {
                assert!(r2.manifest_roots.is_empty());
                assert_eq!(r2.sev_snp_report.len(), 50);
                assert_eq!(r2.server_static_pub, [0xBBu8; 32]);
                assert_eq!(r2.vcek_pem.len(), 1500);
                assert_eq!(r2.vcek_pem[0], 0xCC);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_decoder_back_compat_no_cert_fields() {
        // Synthesise a wire payload that ends right after git_rev —
        // mimics what a V2-only server (pre-Slice-D.2) would emit.
        // The decoder should fill the cert fields with empty rather
        // than erroring with "truncated".
        let mut payload = Vec::new();
        payload.push(RESP_ATTEST);
        payload.extend_from_slice(&0u32.to_le_bytes()); // sev_snp_report len
        payload.push(0u8); // n_roots
        payload.extend_from_slice(&[0u8; 32]); // binary_sha256
        payload.extend_from_slice(&[0u8; 32]); // server_static_pub
        payload.extend_from_slice(&3u16.to_le_bytes()); // git_rev len
        payload.extend_from_slice(b"abc"); // git_rev
        // INTENTIONALLY no cert fields — pre-D.2 server behavior.

        let decoded = Response::decode(&payload).unwrap();
        match decoded {
            Response::Attest(r) => {
                assert_eq!(r.git_rev, "abc");
                assert!(r.ark_pem.is_empty(), "ark_pem should default empty");
                assert!(r.ask_pem.is_empty(), "ask_pem should default empty");
                assert!(r.vcek_pem.is_empty(), "vcek_pem should default empty");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_decoder_rejects_truncated_cert_length() {
        // Build a payload where the ark_pem length prefix starts but
        // is cut short mid-u32 — must error, not silently truncate.
        let mut payload = Vec::new();
        payload.push(RESP_ATTEST);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(0u8);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&0u16.to_le_bytes());
        // Only 2 of the 4 length-prefix bytes for ark_pem.
        payload.extend_from_slice(&[0xCC, 0xDD]);

        let err = Response::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(format!("{}", err).contains("ark_pem"), "got: {}", err);
    }
}
