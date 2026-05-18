//! Rust bindings for OnionPIRv2 — a high-performance PIR library based on
//! BV key-switching (no SEAL special prime).
//!
//! See [`Server`] and [`Client`] for the entry points. Most users should use
//! the high-level wrappers; the raw FFI is in the private [`ffi`] module.
//!
//! ## Example
//!
//! ```no_run
//! use onionpir::{Server, Client};
//!
//! let info = onionpir::params_info(0);
//! let pt_idx = 42;
//!
//! let mut server = Server::new(0);
//! server.gen_data(&[pt_idx]); // pre-record this plaintext for the test path
//!
//! let mut client = Client::new(0);
//! let client_id = client.id();
//! server.set_galois_keys(client_id, &client.galois_keys());
//! server.set_gsw_key(client_id, &client.gsw_key());
//!
//! let query = client.generate_query(pt_idx);
//! let response = server.answer_query(client_id, &query);
//! let decrypted = client.decrypt_response(&response);
//! let actual = server.get_original_plaintext(pt_idx);
//! assert_eq!(decrypted, actual);
//! ```

use std::os::raw::c_void;

// ============================================================================
// Raw FFI declarations (mirror cpp/includes/onion_ffi.h)
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct COnionBuf {
    data: *mut u8,
    len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ParamsInfo {
    pub num_entries: u64,
    pub entry_size: u64,
    pub num_plaintexts: u64,
    pub fst_dim_sz: u64,
    pub other_dim_sz: u64,
    pub poly_degree: u64,
    pub rns_mod_count: u64,
    pub coeff_val_cnt: u64,
    pub db_size_mb: f64,
    pub physical_size_mb: f64,
}

type ClientHandle = *mut c_void;
type ServerHandle = *mut c_void;
type KeyStoreHandle = *mut c_void;
type QueueHandle = *mut c_void;

#[link(name = "onionpir", kind = "static")]
extern "C" {
    fn onion_free_buf(buf: COnionBuf);

    fn onion_params_info(num_entries: u64) -> ParamsInfo;

    fn onion_client_new(num_entries: u64) -> ClientHandle;
    fn onion_client_free(h: ClientHandle);
    fn onion_client_id(h: ClientHandle) -> u64;
    fn onion_client_new_from_sk(num_entries: u64, client_id: u64,
                                sk_data: *const u8, sk_len: usize) -> ClientHandle;
    fn onion_client_export_secret_key(h: ClientHandle) -> COnionBuf;
    fn onion_client_galois_keys(h: ClientHandle) -> COnionBuf;
    fn onion_client_gsw_key(h: ClientHandle) -> COnionBuf;
    fn onion_client_generate_query(h: ClientHandle, pt_idx: u64) -> COnionBuf;
    fn onion_client_decrypt_response(h: ClientHandle, response: *const u8, len: usize) -> COnionBuf;

    fn onion_server_new(num_entries: u64) -> ServerHandle;
    fn onion_server_free(h: ServerHandle);
    fn onion_server_gen_data(h: ServerHandle, indices: *const u64, num_indices: usize);
    fn onion_server_push_plaintexts(h: ServerHandle, plaintexts: *const u64,
                                    count: u64, offset: u64,
                                    record_indices: *const u64,
                                    num_record_indices: usize) -> i32;
    fn onion_server_get_original_plaintext(h: ServerHandle, pt_idx: u64) -> COnionBuf;
    fn onion_server_set_galois_keys(h: ServerHandle, client_id: u64, data: *const u8, len: usize);
    fn onion_server_set_gsw_key(h: ServerHandle, client_id: u64, data: *const u8, len: usize);
    fn onion_server_answer_query(
        h: ServerHandle,
        client_id: u64,
        query: *const u8,
        query_len: usize,
    ) -> COnionBuf;

    fn onion_server_save_db(h: ServerHandle, path: *const i8) -> i32;
    fn onion_server_load_db(h: ServerHandle, path: *const i8) -> i32;
    fn onion_server_load_db_from_borrowed(h: ServerHandle, data: *const u8, len: usize) -> i32;

    fn onion_key_store_new() -> KeyStoreHandle;
    fn onion_key_store_free(h: KeyStoreHandle);
    fn onion_key_store_set_galois_keys(h: KeyStoreHandle, client_id: u64,
                                        data: *const u8, len: usize);
    fn onion_key_store_set_gsw_key(h: KeyStoreHandle, client_id: u64,
                                    data: *const u8, len: usize);
    fn onion_key_store_has_client(h: KeyStoreHandle, client_id: u64) -> i32;
    fn onion_key_store_remove(h: KeyStoreHandle, client_id: u64);
    fn onion_key_store_size(h: KeyStoreHandle) -> u64;
    fn onion_server_set_key_store(server: ServerHandle, store: KeyStoreHandle);

    fn onion_queue_new(server: ServerHandle) -> QueueHandle;
    fn onion_queue_free(h: QueueHandle);
    fn onion_queue_stop(h: QueueHandle);
    fn onion_queue_submit(h: QueueHandle, client_id: u64,
                          query: *const u8, query_len: usize) -> u64;
    fn onion_queue_status(h: QueueHandle, ticket: u64) -> i32;
    fn onion_queue_result(h: QueueHandle, ticket: u64) -> COnionBuf;

    fn onion_server_set_shared_database(h: ServerHandle,
                                        store: *const u64,
                                        shared_num_entries: u64,
                                        index_table: *const u32,
                                        index_table_len: u64) -> i32;
}

// ============================================================================
// Buffer marshalling
// ============================================================================

fn buf_to_vec(buf: COnionBuf) -> Vec<u8> {
    if buf.data.is_null() || buf.len == 0 {
        // SAFETY: even if data is non-null with len 0, freeing is still safe.
        unsafe { onion_free_buf(buf) };
        return Vec::new();
    }
    // Copy out (FFI buffer is malloc'd; we don't want Rust's allocator to free it).
    // SAFETY: data was allocated by malloc on the C side; buf.len bytes are valid.
    let slice = unsafe { std::slice::from_raw_parts(buf.data, buf.len) };
    let vec = slice.to_vec();
    // SAFETY: we own buf; free it on the C side.
    unsafe { onion_free_buf(buf) };
    vec
}

// ============================================================================
// Free functions
// ============================================================================

/// Inspect the PIR shape for a given target plaintext count.
///
/// Pass `num_entries = 0` to preview the compile-time default. Any
/// non-zero value previews the shape a `Server::new(num_entries)` or
/// `Client::new(num_entries)` would get. Useful for pre-flighting
/// storage and matmul cost decisions without constructing the server.
pub fn params_info(num_entries: u64) -> ParamsInfo {
    unsafe { onion_params_info(num_entries) }
}

// ============================================================================
// Client
// ============================================================================

/// A PIR client. Owns its secret key, BV galois keys, and GSW(s) key.
pub struct Client {
    h: ClientHandle,
}

// Handle is private and access is serialized through &mut self / methods.
unsafe impl Send for Client {}

impl Client {
    /// Construct a fresh client.
    ///
    /// `num_entries` shapes the client's `PirParams` for that many
    /// plaintexts. Pass `0` to use the compile-time default. The client's
    /// shape must match the server it talks to — query bytes encode the
    /// PirParams-derived `fst_dim_sz` / `num_dims`.
    pub fn new(num_entries: u64) -> Self {
        let h = unsafe { onion_client_new(num_entries) };
        assert!(!h.is_null(), "onion_client_new returned null");
        Self { h }
    }

    /// Reconstruct a client from a previously-exported secret key plus the
    /// id the server already knows. `num_entries` must match the value used
    /// when the original client was constructed (pass `0` if the original
    /// used the default). Returns `None` on size / format mismatch.
    pub fn from_secret_key(num_entries: u64, client_id: u64, sk: &[u8]) -> Option<Self> {
        let h = unsafe { onion_client_new_from_sk(num_entries, client_id, sk.as_ptr(), sk.len()) };
        if h.is_null() { None } else { Some(Self { h }) }
    }

    /// Serialized secret key. Pair with `Client::from_secret_key` to restore
    /// this client in another process. The bytes are sensitive — they fully
    /// recover the client's identity.
    pub fn export_secret_key(&self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_export_secret_key(self.h) })
    }

    /// The client's auto-assigned id. Pair with `Server::set_*` calls on the
    /// receiving side to bind the keys to this client.
    pub fn id(&self) -> u64 {
        unsafe { onion_client_id(self.h) }
    }

    /// Serialized BV galois keys. Hand to `Server::set_galois_keys`.
    pub fn galois_keys(&self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_galois_keys(self.h) })
    }

    /// Serialized GSW(s) key. Hand to `Server::set_gsw_key`.
    pub fn gsw_key(&self) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_gsw_key(self.h) })
    }

    /// Serialized PIR query for plaintext index `pt_idx`.
    /// `pt_idx` must be in `[0, params.num_plaintexts)`.
    pub fn generate_query(&self, pt_idx: u64) -> Vec<u8> {
        buf_to_vec(unsafe { onion_client_generate_query(self.h, pt_idx) })
    }

    /// Decrypt a server response. Returns the recovered plaintext as
    /// `[u32 N (LE)][u64 coeff_i for i in 0..N]`. Compare against
    /// `Server::get_original_plaintext` to verify correctness.
    pub fn decrypt_response(&self, response: &[u8]) -> Vec<u8> {
        buf_to_vec(unsafe {
            onion_client_decrypt_response(self.h, response.as_ptr(), response.len())
        })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { onion_client_free(self.h) };
    }
}

// ============================================================================
// Server
// ============================================================================

/// A PIR server. Holds the (preprocessed) database and per-client keys.
pub struct Server {
    h: ServerHandle,
}

unsafe impl Send for Server {}

impl Server {
    /// Construct a fresh server.
    ///
    /// `num_entries` shapes the server's `PirParams` for that many
    /// plaintexts. Pass `0` to use the compile-time default
    /// (`DBConsts::DB_SIZE_MB`-derived). For multi-tenant deployments
    /// that instantiate many servers at different scales, pass each
    /// server its own `num_entries` so its DB / matmul shape fits the
    /// data it actually holds — avoids paying the storage and per-query
    /// cost of the largest-server-shaped DB on every instance.
    ///
    /// Note: `calculate_db_shape` rounds the request up to a
    /// matmul-friendly size, so `params_info().num_plaintexts` may
    /// exceed the requested value.
    pub fn new(num_entries: u64) -> Self {
        let h = unsafe { onion_server_new(num_entries) };
        assert!(!h.is_null(), "onion_server_new returned null");
        Self { h }
    }

    /// Populate the database with random data. Optionally pass the plaintext
    /// indices you'll query so `get_original_plaintext` returns the correct
    /// pre-NTT plaintexts for those rows (the server doesn't keep a copy of
    /// the full DB in memory).
    pub fn gen_data(&mut self, query_indices: &[u64]) {
        unsafe {
            onion_server_gen_data(self.h, query_indices.as_ptr(), query_indices.len());
        }
    }

    /// Push externally-provided plaintexts into the DB.
    ///
    /// `plaintexts` is a flat slice of `count * N` u64s; plaintext `p`
    /// occupies coefficients `[p*N, (p+1)*N)` and each value must be in
    /// `[0, t)`. The chunk is stored at DB slots `[offset, offset+count)`.
    ///
    /// `record_indices`: optional subset of `[offset, offset+count)` to keep
    /// pre-NTT for `get_original_plaintext` (test path).
    ///
    /// Returns `false` if `offset + count` overflows `num_pt` or the engine
    /// rejected the call.
    pub fn push_plaintexts(&mut self, plaintexts: &[u64], count: u64, offset: u64,
                           record_indices: &[u64]) -> bool {
        let r_ptr = if record_indices.is_empty() { std::ptr::null() }
                    else { record_indices.as_ptr() };
        unsafe {
            onion_server_push_plaintexts(self.h, plaintexts.as_ptr(),
                                          count, offset,
                                          r_ptr, record_indices.len()) != 0
        }
    }

    /// Returns the recorded pre-NTT plaintext for `pt_idx`.
    /// Only valid for indices passed to a prior `gen_data` call.
    pub fn get_original_plaintext(&self, pt_idx: u64) -> Vec<u8> {
        buf_to_vec(unsafe { onion_server_get_original_plaintext(self.h, pt_idx) })
    }

    /// Register a client's serialized BV galois keys.
    pub fn set_galois_keys(&mut self, client_id: u64, data: &[u8]) {
        unsafe { onion_server_set_galois_keys(self.h, client_id, data.as_ptr(), data.len()) };
    }

    /// Register a client's serialized GSW(s) key.
    pub fn set_gsw_key(&mut self, client_id: u64, data: &[u8]) {
        unsafe { onion_server_set_gsw_key(self.h, client_id, data.as_ptr(), data.len()) };
    }

    /// Run the full PIR query and return the bit-packed response.
    pub fn answer_query(&mut self, client_id: u64, query: &[u8]) -> Vec<u8> {
        buf_to_vec(unsafe {
            onion_server_answer_query(self.h, client_id, query.as_ptr(), query.len())
        })
    }

    /// Save the post-NTT, realigned database to `path`. Returns `false` on I/O
    /// failure or if no DB has been populated yet.
    pub fn save_db(&self, path: &str) -> bool {
        let c = std::ffi::CString::new(path).expect("path contains NUL byte");
        unsafe { onion_server_save_db(self.h, c.as_ptr()) != 0 }
    }

    /// Load a previously-saved DB. Returns `false` if the file is missing or
    /// the on-disk layout doesn't match the server's compile-time config.
    pub fn load_db(&mut self, path: &str) -> bool {
        let c = std::ffi::CString::new(path).expect("path contains NUL byte");
        unsafe { onion_server_load_db(self.h, c.as_ptr()) != 0 }
    }

    /// Zero-copy alias an already-formatted DB buffer. The buffer must outlive
    /// the server. Returns `false` on header mismatch / size mismatch.
    ///
    /// # Safety
    /// `data` must remain valid for the lifetime of the server. The server
    /// reads (but does not write) it during every query.
    pub unsafe fn load_db_from_borrowed(&mut self, data: &[u8]) -> bool {
        onion_server_load_db_from_borrowed(self.h, data.as_ptr(), data.len()) != 0
    }

    /// Attach a shared NTT-expanded backing store and a per-server index
    /// table. The matmul gathers via `index_table` on each query. Frees
    /// the server's own DB buffer.
    ///
    /// `store` layout: `[level * shared_num_entries + entry_id]`. The data
    /// is what `save_db` writes after the header (i.e. raw `db_aligned_`
    /// bytes interpreted as `u64`).
    ///
    /// `index_table.len()` must equal `params_info().num_plaintexts`. Each
    /// entry must be `< shared_num_entries`.
    ///
    /// Returns `false` on validation failure (composite config, length
    /// mismatch, etc.). Pass empty slices to detach the shared store.
    ///
    /// # Safety
    /// Both `store` and `index_table` must outlive the server. The server
    /// reads (but does not write) them during every query.
    pub unsafe fn set_shared_database(&mut self,
                                       store: &[u64],
                                       shared_num_entries: u64,
                                       index_table: &[u32]) -> bool {
        let len = onion_server_set_shared_database(
            self.h,
            if store.is_empty() { std::ptr::null() } else { store.as_ptr() },
            shared_num_entries,
            if index_table.is_empty() { std::ptr::null() } else { index_table.as_ptr() },
            index_table.len() as u64,
        );
        len != 0
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe { onion_server_free(self.h) };
    }
}

// ============================================================================
// SharedKeyStore — deserialize keys once, share across many Servers
// ============================================================================

/// A shared cache of deserialized client keys.
///
/// One store can back many [`Server`] instances. Attach with
/// [`Server::set_key_store`]; once attached, the server's `set_galois_keys` /
/// `set_gsw_key` calls forward into the store, and its query path looks up
/// keys from the store. Internal LRU eviction caps the cache at 100 clients.
///
/// Lifetime: the store must outlive every attached server. The intended
/// pattern is to wrap it in `std::sync::Arc<KeyStore>` and hold one Arc
/// alongside each server.
///
/// Thread safety: the underlying C++ store is not internally synchronized.
/// Callers must serialize key registration against query processing
/// themselves (e.g. a `parking_lot::Mutex<()>` outside).
pub struct KeyStore {
    h: KeyStoreHandle,
}

unsafe impl Send for KeyStore {}
unsafe impl Sync for KeyStore {}

impl KeyStore {
    pub fn new() -> Self {
        let h = unsafe { onion_key_store_new() };
        assert!(!h.is_null(), "onion_key_store_new returned null");
        Self { h }
    }

    /// Raw FFI handle — exposed so `Server::set_key_store` can wire it up.
    fn raw(&self) -> KeyStoreHandle { self.h }

    /// Register a client's serialized BV galois keys. Evicts the LRU client
    /// if the store is full.
    pub fn set_galois_keys(&self, client_id: u64, data: &[u8]) {
        unsafe { onion_key_store_set_galois_keys(self.h, client_id, data.as_ptr(), data.len()) };
    }

    /// Register a client's serialized GSW(s) key. Evicts the LRU client
    /// if the store is full.
    pub fn set_gsw_key(&self, client_id: u64, data: &[u8]) {
        unsafe { onion_key_store_set_gsw_key(self.h, client_id, data.as_ptr(), data.len()) };
    }

    /// True if both key types are loaded for this client.
    pub fn has_client(&self, client_id: u64) -> bool {
        unsafe { onion_key_store_has_client(self.h, client_id) != 0 }
    }

    /// Remove a client's entries. No-op if absent.
    pub fn remove(&self, client_id: u64) {
        unsafe { onion_key_store_remove(self.h, client_id) };
    }

    /// Current number of cached clients (with ≥ 1 key registered).
    pub fn size(&self) -> u64 {
        unsafe { onion_key_store_size(self.h) }
    }
}

impl Default for KeyStore {
    fn default() -> Self { Self::new() }
}

impl Drop for KeyStore {
    fn drop(&mut self) {
        unsafe { onion_key_store_free(self.h) };
    }
}

// ============================================================================
// QueryQueue — async worker-thread wrapper around Server::answer_query
// ============================================================================

/// Status of an in-flight ticket. Mirrors the C ABI's `ONION_QUERY_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryStatus {
    Queued,
    Processing,
    Done,
    Error,
    NotFound,
}

impl QueryStatus {
    fn from_raw(v: i32) -> Self {
        match v {
            0 => Self::Queued,
            1 => Self::Processing,
            2 => Self::Done,
            3 => Self::Error,
            _ => Self::NotFound,
        }
    }
}

/// Worker-thread wrapper around a [`Server`]. Submit queries, poll status,
/// then fetch results.
///
/// **Lifetime contract**: the wrapped `Server` must outlive the `QueryQueue`.
/// While the queue has pending or in-flight work, callers must NOT mutate the
/// server (e.g. `set_galois_keys`, `gen_data`, `push_plaintexts`) — drain
/// tickets first or call [`QueryQueue::stop`].
pub struct QueryQueue<'s> {
    h: QueueHandle,
    _phantom: std::marker::PhantomData<&'s Server>,
}

unsafe impl Send for QueryQueue<'_> {}

impl<'s> QueryQueue<'s> {
    /// Spawn the worker thread for `server`. Borrows the server immutably
    /// — concurrent direct calls to `server.answer_query` would race with
    /// the worker, so the borrow checker forbids them by holding the
    /// shared reference for the queue's lifetime.
    pub fn new(server: &'s mut Server) -> Self {
        let h = unsafe { onion_queue_new(server.h) };
        assert!(!h.is_null(), "onion_queue_new returned null");
        Self { h, _phantom: std::marker::PhantomData }
    }

    /// Enqueue a query. Returns the ticket, or `None` if the queue has been
    /// stopped.
    pub fn submit(&self, client_id: u64, query: &[u8]) -> Option<u64> {
        let t = unsafe {
            onion_queue_submit(self.h, client_id, query.as_ptr(), query.len())
        };
        if t == 0 { None } else { Some(t) }
    }

    /// Non-blocking status.
    pub fn status(&self, ticket: u64) -> QueryStatus {
        QueryStatus::from_raw(unsafe { onion_queue_status(self.h, ticket) })
    }

    /// Fetch and consume the result for `ticket`. Returns `Some(bytes)` if
    /// the ticket reached `Done` (response bytes) or `Error` (UTF-8 error
    /// message); returns `None` otherwise.
    pub fn result(&self, ticket: u64) -> Option<Vec<u8>> {
        let buf = unsafe { onion_queue_result(self.h, ticket) };
        if buf.data.is_null() { None } else { Some(buf_to_vec(buf)) }
    }

    /// Cooperative shutdown. Stops accepting new submissions, lets the
    /// worker finish its current query, then joins. Idempotent.
    pub fn stop(&self) {
        unsafe { onion_queue_stop(self.h) };
    }
}

impl Drop for QueryQueue<'_> {
    fn drop(&mut self) {
        unsafe { onion_queue_free(self.h) };
    }
}

impl Server {
    /// Attach a shared key store. After this call, `set_galois_keys` /
    /// `set_gsw_key` forward into the store, and the query path looks keys
    /// up from there. Pass `None` to detach.
    ///
    /// # Safety
    /// The store must outlive this server. Hold onto an `Arc<KeyStore>`
    /// alongside the server (or longer) to guarantee that.
    pub unsafe fn set_key_store(&mut self, store: Option<&KeyStore>) {
        let raw = store.map_or(std::ptr::null_mut(), |s| s.raw());
        onion_server_set_key_store(self.h, raw);
    }
}
