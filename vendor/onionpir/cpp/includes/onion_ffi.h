// OnionPIRv2 C-ABI for Rust / Java / native consumers.
//
// Minimum-viable surface tied to the upstream BV-keyswitch flow (see
// src/tests/test_pir.cpp for the reference end-to-end transcript). The fork's
// previous extra features (load_db_from_borrowed, SharedKeyStore, async
// QueryQueue, indirect-database mode) are not included here — they will be
// re-introduced in a later phase.
//
// All variable-length return values are passed back via OnionBuf and must be
// freed by the caller with onion_free_buf().
//
// Threading: server / client handles are NOT thread-safe; callers must
// serialize access to a given handle.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// ============================================================================
//   Owned byte buffer returned from variable-length producers
// ============================================================================

typedef struct {
    uint8_t *data;
    size_t   len;
} OnionBuf;

// Frees the buffer; pass-by-value matches how it was returned. No-op on NULL.
void onion_free_buf(OnionBuf buf);

// ============================================================================
//   Database / parameter shape
// ============================================================================

typedef struct {
    uint64_t num_entries;        // padded entry count (>= requested)
    uint64_t entry_size;         // bytes per entry
    uint64_t num_plaintexts;     // total plaintexts (== fst_dim_sz * other_dim_sz)
    uint64_t fst_dim_sz;
    uint64_t other_dim_sz;
    uint64_t poly_degree;        // N (e.g. 4096 in the secure config)
    uint64_t rns_mod_count;      // K (1 for single-mod, 2 for K2_MP)
    uint64_t coeff_val_cnt;      // poly_degree * rns_mod_count
    double   db_size_mb;
    double   physical_size_mb;
} OnionPirParamsInfo;

// num_entries=0 → use the compiled-in default from DBConsts.
OnionPirParamsInfo onion_params_info(uint64_t num_entries);

// ============================================================================
//   Opaque handles
// ============================================================================

typedef void *OnionServerHandle;
typedef void *OnionClientHandle;

// ============================================================================
//   Client
// ============================================================================
//
// Lifecycle: each client owns its own secret key, GSW key, and BV galois keys
// (generated lazily on first call). To pair a client with a server, ship the
// galois-keys and gsw-key blobs to the server side via onion_server_set_*.

OnionClientHandle onion_client_new(uint64_t num_entries);
void              onion_client_free(OnionClientHandle h);
uint64_t          onion_client_id(OnionClientHandle h);

// Reconstruct a client from a previously-exported secret key. `client_id`
// should match the id the server already knows (so its galois / gsw key
// registration still resolves). Returns NULL on size / format mismatch.
OnionClientHandle onion_client_new_from_sk(uint64_t num_entries,
                                           uint64_t client_id,
                                           const uint8_t *sk_data,
                                           size_t sk_len);

// Serialized secret key. Wire format: [u32 word_count_LE][u64 sk_words[…]].
// Caller frees with onion_free_buf. Treat the bytes as sensitive — they
// fully recover the client's identity.
OnionBuf onion_client_export_secret_key(OnionClientHandle h);

// Serialized BV galois keys for this client. Caller frees.
OnionBuf onion_client_galois_keys(OnionClientHandle h);

// Serialized GSW(s) key for this client. Caller frees.
OnionBuf onion_client_gsw_key(OnionClientHandle h);

// Serialized query for plaintext index pt_idx. Caller frees.
// pt_idx must be in [0, params.num_plaintexts).
OnionBuf onion_client_generate_query(OnionClientHandle h, uint64_t pt_idx);

// Decrypts a server response (bit-packed bytes as produced by
// onion_server_answer_query). Returns the N-coefficient plaintext as a flat
// uint64 array (each coefficient < t), serialized as
// `[u32 N][u64 coeff_0]…[u64 coeff_{N-1}]`. Caller frees.
OnionBuf onion_client_decrypt_response(OnionClientHandle h,
                                       const uint8_t *response,
                                       size_t response_len);

// ============================================================================
//   Server
// ============================================================================

OnionServerHandle onion_server_new(uint64_t num_entries);
void              onion_server_free(OnionServerHandle h);

// Populate the database with random data. If record_indices is non-null and
// num_indices > 0, only those plaintext indices are retained for
// onion_server_get_original_plaintext (test convenience to avoid keeping the
// full pre-NTT DB in memory).
void onion_server_gen_data(OnionServerHandle h,
                           const uint64_t *record_indices,
                           size_t num_indices);

// Push externally-provided plaintexts into the DB. `plaintexts` is a flat
// uint64 array of size count * N (where N is poly_degree); each plaintext
// occupies N contiguous coefficients, each in [0, t). Stores plaintexts in
// DB slots [offset, offset + count); offset + count must be <= num_pt.
//
// Pass record_indices = nullptr (or num_record_indices = 0) for production;
// any indices listed are retained pre-NTT for the test helper
// onion_server_get_original_plaintext.
//
// Returns 1 on success, 0 on range overflow / error.
int onion_server_push_plaintexts(OnionServerHandle h,
                                 const uint64_t *plaintexts,
                                 uint64_t count,
                                 uint64_t offset,
                                 const uint64_t *record_indices,
                                 size_t num_record_indices);

// Returns the pre-NTT plaintext at pt_idx as `[u32 N][u64 coeff_0]…`.
// Only valid for indices that were passed to onion_server_gen_data.
// Caller frees.
OnionBuf onion_server_get_original_plaintext(OnionServerHandle h,
                                             uint64_t pt_idx);

// Register a client's keys. The keys are deserialized once and held until the
// client is removed.
void onion_server_set_galois_keys(OnionServerHandle h, uint64_t client_id,
                                  const uint8_t *data, size_t len);
void onion_server_set_gsw_key(OnionServerHandle h, uint64_t client_id,
                              const uint8_t *data, size_t len);

// Run the full PIR query and return the bit-packed response. Caller frees.
OnionBuf onion_server_answer_query(OnionServerHandle h, uint64_t client_id,
                                   const uint8_t *query, size_t query_len);

// ─── Preprocessed-DB persistence ───────────────────────────────────────────
// Save the post-NTT, realigned database (populated by onion_server_gen_data,
// later also by push_chunk) to a file. Returns 1 on success, 0 on failure.
int onion_server_save_db(OnionServerHandle h, const char *path);

// Load a previously-saved DB. Layout / num_pt / coeff count must match the
// server's compile-time config. Returns 1 on success, 0 on mismatch / I/O
// error.
int onion_server_load_db(OnionServerHandle h, const char *path);

// Zero-copy: alias an already-formatted DB buffer. The buffer must outlive
// the server and start with the standard save_db header.
int onion_server_load_db_from_borrowed(OnionServerHandle h,
                                       const uint8_t *data, size_t len);

// ─── SharedKeyStore ────────────────────────────────────────────────────────
// A single store of (deserialized) client galois + GSW keys, shared across
// many servers. Bounded LRU (max 100 clients today). Attach with
// onion_server_set_key_store; the store must outlive every attached server.

typedef void *OnionKeyStoreHandle;

OnionKeyStoreHandle onion_key_store_new(void);
void                onion_key_store_free(OnionKeyStoreHandle h);

// Register a client's serialized key blob (same wire format as
// onion_server_set_galois_keys / onion_server_set_gsw_key).
// May silently drop the LRU client to fit MAX_CLIENTS.
void onion_key_store_set_galois_keys(OnionKeyStoreHandle h, uint64_t client_id,
                                     const uint8_t *data, size_t len);
void onion_key_store_set_gsw_key(OnionKeyStoreHandle h, uint64_t client_id,
                                 const uint8_t *data, size_t len);

// 1 if both key types are loaded for client_id, else 0.
int  onion_key_store_has_client(OnionKeyStoreHandle h, uint64_t client_id);
// Remove a client from the store. No-op if absent.
void onion_key_store_remove(OnionKeyStoreHandle h, uint64_t client_id);
// Number of cached clients (with at least one key registered).
uint64_t onion_key_store_size(OnionKeyStoreHandle h);

// Attach a store to a server. After this call, set_galois_keys /
// set_gsw_key on the server forward into the store, and the query path
// looks keys up from the store. Pass NULL for `store` to detach.
// `store` must outlive `server`.
void onion_server_set_key_store(OnionServerHandle server,
                                OnionKeyStoreHandle store);

// ─── Indirect DB mode ──────────────────────────────────────────────────────
//
// Attach a shared NTT-expanded backing store; each call's `index_table` maps
// this server's logical plaintext ids → physical entry ids in `store`. The
// store must outlive the server. Layout: store[level * shared_num_entries +
// entry_id], same layout the matmul reads internally. db_coeff_t is uint64
// in the default config (n=2048, K=1).
//
// Pass store=NULL to detach (after which the server has no DB until a fresh
// gen_data / push_plaintexts / load_db).
//
// Returns 1 on success, 0 on validation failure (composite-first-dim
// config, mismatched index_table_len, etc).
int onion_server_set_shared_database(OnionServerHandle h,
                                     const uint64_t *store,
                                     uint64_t shared_num_entries,
                                     const uint32_t *index_table,
                                     uint64_t index_table_len);

// ─── Async QueryQueue ──────────────────────────────────────────────────────
//
// Worker-thread-backed async wrapper around onion_server_answer_query.
// Submit a query (returns a ticket), poll status, then fetch the result.
// The queue holds a non-owning reference to the server — the server must
// outlive the queue. The caller must NOT touch the server (set keys,
// gen_data, push_plaintexts) while the queue has pending or in-flight
// work — drain first or call onion_queue_stop.

typedef void *OnionQueueHandle;

enum {
    ONION_QUERY_QUEUED     = 0,
    ONION_QUERY_PROCESSING = 1,
    ONION_QUERY_DONE       = 2,
    ONION_QUERY_ERROR      = 3,
    ONION_QUERY_NOT_FOUND  = 4,
};

OnionQueueHandle onion_queue_new(OnionServerHandle server);
void             onion_queue_free(OnionQueueHandle h);
void             onion_queue_stop(OnionQueueHandle h);

// Enqueue. Returns a non-zero ticket, or 0 if the queue has been stopped.
uint64_t onion_queue_submit(OnionQueueHandle h, uint64_t client_id,
                            const uint8_t *query, size_t query_len);

// Non-blocking status. Returns one of the ONION_QUERY_* constants.
int onion_queue_status(OnionQueueHandle h, uint64_t ticket);

// Fetch + consume. Returns an OnionBuf with the response bytes (status
// DONE) or the UTF-8 error message (status ERROR). On QUEUED/PROCESSING/
// NOT_FOUND the buf has data == NULL and len == 0. Caller frees.
OnionBuf onion_queue_result(OnionQueueHandle h, uint64_t ticket);

#ifdef __cplusplus
}  // extern "C"
#endif
