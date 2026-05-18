#pragma once

// SharedKeyStore — deserialize-once, share-across-many for client keys.
//
// In a multi-tenant deployment many PirServer instances share the same
// underlying PIR parameters. Each client's BV galois keys + GSW(s) key add
// up to a few MB; if every server keeps its own copy the memory bill
// scales with (n_servers × n_clients). With this store, every server
// reads from a single shared cache — memory scales with n_clients only.
//
// The store also enforces a cap on the number of cached clients with an
// LRU eviction policy, so a long-running server doesn't grow unboundedly
// as clients come and go.
//
// Thread safety: every public method is internally serialized by mu_.
// However, get_galois_keys / get_gsw_key return `const &` into the
// internal maps — once they return, the caller-held reference is no
// longer protected by mu_. The caller MUST keep the keystore stable
// for the entire lifetime of that reference (no concurrent set_* /
// remove / eviction that could touch the same client_id). The intended
// pattern: registration runs on a setup thread, query processing on
// worker threads; the two never overlap in time, but multiple worker
// threads CAN run get_* + touch() concurrently against the same client.

#include "bv_keyswitch.h"
#include "gsw.h"

#include <cstddef>
#include <list>
#include <mutex>
#include <unordered_map>

class SharedKeyStore {
public:
    // MAX_CLIENTS bounds the per-store memory footprint. Adding the
    // (MAX_CLIENTS + 1)-th client evicts the least-recently-used one.
    // 100 is the same heuristic the pre-port fork used and is comfortable
    // for a single-host serving up to ~hundred concurrent identities.
    static constexpr size_t MAX_CLIENTS = 100;

    SharedKeyStore() = default;
    ~SharedKeyStore() = default;

    SharedKeyStore(const SharedKeyStore &) = delete;
    SharedKeyStore &operator=(const SharedKeyStore &) = delete;

    // Register a client's BV galois keys (already deserialized by the
    // caller's FFI / wire layer). The store takes ownership.
    void set_galois_keys(size_t client_id, bvks::BvGaloisKeys keys);

    // Register a client's GSW(s) key. The store takes ownership.
    void set_gsw_key(size_t client_id, GSWCt key);

    // Look up keys. Both throw std::out_of_range if the client isn't
    // registered. Calling these does NOT change LRU order — only
    // touch() does. (PirServer touches before its query path so the
    // LRU reflects active clients, not arbitrary lookups.)
    const bvks::BvGaloisKeys &get_galois_keys(size_t client_id) const;
    const GSWCt              &get_gsw_key(size_t client_id) const;

    // True if BOTH key types are registered for this client.
    bool has_client(size_t client_id) const;

    // Promote a client to most-recently-used. Cheap (O(1)); call this on
    // the query path so eviction targets idle clients.
    void touch(size_t client_id);

    // Remove a client's entries (galois + gsw). No-op if not present.
    void remove(size_t client_id);

    // Current number of cached clients (with at least one key registered).
    size_t size() const;

private:
    std::unordered_map<size_t, bvks::BvGaloisKeys> galois_;
    std::unordered_map<size_t, GSWCt>              gsw_;

    // LRU bookkeeping: front = MRU, back = LRU. lru_pos_ holds an
    // iterator into lru_order_ for O(1) splice on touch().
    std::list<size_t>                                              lru_order_;
    std::unordered_map<size_t, std::list<size_t>::iterator>        lru_pos_;

    // Serializes every public method (and the private helpers they call).
    // `mutable` so const accessors can take the lock too.
    mutable std::mutex mu_;

    // Called on every set_* and touch(). If size exceeds MAX_CLIENTS,
    // pops the LRU client and erases its keys.
    void evict_if_full();
    // Helper: ensure client_id is present in the LRU list (insert at front
    // if new). Used by set_galois_keys / set_gsw_key / touch.
    void promote_to_front(size_t client_id);
};
