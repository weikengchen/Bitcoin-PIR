#include "shared_key_store.h"

#include <stdexcept>
#include <string>
#include <utility>

// All public methods take mu_. promote_to_front / evict_if_full are
// private helpers called only from already-locked public methods, so they
// don't lock themselves (would deadlock).

void SharedKeyStore::set_galois_keys(size_t client_id, bvks::BvGaloisKeys keys) {
    std::lock_guard<std::mutex> lock(mu_);
    galois_[client_id] = std::move(keys);
    promote_to_front(client_id);
    evict_if_full();
}

void SharedKeyStore::set_gsw_key(size_t client_id, GSWCt key) {
    std::lock_guard<std::mutex> lock(mu_);
    gsw_[client_id] = std::move(key);
    promote_to_front(client_id);
    evict_if_full();
}

const bvks::BvGaloisKeys &
SharedKeyStore::get_galois_keys(size_t client_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = galois_.find(client_id);
    if (it == galois_.end()) {
        throw std::out_of_range(
            "SharedKeyStore: no galois keys for client_id "
            + std::to_string(client_id));
    }
    // Reference outlives the lock — caller must keep the store stable for
    // its lifetime (see class header doc). Intended pattern: registration
    // and query processing don't overlap in time.
    return it->second;
}

const GSWCt &SharedKeyStore::get_gsw_key(size_t client_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = gsw_.find(client_id);
    if (it == gsw_.end()) {
        throw std::out_of_range(
            "SharedKeyStore: no gsw key for client_id "
            + std::to_string(client_id));
    }
    return it->second;
}

bool SharedKeyStore::has_client(size_t client_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    return galois_.count(client_id) && gsw_.count(client_id);
}

void SharedKeyStore::touch(size_t client_id) {
    std::lock_guard<std::mutex> lock(mu_);
    // Only LRU-promote known clients. Touching an unknown id is a no-op
    // — callers shouldn't insert phantom entries via touch.
    if (lru_pos_.count(client_id)) {
        promote_to_front(client_id);
    }
}

void SharedKeyStore::remove(size_t client_id) {
    std::lock_guard<std::mutex> lock(mu_);
    galois_.erase(client_id);
    gsw_.erase(client_id);
    auto it = lru_pos_.find(client_id);
    if (it != lru_pos_.end()) {
        lru_order_.erase(it->second);
        lru_pos_.erase(it);
    }
}

size_t SharedKeyStore::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return lru_order_.size();
}

void SharedKeyStore::promote_to_front(size_t client_id) {
    auto it = lru_pos_.find(client_id);
    if (it != lru_pos_.end()) {
        // Move existing entry to the front.
        lru_order_.splice(lru_order_.begin(), lru_order_, it->second);
    } else {
        lru_order_.push_front(client_id);
        lru_pos_[client_id] = lru_order_.begin();
    }
}

void SharedKeyStore::evict_if_full() {
    while (lru_order_.size() > MAX_CLIENTS) {
        const size_t victim = lru_order_.back();
        lru_order_.pop_back();
        lru_pos_.erase(victim);
        galois_.erase(victim);
        gsw_.erase(victim);
    }
}
