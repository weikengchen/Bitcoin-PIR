#pragma once

// QueryQueue — async wrapper around PirServer::make_query.
//
// A single worker thread drains submitted queries one at a time and stores
// the bit-packed response in a result map keyed by an opaque ticket.
// Callers submit() to enqueue, poll status() until QUERY_DONE, then
// result() to retrieve and consume the bytes.
//
// Threading contract:
//   * The queue owns one worker thread that calls make_query() / wire-packs
//     the response. Because PirServer itself is not thread-safe, callers
//     must NOT touch the underlying server (set_client_*_key, gen_data,
//     push_plaintexts, etc.) while the queue is processing — drain the
//     pending work first (e.g. by waiting for status() == DONE for every
//     outstanding ticket) and ideally call stop() before mutating server
//     state.
//   * submit / status / result / stop are themselves thread-safe and can
//     be called concurrently by multiple producer threads.
//
// Result lifetime: once a ticket reaches DONE (or ERROR), its bytes sit in
// the result map until result() is called. Callers MUST drain finished
// tickets or the map grows unboundedly. There's intentionally no automatic
// expiry — keeping the policy explicit at the call site.

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

class PirServer;

enum class QueryStatus : int {
    Queued     = 0,
    Processing = 1,
    Done       = 2,
    Error      = 3,
    NotFound   = 4,
};

class QueryQueue {
public:
    explicit QueryQueue(PirServer &server);
    ~QueryQueue();                   // calls stop() if not already stopped

    QueryQueue(const QueryQueue &) = delete;
    QueryQueue &operator=(const QueryQueue &) = delete;

    // Enqueue. Returns a non-zero ticket. The query bytes are the same
    // wire format that PirServer::make_query expects via the FFI
    // (serialized RlweCt; see src/onion_ffi.cpp). After this call returns
    // the caller no longer needs the input buffer. If the queue has been
    // stopped, returns 0.
    std::uint64_t submit(std::size_t client_id,
                         const std::uint8_t *query, std::size_t query_len);

    // Non-blocking status poll. Tickets disappear from the map when
    // result() consumes them; subsequent polls return NotFound.
    QueryStatus status(std::uint64_t ticket);

    // Fetch and consume. Returns true and fills `out_bytes` only when the
    // ticket's status is Done (response bytes) or Error (UTF-8 message);
    // returns false on Queued / Processing / NotFound. The ticket is
    // removed from the map on a true return.
    bool result(std::uint64_t ticket, std::vector<std::uint8_t> &out_bytes);

    // Cooperative shutdown. Stops accepting new submissions, lets the
    // worker finish its current item, then joins. Idempotent. Called from
    // the destructor.
    void stop();

private:
    struct Job {
        std::uint64_t                 ticket;
        std::size_t                   client_id;
        std::vector<std::uint8_t>     query_bytes;
    };
    struct ResultEntry {
        QueryStatus               status = QueryStatus::Queued;
        std::vector<std::uint8_t> bytes;     // packed response (Done) or error msg (Error)
    };

    PirServer &server_;

    std::mutex                mu_;
    std::condition_variable   cv_;
    std::deque<Job>           pending_;
    std::unordered_map<std::uint64_t, ResultEntry> results_;
    std::uint64_t             processing_ticket_ = 0;   // 0 = idle
    std::atomic<std::uint64_t> next_ticket_{1};
    std::atomic<bool>         stopped_{false};

    std::thread               worker_;

    void run();
};
