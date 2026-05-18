#include "query_queue.h"
#include "server.h"
#include "rlwe.h"

#include <cstring>
#include <sstream>
#include <stdexcept>
#include <utility>

// Forward declare the serializers from onion_ffi.cpp. We share them so the
// queue speaks the exact same wire format as the synchronous answer_query
// path, which means clients can use either interchangeably.
namespace {

// Local copy of the LE Reader/Writer + RlweCt (de)serializer used by
// onion_ffi.cpp. Kept duplicated rather than exported because:
//   - onion_ffi.cpp's anonymous namespace keeps them TU-local on purpose
//   - this file is the only other consumer
//   - the format is just a few u32/u64 reads, easy to keep in sync
struct Reader {
    const std::uint8_t *p;
    const std::uint8_t *end;
    Reader(const std::uint8_t *d, std::size_t n) : p(d), end(d + n) {}
    bool has(std::size_t n) const {
        return static_cast<std::size_t>(end - p) >= n;
    }
    std::uint32_t u32() {
        if (!has(4)) throw std::runtime_error("queue: short read (u32)");
        std::uint32_t v = static_cast<std::uint32_t>(p[0])
                        | (static_cast<std::uint32_t>(p[1]) << 8)
                        | (static_cast<std::uint32_t>(p[2]) << 16)
                        | (static_cast<std::uint32_t>(p[3]) << 24);
        p += 4;
        return v;
    }
    void u64_array(std::uint64_t *dst, std::size_t n) {
        const std::size_t bytes = n * sizeof(std::uint64_t);
        if (!has(bytes)) throw std::runtime_error("queue: short read (u64 array)");
        std::memcpy(dst, p, bytes);
        p += bytes;
    }
};

RlweCt deserialize_query(const std::uint8_t *data, std::size_t len) {
    Reader r(data, len);
    const std::uint32_t ntt = r.u32();
    const std::uint32_t poly = r.u32();
    RlweCt ct;
    ct.ntt_form = (ntt != 0);
    ct.c0.assign(poly, 0);
    ct.c1.assign(poly, 0);
    r.u64_array(ct.c0.data(), poly);
    r.u64_array(ct.c1.data(), poly);
    return ct;
}

}  // namespace

QueryQueue::QueryQueue(PirServer &server) : server_(server) {
    worker_ = std::thread(&QueryQueue::run, this);
}

QueryQueue::~QueryQueue() {
    stop();
}

std::uint64_t QueryQueue::submit(std::size_t client_id,
                                  const std::uint8_t *query,
                                  std::size_t query_len) {
    if (stopped_.load()) return 0;
    const std::uint64_t ticket = next_ticket_.fetch_add(1);
    Job job{ticket, client_id, std::vector<std::uint8_t>(query, query + query_len)};
    {
        std::lock_guard<std::mutex> lk(mu_);
        pending_.push_back(std::move(job));
        results_[ticket].status = QueryStatus::Queued;
    }
    cv_.notify_one();
    return ticket;
}

QueryStatus QueryQueue::status(std::uint64_t ticket) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = results_.find(ticket);
    if (it == results_.end()) return QueryStatus::NotFound;
    return it->second.status;
}

bool QueryQueue::result(std::uint64_t ticket,
                        std::vector<std::uint8_t> &out_bytes) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = results_.find(ticket);
    if (it == results_.end()) return false;
    if (it->second.status != QueryStatus::Done
            && it->second.status != QueryStatus::Error) {
        return false;
    }
    out_bytes = std::move(it->second.bytes);
    results_.erase(it);
    return true;
}

void QueryQueue::stop() {
    bool expected = false;
    if (!stopped_.compare_exchange_strong(expected, true)) {
        // Another caller already stopped us — just wait for the worker.
        if (worker_.joinable()) worker_.join();
        return;
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

void QueryQueue::run() {
    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [&] { return stopped_.load() || !pending_.empty(); });
            if (stopped_.load() && pending_.empty()) return;
            job = std::move(pending_.front());
            pending_.pop_front();
            processing_ticket_ = job.ticket;
            results_[job.ticket].status = QueryStatus::Processing;
        }

        // Process outside the lock so the worker doesn't block submit/status
        // callers for the duration of a query (~50 ms each).
        std::vector<std::uint8_t> response_bytes;
        std::string                error_msg;
        try {
            RlweCt query = deserialize_query(job.query_bytes.data(),
                                              job.query_bytes.size());
            RlweCt response = server_.make_query(job.client_id, query);
            std::stringstream ss;
            server_.save_resp_to_stream(response, ss);
            const std::string s = ss.str();
            response_bytes.assign(s.begin(), s.end());
        } catch (const std::exception &e) {
            error_msg = e.what();
        } catch (...) {
            error_msg = "unknown error";
        }

        {
            std::lock_guard<std::mutex> lk(mu_);
            auto &entry = results_[job.ticket];
            if (error_msg.empty()) {
                entry.status = QueryStatus::Done;
                entry.bytes  = std::move(response_bytes);
            } else {
                entry.status = QueryStatus::Error;
                entry.bytes.assign(error_msg.begin(), error_msg.end());
            }
            processing_ticket_ = 0;
        }
        // No notify needed for status polling; callers spin or sleep.
    }
}
