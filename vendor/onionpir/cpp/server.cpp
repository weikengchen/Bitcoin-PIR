#include "server.h"
#include "gsw.h"
#include "rlwe.h"
#include "utils.h"
#include "matrix.h"
#include "hexl/hexl.hpp"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <random>
#include <sstream>
#include <bit>
#include <cstdint>
#include <unordered_set>

#if defined(__AVX512F__)
    #include <immintrin.h>
#elif defined(__AVX2__)
    #include <immintrin.h>
#endif

#ifdef _DEBUG
#include <bitset>
#endif

// client_bv_galois_keys_, client_gsw_keys_, and db_ are not set yet.
PirServer::PirServer(const PirParams &pir_params)
    : pir_params_(pir_params),
      num_pt_(pir_params.get_num_pt()),
      key_gsw_(pir_params, pir_params.get_l_key(), pir_params.get_base_log2_key()),
      data_gsw_(pir_params, pir_params.get_l(), pir_params.get_base_log2()) {
  const size_t db_elem_cnt = num_pt_ * pir_params_.get_coeff_val_cnt();
  if (pir_params_.get_composite_rns().enabled) {
    // Composite path: two u32 arrays (mod q1 and mod q2) with the same
    // coeff-major layout. Bytes match the u64 DB on the standard path.
    db_lo_ = make_unique_aligned<uint32_t, 64>(db_elem_cnt);
    db_hi_ = make_unique_aligned<uint32_t, 64>(db_elem_cnt);
    db_lo_ptr_ = db_lo_.get();
    db_hi_ptr_ = db_hi_.get();
  } else {
    // after NTT, each database polynomial coefficient will be in mod q. Hence,
    // each pt coefficient is represented by K many uint64_t, same as the ciphertext.
    db_aligned_ = make_unique_aligned<db_coeff_t, 64>(db_elem_cnt);
    db_ptr_ = db_aligned_.get();
  }
  fill_inter_res();
}

PirServer::~PirServer() {
}

namespace { constexpr size_t TILE = 8; }

// Internal worker. NTT each plaintext in `tile_pt` (bs of them, each N
// coefficients) and transpose-scatter into db_aligned_ (or db_lo_/db_hi_ for
// the composite path) at index `pb`. Records any indices in `record_set`
// pre-NTT for direct_get_original_plaintext. `stage` is caller-owned scratch
// of size K * TILE * N.
void PirServer::process_plaintext_tile(const uint64_t *tile_pt, size_t bs,
                                       size_t pb,
                                       const std::unordered_set<size_t> &record_set,
                                       uint64_t *stage) {
  const size_t coeff_count = DBConsts::PolyDegree;
  const auto &rns_mods = pir_params_.get_rns_mods();
  const size_t K = rns_mods.size();
  const auto &crt = pir_params_.get_composite_rns();

  // Record tagged plaintexts pre-NTT. Must happen before we mutate tile_pt
  // (the composite path does the NTT in place).
  for (size_t p = 0; p < bs; ++p) {
    const size_t poly_id = pb + p;
    if (record_set.count(poly_id)) {
      RlwePt pt;
      pt.data.assign(tile_pt + p * coeff_count,
                     tile_pt + (p + 1) * coeff_count);
      recorded_pts_[poly_id] = std::move(pt);
    }
  }

  if (crt.enabled) {
    // Composite path: NTT under Q = q1*q2 in place, then split each
    // coefficient into (mod q1, mod q2) u32 limbs in the coeff-major layout.
    // We need a writable copy of tile_pt since ntt_fwd is in place.
    std::vector<uint64_t> scratch(tile_pt, tile_pt + bs * coeff_count);
    const uint64_t Q  = rns_mods[0];
    const uint64_t q1 = crt.q1;
    const uint64_t q2 = crt.q2;
    for (size_t p = 0; p < bs; ++p) {
      uint64_t *coeffs = scratch.data() + p * coeff_count;
      utils::ntt_fwd(coeffs, coeff_count, Q);
      const size_t poly_id = pb + p;
      for (size_t coeff_idx = 0; coeff_idx < coeff_count; ++coeff_idx) {
        const uint64_t c = coeffs[coeff_idx];
        const size_t idx = coeff_idx * num_pt_ + poly_id;
        db_lo_[idx] = static_cast<uint32_t>(c % q1);
        db_hi_[idx] = static_cast<uint32_t>(c % q2);
      }
    }
    return;
  }

  // Standard path: NTT each plaintext under each q_k into `stage`, then
  // tile-transpose-write into db_aligned_. Layout matches the matmul:
  // db_aligned_[coeff_idx * num_pt_ + poly_id], coeff_idx in [0, K*N).
  for (size_t k = 0; k < K; ++k) {
    const uint64_t qk = rns_mods[k];
    uint64_t *limb_base = stage + k * TILE * coeff_count;
    for (size_t p = 0; p < bs; ++p) {
      uint64_t *dst = limb_base + p * coeff_count;
      const uint64_t *src = tile_pt + p * coeff_count;
      for (size_t i = 0; i < coeff_count; ++i) dst[i] = src[i] % qk;
      utils::ntt_fwd(dst, coeff_count, qk);
    }
  }
  for (size_t k = 0; k < K; ++k) {
    uint64_t *limb_base = stage + k * TILE * coeff_count;
    for (size_t coeff_idx = 0; coeff_idx < coeff_count; ++coeff_idx) {
      db_coeff_t *out = db_aligned_.get() +
                        (k * coeff_count + coeff_idx) * num_pt_ + pb;
      for (size_t p = 0; p < bs; ++p) {
        out[p] = static_cast<db_coeff_t>(limb_base[p * coeff_count + coeff_idx]);
      }
    }
  }
}

// Fills the database with random data. Streams in tiles so peak RAM stays at
// ~|db_aligned_| (one copy) rather than 2x.
void PirServer::gen_data(const std::vector<size_t>& record_indices) {
  BENCH_PRINT("Generating random data for the server database...");
  std::mt19937_64 rng(std::random_device{}());
  recorded_pts_.clear();
  recorded_pts_.reserve(record_indices.size());
  std::unordered_set<size_t> record_set(record_indices.begin(),
                                        record_indices.end());

  const size_t coeff_count = DBConsts::PolyDegree;
  const uint64_t plain_mod = pir_params_.get_plain_mod();
  const size_t K = pir_params_.get_rns_mods().size();

  TIME_ONCE_START("DB gen+NTT+realign");
  std::vector<uint64_t> tile_pt(TILE * coeff_count);
  std::vector<uint64_t> stage(K * TILE * coeff_count);

  for (size_t pb = 0; pb < num_pt_; pb += TILE) {
    const size_t bs = std::min(TILE, num_pt_ - pb);
    for (size_t p = 0; p < bs; ++p) {
      uint64_t *dst = tile_pt.data() + p * coeff_count;
      for (size_t i = 0; i < coeff_count; ++i) dst[i] = rng() % plain_mod;
    }
    process_plaintext_tile(tile_pt.data(), bs, pb, record_set, stage.data());
  }
  TIME_ONCE_END("DB gen+NTT+realign");
  PRINT_ONCE("DB gen+NTT+realign");
}

void PirServer::push_plaintexts(const uint64_t *plaintexts, size_t count,
                                size_t offset,
                                const std::vector<size_t> &record_indices) {
  if (count == 0) return;
  if (offset + count > num_pt_) {
    throw std::out_of_range(
        "push_plaintexts: offset + count > num_pt (" +
        std::to_string(offset) + " + " + std::to_string(count) + " > " +
        std::to_string(num_pt_) + ")");
  }

  std::unordered_set<size_t> record_set(record_indices.begin(),
                                        record_indices.end());

  const size_t coeff_count = DBConsts::PolyDegree;
  const size_t K = pir_params_.get_rns_mods().size();
  std::vector<uint64_t> stage(K * TILE * coeff_count);

  for (size_t i = 0; i < count; i += TILE) {
    const size_t bs = std::min(TILE, count - i);
    process_plaintext_tile(plaintexts + i * coeff_count, bs, offset + i,
                           record_set, stage.data());
  }
}

// ───────────────────────────── DB persistence ──────────────────────────────
//
// On-disk format (all little-endian, machine-native u64 layout):
//   header: [magic][version][layout_id][num_pt][coeff_val_cnt][data_bytes]
//   data:   raw bytes of size data_bytes
//
// layout_id bits:
//   bit 0 — composite split (db_lo_ || db_hi_ as u32 arrays)
//   bit 1 — db_coeff_t is uint32_t (vs uint64_t)
//
// load_db_from_borrowed treats `data` as the start of the header. Bytes after
// the header are aliased in place; the caller must keep them alive.

namespace {
constexpr uint64_t PREPROC_MAGIC   = 0x4F50495256325F44ULL;  // "D_2VRIPO" LE
constexpr uint64_t PREPROC_VERSION = 1;
constexpr size_t   HEADER_U64S     = 6;
constexpr size_t   HEADER_BYTES    = HEADER_U64S * sizeof(uint64_t);

uint64_t compute_layout_id(bool composite, bool db_coeff_is_u32) {
  uint64_t id = 0;
  if (composite)        id |= 1ULL;
  if (db_coeff_is_u32)  id |= 2ULL;
  return id;
}
}  // namespace

void PirServer::save_db_to_file(const std::string &path) const {
  const bool composite = pir_params_.get_composite_rns().enabled;
  const bool db_u32    = (sizeof(db_coeff_t) == 4);
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const size_t elem_cnt = num_pt_ * coeff_val_cnt;

  const uint8_t *src       = nullptr;
  size_t         data_bytes = 0;
  if (composite) {
    if (!db_lo_ptr_ || !db_hi_ptr_)
      throw std::runtime_error("save_db_to_file: composite DB not loaded");
    data_bytes = 2 * elem_cnt * sizeof(uint32_t);
    // We write db_lo_ then db_hi_ — both contiguous u32 arrays.
  } else {
    if (!db_ptr_)
      throw std::runtime_error("save_db_to_file: standard DB not loaded");
    src        = reinterpret_cast<const uint8_t *>(db_ptr_);
    data_bytes = elem_cnt * sizeof(db_coeff_t);
  }

  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) throw std::runtime_error("save_db_to_file: cannot open " + path);

  uint64_t header[HEADER_U64S] = {
      PREPROC_MAGIC, PREPROC_VERSION,
      compute_layout_id(composite, db_u32),
      static_cast<uint64_t>(num_pt_),
      static_cast<uint64_t>(coeff_val_cnt),
      static_cast<uint64_t>(data_bytes),
  };
  out.write(reinterpret_cast<const char *>(header), HEADER_BYTES);
  if (composite) {
    out.write(reinterpret_cast<const char *>(db_lo_ptr_),
              elem_cnt * sizeof(uint32_t));
    out.write(reinterpret_cast<const char *>(db_hi_ptr_),
              elem_cnt * sizeof(uint32_t));
  } else {
    out.write(reinterpret_cast<const char *>(src), data_bytes);
  }
  if (!out) throw std::runtime_error("save_db_to_file: write failed");
  out.close();

  const double mb = (HEADER_BYTES + data_bytes) / (1024.0 * 1024.0);
  BENCH_PRINT("Saved preprocessed DB to " << path << " (" << mb << " MB)");
}

// Shared header validation. Returns true on match; never throws.
static bool validate_header(const uint64_t header[HEADER_U64S],
                            size_t expected_num_pt,
                            size_t expected_coeff_val_cnt,
                            uint64_t expected_layout_id,
                            size_t expected_data_bytes) {
  return header[0] == PREPROC_MAGIC
      && header[1] == PREPROC_VERSION
      && header[2] == expected_layout_id
      && header[3] == expected_num_pt
      && header[4] == expected_coeff_val_cnt
      && header[5] == expected_data_bytes;
}

bool PirServer::load_db_from_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;

  uint64_t header[HEADER_U64S];
  in.read(reinterpret_cast<char *>(header), HEADER_BYTES);
  if (!in) return false;

  const bool composite = pir_params_.get_composite_rns().enabled;
  const bool db_u32    = (sizeof(db_coeff_t) == 4);
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const size_t elem_cnt = num_pt_ * coeff_val_cnt;
  const size_t expected_bytes = composite
      ? 2 * elem_cnt * sizeof(uint32_t)
      : elem_cnt * sizeof(db_coeff_t);
  const uint64_t expected_layout = compute_layout_id(composite, db_u32);

  if (!validate_header(header, num_pt_, coeff_val_cnt,
                       expected_layout, expected_bytes)) {
    return false;
  }

  if (composite) {
    in.read(reinterpret_cast<char *>(db_lo_.get()),
            elem_cnt * sizeof(uint32_t));
    in.read(reinterpret_cast<char *>(db_hi_.get()),
            elem_cnt * sizeof(uint32_t));
    if (!in) return false;
    db_lo_ptr_ = db_lo_.get();
    db_hi_ptr_ = db_hi_.get();
  } else {
    in.read(reinterpret_cast<char *>(db_aligned_.get()),
            elem_cnt * sizeof(db_coeff_t));
    if (!in) return false;
    db_ptr_ = db_aligned_.get();
  }

  BENCH_PRINT("Loaded preprocessed DB from " << path);
  return true;
}

void PirServer::set_shared_database(const db_coeff_t *store,
                                    size_t shared_num_entries,
                                    const uint32_t *index_table,
                                    size_t index_table_len) {
  if (pir_params_.get_composite_rns().enabled) {
    throw std::runtime_error(
        "set_shared_database: composite-first-dim path is not supported");
  }
  if (store == nullptr) {
    // Detach. Server now has no DB until gen_data / load_db / push_plaintexts.
    shared_store_ = nullptr;
    shared_num_entries_ = 0;
    index_table_ = nullptr;
    index_table_len_ = 0;
    return;
  }
  if (index_table_len != num_pt_) {
    throw std::invalid_argument(
        "set_shared_database: index_table_len (" + std::to_string(index_table_len)
        + ") != num_pt (" + std::to_string(num_pt_) + ")");
  }
  shared_store_ = store;
  shared_num_entries_ = shared_num_entries;
  index_table_ = index_table;
  index_table_len_ = index_table_len;
  // Free the owned per-instance buffer — the whole point is to save memory.
  db_aligned_.reset();
  db_ptr_ = nullptr;  // not used in indirect mode
}

bool PirServer::load_db_from_borrowed(const uint8_t *data, size_t len) {
  if (!data || len < HEADER_BYTES) return false;
  uint64_t header[HEADER_U64S];
  std::memcpy(header, data, HEADER_BYTES);

  const bool composite = pir_params_.get_composite_rns().enabled;
  const bool db_u32    = (sizeof(db_coeff_t) == 4);
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const size_t elem_cnt = num_pt_ * coeff_val_cnt;
  const size_t expected_bytes = composite
      ? 2 * elem_cnt * sizeof(uint32_t)
      : elem_cnt * sizeof(db_coeff_t);
  const uint64_t expected_layout = compute_layout_id(composite, db_u32);

  if (!validate_header(header, num_pt_, coeff_val_cnt,
                       expected_layout, expected_bytes)) {
    return false;
  }
  if (len < HEADER_BYTES + expected_bytes) return false;

  // Alignment: the matmul prefers 64-byte alignment for AVX-512 paths and
  // hint-only for everything else. We don't enforce it — callers who care
  // about peak throughput should align the buffer themselves.
  const uint8_t *payload = data + HEADER_BYTES;
  if (composite) {
    db_lo_ptr_ = reinterpret_cast<const uint32_t *>(payload);
    db_hi_ptr_ = reinterpret_cast<const uint32_t *>(payload + elem_cnt * sizeof(uint32_t));
    // Free the owned buffers — we're aliasing the borrowed one now.
    db_lo_.reset();
    db_hi_.reset();
  } else {
    db_ptr_ = reinterpret_cast<const db_coeff_t *>(payload);
    db_aligned_.reset();
  }
  return true;
}

void PirServer::prep_query(std::vector<RlweCt> &fst_dim_query,
                           std::vector<db_coeff_t> &query_data) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();       // 256
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // 4096
  const size_t slice_sz = fst_dim_sz * 2;
  const auto &rns_mods = pir_params_.get_rns_mods();
  const size_t K = rns_mods.size();
  constexpr size_t N = DBConsts::PolyDegree;
 
  // transform the selection vector to ntt form
  for (size_t i = 0; i < fst_dim_query.size(); i++) {
    RlweCt &ct = fst_dim_query[i];
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      utils::ntt_fwd(ct.c0.data() + mod_id * N, N, rns_mods[mod_id]);
      utils::ntt_fwd(ct.c1.data() + mod_id * N, N, rns_mods[mod_id]);
    }
    ct.ntt_form = true;
  }
 
  // Pre-fetch the data pointers to avoid repeated indirect access
  std::vector<const uint64_t *> data0_ptrs(fst_dim_sz);
  std::vector<const uint64_t *> data1_ptrs(fst_dim_sz);

  // Prefetch all pointers
  for (size_t i = 0; i < fst_dim_sz; ++i) {
    data0_ptrs[i] = fst_dim_query[i].c0.data();
    data1_ptrs[i] = fst_dim_query[i].c1.data();
  }

  // Process in blocks to improve cache locality
  const size_t BLOCK_SIZE = 8;
  // Fallback to scalar implementation if no SIMD is available
  for (size_t slice_block = 0; slice_block < coeff_val_cnt;
       slice_block += BLOCK_SIZE) {
    const size_t slice_block_end =
        std::min(slice_block + BLOCK_SIZE, coeff_val_cnt);

    for (size_t i = 0; i < fst_dim_sz; ++i) {
      const uint64_t *p0 = data0_ptrs[i];
      const uint64_t *p1 = data1_ptrs[i];

      // Process a block of slices for the same i value (improves temporal
      // locality)
      for (size_t slice_id = slice_block; slice_id < slice_block_end;
           ++slice_id) {
        const size_t idx = slice_id * slice_sz + i * 2;
        query_data[idx] = static_cast<db_coeff_t>(p0[slice_id]);
        query_data[idx + 1] = static_cast<db_coeff_t>(p1[slice_id]);
      }
    }
  }
}

void PirServer::prep_query_composite(const std::vector<RlweCt> &fst_dim_query,
                                     uint32_t *query_lo, uint32_t *query_hi) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const size_t slice_sz = fst_dim_sz * 2;
  const auto &crt = pir_params_.get_composite_rns();
  const uint64_t q1 = crt.q1;
  const uint64_t q2 = crt.q2;

  std::vector<const uint64_t *> data0_ptrs(fst_dim_sz);
  std::vector<const uint64_t *> data1_ptrs(fst_dim_sz);
  for (size_t i = 0; i < fst_dim_sz; ++i) {
    data0_ptrs[i] = fst_dim_query[i].c0.data();
    data1_ptrs[i] = fst_dim_query[i].c1.data();
  }

  constexpr size_t BLOCK_SIZE = 8;
  for (size_t slice_block = 0; slice_block < coeff_val_cnt;
       slice_block += BLOCK_SIZE) {
    const size_t slice_block_end =
        std::min(slice_block + BLOCK_SIZE, coeff_val_cnt);
    for (size_t i = 0; i < fst_dim_sz; ++i) {
      const uint64_t *p0 = data0_ptrs[i];
      const uint64_t *p1 = data1_ptrs[i];
      for (size_t slice_id = slice_block; slice_id < slice_block_end;
           ++slice_id) {
        const size_t idx = slice_id * slice_sz + i * 2;
        const uint64_t v0 = p0[slice_id];
        const uint64_t v1 = p1[slice_id];
        query_lo[idx]     = static_cast<uint32_t>(v0 % q1);
        query_lo[idx + 1] = static_cast<uint32_t>(v1 % q1);
        query_hi[idx]     = static_cast<uint32_t>(v0 % q2);
        query_hi[idx + 1] = static_cast<uint32_t>(v1 % q2);
      }
    }
  }
}

// Computes a dot product between the fst_dim_query and the database for the
// first dimension with a delayed modulus optimization. fst_dim_query should
// be transformed to ntt.
std::vector<RlweCt>
PirServer::evaluate_first_dim(std::vector<RlweCt> &fst_dim_query) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();  // number of plaintexts in the first dimension
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();  // number of plaintexts in the other dimensions
  const size_t K = pir_params_.K();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // polydegree * RNS moduli count
  const size_t one_ct_sz = 2 * coeff_val_cnt; // Ciphertext has two polynomials
  const auto &rns_mods = pir_params_.get_rns_mods();
  constexpr size_t N = DBConsts::PolyDegree;

  const auto &crt = pir_params_.get_composite_rns();
  if (crt.enabled) {
    // Composite path: NTT each fst_dim_query under q = q1*q2 (single mod),
    // split DB & query into (mod q1, mod q2) u32 limbs, run two parallel
    // 32x32->64 matmuls, CRT-compose results back to mod q, then INTT mod q.
    const uint64_t q = rns_mods[0];
    for (size_t i = 0; i < fst_dim_query.size(); ++i) {
      RlweCt &ct = fst_dim_query[i];
      utils::ntt_fwd(ct.c0.data(), N, q);
      utils::ntt_fwd(ct.c1.data(), N, q);
      ct.ntt_form = true;
    }

    std::fill(inter_res_lo_.begin(), inter_res_lo_.end(), 0);
    std::fill(inter_res_hi_.begin(), inter_res_hi_.end(), 0);

    TIME_START(FST_DIM_PREP);
    std::vector<uint32_t> query_lo(fst_dim_sz * one_ct_sz);
    std::vector<uint32_t> query_hi(fst_dim_sz * one_ct_sz);
    prep_query_composite(fst_dim_query, query_lo.data(), query_hi.data());
    TIME_END(FST_DIM_PREP);

    TIME_START(CORE_TIME);
    level_mat_mat_32(db_lo_ptr_, query_lo.data(), inter_res_lo_.data(),
                     other_dim_sz, fst_dim_sz, coeff_val_cnt, crt.q1);
    level_mat_mat_32(db_hi_ptr_, query_hi.data(), inter_res_hi_.data(),
                     other_dim_sz, fst_dim_sz, coeff_val_cnt, crt.q2);
    TIME_END(CORE_TIME);

    TIME_START(FST_INTER_TO_CTS_TIME);
    std::vector<RlweCt> result;
    result.reserve(other_dim_sz);
    inter_to_cts_composite(result, inter_res_lo_.data(), inter_res_hi_.data());
    TIME_END(FST_INTER_TO_CTS_TIME);
    return result;
  }

  // fill the intermediate result with zeros
  std::fill(inter_res_.begin(), inter_res_.end(), 0);

  // reallocate the query data to a continuous memory
  TIME_START(FST_DIM_PREP);
  std::vector<db_coeff_t> query_data(fst_dim_sz * one_ct_sz);
  prep_query(fst_dim_query, query_data);
  TIME_END(FST_DIM_PREP);

  /*
  Imagine DB as a (other_dim_sz * fst_dim_sz) matrix, where each element is a
  vector of size coeff_val_cnt. In OnionPIRv1, the first dimension is doing the
  component wise matrix multiplication. Further details can be found in the "matrix.h" file.
  */
  // prepare the matrices. db_ptr_ aliases either db_aligned_ (owned) or a
  // caller-borrowed buffer; matmul is read-only so the const_cast is safe.
  // Indirect mode (shared_store_ set) gathers via index_table_ into a
  // transient buffer before invoking the matmul kernel — keeps the kernel
  // (including its AVX-512 fast path) unchanged.
  std::vector<db_coeff_t> gathered;
  const db_coeff_t *matmul_src = db_ptr_;
  if (shared_store_) {
    gathered.resize(coeff_val_cnt * num_pt_);
    // shared_store_ layout: [level * shared_num_entries + entry_id]
    // gathered layout:      [level * num_pt + pt_id]
    for (size_t level = 0; level < coeff_val_cnt; ++level) {
      const db_coeff_t *level_src = shared_store_ + level * shared_num_entries_;
      db_coeff_t *level_dst = gathered.data() + level * num_pt_;
      for (size_t pt = 0; pt < num_pt_; ++pt) {
        level_dst[pt] = level_src[index_table_[pt]];
      }
    }
    matmul_src = gathered.data();
  }
  db_matrix_t db_mat { const_cast<db_coeff_t *>(matmul_src),
                       other_dim_sz, fst_dim_sz, coeff_val_cnt };
  db_matrix_t query_mat { query_data.data(), fst_dim_sz, 2, coeff_val_cnt };
  inter_matrix_t inter_res_mat { inter_res_.data(), other_dim_sz, 2, coeff_val_cnt };

  // Per-level modulus: level lvl spans coefficients of limb (lvl / N).
  std::vector<uint64_t> level_qs(coeff_val_cnt);
  for (size_t k = 0; k < K; ++k) {
    std::fill(level_qs.begin() + k * N, level_qs.begin() + (k + 1) * N, rns_mods[k]);
  }
  TIME_START(CORE_TIME);
  level_mat_mat(&db_mat, &query_mat, &inter_res_mat, level_qs.data());
  TIME_END(CORE_TIME);

  // ========== transform the intermediate to coefficient form. Delay the modulus operation ==========
  TIME_START(FST_INTER_TO_CTS_TIME);
  std::vector<RlweCt> result; // output vector
  result.reserve(other_dim_sz);
  inter_to_cts(result, inter_res_.data());
  TIME_END(FST_INTER_TO_CTS_TIME);

  return result;
}


void PirServer::inter_to_cts(std::vector<RlweCt> &result, const inter_coeff_t *__restrict inter_res) {
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t K = pir_params_.K();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const auto &rns_mods = pir_params_.get_rns_mods();
  const size_t coeff_val_cnt = coeff_count * K;
  const size_t inter_padding = other_dim_sz * 2;  // distance between coefficients in inter_res

  // We need to unroll the loop to process multiple ciphertexts at once.
  // Otherwise, this function is basically reading the intermediate result
  // with a stride of inter_padding, which causes many cache misses.
  constexpr size_t unroll_factor = 16;

  // Process ciphertexts in blocks of unroll_factor for the main part
  const size_t main_blocks = other_dim_sz / unroll_factor;
  for (size_t block = 0; block < main_blocks; block++) {
    const size_t j = block * unroll_factor;

    // Create an array of ciphertexts.
    std::array<RlweCt, unroll_factor> cts;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      cts[idx].c0.assign(coeff_val_cnt, 0);
      cts[idx].c1.assign(coeff_val_cnt, 0);
    }

    // Compute the base indices for each ciphertext's two intermediate parts.
    // For ciphertext idx, poly0 uses base index: j*2 + 2*idx and poly1 uses j*2 + 2*idx + 1.
    std::array<size_t, unroll_factor> base0, base1;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      base0[idx] = j * 2 + 2 * idx;
      base1[idx] = j * 2 + 2 * idx + 1;
    }

    // Initialize intermediate indices and ciphertext write indices.
    std::array<size_t, unroll_factor> inter_idx0 = {0};  // for poly0 of each ciphertext
    std::array<size_t, unroll_factor> inter_idx1 = {0};  // for poly1 of each ciphertext
    std::array<size_t, unroll_factor> ct_idx0    = {0};  // write index for poly0
    std::array<size_t, unroll_factor> ct_idx1    = {0};  // write index for poly1

    // Process each modulus and coefficient. The `% q` is mathematically
    // redundant (mat_mat already reduces per output write)
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      // const uint64_t q = rns_mods[mod_id];
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        #pragma unroll
        for (size_t idx = 0; idx < unroll_factor; idx++) {
          inter_coeff_t x0 = inter_res[ base0[idx] + inter_idx0[idx] * inter_padding ];
          // cts[idx].c0[ ct_idx0[idx]++ ] = static_cast<uint64_t>(x0 % q);
          cts[idx].c0[ ct_idx0[idx]++ ] = static_cast<uint64_t>(x0);

          inter_coeff_t x1 = inter_res[ base1[idx] + inter_idx1[idx] * inter_padding ];
          cts[idx].c1[ ct_idx1[idx]++ ] = static_cast<uint64_t>(x1);

          inter_idx0[idx]++;
          inter_idx1[idx]++;
        }
      }
    }

    // Mark each ciphertext as being in NTT form and then transform back.
    #pragma unroll
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      for (size_t mod_id = 0; mod_id < K; mod_id++) {
        utils::ntt_inv(cts[idx].c0.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
        utils::ntt_inv(cts[idx].c1.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
      }
      cts[idx].ntt_form = false;
      result.emplace_back(std::move(cts[idx]));
    }
  }

  // Handle remaining ciphertexts individually for edge cases
  const size_t remaining_start = main_blocks * unroll_factor;
  for (size_t j = remaining_start; j < other_dim_sz; j++) {
    // Create a single ciphertext
    RlweCt ct;
    ct.c0.assign(coeff_val_cnt, 0);
    ct.c1.assign(coeff_val_cnt, 0);

    // Compute the base indices for this ciphertext's two intermediate parts
    const size_t base0 = j * 2;
    const size_t base1 = j * 2 + 1;

    // Initialize intermediate indices and ciphertext write indices
    size_t inter_idx0 = 0;  // for poly0
    size_t inter_idx1 = 0;  // for poly1
    size_t ct_idx0 = 0;     // write index for poly0
    size_t ct_idx1 = 0;     // write index for poly1

    // Edge-case loop (other_dim_sz % unroll_factor != 0). Same gather-and-cast
    // as the unrolled block above; mat_mat already produced values < q.
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        inter_coeff_t x0 = inter_res[base0 + inter_idx0 * inter_padding];
        ct.c0[ct_idx0++] = static_cast<uint64_t>(x0);

        inter_coeff_t x1 = inter_res[base1 + inter_idx1 * inter_padding];
        ct.c1[ct_idx1++] = static_cast<uint64_t>(x1);

        inter_idx0++;
        inter_idx1++;
      }
    }

    // Mark ciphertext as being in NTT form and then transform back
    for (size_t mod_id = 0; mod_id < K; mod_id++) {
      utils::ntt_inv(ct.c0.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
      utils::ntt_inv(ct.c1.data() + mod_id * coeff_count, coeff_count, rns_mods[mod_id]);
    }
    ct.ntt_form = false;
    result.emplace_back(std::move(ct));
  }
}

void PirServer::inter_to_cts_composite(std::vector<RlweCt> &result,
                                       const uint64_t *inter_lo,
                                       const uint64_t *inter_hi) {
  const auto &crt = pir_params_.get_composite_rns();
  const uint64_t q1 = crt.q1;
  const uint64_t q2 = crt.q2;
  const uint64_t q1_inv_mod_q2 = crt.q1_inv_mod_q2;
  const uint64_t q = q1 * q2;
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t inter_padding = other_dim_sz * 2;

  // Garner CRT compose: (lo, hi) → lo + q1 * ((hi − lo) · q1_inv mod q2).
  // Since q1, q2 < 2^29, diff·q1_inv stays under 2^58 — no 128-bit mul.
  auto compose = [q1, q2, q1_inv_mod_q2](uint64_t lo, uint64_t hi) -> uint64_t {
    const uint64_t lo_mod_q2 = lo % q2;
    const uint64_t diff = (hi + q2 - lo_mod_q2) % q2;
    const uint64_t k = (diff * q1_inv_mod_q2) % q2;
    return lo + q1 * k;
  };

  constexpr size_t unroll_factor = 16;
  const size_t main_blocks = other_dim_sz / unroll_factor;
  for (size_t block = 0; block < main_blocks; block++) {
    const size_t j = block * unroll_factor;
    std::array<RlweCt, unroll_factor> cts;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      cts[idx].c0.assign(coeff_count, 0);
      cts[idx].c1.assign(coeff_count, 0);
    }
    for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
      const size_t row = coeff_id * inter_padding;
      #pragma unroll
      for (size_t idx = 0; idx < unroll_factor; idx++) {
        const size_t b0 = row + j * 2 + 2 * idx;
        const size_t b1 = b0 + 1;
        cts[idx].c0[coeff_id] = compose(inter_lo[b0], inter_hi[b0]);
        cts[idx].c1[coeff_id] = compose(inter_lo[b1], inter_hi[b1]);
      }
    }
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      utils::ntt_inv(cts[idx].c0.data(), coeff_count, q);
      utils::ntt_inv(cts[idx].c1.data(), coeff_count, q);
      cts[idx].ntt_form = false;
      result.emplace_back(std::move(cts[idx]));
    }
  }

  for (size_t j = main_blocks * unroll_factor; j < other_dim_sz; j++) {
    RlweCt ct;
    ct.c0.assign(coeff_count, 0);
    ct.c1.assign(coeff_count, 0);
    for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
      const size_t b0 = coeff_id * inter_padding + j * 2;
      const size_t b1 = b0 + 1;
      ct.c0[coeff_id] = compose(inter_lo[b0], inter_hi[b0]);
      ct.c1[coeff_id] = compose(inter_lo[b1], inter_hi[b1]);
    }
    utils::ntt_inv(ct.c0.data(), coeff_count, q);
    utils::ntt_inv(ct.c1.data(), coeff_count, q);
    ct.ntt_form = false;
    result.emplace_back(std::move(ct));
  }
}

RlweCt PirServer::evaluate_other_dim(std::vector<RlweCt> &mid_db, std::vector<GSWCt> &selectors) {
  // Handle single dimension case
  if (pir_params_.get_num_dims() == 1) {
    // For single dimension, we just return the first (and only) ciphertext
    return mid_db[0];
  }
  
  size_t h = pir_params_.get_num_dims() - 1;
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  // For multiple dimensions, calculate the results vector size properly
  const size_t perfect_size = (1 << (h - 1)); // second to last level size
  
  // handling the last level
  const size_t last_level_sz = 2 * other_dim_sz - (1 << h);
  const size_t offset = other_dim_sz - last_level_sz;
  
  for (size_t i = 0; i < last_level_sz; i += 2) { // i is the index within the last level.
    size_t corrected_idx = i + offset;  // index in the database.
    auto &x = mid_db[corrected_idx];
    auto &y = mid_db[corrected_idx + 1];
    ext_prod_mux(x, y, selectors[0], mid_db[i / 2 + offset]);
  }
  
  for (size_t a = 1; a < selectors.size(); a++) { // starting from the second to the last level
    const size_t level_sz = (1 << (h - a));
    const size_t half = level_sz >> 1;
    for (size_t i = 0; i < half; i++) {
      auto &x = mid_db[i];
      auto &y = mid_db[i + half];
      ext_prod_mux(x, y, selectors[a], mid_db[i]);
    }
  }
  return mid_db[0];
}


void PirServer::ext_prod_mux(RlweCt &x, RlweCt &y, GSWCt &selection_cipher, RlweCt &result) {
    constexpr size_t N = DBConsts::PolyDegree;
    const auto &qs = pir_params_.get_rns_mods();
    const size_t K = qs.size();

    auto sub_k = [&](RlweCt &a, const RlweCt &b) {
      for (size_t k = 0; k < K; ++k) {
        intel::hexl::EltwiseSubMod(a.c0.data() + k * N, a.c0.data() + k * N,
                                   b.c0.data() + k * N, N, qs[k]);
        intel::hexl::EltwiseSubMod(a.c1.data() + k * N, a.c1.data() + k * N,
                                   b.c1.data() + k * N, N, qs[k]);
      }
    };
    auto add_inplace_k = [&](RlweCt &a, const RlweCt &b) {
      for (size_t k = 0; k < K; ++k) {
        intel::hexl::EltwiseAddMod(a.c0.data() + k * N, a.c0.data() + k * N,
                                   b.c0.data() + k * N, N, qs[k]);
        intel::hexl::EltwiseAddMod(a.c1.data() + k * N, a.c1.data() + k * N,
                                   b.c1.data() + k * N, N, qs[k]);
      }
    };
    auto add_k = [&](const RlweCt &a, const RlweCt &b, RlweCt &c) {
      c.c0.resize(K * N);
      c.c1.resize(K * N);
      c.ntt_form = a.ntt_form;
      for (size_t k = 0; k < K; ++k) {
        intel::hexl::EltwiseAddMod(c.c0.data() + k * N, a.c0.data() + k * N,
                                   b.c0.data() + k * N, N, qs[k]);
        intel::hexl::EltwiseAddMod(c.c1.data() + k * N, a.c1.data() + k * N,
                                   b.c1.data() + k * N, N, qs[k]);
      }
    };
    auto intt_k = [&](RlweCt &ct) {
      for (size_t k = 0; k < K; ++k) {
        utils::ntt_inv(ct.c0.data() + k * N, N, qs[k]);
        utils::ntt_inv(ct.c1.data() + k * N, N, qs[k]);
      }
      ct.ntt_form = false;
    };

    // ========== y = y - x ==========
    TIME_START(OTHER_DIM_ADD_SUB);
    sub_k(y, x);
    TIME_END(OTHER_DIM_ADD_SUB);

    // ========== y = b * (y - x) ========== output will be in NTT form
    TIME_START(OTHER_DIM_MUX_EXTERN);
    data_gsw_.external_product(selection_cipher, y, y, LogContext::OTHER_DIM_MUX);
    TIME_END(OTHER_DIM_MUX_EXTERN);

    // ========== y = INTT(y) ==========
    TIME_START(OTHER_DIM_INTT);
    intt_k(y);
    TIME_END(OTHER_DIM_INTT);

    // ========== result = y + x ==========
    TIME_START(OTHER_DIM_ADD_SUB);
    if (&result == &x) {
      add_inplace_k(x, y);
    } else {
      add_k(x, y, result);
    }
    TIME_END(OTHER_DIM_ADD_SUB);
}

//  single-loop level-order expansion  (root index = 1)
std::vector<RlweCt>
PirServer::fast_expand_qry(std::size_t client_id, RlweCt &ciphertext) const {
  // ============== parameters
  const size_t useful_cnt = pir_params_.get_fst_dim_sz() +
                            pir_params_.get_l() *
                                (pir_params_.get_num_dims() - 1); // u
  const size_t expan_height = pir_params_.get_expan_height(); // h
  const size_t capacity = size_t{1} << expan_height;          // 2^h
  // Source of truth: shared store if attached, else this server's own map.
  if (shared_key_store_) shared_key_store_->touch(client_id);
  const auto &bv_galois_key = shared_key_store_
      ? shared_key_store_->get_galois_keys(client_id)
      : client_bv_galois_keys_.at(client_id);
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = pir_params_.get_rns_mods();
  const size_t K = qs.size();

  // K-aware per-limb helpers. All ciphertexts in this routine are coefficient
  // form, K-limb, with c0/c1 each holding K*N uint64_t.
  auto rlwe_add_k = [&](const RlweCt &a, const RlweCt &b, RlweCt &c) {
    c.c0.resize(K * N);
    c.c1.resize(K * N);
    c.ntt_form = a.ntt_form;
    for (size_t k = 0; k < K; ++k) {
      intel::hexl::EltwiseAddMod(c.c0.data() + k * N, a.c0.data() + k * N,
                                 b.c0.data() + k * N, N, qs[k]);
      intel::hexl::EltwiseAddMod(c.c1.data() + k * N, a.c1.data() + k * N,
                                 b.c1.data() + k * N, N, qs[k]);
    }
  };
  auto rlwe_sub_inplace_k = [&](RlweCt &a, const RlweCt &b) {
    for (size_t k = 0; k < K; ++k) {
      intel::hexl::EltwiseSubMod(a.c0.data() + k * N, a.c0.data() + k * N,
                                 b.c0.data() + k * N, N, qs[k]);
      intel::hexl::EltwiseSubMod(a.c1.data() + k * N, a.c1.data() + k * N,
                                 b.c1.data() + k * N, N, qs[k]);
    }
  };
  auto rlwe_shift_k = [&](const RlweCt &src, RlweCt &dst, size_t index) {
    dst.c0.resize(K * N);
    dst.c1.resize(K * N);
    dst.ntt_form = src.ntt_form;
    for (size_t k = 0; k < K; ++k) {
      utils::negacyclic_shift_poly_coeffmod(src.c0.data() + k * N, N, index,
                                            qs[k], dst.c0.data() + k * N);
      utils::negacyclic_shift_poly_coeffmod(src.c1.data() + k * N, N, index,
                                            qs[k], dst.c1.data() + k * N);
    }
  };

  // ============== storage   – index 0 is *unused*, root is slot 1
  std::vector<RlweCt> cts(2 * capacity); // slots 0 … 2*capacity-1
  cts[1] = ciphertext;

  // ============== level-order walk, skip right-of-u sub-trees
  for (size_t i = 1; i < capacity; ++i) { // internal nodes only
    const int k = int{1} << (std::bit_width(i) - 1); // k = 2^{⌊log i⌋}   (span of this sub-tree)

    const size_t left_leaf = i * capacity / k - capacity;
    if (left_leaf >= useful_cnt)
      continue;

    RlweCt c_prime = cts[i];
    const uint32_t galois_k = DBConsts::PolyDegree / k + 1;
    TIME_START(APPLY_GALOIS);
    bvks::bv_apply_galois_inplace(c_prime, galois_k,
                                  bv_galois_key.get(galois_k),
                                  pir_params_);
    TIME_END(APPLY_GALOIS);
    TIME_START("add_sub");
    rlwe_add_k(cts[i], c_prime, cts[2 * i]);
    rlwe_sub_inplace_k(cts[i], c_prime);
    TIME_END("add_sub");

    TIME_START("shift polynomial");
    rlwe_shift_k(cts[i], cts[2 * i + 1], static_cast<size_t>(-k));
    TIME_END("shift polynomial");
  }

  // ==============  return the first  u  leaves: heap slots  capacity … capacity+u−1
  return std::vector<RlweCt>(
      std::make_move_iterator(cts.begin() + capacity),
      std::make_move_iterator(cts.begin() + capacity + useful_cnt));
}

void PirServer::set_client_bv_galois_key(const size_t client_id, bvks::BvGaloisKeys bv_keys) {
  if (shared_key_store_) {
    shared_key_store_->set_galois_keys(client_id, std::move(bv_keys));
  } else {
    client_bv_galois_keys_[client_id] = std::move(bv_keys);
  }
}

void PirServer::set_client_gsw_key(const size_t client_id, GSWCt gsw_key) {
  if (shared_key_store_) {
    shared_key_store_->set_gsw_key(client_id, std::move(gsw_key));
  } else {
    client_gsw_keys_[client_id] = std::move(gsw_key);
  }
}


// Get original plaintext (before NTT transformation) from recorded entries
RlwePt PirServer::direct_get_original_plaintext(const size_t plaintext_idx) const {
  auto it = recorded_pts_.find(plaintext_idx);
  if (it == recorded_pts_.end()) {
    throw std::invalid_argument("Plaintext index " + std::to_string(plaintext_idx) + " was not recorded during gen_data()");
  }
  return it->second;
}


RlweCt PirServer::make_query(const size_t client_id, RlweCt &query) {
  // receive the query from the client

  // ========================== Expansion & conversion ==========================
  TIME_START(EXPAND_TIME);
  std::vector<RlweCt> query_vector = fast_expand_qry(client_id, query);
  TIME_END(EXPAND_TIME);

  // Reconstruct RGSW queries
  TIME_START(CONVERT_TIME);
  const size_t l_ep = pir_params_.get_l();
  std::vector<GSWCt> gsw_vec(pir_params_.get_num_dims() - 1); // GSW ciphertexts
  if (pir_params_.get_num_dims() != 1) {  // if we do need futher dimensions
    for (size_t i = 1; i < pir_params_.get_num_dims(); i++) {
      // l_ep RLWE ciphertexts per dim (one per gadget power).
      std::vector<RlweCt> lwe_vector;
      lwe_vector.reserve(l_ep);
      for (size_t k = 0; k < l_ep; ++k) {
        auto ptr = pir_params_.get_fst_dim_sz() + (i - 1) * l_ep + k;
        lwe_vector.push_back(query_vector[ptr]);
      }
      // Converting the BFV ciphertexts to GSW ciphertext by doing external product
      // (client_gsw_keys_ when no shared store; SharedKeyStore::get_gsw_key when attached).
      const GSWCt &gsw_for_client = shared_key_store_
          ? shared_key_store_->get_gsw_key(client_id)
          : client_gsw_keys_[client_id];
      key_gsw_.query_to_gsw(lwe_vector, const_cast<GSWCt &>(gsw_for_client), gsw_vec[i - 1]);
    }
  }
  TIME_END(CONVERT_TIME);

  // ========================== Evaluations ==========================
  // Evaluate the first dimension
  TIME_START(FST_DIM_TIME);
  query_vector.resize(pir_params_.get_fst_dim_sz());
  std::vector<RlweCt> mid_db = evaluate_first_dim(query_vector);
  TIME_END(FST_DIM_TIME);

  // Evaluate the other dimensions
  TIME_START(OTHER_DIM_TIME);
  RlweCt result = evaluate_other_dim(mid_db, gsw_vec);
  TIME_END(OTHER_DIM_TIME);

  // ========================== Post-processing ==========================
  TIME_START(MOD_SWITCH);
  // we can always switch to the small modulus it correctness is guaranteed.
  if (DBConsts::SmallQWidth < DBConsts::RnsMods[0]) {
    DEBUG_PRINT("Modulus switching for a single modulus...");
    const uint64_t small_q = pir_params_.get_small_q();
    mod_switch_inplace(result, small_q);
  }

  TIME_END(MOD_SWITCH);
  DEBUG_PRINT("Modulus switching done.");

  return result;
}


size_t PirServer::save_resp_to_stream(const RlweCt &response,
                                      std::stringstream &stream) {
  // For now, we only serve the single modulus case.

  // --- 1.  Runtime parameters ------------------------------------------------
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DBConsts::PolyDegree;

  // --- 2.  Bit-packing state -------------------------------------------------
  uint8_t byte_buf = 0;   // currently accumulated bits (LSB-first)
  size_t bits_filled = 0; // number of valid bits in byte_buf
  size_t total_bytes = 0; // bytes written so far

  auto flush_byte = [&]() {
    stream.put(static_cast<char>(byte_buf));
    ++total_bytes;
    byte_buf = 0;
    bits_filled = 0;
  };

  // --- 3.  Write every coefficient of the two polynomials -------------------
  for (size_t poly_id = 0; poly_id < 2; ++poly_id) {
    const uint64_t *data = response.data(poly_id);

    for (size_t i = 0; i < coeff_count; ++i) {
      uint64_t coeff = data[i] & ((1ULL << small_q_width) - 1); // keep LS bits only
      size_t bits_written = 0;

      while (bits_written < small_q_width) {
        const size_t room = 8 - bits_filled; // free bits in buffer
        const size_t bits_to_take = std::min(room, small_q_width - bits_written);

        const uint8_t chunk = static_cast<uint8_t>(
            (coeff >> bits_written) & ((1ULL << bits_to_take) - 1));

        byte_buf |= static_cast<uint8_t>(chunk << bits_filled);
        bits_filled += bits_to_take;
        bits_written += bits_to_take;

        if (bits_filled == 8)
          flush_byte();
      }
    }
  }

  // --- 4.  Flush padding byte (if any) --------------------------------------
  if (bits_filled != 0)
    flush_byte();

  return total_bytes;
}



void PirServer::fill_inter_res() {
  const size_t K = pir_params_.K();
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t elem_cnt = other_dim_sz * DBConsts::PolyDegree * K * 2;
  if (pir_params_.get_composite_rns().enabled) {
    inter_res_lo_.resize(elem_cnt);
    inter_res_hi_.resize(elem_cnt);
  } else {
    inter_res_.resize(elem_cnt);
  }
}

void PirServer::mod_switch_inplace(RlweCt &ciphertext, const uint64_t q) {
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  constexpr size_t K = DBConsts::RnsMods.size();
  const auto &qs = pir_params_.get_rns_mods();

  if constexpr (K == 1) {
    const uint64_t Q = qs[0];
    uint64_t *data0 = ciphertext.c0.data();
    uint64_t *data1 = ciphertext.c1.data();
    for (size_t i = 0; i < coeff_count; i++) {
      data0[i] = utils::rescale(data0[i], Q, q);
      data1[i] = utils::rescale(data1[i], Q, q);
    }
  } else {
    // K=2: CRT-compose each coefficient, drop q1 with rounding, then reuse the
    // single-limb centered rescale q0 -> q. This avoids a 120-bit by 50-bit
    // product in the 60+60-bit config.
    const uint64_t q0 = qs[0];
    const uint64_t q1 = qs[1];
    const uint64_t q0_inv_mod_q1 = pir_params_.get_rns_tables().q0_inv_mod_q1;

    auto drop_q1 = [&](uint64_t r0, uint64_t r1) -> uint64_t {
      const uint64_t r0_mod_q1 = r0 % q1;
      const uint64_t diff = (r1 + q1 - r0_mod_q1) % q1;
      const uint64_t s = static_cast<uint64_t>(
          (static_cast<uint128_t>(diff) * q0_inv_mod_q1) % q1);
      const uint128_t x = static_cast<uint128_t>(q0) * s + r0;
      uint64_t out = static_cast<uint64_t>((x + (static_cast<uint128_t>(q1) >> 1)) / q1);
      return (out >= q0) ? (out - q0) : out;
    };

    uint64_t *c0_lo = ciphertext.c0.data();
    uint64_t *c0_hi = ciphertext.c0.data() + coeff_count;
    uint64_t *c1_lo = ciphertext.c1.data();
    uint64_t *c1_hi = ciphertext.c1.data() + coeff_count;
    for (size_t i = 0; i < coeff_count; ++i) {
      c0_lo[i] = utils::rescale(drop_q1(c0_lo[i], c0_hi[i]), q0, q);
      c1_lo[i] = utils::rescale(drop_q1(c1_lo[i], c1_hi[i]), q0, q);
    }
    // Output is single-limb under modulus q.
    ciphertext.c0.resize(coeff_count);
    ciphertext.c1.resize(coeff_count);
  }
}










