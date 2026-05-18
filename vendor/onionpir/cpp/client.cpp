#include "client.h"
#include "pir.h"
#include "utils.h"
#include "gsw.h"
#include "rlwe.h"
#include "hexl/hexl.hpp"
#include <cassert>
#include <random>
#include <sstream>


// Build the K-limb sk lazily because its construction depends on PirParams.
static RlweSk make_client_sk(const PirParams &pir_params, std::mt19937_64 &rng) {
  const auto &qs_arr = pir_params.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  return gen_secret_key_rns(DBConsts::PolyDegree, qs, rng);
}

PirClient::PirClient(const PirParams &pir_params)
    : client_id_(rand()), pir_params_(pir_params),
      rng_(std::random_device{}()),
      rlwe_sk_(make_client_sk(pir_params, rng_)) {}

PirClient::PirClient(const PirParams &pir_params, size_t client_id, RlweSk sk)
    : client_id_(client_id), pir_params_(pir_params),
      rng_(std::random_device{}()),
      rlwe_sk_(std::move(sk)) {}

GSWCt PirClient::generate_gsw_from_key() {
  constexpr size_t N = DBConsts::PolyDegree;

  // Recover ternary sk in coefficient form under q_0, then re-canonicalise
  // {-1 ↔ q_0-1} → {-1 ↔ q_k-1} for each limb. We pass the q_0 form to
  // plain_to_gsw, which re-encodes -1 per limb as the matching q_k-1.
  const uint64_t q0 = pir_params_.get_rns_mods()[0];
  std::vector<uint64_t> sk_coef(rlwe_sk_.data.begin(),
                                rlwe_sk_.data.begin() + N);
  utils::ntt_inv(sk_coef.data(), N, q0);

  GSWEval key_gsw(pir_params_, pir_params_.get_l_key(), pir_params_.get_base_log2_key());
  return key_gsw.plain_to_gsw(sk_coef, rlwe_sk_, rng_);
}


std::vector<size_t> PirClient::get_query_indices(size_t pt_idx) {
  const size_t col_idx = pt_idx % pir_params_.get_fst_dim_sz();  // the first dimension
  const size_t row_idx = pt_idx / pir_params_.get_fst_dim_sz();  // the rest of the dimensions
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t d = pir_params_.get_num_dims();
  const size_t h = d - 1; // the height of the further dimension complete binary tree.
  
  std::vector<size_t> query_indices = {col_idx};

  // Handle single dimension case
  if (d == 1) {
    // For single dimension, we only need the column index
    DEBUG_PRINT("Single dimension case - returning col_idx: " << col_idx);
    return query_indices;
  }
  
  const size_t r = 2 * other_dim_sz - (1 << h);   // the number of elements in the last level of the complete binary tree.
  const size_t sl = other_dim_sz - r;

  // the last r elements lives in the last level of the complete binary tree.
  // It is an even number but it is not a power of 2.
  // The rest sl elements lives in the second to last level of the complete binary tree.
  // Observe that other_dim_sz - r/2 = 2^(h-1), which is the number of nodes in the second to last level of the complete binary tree.
  // we use the first selection bit to compute the mux for the first r elements.
  // The rest is a normal perfect binary tree. 
  // the first selection bit is special:
  size_t perfect_idx;
  if (row_idx < other_dim_sz - r) {
    query_indices.push_back(0);
    perfect_idx = row_idx;
  } else {
    size_t corrected_idx = row_idx - sl;
    query_indices.push_back(corrected_idx % 2);
    perfect_idx = sl + corrected_idx / 2;
  }
  
  // For the remaining perfect tree levels, emit bits MSB-first
  if (h > 1) {
    // There are (h - 1) bits for the perfect subtree
    for (size_t k = h - 2; k + 1 > 0; k--) {
      query_indices.push_back((perfect_idx >> k) & 1ULL);
      if (k == 0) break;
    }
  }
  
  return query_indices;
}




RlweCt PirClient::fast_generate_query(const size_t pt_idx) {
  constexpr size_t N = DBConsts::PolyDegree;
  constexpr size_t K = DBConsts::RnsMods.size();
  const auto &qs_arr = pir_params_.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  const uint64_t t = pir_params_.get_plain_mod();
  const double sigma = pir_params_.get_noise_std_dev();

  std::vector<size_t> query_indices = get_query_indices(pt_idx);
  PRINT_INT_ARRAY("\t\tquery_indices", query_indices.data(), query_indices.size());
  const size_t expan_height = pir_params_.get_expan_height();
  const size_t capacity = size_t{1} << expan_height;  // 2^h slots after expansion

  uint64_t inverse = 0;
  utils::try_invert_uint_mod(capacity, t, inverse);
  const size_t reversed_index = utils::bit_reverse(query_indices[0], expan_height);
  DEBUG_PRINT("reversed_index: " << reversed_index << ", query_indices[0]: " << query_indices[0]);

  // BFV encrypt under sk: c0 = -(a*s+e) + round(Q*m/t), c1 = a (coeff form).
  // Per-limb gadget injection: scaled mod q_k for each k.
  RlweCt query;
  encrypt_zero_rns(rlwe_sk_, N, qs, sigma, rng_, query, /*ntt_form=*/false);

  // Adding 1^{-1} as a message to the query so that after expansion, the query will have 1's in the correct positions.
  if constexpr (K == 1) {
    const uint64_t Q = qs[0];
    const uint64_t scaled = utils::round_div_u128((uint128_t)Q * inverse, t) % Q;
    query.c0[reversed_index] = (query.c0[reversed_index] + scaled) % Q;
  } else {
    const uint128_t Q = static_cast<uint128_t>(qs[0]) * qs[1];
    const uint128_t Delta = Q / t;
    const uint64_t r = static_cast<uint64_t>(Q - Delta * t);
    const uint64_t r_inverse_round =
        static_cast<uint64_t>((static_cast<uint128_t>(r) * inverse + (t >> 1)) / t);
    const uint128_t scaled_mp = Delta * inverse + r_inverse_round;
    for (size_t k = 0; k < K; ++k) {
      const uint64_t scaled_k = static_cast<uint64_t>(scaled_mp % qs[k]);
      const size_t idx = k * N + reversed_index;
      query.c0[idx] = (query.c0[idx] + scaled_k) % qs[k];
    }
  }

  add_gsw_to_query(query, query_indices);
  return query;
}


void PirClient::add_gsw_to_query(RlweCt &query, const std::vector<size_t> query_indices) {
  // no further dimensions
  if (query_indices.size() == 1) { return; }
  const size_t expan_height = pir_params_.get_expan_height();
  const size_t capacity = size_t{1} << expan_height;  // 2^h slots after expansion
  const size_t l = pir_params_.get_l();
  const auto rns_mods = pir_params_.get_rns_mods();
  const size_t K = pir_params_.K();
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();

  // 1/capacity per limb, cancels the scaling factor introduced by expansion.
  std::vector<uint64_t> inv(K);
  for (size_t k = 0; k < K; k++) {
    uint64_t result;
    utils::try_invert_uint_mod(capacity, rns_mods[k], result);
    inv[k] = result;
  }

  // MP gadget table: gadget[k][p] = B^(l-1-p) mod q_k. MSB-first
  // (p=0 = largest power), matching plain_to_gsw.
  std::vector<std::vector<uint64_t>> gadget =
      utils::gsw_gadget(l, pir_params_.get_base_log2(), rns_mods);

  // Algorithm 1 from the OnionPIR paper: when bit i is "1", write gadget powers
  // (scaled by 1/capacity) into the slots that the expansion will turn into
  // BFV ciphertexts encoding B^p · m for each gadget power p.
  auto q_head = query.data(0);
  for (size_t i = 1; i < query_indices.size(); i++) {
    if (query_indices[i] != 1) continue;

    // l slots per dim, gadget value written under every limb.
    for (size_t k = 0; k < l; k++) {
      const size_t coef_pos = fst_dim_sz + (i - 1) * l + k;
      const size_t reversed_idx = utils::bit_reverse(coef_pos, expan_height);
      for (size_t mod_id = 0; mod_id < K; mod_id++) {
        const size_t pad = mod_id * DBConsts::PolyDegree;
        inter_coeff_t mod = rns_mods[mod_id];
        uint64_t coef = (inter_coeff_t)gadget[mod_id][k] * inv[mod_id] % mod;
        q_head[reversed_idx + pad] = (q_head[reversed_idx + pad] + coef) % mod;
      }
    }
  }
}


// Shared single-mod decryption under modulus `q` using the matching sk.
// Computes phase = c0 + c1*s (mod q), recovers m = round(phase * t / q),
// and returns (plaintext, noise_budget).
static void decrypt_phase_single_mod(const RlweCt &ct,
                                     const uint64_t *sk_ntt,
                                     uint64_t q, uint64_t t,
                                     RlwePt &out_pt,
                                     int &out_budget) {
  constexpr size_t N = DBConsts::PolyDegree;

  std::vector<uint64_t> phase(N);
  std::vector<uint64_t> c0(N), c1(N);
  for (size_t i = 0; i < N; i++) {
    c0[i] = ct.c0[i] % q;
    c1[i] = ct.c1[i] % q;
  }

  // Compute a * s (mod q) in NTT.
  if (ct.ntt_form) {
    intel::hexl::EltwiseMultMod(phase.data(), c1.data(), sk_ntt, N, q, 1);
    utils::ntt_inv(phase.data(), N, q);
    utils::ntt_inv(c0.data(), N, q);
  } else {
    utils::ntt_fwd(c1.data(), N, q);
    intel::hexl::EltwiseMultMod(phase.data(), c1.data(), sk_ntt, N, q, 1);
    utils::ntt_inv(phase.data(), N, q);
  }
  // Add c0 in coefficient form (mod q).
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0.data(), N, q);

  out_pt.data.assign(N, 0);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;

  for (size_t i = 0; i < N; i++) {
    uint64_t m = utils::round_div_u128((uint128_t)phase[i] * t, q) % t;
    out_pt.data[i] = m;

    // Compare against round(q*m/t), not floor(q/t)*m: when q is not a multiple
    // of t, the latter undercounts by m*(q mod t)/t and inflates the residue.
    uint64_t approx = utils::round_div_u128((uint128_t)q * m, t) % q;
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }

  out_budget = (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
}

RlwePt PirClient::decrypt_ct(const RlweCt &ct) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs_arr = pir_params_.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  const uint64_t t = pir_params_.get_plain_mod();
  RlwePt result;
  decrypt_rns(ct, rlwe_sk_, N, qs, t, pir_params_.get_rns_tables(), result);
  return result;
}

RlweCt PirClient::fresh_zero_ct() {
  // Testing only.
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs_arr = pir_params_.get_rns_mods();
  const std::vector<uint64_t> qs(qs_arr.begin(), qs_arr.end());
  const double sigma = pir_params_.get_noise_std_dev();
  RlweCt ct;
  encrypt_zero_rns(rlwe_sk_, N, qs, sigma, rng_, ct, /*ntt_form=*/false);
  return ct;
}

int PirClient::noise_budget(const RlweCt &ct) {
  // Single-mod budget under the first limb. Used as a pre-mod-switch indicator
  // (the K-aware decrypt_rns path does not expose noise; this matches the K=1
  // historical behaviour and is good enough as a debug signal).
  const uint64_t q = pir_params_.get_rns_mods()[0];
  const uint64_t t = pir_params_.get_plain_mod();
  RlwePt tmp;
  int budget = 0;
  decrypt_phase_single_mod(ct, rlwe_sk_.data.data(), q, t, tmp, budget);
  return budget;
}



RlweCt PirClient::load_resp_from_stream(std::stringstream &resp_stream) {
  // For now, we only serve the single modulus case.
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DBConsts::PolyDegree;

  RlweCt result;
  result.c0.assign(coeff_count, 0);
  result.c1.assign(coeff_count, 0);

  uint8_t current_byte = 0;
  size_t bits_left = 0;
  auto next_bit = [&]() -> uint8_t {
    if (bits_left == 0) {
      int ch = resp_stream.get();
      if (ch == EOF)
        throw std::runtime_error("unexpected end of response stream");
      current_byte = static_cast<uint8_t>(ch);
      bits_left = 8;
    }
    uint8_t bit = current_byte & 1;
    current_byte >>= 1;
    --bits_left;
    return bit;
  };
  auto read_coeff = [&](uint64_t &dest) {
    dest = 0;
    for (size_t j = 0; j < small_q_width; ++j)
      dest |= static_cast<uint64_t>(next_bit()) << j;
  };

  for (size_t i = 0; i < coeff_count; ++i) read_coeff(result.c0[i]);
  for (size_t i = 0; i < coeff_count; ++i) read_coeff(result.c1[i]);
  result.ntt_form = false;
  return result;
}


RlwePt PirClient::decrypt_mod_q(const RlweCt &ct) const {
  // Custom single-mod decryption. Computes phase = c0 + c1*s (mod small_q),
  // then recovers plaintext via round(phase * t / q) and measures noise.
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q = pir_params_.get_small_q();
  const uint64_t t = pir_params_.get_plain_mod();

  std::vector<uint64_t> phase(N);
  std::vector<uint64_t> c0(N), c1_ntt(N);
  // Reduce mod q in case mod_switch_inplace produced values = q (from rounding)
  for (size_t i = 0; i < N; i++) {
    c0[i] = ct.c0[i] % q;
    c1_ntt[i] = ct.c1[i] % q;
  }
  std::vector<uint64_t> sk_ntt_small_q = get_sk_ntt_small_q(pir_params_.get_rns_mods()[0], q);
  utils::ntt_fwd(c1_ntt.data(), N, q);
  intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk_ntt_small_q.data(), N, q, 1);
  utils::ntt_inv(phase.data(), N, q);
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0.data(), N, q);

  RlwePt result;
  result.data.assign(N, 0);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;

  for (size_t i = 0; i < N; i++) {
    uint64_t m = utils::round_div_u128((uint128_t)phase[i] * t, q) % t;
    result.data[i] = m;

    uint64_t approx = utils::round_div_u128((uint128_t)q * m, t) % q;
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }

  int budget = (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
  BENCH_PRINT("Noise budget after decryption: " << budget
              << " (max noise: " << max_noise << ")");

  return result;
}


std::vector<uint64_t> PirClient::get_sk_ntt_small_q(uint64_t old_q, uint64_t small_q) const {
  constexpr size_t N = DBConsts::PolyDegree;

  // rlwe_sk_ is K-limb in NTT form (limb k under q_k). The first limb under
  // q_0 = old_q is what we need; ternary coefficients reduce identically across
  // limbs so the first limb's coefficient form recovers {-1, 0, 1}.
  std::vector<uint64_t> sk_coef(rlwe_sk_.data.begin(),
                                rlwe_sk_.data.begin() + N);
  utils::ntt_inv(sk_coef.data(), N, old_q);

  // Rewrite -1 mod old_q as -1 mod small_q (sk is ternary: {0, 1, -1}).
  std::vector<uint64_t> sk_ntt_small_q_(N);
  for (size_t i = 0; i < N; i++) {
    sk_ntt_small_q_[i] = (sk_coef[i] > 1) ? (small_q - 1) : sk_coef[i];
  }
  utils::ntt_fwd(sk_ntt_small_q_.data(), N, small_q);
  return sk_ntt_small_q_;
}
