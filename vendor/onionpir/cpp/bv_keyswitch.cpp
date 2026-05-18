#include "bv_keyswitch.h"
#include "database_constants.h"
#include "logging.h"
#include "utils.h"
#include "hexl/hexl.hpp"
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace bvks {

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------


// Signed (zero-centered) gadget decomposition.
// Digits are in [-B/2, B/2), stored mod q. Reconstruction: Σ out[i]·B^i ≡ val (mod q).
// out[0] = least significant digit (B^0), out[num_digits-1] = most significant.
void signed_gadget_decompose(uint64_t val, size_t base_log2,
                             uint64_t q, uint64_t *out, size_t num_digits) {
  const uint64_t half_q = q >> 1;
  const int64_t nativeSubgBits = 64 - static_cast<int64_t>(base_log2);

  // Center: [0, q) → (-q/2, q/2]
  int64_t d = (val > half_q)
      ? static_cast<int64_t>(val) - static_cast<int64_t>(q)
      : static_cast<int64_t>(val);

  // The goal here: d = r_0 B^0 + r_1 B^1 + r_2 B^2 + ... with r_i in [-B/2, B/2).

  for (size_t i = 0; i < num_digits; ++i) {
    // Extract signed digit: sign-extend the lowest base_log2 bits
    int64_t r = (d << nativeSubgBits) >> nativeSubgBits;
    d -= r;
    d >>= base_log2;
    out[i] = (r >= 0) ? static_cast<uint64_t>(r)
                      : static_cast<uint64_t>(r + static_cast<int64_t>(q));
  }
}

void signed_gadget_decompose_mp(uint128_t val, uint128_t Q, size_t base_log2,
                                int64_t *out, size_t num_digits) {
  using i128 = __int128_t;
  const uint128_t half_Q = Q >> 1;
  const uint64_t  B      = uint64_t(1) << base_log2;
  const uint64_t  half_B = B >> 1;
  const uint64_t  B_mask = B - 1;

  i128 d = (val > half_Q) ? static_cast<i128>(val) - static_cast<i128>(Q)
                          : static_cast<i128>(val);
  for (size_t i = 0; i < num_digits; ++i) {
    const uint64_t low = static_cast<uint64_t>(d) & B_mask;
    int64_t r;
    if (low > half_B) {
      r = static_cast<int64_t>(low) - static_cast<int64_t>(B);
      d = (d >> base_log2) + 1;
    } else {
      r = static_cast<int64_t>(low);
      d >>= base_log2;
    }
    out[i] = r;
  }
}

// Gadget base log: floor(log_q_data / L_KS) + 1.
// The +1 guarantees B^L_KS > q, giving the signed-digit decomposition
// enough headroom to absorb carries without leaving a non-zero residue in
// the discarded (L_KS-th) digit. Without it, configurations where
// base_log2 * L_KS == q_bits (e.g. L_KS=10 or 12 at q ~ 2^60) leak an
// uncompensated sigma_k(s) * (B^L_KS mod q) term into the keyswitch noise.
// Matches Spiral's convention (spiral/include/util.h:get_bits_per).
static inline size_t bv_base_log2(const PirParams &pir_params) {
  const size_t q_bits = pir_params.get_ct_mod_width();
  return q_bits / L_KS + 1;
}

// Compute (1 << (i * base_log2)) mod q, safely.
static inline uint64_t power_of_two_mod(size_t exp_bits, uint64_t q) {
  // Use repeated doubling mod q so we never overflow.
  uint64_t result = 1 % q;
  for (size_t b = 0; b < exp_bits; ++b) {
    result = (static_cast<uint128_t>(result) << 1) % q;
  }
  return result;
}

// ----------------------------------------------------------------------------
// BvGaloisKeys: lookup, size, simple serialization
// ----------------------------------------------------------------------------

const BvKeySwitchKey &BvGaloisKeys::get(uint32_t galois_k) const {
  for (auto &k : keys) {
    if (k.galois_k == galois_k)
      return k;
  }
  throw std::out_of_range("BvGaloisKeys::get: galois_k not found");
}

// bool BvGaloisKeys::has(uint32_t galois_k) const {
//   for (auto &k : keys) {
//     if (k.galois_k == galois_k)
//       return true;
//   }
//   return false;
// }

// size_t BvGaloisKeys::save(std::ostream &stream, bool /*use_seed*/) const {
//   // Simple uint64 dump — not bit-packed. Use compute_size_bytes for the
//   // theoretical bit-packed size that we care about in measurements.
//   size_t written = 0;
//   auto wr = [&](const void *p, size_t n) {
//     stream.write(reinterpret_cast<const char *>(p), n);
//     written += n;
//   };
//   uint32_t num = static_cast<uint32_t>(keys.size());
//   wr(&num, sizeof(num));
//   for (auto &k : keys) {
//     wr(&k.galois_k, sizeof(k.galois_k));
//     uint32_t t = static_cast<uint32_t>(k.cts.size());
//     wr(&t, sizeof(t));
//     for (auto &ct : k.cts) {
//       uint32_t n = static_cast<uint32_t>(ct.a.size());
//       wr(&n, sizeof(n));
//       wr(ct.a.data(), n * sizeof(uint64_t));
//       wr(ct.b.data(), n * sizeof(uint64_t));
//     }
//   }
//   return written;
// }

// void BvGaloisKeys::load(std::istream &stream) {
//   auto rd = [&](void *p, size_t n) {
//     stream.read(reinterpret_cast<char *>(p), n);
//   };
//   uint32_t num;
//   rd(&num, sizeof(num));
//   keys.clear();
//   keys.resize(num);
//   for (auto &k : keys) {
//     rd(&k.galois_k, sizeof(k.galois_k));
//     uint32_t t;
//     rd(&t, sizeof(t));
//     k.cts.resize(t);
//     for (auto &ct : k.cts) {
//       uint32_t n;
//       rd(&n, sizeof(n));
//       ct.a.resize(n);
//       ct.b.resize(n);
//       rd(ct.a.data(), n * sizeof(uint64_t));
//       rd(ct.b.data(), n * sizeof(uint64_t));
//     }
//   }
// }

// ----------------------------------------------------------------------------
// Key generation (client side)
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// K-aware helpers shared between K=1 and K=2 paths.
// ----------------------------------------------------------------------------

// Sample shared signed Gaussian e (one int64 per coefficient), reduced into
// [0, q_k) for each limb. out has size N * K.
static void sample_gaussian_shared_rns(uint64_t *out, size_t N,
                                       const std::vector<uint64_t> &qs,
                                       double sigma, std::mt19937_64 &rng) {
  std::normal_distribution<double> dist(0.0, sigma);
  std::vector<int64_t> e(N);
  for (size_t i = 0; i < N; ++i) e[i] = std::llround(dist(rng));
  for (size_t k = 0; k < qs.size(); ++k) {
    const uint64_t qk = qs[k];
    uint64_t *out_k = out + k * N;
    for (size_t i = 0; i < N; ++i) {
      const int64_t v = e[i];
      if (v >= 0) {
        out_k[i] = static_cast<uint64_t>(v) % qk;
      } else {
        const uint64_t abs_v = static_cast<uint64_t>(-v) % qk;
        out_k[i] = (abs_v == 0) ? 0 : qk - abs_v;
      }
    }
  }
}

// Build one RLWE row of a KSK. Encrypts msg under all K limbs:
//   for each output limb j: b_j = msg_j - a_j · sk_j + e_j
// where msg_j is supplied per-limb in NTT form (size N · K), and e is shared
// across limbs (signed Gaussian, then reduced per-limb).
static void build_ksk_row_rns(const std::vector<uint64_t> &msg_ntt,
                              const RlweSk &sk,
                              const std::vector<uint64_t> &qs,
                              double sigma, std::mt19937_64 &rng,
                              BvRlweCt &ct) {
  constexpr size_t N = DBConsts::PolyDegree;
  const size_t K = qs.size();
  ct.a.assign(N * K, 0);
  ct.b.assign(N * K, 0);

  for (size_t k = 0; k < K; ++k) {
    utils::sample_uniform_poly(ct.a.data() + k * N, N, qs[k], rng);
  }
  std::vector<uint64_t> e(N * K);
  sample_gaussian_shared_rns(e.data(), N, qs, sigma, rng);

  std::vector<uint64_t> as(N);
  for (size_t k = 0; k < K; ++k) {
    const uint64_t qk = qs[k];
    uint64_t *a_k = ct.a.data() + k * N;
    uint64_t *b_k = ct.b.data() + k * N;
    uint64_t *e_k = e.data() + k * N;
    utils::ntt_fwd(a_k, N, qk);
    utils::ntt_fwd(e_k, N, qk);
    intel::hexl::EltwiseMultMod(as.data(), a_k, sk.data.data() + k * N,
                                N, qk, 1);
    intel::hexl::EltwiseSubMod(b_k, msg_ntt.data() + k * N, as.data(), N, qk);
    intel::hexl::EltwiseAddMod(b_k, b_k, e_k, N, qk);
  }
}

BvKeySwitchKey gen_bv_ks_key(const PirParams &pir_params,
                             const RlweSk &sk, uint32_t galois_k,
                             std::mt19937_64 &rng) {
  const double sigma = pir_params.get_noise_std_dev();
  constexpr size_t N = DBConsts::PolyDegree;
  constexpr size_t K = DBConsts::RnsMods.size();
  static_assert(K <= 2, "MP keyswitch supports K <= 2 only");

  const auto &qs = pir_params.get_rns_mods();

  // σ_k(s) per limb, in NTT form.
  std::vector<uint64_t> sigma_s(N * K);
  for (size_t k = 0; k < K; ++k) {
    utils::automorphism_ntt(sk.data.data() + k * N, N, galois_k, qs[k],
                            sigma_s.data() + k * N);
  }

  BvKeySwitchKey ksk;
  ksk.galois_k = galois_k;

  // MP gadget: L_KS rows, each row encrypts σ(s) · B^i under all K limbs.
  const size_t base_log2 = bv_base_log2(pir_params);
  ksk.cts.resize(L_KS);
  std::vector<uint64_t> msg(N * K);
  for (size_t i = 0; i < L_KS; ++i) {
    for (size_t k = 0; k < K; ++k) {
      const uint64_t qk = qs[k];
      const uint64_t Bi = power_of_two_mod(i * base_log2, qk);
      intel::hexl::EltwiseFMAMod(msg.data() + k * N, sigma_s.data() + k * N,
                                 Bi, nullptr, N, qk, 1);
    }
    build_ksk_row_rns(msg, sk, qs, sigma, rng, ksk.cts[i]);
  }

  return ksk;
}

BvGaloisKeys gen_bv_galois_keys(const PirParams &pir_params,
                                const RlweSk &sk) {
  BvGaloisKeys result;
  const size_t expan_height = pir_params.get_expan_height();
  constexpr size_t N = DBConsts::PolyDegree;

  std::mt19937_64 rng(std::random_device{}());

  result.keys.reserve(expan_height);
  // creates 2049, 1025, 513, ... keys.
  for (size_t i = 0; i < expan_height; ++i) {
    const uint32_t galois_k = static_cast<uint32_t>((N >> i) + 1);
    result.keys.push_back(gen_bv_ks_key(pir_params, sk, galois_k, rng));
  }
  return result;
}

// ----------------------------------------------------------------------------
// Server-side apply
// ----------------------------------------------------------------------------

// Scratch reused across calls to bv_apply_galois_inplace.
//
// Thread-local because parallel PirServer::answer_query (downstream
// rayon::par_iter_mut over per-group servers) hits bv_apply_galois_inplace
// concurrently on different ciphertexts but the same params shape. With a
// process-global scratch, the writes via the cached pointers race; the
// matmul produces silent ciphertext corruption rather than panicking.
// Per-thread scratch is the smallest correct fix — see
// REQUEST_THREAD_SAFETY_FROM_BITCOIN_PIR.md §2.
//
// Memory cost: ~(5 + L_KS) * N * 8 B per thread (≈144 KB at N=2048, L_KS=4).
namespace {
struct GaloisScratch {
  std::vector<uint64_t> c0_perm, c1_perm, delta_a, delta_b, tmp;
  std::vector<uint64_t> digits;  // L_KS contiguous N-blocks (row-major)
};
thread_local GaloisScratch g_scratch;
}  // namespace

// K=1: signed gadget decomposition (existing path, tighter noise).
static void bv_apply_galois_inplace_k1(RlweCt &ct, uint32_t galois_k,
                                       const BvKeySwitchKey &key,
                                       const PirParams &pir_params) {
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q_val = pir_params.get_rns_mods()[0];
  const size_t base_log2 = bv_base_log2(pir_params);

  GaloisScratch &s = g_scratch;
  if (s.c0_perm.size() != N) {
    s.c0_perm.resize(N);
    s.c1_perm.resize(N);
    s.delta_a.resize(N);
    s.delta_b.resize(N);
    s.tmp.resize(N);
    s.digits.resize(L_KS * N);
  }
  uint64_t *const c0_perm = s.c0_perm.data();
  uint64_t *const c1_perm = s.c1_perm.data();
  uint64_t *const delta_b = s.delta_b.data();
  uint64_t *const delta_a = s.delta_a.data();
  uint64_t *const tmp = s.tmp.data();
  uint64_t *const digits = s.digits.data();

  TIME_START(APPLY_GAL_SIGMA);
  utils::automorphism_coeff(ct.data(0), N, galois_k, q_val, c0_perm);
  utils::automorphism_coeff(ct.data(1), N, galois_k, q_val, c1_perm);
  TIME_END(APPLY_GAL_SIGMA);

  TIME_START(APPLY_GAL_DECOMP);
  for (size_t k = 0; k < N; ++k) {
    uint64_t digit_vals[L_KS];
    signed_gadget_decompose(c1_perm[k], base_log2, q_val, digit_vals, L_KS);
    for (size_t i = 0; i < L_KS; ++i) {
      digits[i * N + k] = digit_vals[i];
    }
  }
  TIME_END(APPLY_GAL_DECOMP);

  {
    uint64_t *digit0 = digits;
    TIME_START(APPLY_GAL_NTT_FWD);
    utils::ntt_fwd(digit0, N, q_val);
    TIME_END(APPLY_GAL_NTT_FWD);
    TIME_START(APPLY_GAL_POINTWISE);
    intel::hexl::EltwiseMultMod(delta_b, digit0, key.cts[0].b.data(), N, q_val, 1);
    intel::hexl::EltwiseMultMod(delta_a, digit0, key.cts[0].a.data(), N, q_val, 1);
    TIME_END(APPLY_GAL_POINTWISE);
  }
  for (size_t i = 1; i < L_KS; ++i) {
    uint64_t *digit_i = digits + i * N;
    TIME_START(APPLY_GAL_NTT_FWD);
    utils::ntt_fwd(digit_i, N, q_val);
    TIME_END(APPLY_GAL_NTT_FWD);
    const auto &ksk_ct = key.cts[i];
    TIME_START(APPLY_GAL_POINTWISE);
    intel::hexl::EltwiseMultMod(tmp, digit_i, ksk_ct.b.data(), N, q_val, 1);
    intel::hexl::EltwiseAddMod(delta_b, delta_b, tmp, N, q_val);
    intel::hexl::EltwiseMultMod(tmp, digit_i, ksk_ct.a.data(), N, q_val, 1);
    intel::hexl::EltwiseAddMod(delta_a, delta_a, tmp, N, q_val);
    TIME_END(APPLY_GAL_POINTWISE);
  }

  TIME_START(APPLY_GAL_NTT_INV);
  utils::ntt_inv(delta_b, N, q_val);
  utils::ntt_inv(delta_a, N, q_val);
  TIME_END(APPLY_GAL_NTT_INV);

  intel::hexl::EltwiseAddMod(c0_perm, c0_perm, delta_b, N, q_val);

  std::memcpy(ct.data(0), c0_perm, N * sizeof(uint64_t));
  std::memcpy(ct.data(1), delta_a, N * sizeof(uint64_t));
}

// K=2: unsigned MP-gadget decomposition. Composes σ(c1) per coefficient to a
// 128-bit MP integer, extracts L_KS digits in [0, B), then for each limb NTTs
// each digit independently and accumulates the inner product against the KSK.
static void bv_apply_galois_inplace_k2(RlweCt &ct, uint32_t galois_k,
                                       const BvKeySwitchKey &key,
                                       const PirParams &pir_params) {
  constexpr size_t N = DBConsts::PolyDegree;
  const auto &qs = pir_params.get_rns_mods();
  const RnsTables &tables = pir_params.get_rns_tables();
  const uint64_t q0 = qs[0], q1 = qs[1];
  const uint64_t q0_inv_mod_q1 = tables.q0_inv_mod_q1;
  const size_t base_log2 = bv_base_log2(pir_params);
  const uint64_t B_mask = (uint64_t(1) << base_log2) - 1;

  // Step 1: per-limb σ on (c0, c1).
  TIME_START(APPLY_GAL_SIGMA);
  std::vector<uint64_t> c0_perm(2 * N), c1_perm(2 * N);
  for (size_t k = 0; k < 2; ++k) {
    utils::automorphism_coeff(ct.data(0) + k * N, N, galois_k, qs[k],
                              c0_perm.data() + k * N);
    utils::automorphism_coeff(ct.data(1) + k * N, N, galois_k, qs[k],
                              c1_perm.data() + k * N);
  }
  TIME_END(APPLY_GAL_SIGMA);

  // Step 2 + 3: per-coef CRT compose σ(c1) → 128-bit MP integer, then signed
  // base-B decomposition with carry. Both bundled under DECOMP since they're
  // the variant-specific gadget extraction work.
  TIME_START(APPLY_GAL_DECOMP);
  std::vector<uint128_t> c1_mp(N);
  for (size_t j = 0; j < N; ++j) {
    const uint64_t r0 = c1_perm[0 * N + j];
    const uint64_t r1 = c1_perm[1 * N + j];
    const uint64_t r0_mod_q1 = r0 % q1;
    const uint64_t diff = (r1 + q1 - r0_mod_q1) % q1;
    const uint64_t s = static_cast<uint64_t>(
        (static_cast<uint128_t>(diff) * q0_inv_mod_q1) % q1);
    c1_mp[j] = static_cast<uint128_t>(q0) * s + r0;
  }

  const uint128_t Q_total = static_cast<uint128_t>(q0) * q1;
  std::vector<int64_t> sdigits(L_KS * N);
  int64_t buf[16];  // L_KS ≤ 16 in all current configs
  for (size_t j = 0; j < N; ++j) {
    signed_gadget_decompose_mp(c1_mp[j], Q_total, base_log2, buf, L_KS);
    for (size_t i = 0; i < L_KS; ++i) sdigits[i * N + j] = buf[i];
  }
  TIME_END(APPLY_GAL_DECOMP);

  // Step 4: for each limb, NTT each digit (rendered into uint64 mod qk) and
  // accumulate inner products against the KSK.
  std::vector<uint64_t> delta_a(2 * N, 0), delta_b(2 * N, 0);
  std::vector<uint64_t> digit_buf(N), prod(N);

  auto render_digits_for_limb = [&](size_t i, uint64_t qk) {
    const int64_t *src = sdigits.data() + i * N;
    for (size_t j = 0; j < N; ++j) {
      const int64_t s = src[j];
      digit_buf[j] = (s >= 0) ? static_cast<uint64_t>(s)
                              : qk - static_cast<uint64_t>(-s);
    }
  };

  for (size_t k = 0; k < 2; ++k) {
    const uint64_t qk = qs[k];
    uint64_t *db_k = delta_b.data() + k * N;
    uint64_t *da_k = delta_a.data() + k * N;

    // First iteration: write instead of accumulate.
    TIME_START(APPLY_GAL_DECOMP);
    render_digits_for_limb(0, qk);
    TIME_END(APPLY_GAL_DECOMP);
    TIME_START(APPLY_GAL_NTT_FWD);
    utils::ntt_fwd(digit_buf.data(), N, qk);
    TIME_END(APPLY_GAL_NTT_FWD);
    TIME_START(APPLY_GAL_POINTWISE);
    intel::hexl::EltwiseMultMod(db_k, digit_buf.data(),
                                key.cts[0].b.data() + k * N, N, qk, 1);
    intel::hexl::EltwiseMultMod(da_k, digit_buf.data(),
                                key.cts[0].a.data() + k * N, N, qk, 1);
    TIME_END(APPLY_GAL_POINTWISE);

    for (size_t i = 1; i < L_KS; ++i) {
      TIME_START(APPLY_GAL_DECOMP);
      render_digits_for_limb(i, qk);
      TIME_END(APPLY_GAL_DECOMP);
      TIME_START(APPLY_GAL_NTT_FWD);
      utils::ntt_fwd(digit_buf.data(), N, qk);
      TIME_END(APPLY_GAL_NTT_FWD);
      TIME_START(APPLY_GAL_POINTWISE);
      intel::hexl::EltwiseMultMod(prod.data(), digit_buf.data(),
                                  key.cts[i].b.data() + k * N, N, qk, 1);
      intel::hexl::EltwiseAddMod(db_k, db_k, prod.data(), N, qk);
      intel::hexl::EltwiseMultMod(prod.data(), digit_buf.data(),
                                  key.cts[i].a.data() + k * N, N, qk, 1);
      intel::hexl::EltwiseAddMod(da_k, da_k, prod.data(), N, qk);
      TIME_END(APPLY_GAL_POINTWISE);
    }

    TIME_START(APPLY_GAL_NTT_INV);
    utils::ntt_inv(db_k, N, qk);
    utils::ntt_inv(da_k, N, qk);
    TIME_END(APPLY_GAL_NTT_INV);

    // c0_perm_k += delta_b_k
    intel::hexl::EltwiseAddMod(c0_perm.data() + k * N, c0_perm.data() + k * N,
                               db_k, N, qk);
  }

  std::memcpy(ct.data(0), c0_perm.data(), 2 * N * sizeof(uint64_t));
  std::memcpy(ct.data(1), delta_a.data(), 2 * N * sizeof(uint64_t));
}


void bv_apply_galois_inplace(RlweCt &ct, uint32_t galois_k,
                             const BvKeySwitchKey &key,
                             const PirParams &pir_params) {
  assert(key.galois_k == galois_k);
  assert(!ct.ntt_form);

  constexpr size_t K = DBConsts::RnsMods.size();

  if constexpr (K == 1) {
    bv_apply_galois_inplace_k1(ct, galois_k, key, pir_params);
  } else {
    bv_apply_galois_inplace_k2(ct, galois_k, key, pir_params);
  }
}

} // namespace bvks
