#include "rlwe.h"
#include "pir.h"      // RnsTables
#include "utils.h"
#include "hexl/hexl.hpp"
#include <cmath>
#include <cstring>
#include <stdexcept>

RlweSk gen_secret_key(size_t N, uint64_t q, std::mt19937_64 &rng) {
  RlweSk sk;
  sk.data.resize(N);
  utils::sample_ternary(sk.data.data(), N, q, rng);
  utils::ntt_fwd(sk.data.data(), N, q);
  return sk;
}

void encrypt_zero(const RlweSk &sk, size_t N, uint64_t q, double sigma,
                  std::mt19937_64 &rng, RlweCt &ct, bool ntt_form) {
  ct.resize(N);

  // Sample a ← U([0, q)) and e ← Gaussian(0, sigma²), both in coefficient form.
  utils::sample_uniform_poly(ct.c1.data(), N, q, rng);
  std::vector<uint64_t> e(N);
  utils::sample_gaussian(e.data(), N, q, sigma, rng);

  // Compute a*s in NTT form. sk is already NTT.
  std::vector<uint64_t> a_ntt(N);
  std::memcpy(a_ntt.data(), ct.c1.data(), N * sizeof(uint64_t));
  utils::ntt_fwd(a_ntt.data(), N, q);
  intel::hexl::EltwiseMultMod(ct.c0.data(), a_ntt.data(), sk.data.data(), N, q, 1);

  // Bring a*s back to coefficient form so we can add e (which is in coef).
  utils::ntt_inv(ct.c0.data(), N, q);

  // c0 = (a*s) + e, then negate: c0 = -(a*s + e).
  intel::hexl::EltwiseAddMod(ct.c0.data(), ct.c0.data(), e.data(), N, q);
  const std::vector<uint64_t> zeros(N, 0);
  intel::hexl::EltwiseSubMod(ct.c0.data(), zeros.data(), ct.c0.data(), N, q);

  if (ntt_form) {
    utils::ntt_fwd(ct.c0.data(), N, q);
    utils::ntt_fwd(ct.c1.data(), N, q);
  }
  ct.ntt_form = ntt_form;
}

void decrypt(const RlweCt &ct, const RlweSk &sk, size_t N, uint64_t q,
             uint64_t t, RlwePt &pt) {
  // We need c0 in coefficient form and c1 in NTT form (for pointwise mult with sk).
  std::vector<uint64_t> c0_coef(N), c1_ntt(N);
  std::memcpy(c0_coef.data(), ct.c0.data(), N * sizeof(uint64_t));
  std::memcpy(c1_ntt.data(),  ct.c1.data(), N * sizeof(uint64_t));

  if (ct.ntt_form) {
    utils::ntt_inv(c0_coef.data(), N, q);
  } else {
    utils::ntt_fwd(c1_ntt.data(), N, q);
  }

  // phase = c1 * s (NTT pointwise), then INTT back to coefficient form.
  std::vector<uint64_t> phase(N);
  intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk.data.data(), N, q, 1);
  utils::ntt_inv(phase.data(), N, q);

  // phase = c0 + c1*s  (coefficient form, values in [0, q)).
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0_coef.data(), N, q);

  // Scale-and-round q → t (centered, integer-exact). Same as round(phase*t/q) mod t.
  pt.data.resize(N);
  for (size_t i = 0; i < N; i++) {
    pt.data[i] = utils::rescale(phase[i], q, t);
  }
}

int decrypt_and_budget(const RlweCt &ct, const RlweSk &sk, size_t N,
                       uint64_t q, uint64_t t, RlwePt &pt) {
  std::vector<uint64_t> c0_coef(N), c1_ntt(N);
  std::memcpy(c0_coef.data(), ct.c0.data(), N * sizeof(uint64_t));
  std::memcpy(c1_ntt.data(),  ct.c1.data(), N * sizeof(uint64_t));
  if (ct.ntt_form) {
    utils::ntt_inv(c0_coef.data(), N, q);
  } else {
    utils::ntt_fwd(c1_ntt.data(), N, q);
  }
  std::vector<uint64_t> phase(N);
  intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk.data.data(), N, q, 1);
  utils::ntt_inv(phase.data(), N, q);
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0_coef.data(), N, q);

  pt.data.resize(N);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;
  for (size_t i = 0; i < N; i++) {
    uint64_t m = utils::rescale(phase[i], q, t);
    pt.data[i] = m;
    uint64_t approx = static_cast<uint64_t>((__uint128_t)delta * m % q);
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }
  return (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
}

void encrypt_bfv(const std::vector<uint64_t> &m, const RlweSk &sk,
                 size_t N, uint64_t q, uint64_t t, double sigma,
                 std::mt19937_64 &rng, RlweCt &ct) {
  encrypt_zero(sk, N, q, sigma, rng, ct, /*ntt_form=*/false);
  const uint64_t delta = q / t;
  for (size_t i = 0; i < N && i < m.size(); i++) {
    const uint64_t scaled = (__uint128_t)delta * (m[i] % t) % q;
    ct.c0[i] = (ct.c0[i] + scaled) % q;
  }
}

void rlwe_add_inplace(RlweCt &a, const RlweCt &b, uint64_t q) {
  const size_t n = a.poly_size();
  intel::hexl::EltwiseAddMod(a.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseAddMod(a.c1.data(), a.c1.data(), b.c1.data(), n, q);
}

void rlwe_sub_inplace(RlweCt &a, const RlweCt &b, uint64_t q) {
  const size_t n = a.poly_size();
  intel::hexl::EltwiseSubMod(a.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseSubMod(a.c1.data(), a.c1.data(), b.c1.data(), n, q);
}

void rlwe_add(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q) {
  const size_t n = a.poly_size();
  c.c0.resize(n);
  c.c1.resize(n);
  intel::hexl::EltwiseAddMod(c.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseAddMod(c.c1.data(), a.c1.data(), b.c1.data(), n, q);
  c.ntt_form = a.ntt_form;
}

void rlwe_sub(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q) {
  const size_t n = a.poly_size();
  c.c0.resize(n);
  c.c1.resize(n);
  intel::hexl::EltwiseSubMod(c.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseSubMod(c.c1.data(), a.c1.data(), b.c1.data(), n, q);
  c.ntt_form = a.ntt_form;
}

void rlwe_ntt_fwd_inplace(RlweCt &ct, uint64_t q, size_t N) {
  utils::ntt_fwd(ct.c0.data(), N, q);
  utils::ntt_fwd(ct.c1.data(), N, q);
  ct.ntt_form = true;
}

void rlwe_ntt_inv_inplace(RlweCt &ct, uint64_t q, size_t N) {
  utils::ntt_inv(ct.c0.data(), N, q);
  utils::ntt_inv(ct.c1.data(), N, q);
  ct.ntt_form = false;
}

// ---------------------------------------------------------------------------
// K-limb (RNS) RLWE primitives.
// ---------------------------------------------------------------------------

namespace {

// Sample one shared ternary pattern; reduce per limb (-1 → q_k - 1).
void sample_ternary_rns(uint64_t *out, size_t N,
                        const std::vector<uint64_t> &qs,
                        std::mt19937_64 &rng) {
  std::uniform_int_distribution<int> dist(0, 2);
  std::vector<int8_t> tern(N);
  for (size_t i = 0; i < N; i++) {
    const int v = dist(rng);
    tern[i] = static_cast<int8_t>(v == 2 ? -1 : v);
  }
  for (size_t k = 0; k < qs.size(); k++) {
    uint64_t *out_k = out + k * N;
    const uint64_t qk = qs[k];
    for (size_t i = 0; i < N; i++) {
      out_k[i] = (tern[i] == 0) ? 0 : (tern[i] > 0 ? 1 : qk - 1);
    }
  }
}

// Sample shared signed Gaussian e; reduce per limb into [0, q_k).
void sample_gaussian_rns(uint64_t *out, size_t N,
                         const std::vector<uint64_t> &qs,
                         double sigma, std::mt19937_64 &rng) {
  std::normal_distribution<double> dist(0.0, sigma);
  std::vector<int64_t> e(N);
  for (size_t i = 0; i < N; i++) e[i] = std::llround(dist(rng));
  for (size_t k = 0; k < qs.size(); k++) {
    const uint64_t qk = qs[k];
    uint64_t *out_k = out + k * N;
    for (size_t i = 0; i < N; i++) {
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

}  // namespace

RlweSk gen_secret_key_rns(size_t N, const std::vector<uint64_t> &qs,
                          std::mt19937_64 &rng) {
  RlweSk sk;
  sk.data.resize(N * qs.size());
  sample_ternary_rns(sk.data.data(), N, qs, rng);
  for (size_t k = 0; k < qs.size(); k++) {
    utils::ntt_fwd(sk.data.data() + k * N, N, qs[k]);
  }
  return sk;
}

void encrypt_zero_rns(const RlweSk &sk, size_t N,
                      const std::vector<uint64_t> &qs,
                      double sigma, std::mt19937_64 &rng,
                      RlweCt &ct, bool ntt_form) {
  const size_t K = qs.size();
  ct.c0.assign(N * K, 0);
  ct.c1.assign(N * K, 0);

  // Per-limb uniform a.
  for (size_t k = 0; k < K; k++) {
    utils::sample_uniform_poly(ct.c1.data() + k * N, N, qs[k], rng);
  }

  // Shared signed e, reduced per limb.
  std::vector<uint64_t> e(N * K);
  sample_gaussian_rns(e.data(), N, qs, sigma, rng);

  // c0_k = -(a_k * sk_k + e_k) mod q_k.
  std::vector<uint64_t> a_ntt(N);
  const std::vector<uint64_t> zeros(N, 0);
  for (size_t k = 0; k < K; k++) {
    const uint64_t q = qs[k];
    uint64_t *c0_k = ct.c0.data() + k * N;
    uint64_t *c1_k = ct.c1.data() + k * N;
    const uint64_t *sk_k = sk.data.data() + k * N;
    const uint64_t *e_k  = e.data()       + k * N;

    std::memcpy(a_ntt.data(), c1_k, N * sizeof(uint64_t));
    utils::ntt_fwd(a_ntt.data(), N, q);
    intel::hexl::EltwiseMultMod(c0_k, a_ntt.data(), sk_k, N, q, 1);
    utils::ntt_inv(c0_k, N, q);

    intel::hexl::EltwiseAddMod(c0_k, c0_k, e_k, N, q);
    intel::hexl::EltwiseSubMod(c0_k, zeros.data(), c0_k, N, q);

    if (ntt_form) {
      utils::ntt_fwd(c0_k, N, q);
      utils::ntt_fwd(c1_k, N, q);
    }
  }
  ct.ntt_form = ntt_form;
}

void encrypt_bfv_rns(const std::vector<uint64_t> &m, const RlweSk &sk,
                     size_t N, const std::vector<uint64_t> &qs, uint64_t t,
                     double sigma, std::mt19937_64 &rng, RlweCt &ct) {
  encrypt_zero_rns(sk, N, qs, sigma, rng, ct, /*ntt_form=*/false);

  const size_t K = qs.size();

  // Q as uint128. Caller upholds sum(log q_k) <= 128.
  uint128_t Q = 1;
  for (uint64_t q : qs) Q *= q;
  const uint128_t Delta = Q / t;
  const uint64_t r = static_cast<uint64_t>(Q - Delta * t);  // Q mod t, < t

  for (size_t i = 0; i < N && i < m.size(); i++) {
    const uint64_t mi = m[i] % t;
    if (mi == 0) continue;
    // round(Q*mi/t) = Δ*mi + round(r*mi/t). Δ*mi < Q < 2^128.
    const uint64_t r_mi_round =
        static_cast<uint64_t>((static_cast<uint128_t>(r) * mi + (t >> 1)) / t);
    const uint128_t scaled = Delta * mi + r_mi_round;

    for (size_t k = 0; k < K; k++) {
      const uint64_t qk = qs[k];
      const uint64_t scaled_k = static_cast<uint64_t>(scaled % qk);
      uint64_t *c0_k = ct.c0.data() + k * N;
      c0_k[i] = (c0_k[i] + scaled_k) % qk;
    }
  }
}

void decrypt_rns(const RlweCt &ct, const RlweSk &sk, size_t N,
                 const std::vector<uint64_t> &qs, uint64_t t,
                 const RnsTables &tables, RlwePt &pt) {
  const size_t K = qs.size();

  // Per-limb phase = c0 + c1*sk in coefficient form.
  std::vector<uint64_t> phase(N * K);
  std::vector<uint64_t> c1_buf(N), c0_buf(N);
  for (size_t k = 0; k < K; k++) {
    const uint64_t q = qs[k];
    const uint64_t *c0_k = ct.c0.data() + k * N;
    const uint64_t *c1_k = ct.c1.data() + k * N;
    const uint64_t *sk_k = sk.data.data() + k * N;
    uint64_t *phase_k = phase.data() + k * N;

    std::memcpy(c1_buf.data(), c1_k, N * sizeof(uint64_t));
    if (!ct.ntt_form) utils::ntt_fwd(c1_buf.data(), N, q);
    intel::hexl::EltwiseMultMod(phase_k, c1_buf.data(), sk_k, N, q, 1);
    utils::ntt_inv(phase_k, N, q);

    if (ct.ntt_form) {
      std::memcpy(c0_buf.data(), c0_k, N * sizeof(uint64_t));
      utils::ntt_inv(c0_buf.data(), N, q);
      intel::hexl::EltwiseAddMod(phase_k, phase_k, c0_buf.data(), N, q);
    } else {
      intel::hexl::EltwiseAddMod(phase_k, phase_k, c0_k, N, q);
    }
  }

  pt.data.resize(N);

  if (K == 1) {
    for (size_t i = 0; i < N; i++) {
      pt.data[i] = utils::rescale(phase[i], qs[0], t);
    }
    return;
  }

  if (K == 2) {
    const uint64_t q0 = qs[0], q1 = qs[1];
    const uint64_t q0_inv_mod_q1 = tables.q0_inv_mod_q1;

    for (size_t i = 0; i < N; i++) {
      const uint64_t p0 = phase[0 * N + i];
      const uint64_t p1 = phase[1 * N + i];
      // CRT compose: phase_mp = p0 + q0 * (((p1 - p0) * q0^{-1}) mod q1)
      const uint64_t p0_mod_q1 = p0 % q1;
      const uint64_t diff = (p1 + q1 - p0_mod_q1) % q1;
      const uint64_t s = static_cast<uint64_t>(
          (static_cast<uint128_t>(diff) * q0_inv_mod_q1) % q1);
      const uint128_t phase_mp = static_cast<uint128_t>(q0) * s + p0;  // < Q

      // Mod-switch q1 → drop: phase' = round(phase_mp / q1) mod q0.
      // (phase_mp + q1/2) / q1 ∈ [0, q0+1] for phase_mp ∈ [0, Q).
      const uint128_t num = phase_mp + (static_cast<uint128_t>(q1) >> 1);
      uint64_t phase_prime = static_cast<uint64_t>(num / q1);
      if (phase_prime >= q0) phase_prime -= q0;

      pt.data[i] = utils::rescale(phase_prime, q0, t);
    }
    return;
  }

  throw std::runtime_error("decrypt_rns: only K = 1 or K = 2 supported");
}

void rlwe_shift(const RlweCt &src, RlweCt &dst, size_t index, uint64_t q, size_t N) {
  if (&dst != &src) {
    dst.c0.resize(N);
    dst.c1.resize(N);
    dst.ntt_form = src.ntt_form;
  }
  utils::negacyclic_shift_poly_coeffmod(src.c0.data(), N, index, q, dst.c0.data());
  utils::negacyclic_shift_poly_coeffmod(src.c1.data(), N, index, q, dst.c1.data());
}
