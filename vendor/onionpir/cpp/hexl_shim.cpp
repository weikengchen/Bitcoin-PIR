// src/hexl_shim.cpp
//
// Scalar + (ARM) NEON fallback implementation of the tiny subset of Intel HEXL
// that this codebase uses. Built only when HEXL is unavailable (ARM / WASM); on
// x86_64 with HEXL enabled, the real library is used instead and this file is
// not compiled.
//
// See hexl_compat/hexl/hexl.hpp for the public API and rationale.
//
// Negacyclic NTT in R_q = Z_q[x] / (x^N + 1):
//   - Iterative Cooley-Tukey radix-2 butterfly.
//   - Twiddles psi^{bit_reverse(k, log2 N)} precomputed in the ctor.
//   - Twiddle butterflies use Shoup modular multiplication: alongside each
//     twiddle w we cache w_shoup = floor(w * 2^64 / q) and reduce a*w to
//     [0, q) with a single uint64x2 -> uint128 multiply (no division). This
//     replaces the previous `(__uint128_t)a*w % q` and is the main scalar
//     speedup on the hot path.
//   - Forward produces bit-reversed output; inverse consumes bit-reversed
//     input and produces natural order (matching HEXL's convention for the
//     codebase: a single forward followed by elementwise ops followed by a
//     single inverse round-trips an array, with the bit-reversed permutation
//     cancelling out).
//
// EltwiseAddMod / EltwiseSubMod are vectorised with NEON on AArch64. The mul
// paths (EltwiseMultMod, EltwiseFMAMod) remain scalar — a 64x64->128 SIMD
// multiply doesn't exist on AArch64 and the split-mul rewrite isn't worth the
// complexity at this scale.

#include "hexl/hexl.hpp"

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <vector>

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#define ONIONPIR_HEXL_SHIM_HAS_NEON 1
#else
#define ONIONPIR_HEXL_SHIM_HAS_NEON 0
#endif

namespace intel {
namespace hexl {

namespace {

// --- Modular arithmetic helpers ---------------------------------------------

inline std::uint64_t addmod(std::uint64_t a, std::uint64_t b,
                            std::uint64_t q) {
  // a, b in [0, q). q < 2^62 so a + b cannot overflow uint64.
  std::uint64_t s = a + b;
  return s >= q ? s - q : s;
}

inline std::uint64_t submod(std::uint64_t a, std::uint64_t b,
                            std::uint64_t q) {
  // a, b in [0, q). Branch-on-underflow.
  return a >= b ? (a - b) : (a + q - b);
}

inline std::uint64_t mulmod(std::uint64_t a, std::uint64_t b,
                            std::uint64_t q) {
  // q < 2^62 so a, b in [0, q) gives product in [0, 2^124) — fits in uint128.
  return static_cast<std::uint64_t>(
      (static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b)) %
      q);
}

// Shoup precompute: w_shoup = floor(w * 2^64 / q). Requires w < q < 2^63.
inline std::uint64_t shoup_precompute(std::uint64_t w, std::uint64_t q) {
  // (w << 64) / q via __uint128_t. w < q so the quotient fits in 64 bits.
  return static_cast<std::uint64_t>(
      (static_cast<unsigned __int128>(w) << 64) /
      static_cast<unsigned __int128>(q));
}

// Shoup modular multiplication: returns a*w mod q in [0, q).
//   q_hat = (a * w_shoup) >> 64   (high 64 bits of the 128-bit product)
//   r     = a*w - q_hat * q       (computed mod 2^64; in [0, 2q) by the bound)
//   r    -= (r >= q) * q          (conditional subtract)
// Correct whenever a, w < q and q < 2^63. Here q < 2^62 so the bound is
// comfortable.
inline std::uint64_t mul_shoup(std::uint64_t a, std::uint64_t w,
                               std::uint64_t w_shoup, std::uint64_t q) {
  const std::uint64_t q_hat = static_cast<std::uint64_t>(
      (static_cast<unsigned __int128>(a) *
       static_cast<unsigned __int128>(w_shoup)) >>
      64);
  // Multiplication wraps mod 2^64; the algebra makes the result fit in
  // [0, 2q), which is < 2^63 so the unsigned subtraction is well-defined.
  std::uint64_t r = a * w - q_hat * q;
  if (r >= q) r -= q;
  return r;
}

inline std::uint64_t reduce(std::uint64_t a, std::uint64_t q) {
  return a >= q ? a % q : a;
}

std::uint64_t powmod(std::uint64_t base, std::uint64_t exp, std::uint64_t q) {
  std::uint64_t result = 1 % q;
  base = reduce(base, q);
  while (exp > 0) {
    if (exp & 1) result = mulmod(result, base, q);
    base = mulmod(base, base, q);
    exp >>= 1;
  }
  return result;
}

// Bit reverse `value` over `bits` bits.
inline std::uint64_t bit_reverse(std::uint64_t value, unsigned bits) {
  std::uint64_t r = 0;
  for (unsigned i = 0; i < bits; ++i) {
    r = (r << 1) | (value & 1);
    value >>= 1;
  }
  return r;
}

inline unsigned log2_pow2(std::size_t n) {
  // n must be a power of two and > 0. Returns log2(n).
  unsigned k = 0;
  while ((std::size_t{1} << k) < n) ++k;
  return k;
}

// Trial-division prime factors of m (m is small in practice: m = 2N, so a
// power of two — just yields {2}). Returns sorted unique primes.
std::vector<std::uint64_t> prime_factors(std::uint64_t m) {
  std::vector<std::uint64_t> out;
  for (std::uint64_t p = 2; p * p <= m; ++p) {
    if (m % p == 0) {
      out.push_back(p);
      while (m % p == 0) m /= p;
    }
  }
  if (m > 1) out.push_back(m);
  return out;
}

}  // namespace

// --- Free functions ---------------------------------------------------------

void EltwiseAddMod(std::uint64_t *out, const std::uint64_t *a,
                   const std::uint64_t *b, std::uint64_t n, std::uint64_t q) {
  std::uint64_t i = 0;
#if ONIONPIR_HEXL_SHIM_HAS_NEON
  // Inputs are guaranteed in [0, q) (callers pre-reduce). q < 2^62, so the
  // sum fits in uint64. A single conditional subtract suffices.
  //
  // Vector pattern per 2-element block:
  //   sum  = a + b
  //   mask = (sum >= q) ? all-ones : all-zeros   (vcgeq_u64)
  //   out  = sum - (mask & q)
  const uint64x2_t q_vec = vdupq_n_u64(q);
  for (; i + 2 <= n; i += 2) {
    const uint64x2_t av = vld1q_u64(a + i);
    const uint64x2_t bv = vld1q_u64(b + i);
    const uint64x2_t sum = vaddq_u64(av, bv);
    const uint64x2_t mask = vcgeq_u64(sum, q_vec);  // 0xFF.. when sum >= q
    const uint64x2_t corr = vandq_u64(mask, q_vec);
    vst1q_u64(out + i, vsubq_u64(sum, corr));
  }
#endif
  for (; i < n; ++i) {
    out[i] = addmod(a[i], b[i], q);
  }
}

void EltwiseSubMod(std::uint64_t *out, const std::uint64_t *a,
                   const std::uint64_t *b, std::uint64_t n, std::uint64_t q) {
  std::uint64_t i = 0;
#if ONIONPIR_HEXL_SHIM_HAS_NEON
  // diff = a - b (mod 2^64). If b > a we underflowed; correct by adding q.
  //   borrow = (b > a) ? all-ones : 0    (vcgtq_u64)
  //   out    = diff + (borrow & q)
  const uint64x2_t q_vec = vdupq_n_u64(q);
  for (; i + 2 <= n; i += 2) {
    const uint64x2_t av = vld1q_u64(a + i);
    const uint64x2_t bv = vld1q_u64(b + i);
    const uint64x2_t diff = vsubq_u64(av, bv);
    const uint64x2_t borrow = vcgtq_u64(bv, av);  // 0xFF.. when b > a
    const uint64x2_t corr = vandq_u64(borrow, q_vec);
    vst1q_u64(out + i, vaddq_u64(diff, corr));
  }
#endif
  for (; i < n; ++i) {
    out[i] = submod(a[i], b[i], q);
  }
}

void EltwiseMultMod(std::uint64_t *out, const std::uint64_t *a,
                    const std::uint64_t *b, std::uint64_t n, std::uint64_t q,
                    std::uint64_t /*in_mod_factor*/) {
  // No NEON path: AArch64 lacks a 64x64->128 SIMD multiply. A split-and-fold
  // implementation is possible but not worth the complexity at this site.
  for (std::uint64_t i = 0; i < n; ++i) {
    out[i] = mulmod(a[i], b[i], q);
  }
}

void EltwiseFMAMod(std::uint64_t *out, const std::uint64_t *a,
                   std::uint64_t scalar, const std::uint64_t *acc,
                   std::uint64_t n, std::uint64_t q,
                   std::uint64_t /*in_mod_factor*/) {
  // Reduce scalar once (callers usually pre-reduce, but be safe).
  scalar = reduce(scalar, q);
  // Scalar `scalar` is constant across the loop — we could Shoup-precompute
  // it here. Profile says this path is not hot in OnionPIR, so we stay
  // scalar for simplicity.
  if (acc != nullptr) {
    for (std::uint64_t i = 0; i < n; ++i) {
      const std::uint64_t prod = mulmod(a[i], scalar, q);
      out[i] = addmod(prod, acc[i], q);
    }
  } else {
    for (std::uint64_t i = 0; i < n; ++i) {
      out[i] = mulmod(a[i], scalar, q);
    }
  }
}

std::uint64_t MinimalPrimitiveRoot(std::uint64_t m, std::uint64_t q) {
  // Need order-m elements in (Z/qZ)*. This requires m | (q - 1).
  if (q < 2) throw std::invalid_argument("MinimalPrimitiveRoot: q < 2");
  if (m == 0) throw std::invalid_argument("MinimalPrimitiveRoot: m == 0");
  if ((q - 1) % m != 0) {
    throw std::invalid_argument(
        "MinimalPrimitiveRoot: m does not divide q-1; no m-th root exists");
  }

  const std::uint64_t cofactor = (q - 1) / m;
  const auto factors = prime_factors(m);

  // Step 1: find ANY primitive m-th root by trying small candidates g.
  // For prime q, phi(m)/m of the (Z/qZ)* elements raise to order m, so the
  // search succeeds in a small bounded number of trials; in practice the
  // first non-trivial g works.
  std::uint64_t gen = 0;
  for (std::uint64_t g = 2; g < q; ++g) {
    const std::uint64_t h = powmod(g, cofactor, q);
    if (h <= 1) continue;
    bool ok = true;
    for (std::uint64_t p : factors) {
      if (powmod(h, m / p, q) == 1) {
        ok = false;
        break;
      }
    }
    if (ok) {
      gen = h;
      break;
    }
  }
  if (gen == 0) {
    throw std::runtime_error("MinimalPrimitiveRoot: no generator found");
  }

  // Step 2: enumerate the order-m subgroup <gen> and take the minimum over
  // primitive elements (gen^k where gcd(k, m) == 1). This is O(m) work, and
  // m = 2N <= 16384 in this codebase, so cheap.
  std::uint64_t minv = gen;  // k = 1 is coprime to m
  std::uint64_t cur = gen;
  for (std::uint64_t k = 2; k < m; ++k) {
    cur = mulmod(cur, gen, q);
    // gcd(k, m): only primitive m-th roots have exponent coprime to m.
    std::uint64_t a = k, b = m;
    while (b) { std::uint64_t t = a % b; a = b; b = t; }
    if (a != 1) continue;
    if (cur < minv) minv = cur;
  }
  return minv;
}

// --- NTT class --------------------------------------------------------------

NTT::NTT(std::size_t N, std::uint64_t q)
    : NTT(N, q, MinimalPrimitiveRoot(2 * static_cast<std::uint64_t>(N), q)) {}

NTT::NTT(std::size_t N, std::uint64_t q, std::uint64_t root) {
  if (N == 0 || (N & (N - 1)) != 0) {
    throw std::invalid_argument("NTT: N must be a positive power of two");
  }
  if (q < 2) {
    throw std::invalid_argument("NTT: q must be >= 2");
  }
  // We use unsigned __int128 for products; require q*q to fit in 128 bits,
  // i.e. q < 2^64. We also require q < 2^62 in practice (matches HEXL) so
  // that addmod's intermediate (a + b) cannot overflow uint64.
  if (q >= (std::uint64_t{1} << 62)) {
    throw std::invalid_argument("NTT: q must fit in 62 bits");
  }

  N_ = N;
  q_ = q;
  root_ = reduce(root, q);
  // inv_root_ and inv_N_: only safe via Fermat when q is prime. For composite
  // q the caller must supply `root` and we still need (root)^{-1} and N^{-1}.
  // We compute them via extended-Euclid-style power, but Fermat is wrong for
  // composite. To stay correct for composite q, use the iterative inverse
  // through extended GCD instead.
  //
  // Implementation note: rather than carry a separate xgcd, we observe that
  // for the values we encounter (q either prime, or q = q1*q2 with q1, q2
  // prime), gcd(root, q) = 1 and gcd(N, q) = 1, so inverses exist. We use
  // extended Euclidean to compute them.

  auto egcd_inv = [](std::uint64_t a_in, std::uint64_t mod) -> std::uint64_t {
    // Solve a * x = 1 (mod mod) for x in [0, mod).
    // Uses signed extended Euclidean. mod < 2^62 so signed __int128 is ample.
    using s128 = __int128;
    s128 old_r = static_cast<s128>(a_in), r = static_cast<s128>(mod);
    s128 old_s = 1, s = 0;
    while (r != 0) {
      s128 quot = old_r / r;
      s128 tmp = r;
      r = old_r - quot * r;
      old_r = tmp;
      tmp = s;
      s = old_s - quot * s;
      old_s = tmp;
    }
    if (old_r != 1) {
      throw std::invalid_argument("NTT: value not invertible mod q");
    }
    s128 m = static_cast<s128>(mod);
    s128 x = old_s % m;
    if (x < 0) x += m;
    return static_cast<std::uint64_t>(x);
  };

  inv_root_ = egcd_inv(root_, q_);
  inv_N_ = egcd_inv(static_cast<std::uint64_t>(N_), q_);

  // Precompute twiddles in bit-reversed order.
  // psi_fwd_[k]  = root^{bit_reverse(k, log2 N)}   mod q   for k in [0, N)
  // psi_inv_[k]  = inv_root^{bit_reverse(k, log2 N)} mod q for k in [0, N)
  const unsigned bits = log2_pow2(N_);
  psi_fwd_.resize(N_);
  psi_inv_.resize(N_);
  psi_fwd_shoup_.resize(N_);
  psi_inv_shoup_.resize(N_);

  // Build powers of root (in natural index k) then permute.
  // Naive: psi_fwd_[k] = root^{bit_reverse(k)}. We compute by iterative
  // multiplication: powers_nat[k] = root^k.
  std::vector<std::uint64_t> pow_fwd(N_);
  std::vector<std::uint64_t> pow_inv(N_);
  pow_fwd[0] = 1 % q_;
  pow_inv[0] = 1 % q_;
  for (std::size_t k = 1; k < N_; ++k) {
    pow_fwd[k] = mulmod(pow_fwd[k - 1], root_, q_);
    pow_inv[k] = mulmod(pow_inv[k - 1], inv_root_, q_);
  }
  for (std::size_t k = 0; k < N_; ++k) {
    const std::uint64_t br = bit_reverse(k, bits);
    psi_fwd_[k] = pow_fwd[br];
    psi_inv_[k] = pow_inv[br];
    psi_fwd_shoup_[k] = shoup_precompute(psi_fwd_[k], q_);
    psi_inv_shoup_[k] = shoup_precompute(psi_inv_[k], q_);
  }
}

void NTT::ComputeForward(std::uint64_t *out, const std::uint64_t *in,
                         std::uint64_t /*in_mod_factor*/,
                         std::uint64_t /*out_mod_factor*/) {
  // In-place safe: copy only if needed; reduce inputs.
  if (out != in) {
    for (std::size_t i = 0; i < N_; ++i) out[i] = reduce(in[i], q_);
  } else {
    for (std::size_t i = 0; i < N_; ++i) out[i] = reduce(out[i], q_);
  }

  // Iterative CT radix-2 butterfly with bit-reversed twiddle table.
  // Stage variables:
  //   m  = number of blocks at this stage (starts at 1, doubles each stage)
  //   t  = butterfly distance (N/2 initially, halves each stage)
  // For each block i in [0, m): twiddle w = psi_fwd_[m + i] with Shoup
  // precompute w_shoup = psi_fwd_shoup_[m + i].
  // For each j in [block_start, block_start + t):
  //   u = out[j], v = mul_shoup(out[j + t], w, w_shoup, q)
  //   out[j]     = u + v   (mod q)
  //   out[j + t] = u - v   (mod q)
  // This matches the SEAL / HEXL convention where psi_fwd_[k] holds
  // root^{bit_reverse_log2N(k)}; the first butterfly stage thus uses
  // psi_fwd_[1] = root^{N/2}, the negacyclic "root of -1".
  //
  // NEON-vectorising the inner butterfly itself is future work: it requires
  // a 64x64->128 split-multiply on AArch64 (no native instruction), and the
  // add/sub-only vectorisation buys little when the multiply stays scalar.
  std::size_t t = N_;
  for (std::size_t m = 1; m < N_; m <<= 1) {
    t >>= 1;
    for (std::size_t i = 0; i < m; ++i) {
      const std::size_t j1 = 2 * i * t;
      const std::size_t j2 = j1 + t;
      const std::uint64_t w = psi_fwd_[m + i];
      const std::uint64_t w_shoup = psi_fwd_shoup_[m + i];
      for (std::size_t j = j1; j < j2; ++j) {
        const std::uint64_t u = out[j];
        const std::uint64_t v = mul_shoup(out[j + t], w, w_shoup, q_);
        out[j]     = addmod(u, v, q_);
        out[j + t] = submod(u, v, q_);
      }
    }
  }
}

void NTT::ComputeInverse(std::uint64_t *out, const std::uint64_t *in,
                         std::uint64_t /*in_mod_factor*/,
                         std::uint64_t /*out_mod_factor*/) {
  // Gentleman-Sande inverse butterflies (bit-reversed twiddles), then scale
  // by N^{-1}. In-place safe.
  if (out != in) {
    for (std::size_t i = 0; i < N_; ++i) out[i] = reduce(in[i], q_);
  } else {
    for (std::size_t i = 0; i < N_; ++i) out[i] = reduce(out[i], q_);
  }

  // Iterative GS radix-2: stage t goes from 1 up to N/2, m from N/2 down to 1.
  //   for each block:
  //     u = out[i + j]
  //     v = out[i + j + t]
  //     out[i + j]     = u + v                                  (mod q)
  //     out[i + j + t] = mul_shoup(u - v, w, w_shoup, q)        (mod q)
  // where w = psi_inv_[m + i], w_shoup = psi_inv_shoup_[m + i].
  std::size_t t = 1;
  for (std::size_t m = N_; m > 1; m >>= 1) {
    const std::size_t half = m >> 1;
    for (std::size_t i = 0; i < half; ++i) {
      const std::size_t j1 = 2 * i * t;
      const std::size_t j2 = j1 + t;
      const std::uint64_t w = psi_inv_[half + i];
      const std::uint64_t w_shoup = psi_inv_shoup_[half + i];
      for (std::size_t j = j1; j < j2; ++j) {
        const std::uint64_t u = out[j];
        const std::uint64_t v = out[j + t];
        out[j]     = addmod(u, v, q_);
        out[j + t] = mul_shoup(submod(u, v, q_), w, w_shoup, q_);
      }
    }
    t <<= 1;
  }

  // Multiply by N^{-1} mod q after the butterflies (correctness invariant
  // called out by the spec: the scaling must come AFTER the butterflies).
  // This is O(N) — staying with the existing scalar mulmod is fine; the
  // hot O(N log N) path is the Shoup-accelerated butterfly above.
  for (std::size_t i = 0; i < N_; ++i) {
    out[i] = mulmod(out[i], inv_N_, q_);
  }
}

}  // namespace hexl
}  // namespace intel
