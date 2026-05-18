#pragma once
#include "pir.h"
#include "rlwe.h"
#include <iostream>
#include <fstream>
#include <random>


#ifdef _DEBUG
#define PRINT_INT_ARRAY(arr_name, arr, size) \
    do {                                     \
        std::cout << arr_name << ": [";      \
        for (size_t i = 0; i < size; ++i) {     \
            std::cout << arr[i];             \
            if (i < size - 1)                \
                std::cout << ", ";           \
        }                                    \
        std::cout << "]" << std::endl;       \
    } while (0)
#endif

#ifdef _BENCHMARK
#define PRINT_INT_ARRAY(arr_name, arr, size) ;  // do nothing
#endif



inline void print_func_name(std::string func_name) {
  PRINT_BAR;
  #ifdef _DEBUG
    std::cout << "                    "<< func_name << "(Debug build)" << std::endl;
  #endif
  #ifdef _BENCHMARK
    std::cout << "                    "<< func_name << "(Benchmark build)" << std::endl;
  #endif
  PRINT_BAR;
}

template <typename T> std::string to_string(T x) {
  std::string ret;
  if (x == 0) {
    return "0";
  }
  while (x) {
    ret += (x % 10) + '0';
    x /= 10;
  }
  reverse(ret.begin(), ret.end());
  return ret;
}

namespace utils {

// Modular inverse using the extended Euclidean algorithm.
// Returns true and sets result = value^{-1} mod modulus if gcd(value, modulus) == 1.
// Returns false if value == 0 or gcd != 1 (not invertible).
// Requires: modulus >= 2, value < modulus.
bool try_invert_uint_mod(uint64_t value, uint64_t modulus, uint64_t &result);

// Deterministic Miller-Rabin primality test for any uint64_t.
// The witness set {2,3,5,7,11,13,17,19,23,29,31,37} is proven deterministic
// for all n < 3.3 * 10^24, which covers the full uint64_t range.
bool is_prime(uint64_t n);

// Apply the Galois automorphism σ_k : x → x^k in Z_q[x]/(x^N+1), coefficient form.
// Input/output in [0, q). Requires k odd, 1 ≤ k < 2N.
// Maps coefficient i to position (i*k) % (2N); wraps with sign flip if index ≥ N.
void automorphism_coeff(const uint64_t *in, size_t N, uint32_t k, uint64_t q, uint64_t *out);

// Same automorphism but input/output in NTT form.
// Internally converts coeff ↔ NTT; 2 extra NTTs but only used in keygen.
void automorphism_ntt(const uint64_t *in, size_t N, uint32_t k, uint64_t q, uint64_t *out);

// Compute round(num / den) for non-negative integers via integer arithmetic.
// Adds den/2 before the division to round to nearest. Caller ensures num + den/2
// does not overflow uint128_t.
inline uint64_t round_div_u128(uint128_t num, uint64_t den) {
  return static_cast<uint64_t>((num + (den >> 1)) / den);
}

// 128-bit right shift of a little-endian 2-uint64 integer (in-place safe).
inline void right_shift_uint128(uint64_t *operand, int shift, uint64_t *result) {
  if (shift == 0) {
    result[0] = operand[0]; result[1] = operand[1];
  } else if (shift < 64) {
    result[0] = (operand[0] >> shift) | (operand[1] << (64 - shift));
    result[1] = operand[1] >> shift;
  } else {
    result[0] = operand[1] >> (shift - 64);
    result[1] = 0;
  }
}

// Negacyclic NTT over Z_q[x]/(x^N+1), implemented via HEXL under the hood.
// The HEXL NTT object for each (N, q) pair is cached thread-locally so repeated
// calls are fast and lock-free.
void ntt_fwd(uint64_t *data, size_t N, uint64_t q);
void ntt_inv(uint64_t *data, size_t N, uint64_t q);

// Register a custom 2N-th root of unity for a single (N, q). HEXL's default
// NTT ctor searches for a primitive root, but only works when q is prime.
// Composite-mod first-dim (q = q1 * q2) needs a CRT-combined root supplied
// externally. Call once during PirParams construction; thread-safe to read
// thereafter.
void register_ntt_root(size_t N, uint64_t q, uint64_t root);

// Garner's CRT combine: given w1 ≡ w (mod q1), w2 ≡ w (mod q2) with
// gcd(q1, q2) = 1, return the unique w ∈ [0, q1*q2). Requires q1*q2 < 2^64.
uint64_t crt_combine(uint64_t w1, uint64_t q1, uint64_t w2, uint64_t q2);

// Barrett reduction for 64-bit x mod 64-bit q.
//
// Precompute once per modulus (barrett_u64_setup); call barrett_reduce_u64
// for hot reductions where the value to reduce is already a uint64_t. This is
// cheaper than the 128-bit-input Barrett reducer: one 64x64->128 multiply, one
// multiply-subtract, and one conditional subtract.
//
// Precondition: q > 0. q == 1 is handled as a degenerate modulus.
struct BarrettU64 {
  uint64_t q;
  uint64_t mu;  // floor(2^64 / q)
};

inline BarrettU64 barrett_u64_setup(uint64_t q) {
  const uint64_t mu = (q == 1)
      ? 0
      : static_cast<uint64_t>((static_cast<uint128_t>(1) << 64) / q);
  return BarrettU64{q, mu};
}

inline uint64_t barrett_reduce_u64(uint64_t x, const BarrettU64 &b) {
  if (b.q == 1) return 0;
  const uint64_t q_est = static_cast<uint64_t>(
      (static_cast<uint128_t>(x) * b.mu) >> 64);
  uint64_t r = x - q_est * b.q;
  if (r >= b.q) r -= b.q;
  return r;
}

// Barrett reduction for 128-bit x mod 64-bit q (SEAL-style).
//
// Precompute once per modulus (barrett_u128_setup); call barrett_reduce_u128
// per coefficient on the hot path. Replaces `x % q` with three full 64×64→128
// multiplies, one 64×64→64 low multiply, a low-64 multiply-subtract, and one
// conditional subtract. No 128-bit divide.
//
// Precondition: q < 2^63. (Our NTT-friendly primes are at most 60 bits.)
//
// How it works: mu = floor(2^128 / q) has up to 65 bits. The full 128×128
// product x·mu would give a 256-bit result; we want floor(x·mu / 2^128), i.e.
// the upper 128. But the Barrett subtraction x - q_est·q is immediately reduced
// mod 2^64 because the true remainder is < 2q < 2^64 — so we only need the low
// 64 bits of q_est. That lets us drop the x_hi·mu_hi high half and all the high
// bits of the upper-128 sum. Net result: 4 mults, a handful of adds, one
// compare-subtract.
//
// Error bound: q_est ≤ floor(x/q) ≤ q_est + 1 (tighter than 2 because mu
// covers the full 2^128 range exactly for odd q), so r = x_lo − q_est·q (mod
// 2^64) lies in [0, 2q). One conditional subtract suffices.
struct BarrettU128 {
  uint64_t q;
  uint64_t mu_lo;   // low 64 bits of floor(2^128 / q)
  uint64_t mu_hi;   // high 64 bits; up to ~(64 − log2(q)) bits actually used
};

inline BarrettU128 barrett_u128_setup(uint64_t q) {
  const uint128_t mu = (~static_cast<uint128_t>(0)) / q;
  return BarrettU128{q, static_cast<uint64_t>(mu),
                     static_cast<uint64_t>(mu >> 64)};
}

inline uint64_t barrett_reduce_u128(uint128_t x, const BarrettU128 &b) {
  const uint64_t x_lo = static_cast<uint64_t>(x);
  const uint64_t x_hi = static_cast<uint64_t>(x >> 64);

  // Round 1: carry = hi(x_lo · mu_lo).
  const uint64_t carry1 = static_cast<uint64_t>(
      (static_cast<uint128_t>(x_lo) * b.mu_lo) >> 64);

  // tmp = x_lo · mu_hi + carry1; keep both halves.
  const uint128_t t1 = static_cast<uint128_t>(x_lo) * b.mu_hi + carry1;
  const uint64_t t1_lo = static_cast<uint64_t>(t1);
  const uint64_t t1_hi = static_cast<uint64_t>(t1 >> 64);

  // Round 2: add x_hi · mu_lo into t1_lo, capture its high half.
  const uint128_t t2 = static_cast<uint128_t>(x_hi) * b.mu_lo + t1_lo;
  const uint64_t carry2 = static_cast<uint64_t>(t2 >> 64);

  // q_est low 64 bits (we only need these).
  const uint64_t q_est_lo = x_hi * b.mu_hi + t1_hi + carry2;

  // Barrett subtract, truncated to low 64 since true remainder is < 2^64.
  uint64_t r = x_lo - q_est_lo * b.q;
  if (r >= b.q) r -= b.q;
  return r;
}

void negacyclic_shift_poly_coeffmod(const uint64_t *poly,
                                    size_t coeff_count, size_t shift,
                                    uint64_t modulus,
                                    uint64_t *result);

// Convert a 128-bit unsigned integer to a string
std::string uint128_to_string(uint128_t value);

/**
 * @brief Construct a RGSW gadget. Notice that the gadget is from large to
 * small, i.e., the first row is B^(log q / log B -1), the final row is 1.
 */
std::vector<std::vector<uint64_t>>
gsw_gadget(size_t l, uint64_t base_log2,
           const std::vector<uint64_t> &rns_mods);

// Generate a prime that is bit_width long
std::uint64_t generate_prime(size_t bit_width);

// Generate one NTT-friendly prime per bit width.  Each returned prime p satisfies
//   p < 2^bit_width,  p ≡ 1 (mod 2N),  p is the largest such prime not already
// returned for the same bit width.  Replaces SEAL's CoeffModulus::Create.
std::vector<uint64_t> generate_ntt_friendly_primes(const std::vector<size_t> &bit_widths,
                                                   size_t N);

// New functions for plaintext handling
void print_plaintext(const RlwePt &plaintext, size_t count = 10);

bool plaintext_is_equal(const RlwePt &plaintext1, const RlwePt &plaintext2);

void print_progress(size_t current, size_t total);

size_t next_pow_of_2(const size_t n);

size_t roundup_div(const size_t numerator, const size_t denominator);


// ---------------------------------------------------------------------------
// Polynomial noise / randomness samplers
// ---------------------------------------------------------------------------

// Error polynomial: e[i] = round(N(0, sigma)) mod q.
// Positive values stored as-is; negative values stored as q - |e| (two's complement mod q).
void sample_gaussian(uint64_t *out, size_t N, uint64_t q, double sigma, std::mt19937_64 &rng);

// Uniform polynomial: a[i] uniformly in [0, q).
void sample_uniform_poly(uint64_t *out, size_t N, uint64_t q, std::mt19937_64 &rng);

// Ternary secret key: s[i] in {0, 1, q-1} with equal probability 1/3 each.
// Stores 0 for 0, 1 for +1, q-1 for -1 (additive inverse).
void sample_ternary(uint64_t *out, size_t N, uint64_t q, std::mt19937_64 &rng);

// Rescale a single coefficient from modulus inp_mod to out_mod using
// centered (signed) round-to-nearest: lifts a into [-inp_mod/2, inp_mod/2),
// computes round(v * out_mod / inp_mod) in i128, and reduces into [0, out_mod).
// Pure integer arithmetic — no FP precision loss. Matches Spiral's rescale.
uint64_t rescale(uint64_t a, uint64_t inp_mod, uint64_t out_mod);

// Given the target number of plaintexts, GSW ell for further dims, and the
// expansion tree height, calculate the database shape under the constraints:
// (1) fst_dim_sz + l*(num_dims-1) <= 2^h
// (2) fst_dim_sz * 2^{num_dims-1} >= target_num_pt
// Multi-dimension shapes (target_num_pt > 2^h) maximize the first dimension
// per the FST_DIM_POW2 policy. A single-dimension DB (target_num_pt <= 2^h)
// gets fst_dim_sz = target_num_pt exactly with num_dims = 1 — no padding.
// Returns {fst_dim_sz, num_dims}.
std::pair<size_t, size_t> calculate_db_shape(size_t target_num_pt, size_t l, size_t h);

// given a number x and a logn, return the bit-reversed number of x
inline size_t bit_reverse(size_t x, size_t logn) {
  size_t n = 1 << logn;
  size_t y = 0;
  for (size_t i = 0; i < logn; i++) {
    y = (y << 1) | (x & 1);
    x >>= 1;
  }
  return y;
  }

  // compute ceil(x/2^k). equivalent to ceil^k(x/2).
  inline size_t repeated_ceil_half(size_t x, size_t k) {
    size_t divisor = 1 << k;
    return (x + divisor - 1) / divisor;
  }


} // namespace utils
