#include "utils.h"
#include "hexl/hexl.hpp"
#include <bit>
#include <cassert>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace {
// Optional custom 2N-th root for a single (N, q). Set once by
// utils::register_ntt_root during PirParams construction, then read-only.
// Used for composite q = q1*q2 since HEXL's default ctor can't search for a
// root when q is non-prime.
size_t g_custom_N = 0;
uint64_t g_custom_q = 0;
uint64_t g_custom_root = 0;

// Per-thread cache of HEXL NTT objects keyed by (N, q). The `cache` itself
// is `thread_local` so concurrent calls from parallel answer_query don't
// race on the `find` / `emplace` pair. Memory cost is bounded: each
// thread holds at most a handful of (N, q) pairs (default config has 1).
// Most (N, q) used here are prime moduli; HEXL's default ctor searches
// for a primitive root. Composite q falls back to the registered custom
// root (`g_custom_*` — written once during PirParams construction, read
// thereafter; safe under the standard "build server before answering"
// init order).
intel::hexl::NTT &get_ntt(size_t N, uint64_t q) {
  struct Key {
    size_t N; uint64_t q;
    bool operator==(const Key &o) const noexcept { return N == o.N && q == o.q; }
  };
  struct Hash {
    size_t operator()(const Key &k) const noexcept {
      return std::hash<size_t>()(k.N) ^ (std::hash<uint64_t>()(k.q) * 0x9E3779B97F4A7C15ULL);
    }
  };
  thread_local std::unordered_map<Key, std::unique_ptr<intel::hexl::NTT>, Hash> cache;
  auto it = cache.find({N, q});
  if (it != cache.end()) return *it->second;
  auto ntt = (N == g_custom_N && q == g_custom_q)
                 ? std::make_unique<intel::hexl::NTT>(N, q, g_custom_root)
                 : std::make_unique<intel::hexl::NTT>(N, q);
  auto ins = cache.emplace(Key{N, q}, std::move(ntt));
  return *ins.first->second;
}
} // namespace

void utils::register_ntt_root(size_t N, uint64_t q, uint64_t root) {
  if (g_custom_N != 0 &&
      (g_custom_N != N || g_custom_q != q || g_custom_root != root)) {
    throw std::invalid_argument(
        "register_ntt_root: a different (N, q, root) is already registered");
  }
  g_custom_N = N;
  g_custom_q = q;
  g_custom_root = root;
}

void utils::automorphism_coeff(const uint64_t *in, size_t N, uint32_t k,
                               uint64_t q, uint64_t *out) {
  const size_t two_n = 2 * N;
  for (size_t i = 0; i < N; i++) {
    size_t dest = (static_cast<uint64_t>(i) * k) % two_n;
    if (dest < N) {
      out[dest] = in[i];
    } else {
      out[dest - N] = (in[i] == 0) ? 0 : (q - in[i]);
    }
  }
}

void utils::automorphism_ntt(const uint64_t *in, size_t N, uint32_t k,
                              uint64_t q, uint64_t *out) {
  // NTT → coeff → automorphism → NTT. Two extra transforms, only used in keygen.
  std::vector<uint64_t> coeff(in, in + N);
  ntt_inv(coeff.data(), N, q);
  automorphism_coeff(coeff.data(), N, k, q, out);
  ntt_fwd(out, N, q);
}

void utils::ntt_fwd(uint64_t *data, size_t N, uint64_t q) {
  get_ntt(N, q).ComputeForward(data, data, 1, 1);
}

void utils::ntt_inv(uint64_t *data, size_t N, uint64_t q) {
  get_ntt(N, q).ComputeInverse(data, data, 1, 1);
}

// Extended Euclidean algorithm: given a, b > 0, returns (gcd, s) such that
// s * a + t * b = gcd.  We only return s since that's the Bezout coefficient
// for `value` in try_invert_uint_mod.
// For moduli < 2^62 the coefficients stay within int64_t range.
static int64_t xgcd(int64_t a, int64_t b, int64_t &s) {
  int64_t s0 = 1, s1 = 0;
  int64_t r0 = a, r1 = b;
  while (r1 != 0) {
    int64_t q = r0 / r1;
    int64_t tmp = r1; r1 = r0 - q * r1; r0 = tmp;
    tmp = s1; s1 = s0 - q * s1; s0 = tmp;
  }
  s = s0;
  return r0; // gcd
}

// (a * b) mod m without overflow, via 128-bit multiply.
static inline uint64_t mulmod_u64(uint64_t a, uint64_t b, uint64_t m) {
  return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % m);
}

// (base^exp) mod m via binary exponentiation.
static uint64_t powmod_u64(uint64_t base, uint64_t exp, uint64_t m) {
  uint64_t result = 1 % m;
  base %= m;
  while (exp > 0) {
    if (exp & 1) result = mulmod_u64(result, base, m);
    base = mulmod_u64(base, base, m);
    exp >>= 1;
  }
  return result;
}

// Miller-Rabin witness check: returns true if `a` is a witness that n is composite.
static bool mr_composite_witness(uint64_t n, uint64_t d, int r, uint64_t a) {
  uint64_t x = powmod_u64(a, d, n);
  if (x == 1 || x == n - 1) return false;
  for (int i = 0; i < r - 1; ++i) {
    x = mulmod_u64(x, x, n);
    if (x == n - 1) return false;
  }
  return true;
}

bool utils::is_prime(uint64_t n) {
  if (n < 2) return false;
  // Small-prime shortcut (also handles witnesses equal to n).
  static constexpr uint64_t small_primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
  for (uint64_t p : small_primes) {
    if (n == p) return true;
    if (n % p == 0) return false;
  }
  // Write n - 1 = d * 2^r with d odd.
  uint64_t d = n - 1;
  int r = 0;
  while ((d & 1) == 0) { d >>= 1; ++r; }
  // Deterministic for all 64-bit n.
  for (uint64_t a : small_primes) {
    if (mr_composite_witness(n, d, r, a)) return false;
  }
  return true;
}

bool utils::try_invert_uint_mod(uint64_t value, uint64_t modulus, uint64_t &result) {
  if (value == 0) return false;
  int64_t s;
  int64_t g = xgcd(static_cast<int64_t>(value), static_cast<int64_t>(modulus), s);
  if (g != 1) return false;
  result = (s < 0) ? static_cast<uint64_t>(s + static_cast<int64_t>(modulus))
                   : static_cast<uint64_t>(s);
  return true;
}


void utils::negacyclic_shift_poly_coeffmod(const uint64_t *poly, size_t coeff_count,
                                           size_t shift, uint64_t modulus,
                                           uint64_t *result) {
  if (shift == 0) {
    std::memcpy(result, poly, coeff_count * sizeof(uint64_t));
    return;
  }

  uint64_t index_raw = shift;
  const uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
  for (size_t i = 0; i < coeff_count; i++, poly++, index_raw++) {
    uint64_t index = index_raw & coeff_count_mod_mask;  // shifted index, possibly wrapping around
    if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*poly) {
      // for those entries that are not wrapped around
      result[index] = *poly;
    } else {
      // For wrapped around entries, we fill in additive inverse.
      result[index] = modulus - *poly;
    }
  }
}

std::string utils::uint128_to_string(uint128_t value) {
    // Split the 128-bit value into two 64-bit parts
    uint64_t high = value >> 64;
    uint64_t low = static_cast<uint64_t>(value);

    std::ostringstream oss;

    // Print the high part, if it's non-zero, to avoid leading zeros
    if (high != 0) {
        oss << high << " * 2^64 + " << low;
    } else {
        oss << low;
    }
    return oss.str();
}



std::vector<std::vector<uint64_t>> utils::gsw_gadget(size_t l, uint64_t base_log2,
                const std::vector<uint64_t> &rns_mods) {
  // Create RGSW gadget.
  const size_t K = rns_mods.size();
  std::vector<std::vector<uint64_t>> gadget(K, std::vector<uint64_t>(l));
  for (size_t i = 0; i < K; i++) {
    const uint64_t mod = rns_mods[i];
    uint64_t pow = 1;
    for (int j = l - 1; j >= 0; j--) {
      gadget[i][j] = pow;
      pow = static_cast<uint64_t>((static_cast<uint128_t>(pow) << base_log2) % mod);
    }
  }
  return gadget;
}

/**
 * @brief Generate the smallest prime that is at least bit_width bits long.
 * @param bit_width >= 2 and <= 64
 * @return std::uint64_t  
 */
uint64_t utils::crt_combine(uint64_t w1, uint64_t q1,
                             uint64_t w2, uint64_t q2) {
  // Garner: w = w1 + q1 * ((w2 - w1) * q1^{-1} mod q2) ∈ [0, q1*q2).
  uint64_t q1_inv;
  if (!try_invert_uint_mod(q1 % q2, q2, q1_inv))
    throw std::invalid_argument("crt_combine: q1, q2 must be coprime");
  const uint64_t diff = (w2 + q2 - (w1 % q2)) % q2;
  const uint64_t k = mulmod_u64(diff, q1_inv, q2);
  return static_cast<uint64_t>(static_cast<uint128_t>(q1) * k + w1);
}

std::uint64_t utils::generate_prime(size_t bit_width) {
  if (bit_width < 2) throw std::invalid_argument("Bit width must be at least 2.");

  // Otherwise, generate a new prime
  std::uint64_t candidate = 1ULL << (bit_width - 1);
  do {
      candidate++;
      // Ensure candidate is odd, as even numbers greater than 2 cannot be prime
      candidate |= 1;
  } while (!utils::is_prime(candidate));
  return candidate;
}

std::vector<uint64_t> utils::generate_ntt_friendly_primes(
    const std::vector<size_t> &bit_widths, size_t N) {
  // For each bit width bw, return the largest prime p < 2^bw with p ≡ 1 mod 2N.
  // If the same bit width appears more than once, return distinct primes by
  // continuing the downward scan from where we stopped last time.
  const uint64_t step = 2 * static_cast<uint64_t>(N);
  std::unordered_map<size_t, uint64_t> next_candidate;
  std::vector<uint64_t> out;
  out.reserve(bit_widths.size());

  for (size_t bw : bit_widths) {
    if (bw < 2 || bw > 63)
      throw std::invalid_argument("bit width out of range [2, 63]");

    auto it = next_candidate.find(bw);
    uint64_t c;
    if (it == next_candidate.end()) {
      const uint64_t upper = (uint64_t{1} << bw);   // exclusive
      // Largest value < 2^bw with value ≡ 1 mod 2N.
      c = upper - 1;
      c -= ((c - 1) % step);
    } else {
      c = it->second;
    }

    while (true) {
      if (c < 2) throw std::runtime_error("No NTT-friendly prime found");
      if (utils::is_prime(c)) break;
      c -= step;
    }
    out.push_back(c);
    next_candidate[bw] = (c >= step) ? (c - step) : 0;
  }
  return out;
}

// New functions for plaintext handling
void utils::print_plaintext(const RlwePt &plaintext, const size_t count) {
  const size_t coeff_count = plaintext.coeff_count();
  for (size_t i = 0; i < std::min(count, coeff_count); ++i) {
    std::cout << plaintext.data[i] << ", ";
  }
  std::cout << std::endl;
}

bool utils::plaintext_is_equal(const RlwePt &plaintext1, const RlwePt &plaintext2) {
  const size_t coeff_count1 = plaintext1.coeff_count();
  const size_t coeff_count2 = plaintext2.coeff_count();

  if (coeff_count1 != coeff_count2) {
    std::cerr << "Plaintexts have different coefficient counts" << std::endl;
    return false;
  }

  for (size_t i = 0; i < coeff_count1; i++) {
    if (plaintext1.data[i] != plaintext2.data[i]) {
      std::cerr << "Plaintexts are not equal at coefficient " << i << std::endl;
      return false;
    }
  }
  return true;
}

void utils::print_progress(size_t current, size_t total) {
    float progress = static_cast<float>(current) / total;
    size_t bar_width = 70;

    // Move the cursor to the beginning and clear the line.
    std::cout << "\r\033[K[";

    size_t pos = static_cast<size_t>(bar_width * progress);
    for (size_t i = 0; i < bar_width; ++i) {
        if (i < pos)
            std::cout << "=";
        else if (i == pos)
            std::cout << ">";
        else
            std::cout << " ";
    }
    std::cout << "] " << size_t(progress * 100.0) << " %";
    std::cout.flush();
}


size_t utils::next_pow_of_2(const size_t n) {
  size_t p = 1;
  while (p < n) {
    p <<= 1;
  }
  return p;
}

size_t utils::roundup_div(const size_t numerator, const size_t denominator) {
  if (denominator == 0) {
    throw std::invalid_argument("roundup_div division by zero");
  }
  return (numerator + denominator - 1) / denominator;
}


// Pick (fst_dim_sz, num_dims) so the database holds ≥ target_num_pt plaintexts
// and the expansion output fits the chosen shape.
//
// The query expansion tree of height h produces capacity = 2^h BFV ciphertexts.
// Of those, the first num_dims - 1 "other" dimensions are each binary muxes
// driven by a full l-row GSW gadget reconstruction, so they consume
//   reserved = l * (num_dims - 1)
// expansion slots. The remaining
//   slack    = capacity - reserved
// slots feed the first dimension. fst_dim_sz is set from slack per the
// FST_DIM_POW2 policy. Database capacity (in plaintexts) is then
//   fst_dim_sz · 2^(num_dims - 1)
// since each "other" dim is binary and doubles the addressable plaintexts.
//
// Single-dimension fast path: when target_num_pt <= capacity the database
// fits in one dimension, and fst_dim_sz is set to the *exact* request rather
// than padded up to capacity. With other_dim_sz = 1 the first dimension IS
// the database — there is no second dimension whose matmul partner the
// FST_DIM_POW2 policy exists to keep cheap — so padding only inflates storage
// and the per-query expansion + matmul cost. Expansion (fast_expand_qry), the
// first-dim matmul (level_mat_mat) and the num_dims==1 branch of
// evaluate_other_dim all accept an arbitrary fst_dim_sz in [1, capacity];
// nothing downstream requires a power of two.
//
// Loop walks num_dims upward and returns the smallest one that meets target.
// max_num_dims is just a loop bound; the inner `reserved >= capacity` break
// is the real correctness guard against size_t underflow.
//
// Args:
//   target_num_pt: minimum plaintexts the DB must hold (= DB_SIZE_MB / pt size).
//   l            : GSW gadget length used for "other"-dim reconstruction (= l_ep).
//   h            : expansion tree height (= TREE_HEIGHT).
// Returns: {fst_dim_sz, num_dims}.
std::pair<size_t, size_t> utils::calculate_db_shape(size_t target_num_pt, size_t l, size_t h) {
  const size_t capacity = size_t{1} << h;

  // Single-dimension fast path — fst_dim_sz is the exact request (see the
  // header comment above). target_num_pt == 0 is left to the loop below.
  if (target_num_pt > 0 && target_num_pt <= capacity) {
    return {target_num_pt, 1};
  }

  const size_t max_num_dims = 1 + (capacity - 1) / l;
  for (size_t num_dims = 1; num_dims <= max_num_dims + 1; num_dims++) {
    const size_t reserved = l * (num_dims - 1);
    if (reserved >= capacity) break;  // guard size_t underflow
    const size_t slack = capacity - reserved;
    const size_t fst_dim_sz = DBConsts::FST_DIM_POW2
        ? (size_t{1} << (std::bit_width(slack) - 1))
        : slack;
    if (fst_dim_sz * (size_t{1} << (num_dims - 1)) >= target_num_pt) {
      return {fst_dim_sz, num_dims};
    }
  }
  throw std::runtime_error("Failed to calculate database shape");
}

// ---------------------------------------------------------------------------
// Polynomial noise / randomness samplers
// ---------------------------------------------------------------------------

void utils::sample_gaussian(uint64_t *out, size_t N, uint64_t q, double sigma,
                             std::mt19937_64 &rng) {
  std::normal_distribution<double> dist(0.0, sigma);
  for (size_t i = 0; i < N; i++) {
    int64_t e = std::llround(dist(rng));
    if (e >= 0) {
      out[i] = static_cast<uint64_t>(e) % q;
    } else {
      uint64_t abs_e = static_cast<uint64_t>(-e) % q;
      out[i] = (abs_e == 0) ? 0 : (q - abs_e);
    }
  }
}

void utils::sample_uniform_poly(uint64_t *out, size_t N, uint64_t q,
                                 std::mt19937_64 &rng) {
  // Rejection sampling to avoid modular bias.
  const uint64_t limit = (~uint64_t{0}) - ((~uint64_t{0}) % q);
  for (size_t i = 0; i < N; i++) {
    uint64_t r;
    do { r = rng(); } while (r >= limit);
    out[i] = r % q;
  }
}

void utils::sample_ternary(uint64_t *out, size_t N, uint64_t q,
                            std::mt19937_64 &rng) {
  // Each coefficient is independently and uniformly in {0, 1, 2}.
  // Map: 0 → 0, 1 → 1, 2 → q-1 (represents -1 mod q).
  std::uniform_int_distribution<int> dist(0, 2);
  for (size_t i = 0; i < N; i++) {
    int v = dist(rng);
    if (v == 0)      out[i] = 0;
    else if (v == 1) out[i] = 1;
    else             out[i] = q - 1;
  }
}

uint64_t utils::rescale(uint64_t a, uint64_t inp_mod, uint64_t out_mod) {
  const int64_t inp_mod_i64 = static_cast<int64_t>(inp_mod);
  const __int128 out_mod_i128 = static_cast<__int128>(out_mod);

  int64_t v = static_cast<int64_t>(a % inp_mod);
  if (v >= inp_mod_i64 / 2) v -= inp_mod_i64;

  const int64_t sign = (v >= 0) ? 1 : -1;
  __int128 val = static_cast<__int128>(v) * static_cast<__int128>(out_mod);
  __int128 r = (val + static_cast<__int128>(sign * (inp_mod_i64 / 2))) /
               static_cast<__int128>(inp_mod);

  r = (r + static_cast<__int128>((inp_mod / out_mod) * out_mod) +
       2 * out_mod_i128) % out_mod_i128;
  return static_cast<uint64_t>((r + out_mod_i128) % out_mod_i128);
}