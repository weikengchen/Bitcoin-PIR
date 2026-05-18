#include "tests.h"

#include <array>
#include <chrono>
#include <limits>
#include <random>
#include <stdexcept>
#include <sstream>
#include <string>

namespace {

void check_case_u64(uint64_t x, uint64_t q) {
  const utils::BarrettU64 b = utils::barrett_u64_setup(q);
  const uint64_t got = utils::barrett_reduce_u64(x, b);
  const uint64_t want = x % q;
  if (got != want) {
    std::ostringstream os;
    os << "barrett_reduce_u64 mismatch: x=" << x
       << " q=" << q << " got=" << got << " want=" << want;
    throw std::runtime_error(os.str());
  }
}

void check_case(uint128_t x, uint64_t q) {
  const utils::BarrettU128 b = utils::barrett_u128_setup(q);
  const uint64_t got = utils::barrett_reduce_u128(x, b);
  const uint64_t want = static_cast<uint64_t>(x % q);
  if (got != want) {
    std::ostringstream os;
    os << "barrett_reduce_u128 mismatch: x_hi=" << static_cast<uint64_t>(x >> 64)
       << " x_lo=" << static_cast<uint64_t>(x)
       << " q=" << q << " got=" << got << " want=" << want;
    throw std::runtime_error(os.str());
  }
}

// Random uint128_t uniformly over [0, 2^width) for width in [1, 128].
uint128_t random_u128(std::mt19937_64 &rng, size_t width) {
  if (width == 0) return 0;
  if (width <= 64) {
    const uint64_t mask = (width == 64) ? ~uint64_t{0} : ((uint64_t{1} << width) - 1);
    return static_cast<uint128_t>(rng() & mask);
  }
  const uint64_t hi_bits = width - 64;
  const uint64_t hi_mask = (hi_bits == 64) ? ~uint64_t{0} : ((uint64_t{1} << hi_bits) - 1);
  const uint128_t hi = static_cast<uint128_t>(rng() & hi_mask) << 64;
  return hi | static_cast<uint128_t>(rng());
}

uint64_t sample_prime(std::mt19937_64 &rng, size_t bit_width) {
  const uint64_t base = utils::generate_prime(bit_width);
  return base; // Deterministic given bit_width; sufficient for this test.
}

} // namespace

void PirTest::test_barrett() {
  print_func_name(__FUNCTION__);

  std::mt19937_64 rng(0xBA77E77Fu);

  // === 64-bit-input reducer: correctness over common and edge moduli ===
  const std::array<uint64_t, 12> q_u64_set = {
      1,
      2,
      3,
      17,
      utils::generate_prime(29),
      utils::generate_prime(32),
      utils::generate_prime(40),
      utils::generate_prime(50),
      utils::generate_prime(60),
      (uint64_t{1} << 63) - 25,
      (uint64_t{1} << 63) + 29,
      std::numeric_limits<uint64_t>::max()};
  constexpr size_t u64_samples_per_modulus = 20000;

  size_t u64_cases = 0;
  for (uint64_t q : q_u64_set) {
    check_case_u64(0, q);
    check_case_u64(1, q);
    check_case_u64(q - 1, q);
    check_case_u64(q, q);
    check_case_u64(q + 1, q);
    check_case_u64(std::numeric_limits<uint64_t>::max(), q);
    u64_cases += 6;

    for (size_t i = 0; i < u64_samples_per_modulus; i++) {
      check_case_u64(rng(), q);
      u64_cases++;
    }
  }

  BENCH_PRINT("Barrett u64 correctness: " << u64_cases << " cases OK");

  // === Correctness grid: every (q_bits, x_bits) combo that actually appears ===
  const std::array<size_t, 7> q_bits_set  = {8, 17, 32, 40, 50, 60, 61};
  const std::array<size_t, 7> x_bits_set  = {16, 32, 64, 96, 120, 127, 128};
  constexpr size_t samples_per_combo = 1000;

  size_t cases = 0;
  for (size_t qb : q_bits_set) {
    const uint64_t q = sample_prime(rng, qb);
    for (size_t xb : x_bits_set) {
      for (size_t i = 0; i < samples_per_combo; i++) {
        const uint128_t x = random_u128(rng, xb);
        check_case(x, q);
        cases++;
      }
    }
  }

  // === Edge cases ===
  const uint64_t q60 = utils::generate_prime(60);
  check_case(0, q60);
  check_case(1, q60);
  check_case(q60 - 1, q60);
  check_case(q60, q60);
  check_case(q60 + 1, q60);
  check_case((uint128_t)q60 * q60, q60);
  check_case(~static_cast<uint128_t>(0), q60);                  // 2^128 - 1
  check_case(~static_cast<uint128_t>(0) - 1, q60);
  check_case(static_cast<uint128_t>(1) << 127, q60);            // top bit only
  check_case((static_cast<uint128_t>(1) << 127) | 1, q60);

  BENCH_PRINT("Barrett correctness: " << cases << " random + 10 edge cases OK");

  // === Perf sanity check: Barrett vs % ===
  //
  // Compute-bound microbenchmark: a small buffer that fits in L1 (16 KB),
  // many passes so cache misses vanish. The only thing varying is the
  // reduction method.
  constexpr size_t N = 1 << 10;              // 1024 coefficients (16 KB)
  constexpr int iters = 20000;               // 20M reductions per variant
  std::vector<uint128_t> xs(N);
  for (size_t i = 0; i < N; i++) xs[i] = random_u128(rng, 120);
  const uint64_t q = q60;
  const utils::BarrettU128 b = utils::barrett_u128_setup(q);

  volatile uint64_t sink = 0;

  // Warm up
  for (int r = 0; r < 10; r++)
    for (size_t i = 0; i < N; i++) sink ^= utils::barrett_reduce_u128(xs[i], b);
  for (int r = 0; r < 10; r++)
    for (size_t i = 0; i < N; i++) sink ^= static_cast<uint64_t>(xs[i] % q);

  using clk = std::chrono::steady_clock;

  auto t0 = clk::now();
  for (int r = 0; r < iters; r++)
    for (size_t i = 0; i < N; i++) sink ^= utils::barrett_reduce_u128(xs[i], b);
  auto t1 = clk::now();

  auto t2 = clk::now();
  for (int r = 0; r < iters; r++)
    for (size_t i = 0; i < N; i++) sink ^= static_cast<uint64_t>(xs[i] % q);
  auto t3 = clk::now();

  const double total = static_cast<double>(iters) * N;
  const double barrett_ns = std::chrono::duration<double, std::nano>(t1 - t0).count() / total;
  const double percent_ns = std::chrono::duration<double, std::nano>(t3 - t2).count() / total;

  // 64-bit-input variant benchmark.
  std::vector<uint64_t> xs64(N);
  for (size_t i = 0; i < N; i++) xs64[i] = rng();
  const utils::BarrettU64 b64 = utils::barrett_u64_setup(q);

  for (int r = 0; r < 10; r++)
    for (size_t i = 0; i < N; i++) sink ^= utils::barrett_reduce_u64(xs64[i], b64);
  for (int r = 0; r < 10; r++)
    for (size_t i = 0; i < N; i++) sink ^= xs64[i] % q;

  auto t4 = clk::now();
  for (int r = 0; r < iters; r++)
    for (size_t i = 0; i < N; i++) sink ^= utils::barrett_reduce_u64(xs64[i], b64);
  auto t5 = clk::now();

  auto t6 = clk::now();
  for (int r = 0; r < iters; r++)
    for (size_t i = 0; i < N; i++) sink ^= xs64[i] % q;
  auto t7 = clk::now();

  const double barrett_u64_ns =
      std::chrono::duration<double, std::nano>(t5 - t4).count() / total;
  const double percent_u64_ns =
      std::chrono::duration<double, std::nano>(t7 - t6).count() / total;

  BENCH_PRINT("Per-reduction cost (q = " << q << ", compute-bound, uint64 input):");
  BENCH_PRINT("  barrett_reduce_u64  : " << barrett_u64_ns << " ns");
  BENCH_PRINT("  x % q               : " << percent_u64_ns << " ns");
  BENCH_PRINT("  speedup             : " << (percent_u64_ns / barrett_u64_ns) << "x");

  BENCH_PRINT("Per-reduction cost (q = " << q << ", compute-bound, uint128 input):");
  BENCH_PRINT("  barrett_reduce_u128 : " << barrett_ns << " ns");
  BENCH_PRINT("  x % q               : " << percent_ns << " ns");
  BENCH_PRINT("  speedup             : " << (percent_ns / barrett_ns) << "x");

  (void)sink;
}
