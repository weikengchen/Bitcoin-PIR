#include "tests.h"

// Quick sanity tests for self-contained arithmetic in utils:
//   - utils::is_prime (deterministic Miller-Rabin)
//   - utils::try_invert_uint_mod (extended Euclidean modular inverse)
void PirTest::test_utils_arith() {
  print_func_name(__FUNCTION__);

  // ===================== is_prime =====================
  BENCH_PRINT("--- utils::is_prime ---");
  const std::vector<uint64_t> primes = {
      2, 3, 5, 7, 11, 13, 97, 1000003,
      1152921504606748673ULL, // 60-bit PIR q
      1152921504606830593ULL, // second PIR prime
      36028797018820609ULL,   // small_q
      (1ULL << 61) - 1,       // Mersenne prime M61
  };
  const std::vector<uint64_t> composites = {
      0, 1, 4, 6, 9, 15, 21, 25, 49, 1000000,
      1152921504606748673ULL - 2,
      1ULL << 61,
      (1ULL << 60) + 1,
      3215031751ULL, // Carmichael-like; smallest strong pseudoprime to bases 2,3,5,7
  };

  int prime_fail = 0, comp_fail = 0;
  for (uint64_t p : primes) {
    if (!utils::is_prime(p)) {
      BENCH_PRINT("  MISS: " << p << " reported composite");
      ++prime_fail;
    }
  }
  for (uint64_t c : composites) {
    if (utils::is_prime(c)) {
      BENCH_PRINT("  MISS: " << c << " reported prime");
      ++comp_fail;
    }
  }
  BENCH_PRINT("  Primes recognized:     " << (primes.size() - prime_fail) << "/" << primes.size());
  BENCH_PRINT("  Composites recognized: " << (composites.size() - comp_fail) << "/" << composites.size());

  // ===================== try_invert_uint_mod =====================
  BENCH_PRINT("\n--- utils::try_invert_uint_mod ---");

  // Pairs where gcd(value, modulus) == 1 (invertible).
  struct Case { uint64_t val, mod; };
  const std::vector<Case> invertible = {
      {3, 7},
      {2, 1152921504606748673ULL},
      {1234567, 1152921504606748673ULL},
      {7, 36028797018820609ULL},
      {1ULL << 20, 1152921504606830593ULL},
  };
  // Pairs where gcd != 1 (should fail).
  const std::vector<Case> non_invertible = {
      {0, 7},
      {6, 9},      // gcd = 3
      {10, 100},   // gcd = 10
  };

  int inv_fail = 0;
  for (auto [val, mod] : invertible) {
    uint64_t inv;
    bool ok = utils::try_invert_uint_mod(val, mod, inv);
    // verify: (val * inv) mod modulus == 1
    __uint128_t prod = static_cast<__uint128_t>(val) * inv;
    uint64_t check = static_cast<uint64_t>(prod % mod);
    if (!ok || check != 1) {
      BENCH_PRINT("  MISS: inv(" << val << ", " << mod << ") -> ok=" << ok
                  << " inv=" << inv << " val*inv%mod=" << check);
      ++inv_fail;
    }
  }
  int noninv_fail = 0;
  for (auto [val, mod] : non_invertible) {
    uint64_t inv;
    bool ok = utils::try_invert_uint_mod(val, mod, inv);
    if (ok) {
      BENCH_PRINT("  MISS: inv(" << val << ", " << mod << ") should have failed, got " << inv);
      ++noninv_fail;
    }
  }
  BENCH_PRINT("  Invertible cases:     " << (invertible.size() - inv_fail) << "/" << invertible.size());
  BENCH_PRINT("  Non-invertible cases: " << (non_invertible.size() - noninv_fail) << "/" << non_invertible.size());

  // ===================== Summary =====================
  BENCH_PRINT("\n--- Summary ---");
  const int total = primes.size() + composites.size() + invertible.size() + non_invertible.size();
  const int failed = prime_fail + comp_fail + inv_fail + noninv_fail;
  BENCH_PRINT("Passed " << (total - failed) << "/" << total << " cases");
}
