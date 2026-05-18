#include "tests.h"
#include <cmath>

void PirTest::test_noise_sampling() {
  print_func_name(__FUNCTION__);

  constexpr size_t N = 10000; // large N for reliable statistics
  PirParams pir_params;
  const uint64_t q = pir_params.get_rns_mods()[0];
  std::mt19937_64 rng(12345);

  // ---------------------------------------------------------------------------
  // Background: sigma_std vs. width parameter (used in Spiral / Respire / Inspire)
  //
  // Spiral/Respire define the discrete Gaussian weight as:
  //   p(x) ∝ exp(-π * x² / width²)
  //
  // The standard Gaussian density is:
  //   f(x) ∝ exp(-x² / (2 * sigma_std²))
  //
  // Matching exponents:  -π / width² = -1 / (2 * sigma_std²)
  //   => sigma_std = width / sqrt(2π)
  //
  // Verification from Spiral source (core.cpp:183-184):
  //   width = 6.4,  std_dev = 2.55323059
  //   6.4 / sqrt(2π) ≈ 2.55323  ✓
  //
  // Our sampler takes sigma_std directly (the standard deviation).
  // ---------------------------------------------------------------------------

  const double SQRT_2PI = std::sqrt(2.0 * M_PI);
  BENCH_PRINT("Sigma/width conversion: sigma_std = width / sqrt(2*pi)");
  BENCH_PRINT("  sqrt(2*pi) = " << SQRT_2PI);
  BENCH_PRINT("Reference values from Spiral (core.cpp:183-184):");
  BENCH_PRINT("  width=6.4  std_dev=2.55323059  check=" << 6.4 / SQRT_2PI);
  BENCH_PRINT("Common parameter conversions:");
  for (double width : {6.4, 6.0, 8.0, 3.2 * SQRT_2PI}) {
    BENCH_PRINT("  width=" << width << "  => sigma_std=" << width / SQRT_2PI);
  }

  // ---------------------------------------------------------------------------
  // Test 1: sample_gaussian — mean ≈ 0, std dev ≈ sigma
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 1: sample_gaussian statistics (sigma_std parameterization) ---");

  auto centred = [&](uint64_t v) -> double {
    // Map from [0, q) to signed (-q/2, q/2].
    // Subtraction must be done in int64_t before converting to double: q is a
    // 60-bit prime (> 2^53), so double(q-1) - double(q) rounds to 0 instead of -1.
    if (v > q / 2)
      return static_cast<double>(static_cast<int64_t>(v) - static_cast<int64_t>(q));
    return static_cast<double>(v);
  };

  int pass1 = 0, total1 = 0;
  for (double sigma_std : {1.0, 3.2, 6.0}) {
    double width_equiv = sigma_std * SQRT_2PI;
    std::vector<uint64_t> buf(N);
    utils::sample_gaussian(buf.data(), N, q, sigma_std, rng);

    double mean = 0.0;
    for (size_t i = 0; i < N; i++) mean += centred(buf[i]);
    mean /= static_cast<double>(N);

    double var = 0.0;
    for (size_t i = 0; i < N; i++) {
      double d = centred(buf[i]) - mean;
      var += d * d;
    }
    var /= static_cast<double>(N);
    double stddev = std::sqrt(var);

    bool mean_ok   = std::abs(mean) < 0.15 * sigma_std;
    bool stddev_ok = std::abs(stddev - sigma_std) / sigma_std < 0.05; // within 5%
    total1 += 2;
    pass1  += (mean_ok ? 1 : 0) + (stddev_ok ? 1 : 0);
    BENCH_PRINT("sigma_std=" << sigma_std << "  (equiv. width=" << width_equiv << ")"
                << "  measured: mean=" << mean << "  stddev=" << stddev
                << "  mean_ok=" << (mean_ok ? "YES" : "NO")
                << "  stddev_ok=" << (stddev_ok ? "YES" : "NO"));
  }

  // ---------------------------------------------------------------------------
  // Test 2: sample_uniform_poly — values in [0, q), uniform distribution
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 2: sample_uniform_poly ---");
  {
    std::vector<uint64_t> buf(N);
    utils::sample_uniform_poly(buf.data(), N, q, rng);

    bool range_ok = std::all_of(buf.begin(), buf.end(), [&](uint64_t v){ return v < q; });

    // Split [0,q) into 8 buckets — expect roughly N/8 each.
    std::vector<size_t> buckets(8, 0);
    for (uint64_t v : buf) buckets[v * 8 / q]++;
    double chi2 = 0.0;
    double expected = static_cast<double>(N) / 8.0;
    for (size_t cnt : buckets) {
      double d = static_cast<double>(cnt) - expected;
      chi2 += d * d / expected;
    }
    // Chi-squared with 7 dof: p=0.001 critical value ≈ 24.3.
    bool uniform_ok = (chi2 < 25.0);
    BENCH_PRINT("Range check (all < q): " << (range_ok ? "OK" : "FAIL"));
    BENCH_PRINT("Chi-squared statistic: " << chi2 << " (pass < 25.0): "
                << (uniform_ok ? "OK" : "FAIL"));
  }

  // ---------------------------------------------------------------------------
  // Test 3: sample_ternary — values in {0, 1, q-1}, roughly equal probability
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 3: sample_ternary ---");
  {
    std::vector<uint64_t> buf(N);
    utils::sample_ternary(buf.data(), N, q, rng);

    size_t cnt0 = 0, cnt1 = 0, cnt_neg1 = 0, cnt_other = 0;
    for (uint64_t v : buf) {
      if (v == 0)          cnt0++;
      else if (v == 1)     cnt1++;
      else if (v == q - 1) cnt_neg1++;
      else                 cnt_other++;
    }
    double expected = static_cast<double>(N) / 3.0;
    bool support_ok = (cnt_other == 0);
    bool balance_ok = (std::abs(static_cast<double>(cnt0)     - expected) < 0.05 * expected &&
                       std::abs(static_cast<double>(cnt1)     - expected) < 0.05 * expected &&
                       std::abs(static_cast<double>(cnt_neg1) - expected) < 0.05 * expected);
    BENCH_PRINT("cnt(0)=" << cnt0 << "  cnt(1)=" << cnt1 << "  cnt(q-1)=" << cnt_neg1
                << "  cnt(other)=" << cnt_other);
    BENCH_PRINT("Support only {0,1,q-1}: " << (support_ok ? "OK" : "FAIL"));
    BENCH_PRINT("Roughly balanced (within 5%): " << (balance_ok ? "OK" : "FAIL"));
  }

  // ---------------------------------------------------------------------------
  // Summary
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Summary ---");
  BENCH_PRINT("Test 1 sub-checks: " << pass1 << "/" << total1
              << " (mean and stddev for 3 sigma values)");
}
