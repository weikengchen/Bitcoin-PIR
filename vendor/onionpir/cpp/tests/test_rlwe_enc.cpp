#include "tests.h"
#include "rlwe.h"
#include "hexl/hexl.hpp"
#include <algorithm>
#include <cmath>

void PirTest::test_rlwe_enc() {
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  const size_t   N     = DBConsts::PolyDegree;
  const uint64_t q     = pir_params.get_rns_mods()[0];
  const uint64_t t     = pir_params.get_plain_mod();
  const double   sigma = pir_params.get_noise_std_dev();

  std::mt19937_64 rng(12345);

  BENCH_PRINT("N=" << N << "  q=" << q << " (" << std::ceil(std::log2(q)) << " bits)"
              << "  t=" << t << "  sigma=" << sigma);

  RlweSk sk = gen_secret_key(N, q, rng);
  BENCH_PRINT("Secret key: " << sk.data.size() << " NTT-form coefficients");

  int passed = 0, total = 0;

  // ---------------------------------------------------------------------------
  // Test 1: encrypt_zero (coef form) → decrypt → all-zeros plaintext
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 1: encrypt_zero (coef) + decrypt → 0 ---");
  {
    RlweCt ct;
    encrypt_zero(sk, N, q, sigma, rng, ct, /*ntt_form=*/false);
    RlwePt pt;
    decrypt(ct, sk, N, q, t, pt);

    size_t nonzero = std::count_if(pt.data.begin(), pt.data.end(),
                                   [](uint64_t v) { return v != 0; });
    bool ok = (nonzero == 0);
    BENCH_PRINT("  nonzero coeffs after decrypt: " << nonzero << " / " << N
                << "  → " << (ok ? "OK" : "FAIL"));
    total++; if (ok) passed++;
  }

  // ---------------------------------------------------------------------------
  // Test 2: zero + delta * m → decrypt → recover m
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 2: encrypt(zero) + delta*m round-trip ---");
  {
    RlweCt ct;
    encrypt_zero(sk, N, q, sigma, rng, ct, /*ntt_form=*/false);

    const uint64_t delta = q / t;
    std::vector<uint64_t> m = {1, 2, 42, 0, 7, t - 1, t / 2, 3};
    for (size_t i = 0; i < m.size(); i++) {
      ct.c0[i] = (ct.c0[i] + (delta * m[i]) % q) % q;
    }

    RlwePt pt;
    decrypt(ct, sk, N, q, t, pt);

    bool ok = true;
    for (size_t i = 0; i < m.size(); i++) {
      if (pt.data[i] != m[i]) {
        BENCH_PRINT("  [" << i << "] expected=" << m[i] << "  got=" << pt.data[i]);
        ok = false;
      }
    }
    BENCH_PRINT("  Round-trip on " << m.size() << " slots: " << (ok ? "OK" : "FAIL"));
    total++; if (ok) passed++;
  }

  // ---------------------------------------------------------------------------
  // Test 3: encrypt_zero in NTT form → decrypt → zero
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 3: encrypt_zero (NTT) + decrypt → 0 ---");
  {
    RlweCt ct;
    encrypt_zero(sk, N, q, sigma, rng, ct, /*ntt_form=*/true);

    // Sanity: ct.ntt_form is true
    bool tag_ok = ct.is_ntt_form();

    RlwePt pt;
    decrypt(ct, sk, N, q, t, pt);

    size_t nonzero = std::count_if(pt.data.begin(), pt.data.end(),
                                   [](uint64_t v) { return v != 0; });
    bool ok = tag_ok && (nonzero == 0);
    BENCH_PRINT("  ntt_form flag set: " << (tag_ok ? "YES" : "NO")
                << "  nonzero coeffs: " << nonzero
                << "  → " << (ok ? "OK" : "FAIL"));
    total++; if (ok) passed++;
  }

  // ---------------------------------------------------------------------------
  // Test 4: fresh-ciphertext noise magnitude — should be small.
  // phase = c0 + c1*s ≡ -e (mod q).  The max |e| over N=2048 samples from
  // N(0, 3.2²) should be roughly 5σ ≈ 16, well under q/2 ≈ 2^59.
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 4: fresh-ciphertext noise magnitude ---");
  {
    RlweCt ct;
    encrypt_zero(sk, N, q, sigma, rng, ct, /*ntt_form=*/false);

    // phase = c0 + c1 * s  (coef form)
    std::vector<uint64_t> c1_ntt = ct.c1;
    utils::ntt_fwd(c1_ntt.data(), N, q);
    std::vector<uint64_t> phase(N);
    intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk.data.data(), N, q, 1);
    utils::ntt_inv(phase.data(), N, q);
    intel::hexl::EltwiseAddMod(phase.data(), phase.data(), ct.c0.data(), N, q);

    uint64_t max_abs = 0;
    for (size_t i = 0; i < N; i++) {
      uint64_t abs_val = (phase[i] > q / 2) ? (q - phase[i]) : phase[i];
      if (abs_val > max_abs) max_abs = abs_val;
    }
    double noise_bits  = (max_abs > 0) ? std::log2(static_cast<double>(max_abs)) : 0;
    double budget_bits = std::log2(static_cast<double>(q) / 2.0) - noise_bits;
    BENCH_PRINT("  max |phase| = " << max_abs << "  (~" << noise_bits << " bits)");
    BENCH_PRINT("  noise budget ≈ " << budget_bits << " bits");

    // Expect max |e| well below q/2. A loose check: max |e| < 100 for sigma=3.2 is
    // overwhelmingly likely (5σ ≈ 16, 10σ ≈ 32, <100 with astronomical probability).
    bool ok = (max_abs < 100);
    BENCH_PRINT("  max |phase| < 100: " << (ok ? "OK" : "FAIL"));
    total++; if (ok) passed++;
  }

  // ---------------------------------------------------------------------------
  // Test 5: σ is actually wired through — larger σ produces larger noise.
  // ---------------------------------------------------------------------------
  BENCH_PRINT("\n--- Test 5: sigma propagation (larger σ → larger max|e|) ---");
  {
    auto max_noise_for_sigma = [&](double s) -> uint64_t {
      RlweCt ct;
      encrypt_zero(sk, N, q, s, rng, ct, /*ntt_form=*/false);
      std::vector<uint64_t> c1_ntt = ct.c1;
      utils::ntt_fwd(c1_ntt.data(), N, q);
      std::vector<uint64_t> phase(N);
      intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk.data.data(), N, q, 1);
      utils::ntt_inv(phase.data(), N, q);
      intel::hexl::EltwiseAddMod(phase.data(), phase.data(), ct.c0.data(), N, q);
      uint64_t m = 0;
      for (size_t i = 0; i < N; i++) {
        uint64_t a = (phase[i] > q / 2) ? (q - phase[i]) : phase[i];
        if (a > m) m = a;
      }
      return m;
    };
    uint64_t e_small = max_noise_for_sigma(1.0);
    uint64_t e_med   = max_noise_for_sigma(3.2);
    uint64_t e_big   = max_noise_for_sigma(30.0);
    BENCH_PRINT("  sigma=1.0   → max|e|=" << e_small);
    BENCH_PRINT("  sigma=3.2   → max|e|=" << e_med);
    BENCH_PRINT("  sigma=30.0  → max|e|=" << e_big);
    bool ok = (e_small < e_med) && (e_med < e_big);
    BENCH_PRINT("  monotonic in sigma: " << (ok ? "OK" : "FAIL"));
    total++; if (ok) passed++;
  }

  BENCH_PRINT("\n--- Summary ---");
  BENCH_PRINT("Passed " << passed << "/" << total << " sub-tests");
}
