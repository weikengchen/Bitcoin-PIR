#include "tests.h"
#include "bv_keyswitch.h"
#include "rlwe.h"
#include "utils.h"
#include <random>

// ============================================================================
// Unit test: signed gadget decomposition
// ============================================================================
static void test_signed_decompose() {
  std::cout << "--- test_signed_decompose ---\n";

  PirParams pir_params;
  const size_t q_bits = pir_params.get_ct_mod_width();
  const size_t base_log2 = (q_bits + bvks::L_KS - 1) / bvks::L_KS;
  const uint64_t B = uint64_t(1) << base_log2;
  const uint64_t q = pir_params.get_rns_mods()[0];
  const uint64_t half_q = q >> 1;

  std::mt19937_64 rng(42);
  constexpr size_t num_tests = 10000;
  size_t max_digit_mag = 0;

  for (size_t t = 0; t < num_tests; ++t) {
    uint64_t val = rng() % q;
    uint64_t digits[bvks::L_KS];
    bvks::signed_gadget_decompose(val, base_log2, q, digits, bvks::L_KS);

    // 1. Reconstruction: Σ digits[i] * B^i ≡ val (mod q)
    uint128_t reconstructed = 0;
    uint128_t Bi = 1;
    for (size_t i = 0; i < bvks::L_KS; ++i) {
      reconstructed = (reconstructed + (static_cast<uint128_t>(digits[i]) * Bi) % q) % q;
      Bi = (Bi * B) % q;
    }
    if (static_cast<uint64_t>(reconstructed) != val) {
      std::cout << "FAIL: reconstruction mismatch at val=" << val
                << " got=" << static_cast<uint64_t>(reconstructed) << "\n";
      return;
    }

    // 2. Each digit has signed magnitude ≤ B/2
    for (size_t i = 0; i < bvks::L_KS; ++i) {
      uint64_t mag = (digits[i] > half_q) ? (q - digits[i]) : digits[i];
      if (mag > max_digit_mag) max_digit_mag = mag;
      if (mag > B / 2) {
        std::cout << "FAIL: digit " << i << " has magnitude " << mag
                  << " > B/2=" << (B / 2) << " at val=" << val << "\n";
        return;
      }
    }
  }

  std::cout << "PASS: " << num_tests << " random values reconstructed correctly\n";
  std::cout << "  base_log2=" << base_log2 << ", B=" << B
            << ", max digit magnitude=" << max_digit_mag << " (B/2=" << (B / 2) << ")\n";
}

// ============================================================================
// Unit test: BV key-switching correctness
//
// Encrypt a known plaintext, apply the galois automorphism σ_k via BV
// key-switching, decrypt natively, and verify the result matches the
// automorphism applied directly to the plaintext.
// ============================================================================
void PirTest::test_bv_keyswitch() {
  test_signed_decompose();
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  constexpr size_t N  = DBConsts::PolyDegree;
  const std::vector<uint64_t> qs(pir_params.get_rns_mods().begin(),
                                 pir_params.get_rns_mods().end());
  const uint64_t t    = pir_params.get_plain_mod();
  const double sigma  = pir_params.get_noise_std_dev();
  const RnsTables &tables = pir_params.get_rns_tables();
  const uint32_t galois_k = 257; // 2^8 + 1

  BENCH_PRINT("K=" << qs.size() << " N=" << N << " t=" << t);

  std::mt19937_64 rng(std::random_device{}());
  RlweSk sk = gen_secret_key_rns(N, qs, rng);

  // Build a plaintext with a few distinctive coefficients.
  std::vector<uint64_t> pt(N, 0);
  pt[0] = 1; pt[1] = 2; pt[2] = 3;
  pt[10] = 10; pt[11] = 11; pt[12] = 12;

  // Encrypt (coeff form).
  RlweCt ct;
  encrypt_bfv_rns(pt, sk, N, qs, t, sigma, rng, ct);

  {
    RlwePt dec;
    decrypt_rns(ct, sk, N, qs, t, tables, dec);
    BENCH_PRINT("fresh decrypt[0..2]: " << dec.data[0] << ", " << dec.data[1] << ", " << dec.data[2]);
  }

  // Expected result after σ_k: apply automorphism to the plaintext directly.
  std::vector<uint64_t> pt_auto(N, 0);
  utils::automorphism_coeff(pt.data(), N, galois_k, t, pt_auto.data());

  // bv_apply_galois_inplace expects a coefficient-form ciphertext.
  auto bv_ksk = bvks::gen_bv_ks_key(pir_params, sk, galois_k, rng);
  bvks::bv_apply_galois_inplace(ct, galois_k, bv_ksk, pir_params);

  RlwePt dec_bv;
  decrypt_rns(ct, sk, N, qs, t, tables, dec_bv);
  // BENCH_PRINT("BV galois decrypt[0..2]: " << dec_bv.data[0] << ", " << dec_bv.data[1] << ", " << dec_bv.data[2]);
  // BENCH_PRINT("coeff at idx " << 1 << " maps to: " << galois_k << " got=" << dec_bv.data[galois_k] << " expected: " << pt_auto[galois_k]);
  // BENCH_PRINT("coeff at idx " << 2 << " maps to: " << galois_k * 2 << " got=" << dec_bv.data[galois_k * 2] << " expected: " << pt_auto[galois_k * 2]);
  // BENCH_PRINT("coeff at idx " << 3 << " maps to: " << galois_k * 3 << " got=" << dec_bv.data[galois_k * 3] << " expected: " << pt_auto[galois_k * 3]);
  // print all the non-zero coeffs.
  for (size_t i = 0; i < N; i++) {
    if (dec_bv.data[i] != 0) {
      std::cout << "coeff[" << i << "] = " << dec_bv.data[i] << "\n";
    }
  }
  
  for (size_t i = 0; i < N; i++) {
    if (pt_auto[i] != 0) {
      std::cout << "coeff[" << i << "] = " << pt_auto[i] << "\n";
    }
  }

  // Compare against expected automorphism of the plaintext.
  size_t diffs = 0;
  for (size_t i = 0; i < N; i++) {
    if (dec_bv.data[i] != pt_auto[i]) {
      if (diffs < 5) {
        std::cout << "  [" << i << "] expected=" << pt_auto[i]
                  << "  got=" << dec_bv.data[i] << "\n";
      }
      ++diffs;
    }
  }
  if (diffs == 0) {
    std::cout << "PASS: BV key-switch matches native automorphism of plaintext\n";
  } else {
    std::cout << "FAIL: " << diffs << " / " << N << " coefficients differ\n";
  }
}
