#include "tests.h"
#include "rlwe.h"
#include <stdexcept>

// Pretty-print an RlwePt like seal::Plaintext::to_string (hex, high-deg first).
static std::string pt_to_string(const RlwePt &pt) {
  std::string s;
  bool first = true;
  for (size_t i = pt.data.size(); i > 0; i--) {
    uint64_t c = pt.data[i - 1];
    if (c == 0) continue;
    if (!first) s += " + ";
    first = false;
    char buf[64];
    if (i - 1 == 0)      std::snprintf(buf, sizeof(buf), "%lX", c);
    else if (i - 1 == 1) std::snprintf(buf, sizeof(buf), "%lXx", c);
    else                 std::snprintf(buf, sizeof(buf), "%lXx^%zu", c, i - 1);
    s += buf;
  }
  return first ? "0" : s;
}

// This is a BFV x GSW example
void PirTest::test_external_product() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  const size_t coeff_count = DBConsts::PolyDegree;

  // ================== Create RGSW(1) ==================
  const size_t gsw_l = pir_params.get_l();
  const size_t base_log2 = pir_params.get_base_log2();
  GSWEval data_gsw(pir_params, gsw_l, base_log2);

  std::vector<uint64_t> one(coeff_count);
  std::vector<uint64_t> zero(coeff_count);
  one[0] = 1;

  const uint64_t q = pir_params.get_rns_mods()[0];
  const uint64_t t = pir_params.get_plain_mod();
  std::mt19937_64 rng(std::random_device{}());
  RlweSk rlwe_sk = gen_secret_key(coeff_count, q, rng);

  GSWCt one_gsw  = data_gsw.plain_to_gsw(one,  rlwe_sk, rng);
  GSWCt zero_gsw = data_gsw.plain_to_gsw(zero, rlwe_sk, rng);

  // ================== Create BFV(a) ==================
  std::vector<uint64_t> a(coeff_count);
  a[0] = t / 2 + 1; a[1] = t / 2 + 2; a[2] = t / 2 + 3;
  RlweCt a_encrypted;
  encrypt_bfv(a, rlwe_sk, coeff_count, q, t,
              pir_params.get_noise_std_dev(), rng, a_encrypted);

  // Expected plaintexts: BFV(a) * RGSW(1) = a, BFV(a) * RGSW(0) = 0.
  RlwePt expect_a;    expect_a.data = a;
  RlwePt expect_zero; expect_zero.data = zero;

  // ================== Test external product ==================
  RlweCt ext_prod_result;
  ext_prod_result.resize(coeff_count);
  RlwePt result;

  data_gsw.external_product(one_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  ext_prod_result.ntt_form = true;
  rlwe_ntt_inv_inplace(ext_prod_result, q, coeff_count);
  {
    int budget = decrypt_and_budget(ext_prod_result, rlwe_sk, coeff_count, q, t, result);
    BENCH_PRINT("BFV(a) * RGSW(1) = " << pt_to_string(result));
    BENCH_PRINT("Noise budget: " << budget);
    if (!utils::plaintext_is_equal(result, expect_a)) {
      throw std::runtime_error("BFV(a) * RGSW(1) != a");
    }
    if (budget <= 0) {
      throw std::runtime_error("BFV(a) * RGSW(1): non-positive noise budget");
    }
  }
  PRINT_BAR;

  data_gsw.external_product(zero_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  ext_prod_result.ntt_form = true;
  rlwe_ntt_inv_inplace(ext_prod_result, q, coeff_count);
  {
    int budget = decrypt_and_budget(ext_prod_result, rlwe_sk, coeff_count, q, t, result);
    BENCH_PRINT("BFV(a) * RGSW(0) = " << pt_to_string(result));
    BENCH_PRINT("Noise budget: " << budget);
    if (!utils::plaintext_is_equal(result, expect_zero)) {
      throw std::runtime_error("BFV(a) * RGSW(0) != 0");
    }
    if (budget <= 0) {
      throw std::runtime_error("BFV(a) * RGSW(0): non-positive noise budget");
    }
  }
  PRINT_BAR;

  // external product: BFV(a) * RGSW(1) for 100 times
  TIME_START("External product");
  for (size_t i = 0; i < 100; i++) {
    data_gsw.external_product(one_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  }
  TIME_END("External product");

  END_EXPERIMENT();
  PRINT_RESULTS();
}
