#include "tests.h"
#include "rlwe.h"

void PirTest::test_decrypt_mod_q() {
  // this is testing if custom decryption works for the original modulus. (no modulus switching involved)
  // ! Use Small parameters for this test
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirClient client(pir_params);

  const size_t coeff_count = DBConsts::PolyDegree;
  const uint64_t q = pir_params.get_rns_mods()[0];
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  std::mt19937_64 rng(std::random_device{}());

  std::vector<uint64_t> a(coeff_count, 0);
  a[0] = 1; a[1] = 2; a[2] = 4;
  BENCH_PRINT("Vector a[0..2]: " << a[0] << " " << a[1] << " " << a[2]);

  RlweCt rlwe_ct;
  encrypt_bfv(a, client.rlwe_sk_, coeff_count, q, t, sigma, rng, rlwe_ct);

  RlwePt result = client.decrypt_mod_q(rlwe_ct);
  BENCH_PRINT("Decrypted result[0..2]: " << result.data[0] << " "
                                         << result.data[1] << " "
                                         << result.data[2]);
}
