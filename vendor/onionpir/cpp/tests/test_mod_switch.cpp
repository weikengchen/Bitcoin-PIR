#include "tests.h"
#include "rlwe.h"
#include <sstream>
#include <stdexcept>

void PirTest::test_mod_switch() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirServer server(pir_params);
  PirClient client(pir_params);
  const size_t coeff_count = DBConsts::PolyDegree;
  const std::vector<uint64_t> qs(pir_params.get_rns_mods().begin(),
                                 pir_params.get_rns_mods().end());
  const uint64_t small_q = pir_params.get_small_q();
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  std::mt19937_64 rng(std::random_device{}());

  std::vector<uint64_t> pt(coeff_count, 0);
  for (size_t i = 0; i < 10; ++i) { pt[i] = rand() % t; }

  BENCH_PRINT("K=" << qs.size() << " new q: " << small_q);

  RlweCt rlwe_ct;
  encrypt_bfv_rns(pt, client.rlwe_sk_, coeff_count, qs, t, sigma, rng, rlwe_ct);

  // decrypt the see the oritinal pt

  server.mod_switch_inplace(rlwe_ct, small_q);

  RlwePt result = client.decrypt_mod_q(rlwe_ct);
  BENCH_PRINT("Client decrypted[0..9]: "
              << result.data[0] << " " << result.data[1] << " " << result.data[2]
              << " " << result.data[3] << " " << result.data[4] << " " << result.data[5]
              << " " << result.data[6] << " " << result.data[7] << " " << result.data[8]
              << " " << result.data[9]);
  for (size_t i = 0; i < coeff_count; i++) {
    if (result.data[i] != pt[i]) {
      std::ostringstream os;
      os << "mod_switch decrypt mismatch at coefficient " << i
         << ": got " << result.data[i] << " want " << pt[i];
      throw std::runtime_error(os.str());
    }
  }

  // verify if ct coeffs are all less than small_q
  bool can_compress = true; // if so, then we can use 32 bits to store the coeffs.
  for (size_t i = 0; i < coeff_count; i++) {
    if (rlwe_ct.c0[i] >= small_q) {
      BENCH_PRINT("rlwe_ct.c0[" << i << "] = " << rlwe_ct.c0[i]);
      BENCH_PRINT("coeff >= small_q");
      can_compress = false;
    }
  }
  BENCH_PRINT("can_compress: " << can_compress);
}
