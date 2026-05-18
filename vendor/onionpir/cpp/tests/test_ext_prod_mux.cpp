#include "tests.h"
#include "rlwe.h"

void PirTest::test_ext_prod_mux() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirServer server(pir_params);
  PirClient client(pir_params);
  const size_t coeff_count = DBConsts::PolyDegree;
  const std::vector<uint64_t> qs(pir_params.get_rns_mods().begin(),
                                 pir_params.get_rns_mods().end());
  const RnsTables &tables = pir_params.get_rns_tables();
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  std::mt19937_64 rng(0x1234ULL);

  std::vector<uint64_t> a(coeff_count, 0), b(coeff_count, 0);
  a[0] = 5; a[1] = 7;
  b[0] = 3; b[1] = 9;

  RlweCt a_ct, b_ct;
  encrypt_bfv_rns(a, client.rlwe_sk_, coeff_count, qs, t, sigma, rng, a_ct);
  encrypt_bfv_rns(b, client.rlwe_sk_, coeff_count, qs, t, sigma, rng, b_ct);

  std::vector<uint64_t> one(coeff_count, 0); one[0] = 1;
  GSWEval data_gsw(pir_params, pir_params.get_l(), pir_params.get_base_log2());
  GSWCt one_gsw = data_gsw.plain_to_gsw(one, client.rlwe_sk_, rng);

  RlweCt result;
  result.c0.assign(coeff_count * qs.size(), 0);
  result.c1.assign(coeff_count * qs.size(), 0);
  server.ext_prod_mux(a_ct, b_ct, one_gsw, result);

  RlwePt pt;
  decrypt_rns(result, client.rlwe_sk_, coeff_count, qs, t, tables, pt);
  BENCH_PRINT("K=" << qs.size() << " mux(RGSW(1), a, b) = b expected; got[0,1,2] = "
                   << pt.data[0] << " " << pt.data[1] << " " << pt.data[2]);
  BENCH_PRINT("expected b[0..2] = " << b[0] << " " << b[1] << " " << b[2]);
  PRINT_BAR;
}
