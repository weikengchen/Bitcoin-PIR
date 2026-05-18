#include "tests.h"

void PirTest::run_test(const std::string &test_name) {
  std::cout << "Running test: " << test_name << std::endl;

  if (test_name == "pir")                    test_pir();
  else if (test_name == "bfv")               bfv_example();
  else if (test_name == "ext_prod")          test_external_product();
  else if (test_name == "ext_prod_mux")      test_ext_prod_mux();
  else if (test_name == "fst_dim")           test_fst_dim_mult();
  else if (test_name == "fast_expand")       test_fast_expand_query();
  else if (test_name == "decrypt_mod_q")     test_decrypt_mod_q();
  else if (test_name == "mod_switch")        test_mod_switch();
  else if (test_name == "db_shape")          test_db_shape();
  else if (test_name == "bv_ks")             test_bv_keyswitch();
  else if (test_name == "cpu_info")          print_cpu_info();
  else if (test_name == "hexl_ntt")          test_hexl_ntt();
  else if (test_name == "utils_arith")       test_utils_arith();
  else if (test_name == "noise_sampling")    test_noise_sampling();
  else if (test_name == "rlwe_enc")          test_rlwe_enc();
  else if (test_name == "barrett")           test_barrett();
  else if (test_name == "plan_params")       plan_params();
  else {
    std::cerr << "Unknown test: " << test_name << std::endl;
    std::cerr << "Available tests: pir, bfv, ext_prod, ext_prod_mux, "
              << "fst_dim, fast_expand, decrypt_mod_q, "
              << "mod_switch, db_shape, hexl_ntt, utils_arith, "
              << "noise_sampling, rlwe_enc, cpu_info, bv_ks, "
              << "plan_params" << std::endl;
  }
}
