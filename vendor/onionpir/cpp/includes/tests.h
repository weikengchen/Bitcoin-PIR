#pragma once

#include <string>

// Common includes used by most tests
#include "gsw.h"
#include "pir.h"
#include "server.h"
#include "client.h"
#include "utils.h"
#include "logging.h"
#include "matrix.h"

#include <cassert>
#include <iostream>
#include <bitset>

inline void print_throughput(const std::string &name, const size_t db_size) {
  double avg_time = GET_AVG_TIME(name);
  double throughput = db_size / (avg_time * 1000);
  BENCH_PRINT(name << ": " << throughput << " MB/s");
}

class PirTest {
  public:
    size_t num_experiments = 10;

    void run_test(const std::string &test_name);

    // ! the main test for PIR
    void test_pir();

    // ======================== BFV & GSW tests ========================
    void bfv_example();
    void test_external_product();
    void test_decrypt_mod_q();
    void test_ext_prod_mux();

    // ======================== Matrix tests ========================
    // simulation of the first dimension multiplication
    void test_fst_dim_mult();

    // ======================== System Information ========================
    void print_cpu_info();

    // ======================== Other tests ========================
    void test_fast_expand_query();
    void test_mod_switch();
    void test_db_shape();
    void test_bv_keyswitch();
    void test_hexl_ntt();
    void test_utils_arith();
    void test_noise_sampling();
    void test_rlwe_enc();
    void test_barrett();

    // Search (tree_height, num_queries, num_other_dims) for minimum total
    // communication in each (QueryMode, GswSource) combination, given the
    // current config's num_pt, L_EP, L_KEY and BFV ciphertext size.
    void plan_params();
};
