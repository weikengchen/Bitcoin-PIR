#include "tests.h"
#include "bv_keyswitch.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// Run a full PIR round-trip on a freshly-shaped `PirParams` and verify every
// probed index decrypts back to the stored plaintext. Exercises the genuinely
// small single-dimension path end to end: query expansion, first-dim matmul,
// the num_dims==1 branch of evaluate_other_dim, mod-switch and decryption.
// Throws on any shape or correctness mismatch.
void run_small_db_e2e(size_t requested_num_pt) {
  PirParams pir_params(requested_num_pt);

  // A single-dimension DB sized exactly to the request — no padding to 2^h.
  if (pir_params.get_num_pt()       != requested_num_pt ||
      pir_params.get_fst_dim_sz()   != requested_num_pt ||
      pir_params.get_num_dims()     != 1 ||
      pir_params.get_other_dim_sz() != 1) {
    throw std::runtime_error(
        "small-DB shape wrong for requested num_pt=" +
        std::to_string(requested_num_pt) + ": num_pt=" +
        std::to_string(pir_params.get_num_pt()) + " fst_dim_sz=" +
        std::to_string(pir_params.get_fst_dim_sz()) + " num_dims=" +
        std::to_string(pir_params.get_num_dims()) + " other_dim_sz=" +
        std::to_string(pir_params.get_other_dim_sz()));
  }

  const size_t n = pir_params.get_num_pt();
  BENCH_PRINT("--- end-to-end: " << n << "-plaintext single-dimension DB ---");

  // Probe the corners and the middle (exercises col_idx / bit_reverse edges).
  std::vector<size_t> probes = {0, 1, n / 2, n - 1};
  std::sort(probes.begin(), probes.end());
  probes.erase(std::unique(probes.begin(), probes.end()), probes.end());

  PirServer server(pir_params);
  server.gen_data(probes);  // records `probes` pre-NTT for verification

  PirClient client(pir_params);
  const size_t client_id = client.get_client_id();
  server.set_client_bv_galois_key(client_id, client.create_bv_galois_keys());
  server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  for (size_t idx : probes) {
    RlweCt query = client.fast_generate_query(idx);
    RlweCt response = server.make_query(client_id, query);

    std::stringstream resp_stream;
    server.save_resp_to_stream(response, resp_stream);
    RlweCt reconstructed = client.load_resp_from_stream(resp_stream);
    RlwePt got = client.decrypt_mod_q(reconstructed);  // prints noise budget

    RlwePt want = server.direct_get_original_plaintext(idx);
    if (!utils::plaintext_is_equal(got, want)) {
      throw std::runtime_error("small-DB PIR mismatch at index " +
                               std::to_string(idx) + " (num_pt=" +
                               std::to_string(n) + ")");
    }
    BENCH_PRINT("  index " << idx << ": correct");
  }
  BENCH_PRINT("end-to-end " << n << "-plaintext DB: PASS");
}

}  // namespace

void PirTest::test_db_shape() {
  print_func_name(__FUNCTION__);

  // calculate_db_shape returns {fst_dim_sz, num_dims}. Assert it against
  // explicit expectations so the single-dimension contract can't silently
  // regress back to the old "pad up to 2^h" behaviour.
  auto expect = [](size_t target, size_t l, size_t h,
                   size_t want_fst, size_t want_nd) {
    auto [fst, nd] = utils::calculate_db_shape(target, l, h);
    if (fst != want_fst || nd != want_nd) {
      throw std::runtime_error(
          "calculate_db_shape(" + std::to_string(target) + "," +
          std::to_string(l) + "," + std::to_string(h) + ") = {" +
          std::to_string(fst) + "," + std::to_string(nd) +
          "}, expected {" + std::to_string(want_fst) + "," +
          std::to_string(want_nd) + "}");
    }
  };

  // Single-dimension (target <= capacity = 2^h): fst_dim_sz is the *exact*
  // request, num_dims == 1. No rounding up to a power of two or to 2^h.
  expect(1,    5, 10, 1,    1);
  expect(16,   5, 10, 16,   1);
  expect(99,   5, 10, 99,   1);   // BitcoinPIR small-DB target
  expect(128,  5, 10, 128,  1);
  expect(257,  5, 10, 257,  1);   // non-power-of-two, odd
  expect(364,  5, 10, 364,  1);   // BitcoinPIR small-DB target
  expect(1024, 5, 10, 1024, 1);   // boundary: exactly capacity
  expect(99,   6, 10, 99,   1);   // single-dim path is independent of l

  // Multi-dimension (target > capacity): unchanged hypercube policy.
  expect(4096, 5, 10, 512, 4);

  // Larger multi-dim searches: assert the returned shape is *valid* — holds
  // the target and fits the expansion tree (fst_dim_sz + l*(num_dims-1) <= 2^h).
  auto check_valid = [](size_t target, size_t l, size_t h) {
    auto [fst, nd] = utils::calculate_db_shape(target, l, h);
    const size_t capacity = size_t{1} << h;
    if (nd < 1)
      throw std::runtime_error("db_shape: num_dims < 1");
    if (fst + l * (nd - 1) > capacity)
      throw std::runtime_error("db_shape: useful_cnt exceeds 2^h");
    if (fst * (size_t{1} << (nd - 1)) < target)
      throw std::runtime_error("db_shape: capacity below target");
    BENCH_PRINT("calculate_db_shape(" << target << "," << l << "," << h
                << ") = {" << fst << "," << nd << "}");
  };
  check_valid(1000000, 5, 9);
  check_valid(1000000, 6, 8);
  BENCH_PRINT("calculate_db_shape unit checks: PASS");

  // End-to-end: genuinely small single-dimension databases.
  run_small_db_e2e(99);
  run_small_db_e2e(364);
}
