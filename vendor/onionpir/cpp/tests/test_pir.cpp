#include "tests.h"
#include "bv_keyswitch.h"
#include <sstream>

void PirTest::test_pir() {
  print_func_name(__FUNCTION__);
  auto success_count = 0;

  // ============== setting parameters for PIR scheme ==============
  PirParams pir_params;
  pir_params.print_params();
  PirServer server(pir_params); // Initialize the server with the parameters

  // Pre-generate all query indices so gen_data() only records what we need
  srand(time(0));
  const size_t num_pt = pir_params.get_num_pt();
  std::vector<size_t> query_indices(num_experiments);
  for (size_t i = 0; i < num_experiments; i++) {
    query_indices[i] = rand() % num_pt;
  }

  BENCH_PRINT("Initializing server...");
  server.gen_data(query_indices);
  BENCH_PRINT("Server initialized");

  // some global results
  size_t galois_key_size = 0;
  size_t query_size = 0;
  size_t resp_size = 0;

  // Run the query process many times.
  for (size_t i = 0; i < num_experiments; i++) {
    BENCH_PRINT("======================== Experiment " << i + 1 << " ========================");

    // ============= OFFLINE PHASE: key materials ==============
    // Initialize the client
    PirClient client(pir_params);
    const size_t client_id = client.get_client_id();
    std::stringstream resp_stream;

    // Client create BV galois keys and gsw(sk)
    auto bv_galois_keys = client.create_bv_galois_keys();
    galois_key_size = pir_params.get_bv_galois_key_size();
    //--------------------------------------------------------------------------------
    // Server receives the BV galois keys and gsw keys
    server.set_client_bv_galois_key(client_id, std::move(bv_galois_keys));
    server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

    // ===================== ONLINE PHASE =====================
    size_t query_pt_idx = query_indices[i];

    TIME_START(CLIENT_TOT_TIME);
    RlweCt query = client.fast_generate_query(query_pt_idx);
    TIME_END(CLIENT_TOT_TIME);
    query_size = pir_params.get_BFV_size();

    TIME_START(SERVER_TOT_TIME);
    RlweCt response = server.make_query(client_id, query);
    TIME_END(SERVER_TOT_TIME);

    // ---------- server send the response to the client -----------
    resp_size = server.save_resp_to_stream(response, resp_stream);

    // ============= CLIENT ===============
    // client gets result from the server and decrypts it
    RlweCt reconstructed_result = client.load_resp_from_stream(resp_stream);
    TIME_START(CLIENT_TOT_TIME);
    RlwePt decrypted_result = client.decrypt_mod_q(reconstructed_result);
    TIME_END(CLIENT_TOT_TIME);

    // ============= Directly get the plaintext from server. Not part of PIR.
    RlwePt actual_plaintext = server.direct_get_original_plaintext(query_pt_idx);

    END_EXPERIMENT();
    // ============= PRINTING RESULTS ===============
    // DEBUG_PRINT("\t\tquery / resp / actual idx:\t" << query_pt_idx << " / " << resp_plaintext_idx << " / " << actual_plaintext_idx);

    if (utils::plaintext_is_equal(decrypted_result, actual_plaintext)) {
      // print a green success message
      std::cout << color_green() << "Success!" << color_reset() << std::endl;
      success_count++;
    } else {
      // print a red failure message
      std::cout << color_red() << "Failure!" << color_reset() << std::endl;
      std::cout << "Query index:\t" << query_pt_idx << std::endl;
      std::cout << "PIR Result:\t";
      utils::print_plaintext(decrypted_result, 20);
      std::cout << "Actual Plaintext:\t";
      utils::print_plaintext(actual_plaintext, 20);
    }
  }

  double avg_server_time = GET_AVG_TIME(SERVER_TOT_TIME);
  double throughput = pir_params.get_DBSize_MB() / (avg_server_time / 1000);

  // ============= PRINTING FINAL RESULTS ===============]
  PRINT_BAR;
  BENCH_PRINT("                                FINAL RESULTS")
  PRINT_BAR;
  BENCH_PRINT("Success rate: " << success_count << "/" << num_experiments);
  BENCH_PRINT("BV galois key size: " << static_cast<double>(galois_key_size) / 1024 << " KB");
  // BENCH_PRINT("gsw key size: " << gsw_key_size << " bytes");
  BENCH_PRINT("gsw key size: " << pir_params.get_gsw_key_size() << " bytes = " << static_cast<double>(pir_params.get_gsw_key_size()) / 1024 << " KB");
  BENCH_PRINT("total key size: " << static_cast<double>(galois_key_size + pir_params.get_gsw_key_size()) / 1024 << "KB");
  BENCH_PRINT("query size: " << query_size << " bytes = " << static_cast<double>(query_size) / 1024 << " KB");
  BENCH_PRINT("response size: " << resp_size << " bytes = " << static_cast<double>(resp_size) / 1024 << " KB");

  PRETTY_PRINT();
  BENCH_PRINT("Server throughput: " << throughput << " MB/s");
}
