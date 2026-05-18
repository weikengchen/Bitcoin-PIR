#pragma once

#include "pir.h"
#include "gsw.h"
#include "bv_keyswitch.h"
#include "rlwe.h"
#include <random>
#include <sstream>

class PirClient {
public:
  PirClient(const PirParams &pirparms);
  // Reconstruct a client from a previously-exported secret key (see
  // get_secret_key). The client_id should match what the server saw,
  // so previously-registered galois/gsw keys still resolve.
  PirClient(const PirParams &pirparms, size_t client_id, RlweSk sk);
  ~PirClient() = default;

  // Borrow the underlying ternary secret key (NTT form, all K limbs).
  // Pair with the from-sk constructor to persist a client across processes.
  const RlweSk &get_secret_key() const { return rlwe_sk_; }

  /**
  Generate a packed query ciphertext for fast_expand_qry.
  @param pt_idx The input to the PIR blackbox.
  */
  RlweCt fast_generate_query(const size_t pt_idx);

  // helper function for fast_generate_query
  void add_gsw_to_query(RlweCt &query, const std::vector<size_t> query_indices);

  // Create custom BV-style Galois keys (no special prime).
  inline bvks::BvGaloisKeys create_bv_galois_keys() {
    return bvks::gen_bv_galois_keys(pir_params_, rlwe_sk_);
  }

  RlwePt decrypt_ct(const RlweCt &ct);
  // Produce the per-client GSW key (encryption of s under the data modulus) in
  // its final flat NTT layout, ready to hand to PirServer::set_client_gsw_key.
  GSWCt generate_gsw_from_key();

  inline size_t get_client_id() const { return client_id_; }

  // Noise budget via a bridge to SEAL's invariant_noise_budget (debug/test only).
  int noise_budget(const RlweCt &ct);


  // Fresh encryption of zero under the data modulus Q. Testing only:
  // used to measure the baseline initial noise budget without the
  // gadget-injection artifacts of fast_generate_query.
  RlweCt fresh_zero_ct();

  // load the response from the stream and recover the ciphertext
  RlweCt load_resp_from_stream(std::stringstream &resp_stream);

  // Decrypt a single-mod RlweCt under small_q using our custom decryptor.
  RlwePt decrypt_mod_q(const RlweCt &ciphertext) const;


  friend class PirTest;

private:
  const size_t client_id_;
  PirParams pir_params_;
  std::mt19937_64 rng_;       // per-client PRNG for noise sampling
  RlweSk rlwe_sk_;            // ternary sk, NTT form under q

  // Gets the query indices for a given plaintext
  std::vector<size_t> get_query_indices(size_t pt_idx);

  // Populate sk_ntt_small_q_ by rewriting rlwe_sk_ from old_q to small_q
  // (ternary sk has -1 ≡ q-1; we need -1 ≡ small_q-1).
  std::vector<uint64_t> get_sk_ntt_small_q(uint64_t old_q, uint64_t small_q) const;

};








