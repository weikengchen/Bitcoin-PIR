#pragma once

#include "gsw.h"
#include "pir.h"
#include "bv_keyswitch.h"
#include "aligned_allocator.h"
#include "shared_key_store.h"
#include <map>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

class PirServer {
public:
  PirServer(const PirParams &pir_params);
  ~PirServer();

  /**
   * Generate random data for the server database and directly set the database.
   * It pushes the data to the database in chunks.
   */
  void gen_data(const std::vector<size_t>& record_indices = {});

  /**
   * Push externally-provided plaintexts into the database. Each plaintext is
   * N coefficients (uint64 each) in [0, t). Plaintexts at indices
   * [offset, offset+count) are NTT-transformed and realigned in place;
   * subsequent queries see the new data immediately. Re-pushing the same
   * range overwrites prior content.
   *
   * Constraints:
   *   - offset + count <= num_pt
   *   - plaintexts contains count * N uint64s, plaintext p at p * N
   *
   * `record_indices`: a (possibly empty) subset of [offset, offset+count) to
   *                   retain pre-NTT for direct_get_original_plaintext.
   */
  void push_plaintexts(const uint64_t *plaintexts, size_t count, size_t offset,
                       const std::vector<size_t> &record_indices = {});

  // ─── Preprocessed-database persistence ────────────────────────────────
  // Save / load the post-NTT, realigned database produced by gen_data() (and,
  // later, by push_chunk()). The on-disk format is:
  //   [u64 magic][u64 num_pt][u64 coeff_val_cnt][u64 layout_id][u64 data_bytes]
  //   [raw bytes of size data_bytes]
  // layout_id encodes db_coeff_t width + composite-mod split (see server.cpp).
  // Standard path stores db_aligned_; composite path stores db_lo_ || db_hi_.
  void save_db_to_file(const std::string &path) const;
  // Returns false if the file is missing or the header doesn't match the
  // server's compile-time config; never throws for these.
  bool load_db_from_file(const std::string &path);
  // Zero-copy alias: caller-owned buffer must outlive the server. Buffer must
  // start with the same header save_db_to_file produces.
  bool load_db_from_borrowed(const uint8_t *data, size_t len);

  // Given the client id and a packed client query, this function first unpacks the query, then returns the retrieved encrypted result.
  RlweCt make_query(const size_t client_id, RlweCt &query);
  // return the number of bits needed to represent the server reponse
  size_t save_resp_to_stream(const RlweCt &response, std::stringstream &resp_stream);
  void set_client_bv_galois_key(const size_t client_id, bvks::BvGaloisKeys bv_keys);
  void set_client_gsw_key(const size_t client_id, GSWCt gsw_key);

  // Attach a non-owning SharedKeyStore. Once attached, set_client_*_key on
  // this server forwards into the store and the query path looks keys up
  // from the store instead of the server's own (now-empty) maps. Pass
  // nullptr to detach. The store must outlive the server (and any other
  // server attached to it).
  void set_shared_key_store(SharedKeyStore *store) { shared_key_store_ = store; }

  // ─── Indirect DB mode (multi-tenant shared backing store) ─────────────
  //
  // Lets many servers share a single, externally-owned NTT-expanded
  // backing store. Each server keeps its own `index_table` mapping its
  // logical plaintext id [0, num_pt) → physical entry id [0,
  // shared_num_entries). The first-dim matmul reads each coefficient via
  // store[level * shared_num_entries + index_table[pt_id]].
  //
  // Constraints:
  //   * Standard path only (composite-first-dim is unsupported here today).
  //   * The buffer at `store` is read-only and must outlive the server.
  //   * `index_table_len` must equal num_pt.
  //   * Each index_table[i] must be < shared_num_entries.
  //
  // On attach, the server's own db_aligned_ buffer is released — memory
  // savings are the whole point. Detach by passing store=nullptr; the
  // server then has no DB and must be repopulated.
  void set_shared_database(const db_coeff_t *store,
                           size_t shared_num_entries,
                           const uint32_t *index_table,
                           size_t index_table_len);

  /**
  Asking the server to return the original plaintext (before NTT transformation) at the given index.
  This is not doing PIR. So this reveals the index to the server. This is
  only for testing purposes.
  */
  RlwePt direct_get_original_plaintext(const size_t index) const;


  // high level: homomorphic matrix vector multiplication between plaintext database and query ciphertext
  // input selection_vector should stay in coefficient form.
  // output will be in coefficient form.
  std::vector<RlweCt> evaluate_first_dim(std::vector<RlweCt> &selection_vector);

  /**
   * @brief A clever way to evaluate the external product for second to last dimensions.
   *
   * @param intermediate_db The BFV ciphertexts after the first dimension evaluation.
   * @param selectors A vector of RGSW(b) ciphertexts, where b \in {0, 1}. 0 to get the first half of the result, 1 to get the second half.
   */
  RlweCt evaluate_other_dim(std::vector<RlweCt> &intermediate_db, std::vector<GSWCt> &selectors);

  // compute x = b * (y - x) + x
  void ext_prod_mux(RlweCt &x, RlweCt &y, GSWCt &selection_cipher, RlweCt &result);


  friend class PirTest;

private:
  size_t num_pt_;
  std::map<size_t, bvks::BvGaloisKeys> client_bv_galois_keys_;
  std::map<size_t, GSWCt> client_gsw_keys_;
  // Non-owning. When non-null, set_client_*_key forwards to this store and
  // the query-path lookup helpers below read from it. See set_shared_key_store.
  SharedKeyStore *shared_key_store_ = nullptr;
  std::unordered_map<size_t, RlwePt> recorded_pts_; // pre-NTT plaintexts for test verification
  std::unique_ptr<db_coeff_t[], AlignedDeleter<db_coeff_t>> db_aligned_; // aligned database for fast first dim
  std::vector<inter_coeff_t> inter_res_; // intermediate result vector for fst dim

  // Composite-mod first-dim path (q = q1 * q2). When DBConsts::CompositeFirstDim
  // is true these replace db_aligned_ + inter_res_: the DB is split into two
  // u32 arrays (one per RNS limb), and the matmul writes into two u64 buffers
  // which are CRT-composed in inter_to_cts_composite.
  std::unique_ptr<uint32_t[], AlignedDeleter<uint32_t>> db_lo_;
  std::unique_ptr<uint32_t[], AlignedDeleter<uint32_t>> db_hi_;

  // Live read pointers for the matmul. Normally alias the unique_ptr buffers
  // above (set in the ctor and reaffirmed after gen_data / load_db_from_file).
  // load_db_from_borrowed retargets them at the caller's buffer; in that mode
  // db_aligned_ / db_lo_ / db_hi_ are released to save the duplicate memory.
  const db_coeff_t *db_ptr_ = nullptr;
  const uint32_t   *db_lo_ptr_ = nullptr;
  const uint32_t   *db_hi_ptr_ = nullptr;

  // Indirect-mode state. shared_store_ non-null ⇒ matmul reads via index_table_.
  const db_coeff_t *shared_store_ = nullptr;
  size_t            shared_num_entries_ = 0;
  const uint32_t   *index_table_ = nullptr;
  size_t            index_table_len_ = 0;
  std::vector<uint64_t> inter_res_lo_;
  std::vector<uint64_t> inter_res_hi_;
  PirParams pir_params_;
  GSWEval key_gsw_;
  GSWEval data_gsw_;

  // we apply new techniques to avoid trivial splits on zero ciphertexts.
  // Notice that a large portion of the query is zero, and they are generated by
  // splitting some zero ciphertexts. Trivial split are the ones that split the
  // zero ciphertexts into two zero ciphertexts. However, to do this, we must
  // make sure that all the first dimension is in the same expansion sub-tree.
  // The expand query used in Cheetah is not suitable for this, though we don't
  // need special permutation for packing when using it.
  // Internal: NTT + realign a tile of `bs` plaintexts whose first plaintext
  // lands at index `pb` in the DB. `tile_pt` holds bs * N pre-NTT
  // coefficients; `stage` is a reusable K * TILE * N scratch buffer the
  // caller owns. Used by both gen_data() and push_plaintexts().
  void process_plaintext_tile(const uint64_t *tile_pt, size_t bs, size_t pb,
                              const std::unordered_set<size_t> &record_set,
                              uint64_t *stage);

  std::vector<RlweCt> fast_expand_qry(size_t client_id, RlweCt &ciphertext) const;

  std::vector<RlweCt> full_expand_qry(size_t client_id, RlweCt &ciphertext) const;

  // Convert the first-dim matmul output `inter_res` into per-ciphertext form.
  // Two responsibilities:
  //   1. Layout transpose. mat_mat writes coeff-major:
  //        inter_res[level][i][p]   for i ∈ [0, other_dim_sz), p ∈ {0,1}
  //      with stride `other_dim_sz * 2` between coefficient levels. The
  //      per-ciphertext layout we want is poly-contiguous:
  //        cts[i].c{p}[level]
  //   2. NTT inverse on each polynomial (database is in NTT form).
  //
  // Assumes mat_mat already produced values < q at every output position
  // (chunked / AVX-512 paths both reduce per output write), so no `% q`
  // is performed here.
  void inter_to_cts(std::vector<RlweCt> &result, const inter_coeff_t *__restrict inter_res);

  // Fill the intermediate_db_ with some ciphertext. We just need to allocate the memory.
  void fill_inter_res();

  void prep_query(std::vector<RlweCt> &fst_dim_query, std::vector<db_coeff_t>& query_data);

  // Composite-mod variant: splits each NTT query coefficient into (mod q1,
  // mod q2) u32 buffers. Inputs are already NTT-transformed under q = q1*q2.
  void prep_query_composite(const std::vector<RlweCt> &fst_dim_query,
                            uint32_t *query_lo, uint32_t *query_hi);

  // Composite-mod variant of inter_to_cts: reads two per-limb u64 buffers,
  // CRT-composes each coefficient back to mod q = q1*q2, then runs a single
  // INTT mod q.
  void inter_to_cts_composite(std::vector<RlweCt> &result,
                              const uint64_t *inter_lo,
                              const uint64_t *inter_hi);

  // customized modulus switch for single mod RlweCt. (Not RNS modulus)
  // The goal is to halve the size of the ciphertext.
  void mod_switch_inplace(RlweCt &ciphertext, const uint64_t small_q);

};
