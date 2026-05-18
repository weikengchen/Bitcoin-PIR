#pragma once
#include "pir.h"
#include "rlwe.h"
#include <random>
#include <vector>


// A GSWCt is a flattened 2l x 2 matrix of polynomials.
typedef std::vector<std::vector<uint64_t>> GSWCt;

class GSWEval {
  private:
    PirParams pir_params_;
    size_t l_;
    size_t base_log2_;

  public:
    GSWEval(const PirParams &pir_params, const size_t l, const size_t base_log2)
        : pir_params_(pir_params), l_(l), base_log2_(base_log2) {}
    ~GSWEval() = default;
    GSWEval(const GSWEval &gsw_eval) = default;

    /*!
      Computes the external product between a GSW ciphertext and a decomposed BFV
      ciphertext.
      @param gsw_enc -GSW Ciphertext, should only encrypt 0 or 1 to prevent large
      noise growth
      @param rlwe_expansion - decomposed vector of BFV ciphertext
      @param ct_poly_size - number of ciphertext polynomials
      @param res_ct - output ciphertext
    */
    void external_product(GSWCt const &gsw_enc, RlweCt const &bfv,
                          RlweCt &res_ct,
                          LogContext context = LogContext::GENERIC);

    /*!
      MP-gadget decomposition (K>=2). Composes the per-coefficient RNS values
      to a multi-precision integer, extracts unsigned base-B digits, then
      decomposes back to RNS. Emits 2 * l_ rows; row p (MSB-first within each
      half) holds the digit at exponent l_-1-p.
      @param ct - input BFV ciphertext (coefficient form, K-limb).
      @param output - decomposed rows, each K*N uint64 in limb-major layout.
    */
    void decomp_rlwe_mp(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                        LogContext context = LogContext::GENERIC);

    // Similar to decomp_rlwe_mp. Use this when rn_mod_cnt = 1. Skips the
    // RNS<->MP conversions; signed-digit decomposition directly under q.
    void decomp_rlwe_single_mod(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                                   LogContext context = LogContext::GENERIC);

    // Transform decomposed coefficients to NTT form
    void decomp_to_ntt(std::vector<std::vector<uint64_t>> &decomp_coeffs,
                      LogContext context = LogContext::GENERIC);

    /*!
      Generates a GSW ciphertext from a BFV ciphertext query.

      @param query - input BFV ciphertext. Should be of size l * 2.
      @param gsw_key - GSW encryption of -s
      @param output - output to store the GSW ciphertext as a vector of vectors of
      polynomial coefficients
    */
    void query_to_gsw(std::vector<RlweCt> query, GSWCt gsw_key,
                      GSWCt &output);

    /*!
      Encrypt a plaintext polynomial as a full GSW ciphertext in NTT form.
      Single-mod only. Produces the flat layout consumed by external_product:
      2*l_ rows, each row = [c0 || c1] of size 2*N (NTT form, mod q).
      @param plaintext - polynomial of length N (or N*K, but
                         only the single-mod case is supported).
      @param sk        - NTT-form ternary secret key.
      @param rng       - randomness source for a, e.
    */
    GSWCt plain_to_gsw(std::vector<uint64_t> const &plaintext,
                               const RlweSk &sk, std::mt19937_64 &rng);

    // Transform the given GSWCipher text from polynomial representation to NTT representation.
    void gsw_ntt_forward(GSWCt &gsw);
};