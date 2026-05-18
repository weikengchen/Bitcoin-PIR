#pragma once

#include "pir.h"
#include "rlwe.h"
#include "database_constants.h"
#include <vector>
#include <cstdint>
#include <random>

// ============================================================================
// BV-Style Galois Key-Switching (No Special Prime)
// ============================================================================
//
// This module implements Brakerski-Vaikuntanathan (BV) key-switching for
// Galois automorphisms, replacing SEAL's GHS-based key-switching in the
// query expansion step.
//
// Unlike GHS, BV does not use a special prime. Each key-switching key is a
// set of L_KS RLWE ciphertexts encrypting σ_k(s) · B^i (for i = 0..L_KS-1)
// under the ciphertext modulus q (product of rns_mods).
//
// Key-switch operation:
//   σ_k(ct) = (σ_k(c0) + Σ d_i · ksk.b[i],  Σ d_i · ksk.a[i])
// where d_i = gadget_decompose(σ_k(c1))[i] and all products are in NTT form.
//
// For the currently active single-limb configuration, K == 1 and
// gadget decomposition is a straightforward bit-shift on uint64 coefficients.

namespace bvks {

// Number of gadget digits per key-switching key. Sourced from DBConsts so
// it lives alongside the other per-config gadget lengths (L_EP, L_KEY).
constexpr size_t L_KS = DBConsts::L_KS;

// A single RLWE ciphertext under the data modulus, stored in NTT form.
// Layout: K * N uint64s per polynomial component.
struct BvRlweCt {
  std::vector<uint64_t> a; // size = K * N
  std::vector<uint64_t> b; // size = K * N
};

// Key-switching key for one automorphism σ_k.
// Contains L_KS RLWE ciphertexts encrypting σ_k(s) · B^i.
struct BvKeySwitchKey {
  uint32_t galois_k = 0;
  std::vector<BvRlweCt> cts; // size = L_KS
};

// Collection of BV key-switching keys, one per expansion-level automorphism.
class BvGaloisKeys {
public:
  std::vector<BvKeySwitchKey> keys;

  const BvKeySwitchKey &get(uint32_t galois_k) const;
};

// ============================================================================
// Key generation (client side)
// ============================================================================

// Generate a single BV key-switching key for automorphism σ_{galois_k}
// under secret key `sk`. The secret key must be in NTT form.
// Error σ is read from pir_params.get_noise_std_dev().
BvKeySwitchKey gen_bv_ks_key(const PirParams &pir_params,
                             const RlweSk &sk, uint32_t galois_k,
                             std::mt19937_64 &rng);

// Generate a full set of BV key-switching keys for all expansion-level
// automorphisms. Error σ is read from pir_params.get_noise_std_dev().
BvGaloisKeys gen_bv_galois_keys(const PirParams &pir_params,
                                const RlweSk &sk);

// ============================================================================
// Gadget decomposition
// ============================================================================

// Signed (zero-centered) gadget decomposition of a single coefficient.
// Input:  val ∈ [0, q), base_log2, q, num_digits
// Output: num_digits digits (out[0]=B^0, out[num_digits-1]=most significant),
//         each stored mod q, representing a signed digit in [-B/2, B/2).
// Reconstruction: Σ out[i] · B^i ≡ val (mod q).
void signed_gadget_decompose(uint64_t val, size_t base_log2,
                             uint64_t q, uint64_t *out, size_t num_digits);

// Multi-precision variant for K=2 (uint128 modulus Q = q0·q1). Centers `val`
// in (-Q/2, Q/2] then emits num_digits signed digits in [-B/2, B/2) as int64_t.
// Callers render each digit to uint64 mod q_k per limb separately, since the
// same digit needs to land under multiple moduli.
void signed_gadget_decompose_mp(uint128_t val, uint128_t Q, size_t base_log2,
                                int64_t *out, size_t num_digits);

// ============================================================================
// Key-switching operation (server side)
// ============================================================================

// Apply automorphism σ_k to `ct` and key-switch back to the original secret key
// using BV. Modifies `ct` in place. `ct` must be in coefficient form on entry
// and remains in coefficient form on return.
//
// Operates on all K limbs.
void bv_apply_galois_inplace(RlweCt &ct, uint32_t galois_k,
                             const BvKeySwitchKey &key,
                             const PirParams &pir_params);

} // namespace bvks
