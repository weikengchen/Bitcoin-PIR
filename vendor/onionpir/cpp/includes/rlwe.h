#pragma once
#include <cstdint>
#include <random>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal RLWE types replacing seal::Ciphertext / seal::SecretKey / seal::Plaintext.
// All polynomials are stored as flat uint64_t arrays in coefficient order.
// For RNS-multi-modulus contexts the limbs are concatenated: mod0 || mod1 || ...
// ---------------------------------------------------------------------------

struct RlweCt {
    std::vector<uint64_t> c0; // first polynomial (size = N * K)
    std::vector<uint64_t> c1; // second polynomial (size = N * K)
    bool ntt_form = false;

    uint64_t       *data(size_t i)       { return i == 0 ? c0.data() : c1.data(); }
    const uint64_t *data(size_t i) const { return i == 0 ? c0.data() : c1.data(); }
    bool &is_ntt_form() { return ntt_form; }

    // Resize both polynomials to n elements (n = N * K).
    void resize(size_t n) { c0.assign(n, 0); c1.assign(n, 0); }

    // Number of elements per polynomial (0 if not yet allocated).
    size_t poly_size() const { return c0.size(); }
};

// Ternary secret key stored in NTT form.
// data has N * K elements: values in {0, 1, q-1} reduced mod each prime.
struct RlweSk {
    std::vector<uint64_t> data;
    size_t poly_size() const { return data.size(); }
};

// Plaintext polynomial. data has N elements in [0, t).
struct RlwePt {
    std::vector<uint64_t> data;
    size_t coeff_count() const { return data.size(); }
};

// ---------------------------------------------------------------------------
// Single-modulus RLWE encryption primitives.
// All functions operate on a single prime q (K == 1).
// Secret keys are always stored in NTT form.
// ---------------------------------------------------------------------------

// Sample a fresh ternary secret key and convert it to NTT form.
RlweSk gen_secret_key(size_t N, uint64_t q, std::mt19937_64 &rng);

// Symmetric encryption of zero under secret key sk:
//   c1 = a  (uniform in [0, q))
//   c0 = -(a*s + e) mod q   where e ~ N(0, sigma²)
// If ntt_form == true, both c0 and c1 are returned in NTT form; otherwise
// both are in coefficient form.
void encrypt_zero(const RlweSk &sk, size_t N, uint64_t q, double sigma,
                  std::mt19937_64 &rng, RlweCt &ct, bool ntt_form = false);

// BFV symmetric encryption of a message polynomial `m` (length N, values < t):
//   c = Enc(0) + (Δ·m, 0)   where Δ = ⌊q/t⌋.
// Encrypts in coefficient form (matches seal::Encryptor::encrypt_symmetric for
// a non-NTT input plaintext).
void encrypt_bfv(const std::vector<uint64_t> &m, const RlweSk &sk,
                 size_t N, uint64_t q, uint64_t t, double sigma,
                 std::mt19937_64 &rng, RlweCt &ct);

// Decrypt a single-modulus ciphertext into a plaintext polynomial modulo t.
//   phase[i] = (c0 + c1 * s)[i]          in [0, q)
//   pt[i]    = round(phase[i] * t / q)   mod t
// ct may be in either NTT or coefficient form (determined by ct.ntt_form).
void decrypt(const RlweCt &ct, const RlweSk &sk, size_t N, uint64_t q,
             uint64_t t, RlwePt &pt);

// Decrypt and also return the invariant noise budget in bits.
// Equivalent to SEAL's Decryptor::invariant_noise_budget + decrypt().
int decrypt_and_budget(const RlweCt &ct, const RlweSk &sk, size_t N,
                       uint64_t q, uint64_t t, RlwePt &pt);

// ---------------------------------------------------------------------------
// RlweCt arithmetic (single-modulus). All operands must be the same NTT form;
// caller upholds the invariant (no runtime check on the hot path).
// ---------------------------------------------------------------------------

void rlwe_add_inplace(RlweCt &a, const RlweCt &b, uint64_t q);
void rlwe_sub_inplace(RlweCt &a, const RlweCt &b, uint64_t q);
void rlwe_add(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q);
void rlwe_sub(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q);

// NTT forward/inverse on both polynomials. Updates ct.ntt_form.
void rlwe_ntt_fwd_inplace(RlweCt &ct, uint64_t q, size_t N);
void rlwe_ntt_inv_inplace(RlweCt &ct, uint64_t q, size_t N);

// Negacyclic shift by `index` of each polynomial (coefficient form only).
// dst may alias src.
void rlwe_shift(const RlweCt &src, RlweCt &dst, size_t index, uint64_t q, size_t N);

// ---------------------------------------------------------------------------
// K-limb (RNS) RLWE primitives.
// All functions operate on K = qs.size() limbs concatenated in mod0 || mod1 || ...
// order. The single-modulus helpers above are the K=1 specialisation.
// Currently supports K = 1 or K = 2 (matching compose_rns_to_mp's range).
// ---------------------------------------------------------------------------

struct RnsTables;  // defined in pir.h; only K=2 fields are used here

// One ternary polynomial reduced and NTT'd per limb. data layout: limb k at
// offset k*N. The same ternary coefficients are used across all limbs.
RlweSk gen_secret_key_rns(size_t N, const std::vector<uint64_t> &qs,
                          std::mt19937_64 &rng);

// Encryption of zero under sk:
//   c1_k = a_k                     (uniform in [0, q_k))
//   c0_k = -(a_k*sk_k + e_k) mod q_k  with shared signed Gaussian e
void encrypt_zero_rns(const RlweSk &sk, size_t N,
                      const std::vector<uint64_t> &qs,
                      double sigma, std::mt19937_64 &rng,
                      RlweCt &ct, bool ntt_form = false);

// BFV encryption: encrypt_zero + add round(Q*m[i]/t) to c0[i] (per-limb).
void encrypt_bfv_rns(const std::vector<uint64_t> &m, const RlweSk &sk,
                     size_t N, const std::vector<uint64_t> &qs, uint64_t t,
                     double sigma, std::mt19937_64 &rng, RlweCt &ct);

// Decrypt: per-limb phase, CRT-compose to MP, mod-switch q1 → drop, then
// rescale q0 → t. tables.q0_inv_mod_q1 must be set when K >= 2.
void decrypt_rns(const RlweCt &ct, const RlweSk &sk, size_t N,
                 const std::vector<uint64_t> &qs, uint64_t t,
                 const RnsTables &tables, RlwePt &pt);
