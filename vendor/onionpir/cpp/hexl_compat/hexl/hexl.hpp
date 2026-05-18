// hexl_compat/hexl/hexl.hpp
//
// Scalar fallback shim for a tiny subset of Intel HEXL's API. This header is
// placed on the include path INSTEAD of the real <hexl/hexl.hpp> when the
// build is configured without HEXL (i.e. ONIONPIR_USE_HEXL is undefined).
//
// Only the surface actually used by this codebase is declared here:
//   - class intel::hexl::NTT
//   - free fns: EltwiseAddMod / EltwiseSubMod / EltwiseMultMod / EltwiseFMAMod
//   - free fn:  MinimalPrimitiveRoot
//
// Implementation lives in src/hexl_shim.cpp. The implementation is plain
// scalar C++ (no SIMD); intended for ARM / WASM builds where HEXL is
// unavailable.
//
// Thread-safety: the NTT class holds mutable internal twiddle vectors; do not
// share a single instance between threads. The caller in src/utils.cpp keeps
// a thread-local cache so each thread gets its own instance.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace intel {
namespace hexl {

// Negacyclic NTT over R_q = Z_q[x] / (x^N + 1).
// N must be a power of two; q must fit in 62 bits (so q*q fits in 128 bits).
//
// Two ctors:
//   - NTT(N, q):       q must be prime (so a primitive 2N-th root can be found
//                      by search via MinimalPrimitiveRoot).
//   - NTT(N, q, root): root is a precomputed 2N-th primitive root of unity
//                      mod q. Use this for composite q (e.g. CRT-composed
//                      moduli) where root-of-unity search isn't available.
//
// Movable, not copyable (holds twiddle vectors).
class NTT {
 public:
  NTT(std::size_t N, std::uint64_t q);
  NTT(std::size_t N, std::uint64_t q, std::uint64_t root);

  NTT(const NTT &) = delete;
  NTT &operator=(const NTT &) = delete;
  NTT(NTT &&) noexcept = default;
  NTT &operator=(NTT &&) noexcept = default;

  // out[i] in [0, q) regardless of in_mod_factor / out_mod_factor values.
  // In-place is supported: callers commonly pass out == in.
  // The mod-factor params are accepted for API compatibility with HEXL but
  // are not used to skip reductions in this scalar fallback.
  void ComputeForward(std::uint64_t *out, const std::uint64_t *in,
                      std::uint64_t in_mod_factor,
                      std::uint64_t out_mod_factor);
  void ComputeInverse(std::uint64_t *out, const std::uint64_t *in,
                      std::uint64_t in_mod_factor,
                      std::uint64_t out_mod_factor);

 private:
  std::size_t N_ = 0;
  std::uint64_t q_ = 0;
  std::uint64_t root_ = 0;      // primitive 2N-th root of unity mod q
  std::uint64_t inv_root_ = 0;  // root^{-1} mod q
  std::uint64_t inv_N_ = 0;     // N^{-1} mod q

  // Forward twiddles: psi_fwd_[k] = root^{bit_reverse(k, log2 N)} mod q
  // (indexed in bit-reversed order so that the iterative CT butterfly reads
  // them sequentially per stage).
  std::vector<std::uint64_t> psi_fwd_;
  // Inverse twiddles: psi_inv_[k] = inv_root^{bit_reverse(k, log2 N)} mod q.
  std::vector<std::uint64_t> psi_inv_;
  // Shoup precomputes for each twiddle: w_shoup = floor(w * 2^64 / q). Used
  // by the NTT butterfly so the per-element mod-mul costs a single widening
  // multiply (plus a conditional subtract) instead of a uint128 division.
  std::vector<std::uint64_t> psi_fwd_shoup_;
  std::vector<std::uint64_t> psi_inv_shoup_;
};

// Element-wise: out[i] = (a[i] + b[i]) mod q.
void EltwiseAddMod(std::uint64_t *out, const std::uint64_t *a,
                   const std::uint64_t *b, std::uint64_t n, std::uint64_t q);

// Element-wise: out[i] = (a[i] - b[i]) mod q.
void EltwiseSubMod(std::uint64_t *out, const std::uint64_t *a,
                   const std::uint64_t *b, std::uint64_t n, std::uint64_t q);

// Element-wise: out[i] = (a[i] * b[i]) mod q.
// in_mod_factor is accepted for API parity; this scalar fallback assumes
// inputs are already in [0, q) (matching how the codebase calls it).
void EltwiseMultMod(std::uint64_t *out, const std::uint64_t *a,
                    const std::uint64_t *b, std::uint64_t n, std::uint64_t q,
                    std::uint64_t in_mod_factor);

// Element-wise fused multiply-add:
//   out[i] = (a[i] * scalar + (acc ? acc[i] : 0)) mod q.
// acc may be nullptr.
void EltwiseFMAMod(std::uint64_t *out, const std::uint64_t *a,
                   std::uint64_t scalar, const std::uint64_t *acc,
                   std::uint64_t n, std::uint64_t q,
                   std::uint64_t in_mod_factor);

// Smallest g in [2, q) such that g^m == 1 (mod q) and g^(m/p) != 1 (mod q)
// for every prime p dividing m. q must be prime. m is even (in practice m=2N
// with N a power of two, so m's only prime factor is 2).
std::uint64_t MinimalPrimitiveRoot(std::uint64_t m, std::uint64_t q);

}  // namespace hexl
}  // namespace intel
