#pragma once
#include <cstddef>
#include <cstdint>
#include <array>

typedef unsigned __int128 uint128_t;

// ============================================================================
// Build-time configuration selector
// ============================================================================
// Override on the cmake/compile line with e.g.
//   -DACTIVE_CONFIG=CONFIG_N2048_K1
// ----------------------------------------------------------------------------
//
// Naming: CONFIG_N{poly_degree}_K{rns_limb_count}[_COMP]. Each config carries
// its own gadget lengths and PlainMod. Keep configs aligned with the run.py
// aliases.
//   CONFIG_N2048_K1        K=1, N=2048, log Q ≈ 60.
//   CONFIG_N2048_K1_COMP   K=1 composite split (q1*q2 ≈ 2^58, 29+29).
//   CONFIG_N2048_K2_MP     K=2, N=2048, log Q ≈ 58.
//   CONFIG_N4096_K2_MP     K=2, N=4096, log Q ≈ 120.
#define CONFIG_N2048_K1          0
#define CONFIG_N2048_K2_MP       1
#define CONFIG_N4096_K2_MP       2
// Composite first-dim split: q = q1*q2 (29+29). Pipeline sees a single ~58-bit
// modulus (single-mod K=1 paths are reused for everything), but the first-dim
// matmul splits each NTT coefficient into (mod q1, mod q2) for 32x32->64
// multiplies.
#define CONFIG_N2048_K1_COMP     3
#ifndef ACTIVE_CONFIG
#define ACTIVE_CONFIG CONFIG_N2048_K1
#endif

namespace DBConsts {

  // ==========================================================================
  // Constants common to all configs
  // ==========================================================================
  // Default 128 MB → num_plaintexts ≈ 40 K (with CONFIG_N2048_K1's 3328-byte
  // plaintexts). BitcoinPIR's UTXO snapshot at height 948454 produces ≈ 946 K
  // OnionPIR entries after dust filtering — way beyond the default. Bump to
  // 3072 MB → num_plaintexts ≈ 968 K, leaving ~2% headroom over current
  // chain-tip data. Tune up further if either:
  //   * chain growth pushes the dust-filtered entry count past ~960 K
  //   * a denser CONFIG variant (CONFIG_N4096_K2_MP at 19968 B/entry) is
  //     adopted — then the appropriate DB_SIZE_MB is correspondingly larger.
  //
  // Override via scripts/run_all_combos.sh's DB_SIZE_MB env var for
  // benchmarking; production stays at the default committed here.
  constexpr size_t DB_SIZE_MB = 3072;
  constexpr double NoiseStdDev = 2.55;  // matches Spiral & InsPIRe.

  // First-dimension shape policy. See utils::calculate_db_shape.
  //   true : fst_dim_sz = largest power of two ≤ slack (OnionPIRv1 hypercube).
  //   false: fst_dim_sz = slack (every leftover expansion slot; non-power-of-2).
  // Tight packing raises DB capacity at the same num_dims but ups first-dim
  // matmul work; pow-2 keeps matmul cheap at the cost of more dims.
  constexpr bool FST_DIM_POW2 = true;

  // ==========================================================================
  // Per-config constants
  // ==========================================================================

#if ACTIVE_CONFIG == CONFIG_N2048_K1
  // Production-tested cell. K=1, log Q = 60.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 14;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 1> RnsMods = {60};
  constexpr bool CompositeFirstDim = false;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {0, 0};

#elif ACTIVE_CONFIG == CONFIG_N2048_K1_COMP
  // K=1 composite: pipeline sees single q ≈ 2^58 (= q1*q2 with q1, q2 ~ 2^29).
  // First-dim matmul splits per-limb to hit the 32x32->64 fast path.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 6;
  constexpr size_t L_KEY        = 10;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 13;
  constexpr size_t SmallQWidth  = 22;
  // Logical (single) RNS view: rns_mods_ holds {q1*q2}, ~58 bits. The 58 here
  // is the bit width passed to inter_coeff_t / db_coeff_t selectors; actual
  // modulus is computed in PirParams::init_composite_rns.
  constexpr std::array<size_t, 1> RnsMods = {58};
  constexpr bool CompositeFirstDim = true;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {29, 29};

#elif ACTIVE_CONFIG == CONFIG_N2048_K2_MP
  // K=2, N=2048. Single CRT-composed gadget of base B = 2^(58/l).
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 10;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 2> RnsMods = {29, 29};
  constexpr bool CompositeFirstDim = false;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {0, 0};

#elif ACTIVE_CONFIG == CONFIG_N4096_K2_MP
  // K=2 at N=4096. Total log Q ≈ 120 — fits in uint128 (MP gadget). With
  // max_ct_mod_width = 60 the matmul takes the uint64→uint128 scalar path
  // (AVX-512 fast path requires uint32→uint64).
  constexpr size_t PolyDegree   = 4096;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 40;
  constexpr size_t SmallQWidth  = 50;
  constexpr std::array<size_t, 2> RnsMods = {60, 60};
  constexpr bool CompositeFirstDim = false;
  constexpr std::array<size_t, 2> FirstDimRNSMods = {0, 0};

#else
  #error "Unknown ACTIVE_CONFIG"
#endif


  // Max bit-width among ciphertext moduli.
  constexpr size_t max_ct_mod_width() {
    size_t w = 0;
    for (size_t i = 0; i < RnsMods.size(); i++)
      if (RnsMods[i] > w) w = RnsMods[i];
    return w;
  }

  // The MP gadget path uses 128-bit multi-precision integers per coefficient
  // (compose_rns_to_mp / decompose_mp_to_rns in gsw.cpp). That works for K ≤ 2
  // and total log Q ≤ 128 bits.
  static_assert(RnsMods.size() <= 2,
                "Only K ≤ 2 is supported by the MP gadget.");

  // Composite split is only meaningful for the single-mod (K=1) view.
  static_assert(!CompositeFirstDim || RnsMods.size() == 1,
                "CompositeFirstDim requires a single composite ct modulus");

} // namespace DBConsts

// ============================================================================
// Per-coefficient storage and accumulator types
// ============================================================================
// db_coeff_t: type for each NTT coefficient stored in the aligned database.
//   ≤32-bit moduli → uint32_t,  >32-bit → uint64_t.
using db_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                      uint32_t, uint64_t>;

// inter_coeff_t: accumulator for first-dimension matrix multiply & gadget
// arithmetic. Must be wide enough for fst_dim_sz × (db_coeff_t × db_coeff_t)
// sums.
//   ≤32-bit moduli → uint64_t,  >32-bit → uint128_t.
using inter_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                         uint64_t, uint128_t>;
