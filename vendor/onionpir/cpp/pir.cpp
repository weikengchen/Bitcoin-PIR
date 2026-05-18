#include "pir.h"
#include "database_constants.h"
#include "utils.h"
#include "hexl/hexl.hpp"

#include <cassert>
#include <cmath>
#include <iostream>
#include <string>

void PirParams::init_composite_rns() {
  // Generate two NTT-friendly primes from FirstDimRNSMods bit widths and
  // combine them: q = q1 * q2, single composite limb visible to the rest of
  // the pipeline. The first-dim matmul will split each NTT coefficient back
  // into (mod q1, mod q2) for 32x32->64 multiplies; everything else (decomp,
  // keyswitch, external product) sees a single ~58-bit modulus.
  std::vector<size_t> rns_bits(DBConsts::FirstDimRNSMods.begin(),
                               DBConsts::FirstDimRNSMods.end());
  auto rns_primes = utils::generate_ntt_friendly_primes(rns_bits,
                                                        DBConsts::PolyDegree);
  const uint64_t q1 = rns_primes[0];
  const uint64_t q2 = rns_primes[1];
  const uint64_t crt_mod = q1 * q2;
  const uint64_t w1 = intel::hexl::MinimalPrimitiveRoot(2 * DBConsts::PolyDegree, q1);
  const uint64_t w2 = intel::hexl::MinimalPrimitiveRoot(2 * DBConsts::PolyDegree, q2);
  const uint64_t w_crt = utils::crt_combine(w1, q1, w2, q2);
  utils::register_ntt_root(DBConsts::PolyDegree, crt_mod, w_crt);
  rns_mods_ = {crt_mod};
  composite_rns_.enabled = true;
  composite_rns_.q1 = q1;
  composite_rns_.q2 = q2;
  composite_rns_.w1 = w1;
  composite_rns_.w2 = w2;
  composite_rns_.w_crt = w_crt;
  uint64_t q1_inv;
  if (!utils::try_invert_uint_mod(q1 % q2, q2, q1_inv))
    throw std::runtime_error("PirParams: q1 and q2 must be coprime");
  composite_rns_.q1_inv_mod_q2 = q1_inv;
}

PirParams::PirParams() : PirParams(0) {}

PirParams::PirParams(size_t target_num_pt_arg)
    : rns_mod_bits_(DBConsts::RnsMods.begin(), DBConsts::RnsMods.end()) {
  if constexpr (DBConsts::CompositeFirstDim) {
    init_composite_rns();
  } else {
    rns_mods_ = utils::generate_ntt_friendly_primes(rns_mod_bits_,
                                                    DBConsts::PolyDegree);
  }

  // =============== Plaintext modulus ===============
  plain_mod_ = utils::generate_prime(DBConsts::PlainMod);

  // =============== Small modulus for mod-switch ===============
  small_q_ = utils::generate_ntt_friendly_primes(
                 {static_cast<int>(DBConsts::SmallQWidth)}, DBConsts::PolyDegree)[0];

  // ================== RNS tables (two-mod CRT constants; unused at rns_cnt=1) ==================
  const size_t rns_cnt = rns_mods_.size();
  rns_tables_.r64_mod_q.resize(rns_cnt);
  for (size_t i = 0; i < rns_cnt; i++) {
    rns_tables_.r64_mod_q[i] = static_cast<uint64_t>(
        (static_cast<uint128_t>(1) << 64) % rns_mods_[i]);
  }
  if (rns_cnt == 2) {
    if (!utils::try_invert_uint_mod(rns_mods_[0] % rns_mods_[1],
                                    rns_mods_[1],
                                    rns_tables_.q0_inv_mod_q1)) {
      throw std::runtime_error("PirParams: coeff moduli not coprime");
    }
  }

  // ================== GSW related parameters ==================
  size_t ct_mod_width = get_ct_mod_width();
  base_log2_ = (ct_mod_width + l_ep_ - 1) / l_ep_;
  base_log2_key_ = (ct_mod_width + l_key_ - 1) / l_key_;

  // =============== Database shape calculation ===============
  // target_num_pt_arg == 0 means "use compile-time default"; any non-zero
  // value right-sizes this PirParams for a per-instance plaintext budget
  // (e.g. multi-tenant servers each holding a different fraction of the
  // global data — see INTEGRATION.md §10).
  size_t target_num_pt = target_num_pt_arg != 0
      ? target_num_pt_arg
      : DBConsts::DB_SIZE_MB * 1024 * 1024 / get_pt_size();
  DEBUG_PRINT("target_num_pt: " << target_num_pt);
  // Per-dim query slot count is l_ep_ (one BFV per gadget power).
  auto [fst_dim_sz, num_dims] = utils::calculate_db_shape(
      target_num_pt, l_ep_, DBConsts::TREE_HEIGHT);
  fst_dim_sz_ = fst_dim_sz;
  num_dims_ = num_dims;
  DEBUG_PRINT("fst_dim_sz: " << fst_dim_sz_ << ", num_dims: " << num_dims_);
  size_t other_dim_sz = utils::roundup_div(target_num_pt, fst_dim_sz_);
  num_pt_ = fst_dim_sz_ * other_dim_sz;
}

const size_t PirParams::get_ct_mod_width() const {
  size_t ct_mod_width = 0;
  for (size_t i = 0; i < K(); ++i) {
    ct_mod_width += rns_mod_bits_[i];
  }
  return ct_mod_width;
}

void PirParams::print_params() const {
  PRINT_BAR;
  std::cout << "                       PIR PARAMETERS                         " << std::endl;
  PRINT_BAR;

  auto print_field = [](const std::string& label, const std::string& value, int label_width = 35) {
    std::string padded_label = label;
    padded_label.resize(label_width, ' ');
    std::cout << "  " << padded_label << "= " << value << std::endl;
  };

  auto print_field_num = [&print_field](const std::string& label, auto value) {
    print_field(label, std::to_string(value));
  };

  // ---- Database shape ----
  print_field_num("Database size (MB)", get_DBSize_MB());
  print_field_num("Physical storage (MB)", get_physical_storage_MB());
  print_field_num("Plaintext size (KB)", get_pt_size() / 1024);
  print_field_num("num_pt", num_pt_);
  print_field_num("fst_dim_sz", fst_dim_sz_);
  print_field_num("num_dims", num_dims_);
  print_field_num("expansion tree height", get_expan_height());

  // ---- Gadget / decomposition ----
  print_field_num("l_ep (data RGSW)",  l_ep_);
  print_field_num("l_key (key RGSW)",  l_key_);
  print_field_num("l_ks (BV keyswitch)", DBConsts::L_KS);
  // print_field_num("base_log2 (data)", base_log2_);
  // print_field_num("base_log2 (key)",  base_log2_key_);

  // ---- Ring / moduli ----
  print_field_num("poly_modulus_degree", DBConsts::PolyDegree);

  std::string bits_str = "[";
  std::string mods_str = "[";
  for (size_t i = 0; i < rns_mods_.size(); ++i) {
    bits_str += std::to_string(rns_mod_bits_[i]);
    mods_str += std::to_string(rns_mods_[i]);
    if (i + 1 < rns_mods_.size()) { bits_str += " + "; mods_str += " + "; }
  }
  bits_str += "] = " + std::to_string(get_ct_mod_width()) + " bits";
  mods_str += "]";
  print_field("rns_mods (bits)", bits_str, 40);
  print_field("rns_mods", mods_str, 40);

  print_field("plain_modulus",
              std::to_string(plain_mod_) + " (log_2 ≈ " +
                  std::to_string(static_cast<int>(std::ceil(std::log2(plain_mod_)))) +
                  ")", 40);

  if (K() == 1) {
    print_field("small_q (mod-switch)",
                std::to_string(small_q_) + " (log_2 ≈ " +
                    std::to_string(static_cast<int>(std::ceil(std::log2(small_q_)))) +
                    ")", 40);
  }

  // ---- Composite-mod first-dim (only when enabled) ----
  if (composite_rns_.enabled) {
    print_field("composite split q1*q2",
                std::to_string(composite_rns_.q1) + " * " +
                    std::to_string(composite_rns_.q2),
                40);
  }

  std::cout << "==============================================================" << std::endl;
}
