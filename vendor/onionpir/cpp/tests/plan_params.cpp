#include "tests.h"

#include <cstdio>

// Pareto table over num_other_dims (y) for the OnionPIRv2 design:
// server-stateful, single packed query, GSWs derived from RGSW(s) via
// query_to_gsw. The user picks a row: smaller y ⇒ fewer external products
// (higher throughput); larger y ⇒ smaller first dim (lower memory traffic
// but more external products).
//
// Parameters
//   target_num_pt   N  — total plaintexts in the database
//   fst_dim_sz      x  — first-dimension size (plaintexts)
//   num_other_dims  y  — number of subsequent (log-folded) dims, each size 2
//   tree_height     k  — depth of per-query expansion tree (1 query → 2^k slots)
//   L_EP               — gadget length for subsequent-dim external products
//
// Constraint:  2^k ≥ x + y · L_EP   and   x · 2^y ≥ N
// Cost (this model): 1 BFV (just the query — keys server-resident).

namespace {

struct Row {
  size_t num_other_dims = 0;
  size_t tree_height = 0;
  size_t fst_dim_sz = 0;
  bool feasible = false;
};

Row best_for_y(size_t y, size_t target_num_pt, size_t L_EP) {
  constexpr size_t MAX_K = 12;
  const size_t reserved_for_gsw = y * L_EP;

  Row best;
  best.num_other_dims = y;

  for (size_t k = 1; k <= MAX_K; k++) {
    const size_t slots = size_t{1} << k;
    if (slots <= reserved_for_gsw) continue;
    const size_t fst_dim_sz = slots - reserved_for_gsw;

    if (y >= 64) continue;
    const size_t covered = fst_dim_sz << y;
    if ((covered >> y) != fst_dim_sz) continue;
    if (covered < target_num_pt) continue;

    best.feasible = true;
    best.tree_height = k;
    best.fst_dim_sz = fst_dim_sz;
    return best;  // smallest feasible k wins
  }
  return best;
}

}  // namespace

void PirTest::plan_params() {
  PirParams pir_params;
  const size_t target_num_pt = pir_params.get_num_pt();
  const size_t L_EP = pir_params.get_l();
  const size_t bfv_bytes = pir_params.get_BFV_size(/*use_seed=*/true);

  std::printf("plan_params: Pareto over num_other_dims (y)\n");
  std::printf("  target_num_pt = %zu, L_EP = %zu, BFV size = %zu B (seed-compressed)\n",
              target_num_pt, L_EP, bfv_bytes);
  std::printf("  smaller y ⇒ fewer external products (higher throughput)\n\n");

  std::printf("    %-3s  %-3s  %-8s  %-10s\n", "y", "k", "fst_dim", "comm (KB)");
  constexpr size_t MAX_Y = 20;
  for (size_t y = 0; y <= MAX_Y; y++) {
    Row r = best_for_y(y, target_num_pt, L_EP);
    if (!r.feasible) continue;
    std::printf("    %-3zu  %-3zu  %-8zu  %10.2f\n",
                r.num_other_dims, r.tree_height, r.fst_dim_sz,
                static_cast<double>(bfv_bytes) / 1024.0);
  }
  std::printf("\n");
}
