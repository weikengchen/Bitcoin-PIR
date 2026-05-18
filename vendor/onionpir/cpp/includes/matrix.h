#pragma once
#include "utils.h"
#include <stdint.h>
#include <stddef.h>

#if defined(__AVX512F__)
    #include <immintrin.h>
#elif defined(__AVX2__)
    #include <immintrin.h>
#endif

// define a structure for a matrix
typedef struct {
    uint64_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} matrix_t;

typedef struct {
    db_coeff_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} db_matrix_t;

typedef struct {
    inter_coeff_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} inter_matrix_t;

typedef struct {
    uint128_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} matrix128_t;


// ! mat_vec functions means matrix-vector multiplication.
// It is used for testing the performance of each method. Otherwise,
// we are doing out = A * B, where A = m * n, B = n * 2, n = DBConsts::MaxFstDimSz


// db_coeff_t x db_coeff_t -> inter_coeff_t multiplication, accumulator
// reduced modulo q periodically to keep the running sum within inter_coeff_t.
// q == 0 disables the periodic reduction (caller asserts no overflow risk).
void mat_mat(const db_coeff_t *__restrict A, const db_coeff_t *__restrict B,
    inter_coeff_t *__restrict out, const size_t rows,
    const size_t cols, uint64_t q);

// Per-level mat_mat. level_qs has length A->levels; level k uses level_qs[k].
void level_mat_mat(db_matrix_t *A, db_matrix_t *B, inter_matrix_t *out,
                   const uint64_t *level_qs);

// No-chunk variant for diagnostics: uses a uint128 accumulator and reduces
// only once per output column. Output type is inter_coeff_t (the value still
// fits since it is a residue mod q). For benchmarking only.
void level_mat_mat_nochunk(db_matrix_t *A, db_matrix_t *B, inter_matrix_t *out,
                           const uint64_t *level_qs);

// Pure uint64 no-chunk variant. WRAPS on overflow when n·q² > 2^64 — output
// is wrong mod q in that case. Diagnostic only: measures the upper-bound
// throughput when the accumulator stays in uint64.
void level_mat_mat_nochunk_u64(const uint32_t *A_data, const uint32_t *B_data,
                               uint64_t *out_data, size_t m, size_t n,
                               size_t levels, const uint64_t *level_qs);

// Pure-stream baseline: read A in the matmul's exact access pattern, no
// multiplies, no B/output. Returns an XOR sink to defeat DCE. Measures the
// single-thread memory-read ceiling for this layout.
uint32_t level_mat_mat_stream_only(const uint32_t *A_data, size_t m,
                                   size_t n, size_t levels);

// Composite-mod first-dim helper: per-limb 32x32 -> 64 mat-mat under a single
// scalar modulus q (typically one of q1, q2 with q < 2^32). Wraps the AVX-512
// SAFE kernel; falls back to scalar 32x32->64 with a single per-output Barrett
// reduce when AVX-512 is not available. Output is reduced mod q.
//   A   : m x n, layout matches level_mat_mat (level-major, row-major)
//   B   : n x 2 (interleaved [B0_k, B1_k]), one level
//   out : m x 2 per level (interleaved)
//   levels : number of levels, must match A
//   q   : single modulus shared across all levels
void level_mat_mat_32(const uint32_t *A_data, const uint32_t *B_data,
                      uint64_t *out_data, size_t m, size_t n, size_t levels,
                      uint64_t q);

// ======================== COMPONENT WISE MULTIPLICATION ========================

// These are examples of component wise multiplication. This demonstrates the
// first dimension multiplication of OnionPIRv1.
// In v1, we think of the database as a matrix of polynomials, where each NTT
// polynomial is stored in a vector. Then, the first dimension is doing a
// matrix-matrix multiplication where each element is a vector, and the
// multiplication is defined by component wise multiplication of the vectors.
// Hence, multiplying one "row" of database and one "column" of query is
// equivalent as doing 2*N*degree many component wise multiplications, where N
// is the first dimension size, say 256.
// ? The question is: will the entire query vector of vectors stay in the cache
// when we scan the second "row" of the database?
// Short answer: No. Bad locality.

// Perform the Matrix Multiplication over a direct product over component wise vector multiplication.
void component_wise_mult(matrix_t *A, matrix_t *B, matrix_t *out);
void component_wise_mult_128(matrix_t *A, matrix_t *B, matrix128_t *out);
#if defined(__AVX512F__)
// This is using intel::hexl::EltwiseMultMod for each component wise multiplication.
void component_wise_mult_direct_mod(matrix_t *A, matrix_t *B, uint64_t *out, const uint64_t mod);
#endif

// ======================== THIRD PARTIES ========================
// Currently, I don't know any libraries that can do 64x64->128 multiplication.
// Here we use 64*64->64 multiplications as the easier alternative.
// If you want a cleaner code, maybe you can write a genearal level_mat_mult
// wrapper, then pass the function pointer to the actual implementation.
// I am being lazy here...
