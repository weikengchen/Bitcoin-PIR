//! Benchmark: parallel hint generation across all K=75 INDEX groups.
//!
//! Strategy: outer rayon par_iter over groups, inner single-threaded PRP.
//! This avoids nested rayon and gives each core one group at a time.
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_hint_bench --features "fastprp,alf"

use build::common::*;
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
#[cfg(feature = "fastprp")]
use harmonypir::prp::fast::FastPrpWrapper;
use harmonypir::prp::Prp;
use harmonypir_wasm::{
    PRP_HMR12, PRP_FASTPRP,
    compute_rounds, derive_group_key, find_best_t, pad_n_for_t,
};

use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::time::Instant;

/// Generate hints for one group, single-threaded.
/// Returns (hints_flat, entries_per_seg, non_empty_count).
fn generate_hints_single_group(
    backend: u8,
    master_key: &[u8; 16],
    group_id: u32,
    table_mmap: &[u8],
    header_size: usize,
    n: usize,
    w: usize,
    padded_n: usize,
    t: usize,
    m: usize,
    domain: usize,
    rounds: usize,
) -> (Vec<u8>, usize) {
    let derived_key = derive_group_key(master_key, group_id);
    let actual_group = group_id as usize;
    let table_offset = header_size + actual_group * n * w;

    // Build PRP.
    let prp: Box<dyn Prp> = match backend {
        PRP_HMR12 => {
            Box::new(HoangPrp::new(domain, rounds, &derived_key))
        }
        #[cfg(feature = "fastprp")]
        PRP_FASTPRP => {
            Box::new(FastPrpWrapper::new(&derived_key, domain))
        }
        // ALF arm removed 2026-05-12 — see harmonypir-wasm/src/lib.rs:36.
        _ => {
            Box::new(HoangPrp::new(domain, rounds, &derived_key))
        }
    };

    // Compute cell assignments — single-threaded.
    // For FastPRP: batch_permute() is already single-threaded — perfect.
    // For HMR12: use shuffle_forward_4way in chunks of 4, no rayon.
    // For ALF: sequential forward() calls.
    let cell_of: Vec<usize> = match backend {
        #[cfg(feature = "fastprp")]
        PRP_FASTPRP => {
            // FastPRP batch_permute is inherently single-threaded.
            use harmonypir::prp::BatchPrp;
            let fp = prp.as_ref() as *const dyn Prp;
            let full = unsafe { &*(fp as *const FastPrpWrapper) }.batch_forward();
            full[..padded_n].to_vec()
        }
        PRP_HMR12 => {
            // HMR12: single-threaded 4-way AES pipelining via Prp::forward_4 (no rayon).
            let mut result = vec![0usize; padded_n];
            let mut i = 0;
            while i + 4 <= padded_n {
                let ys = prp.forward_4([i, i + 1, i + 2, i + 3]);
                result[i]   = ys[0];
                result[i+1] = ys[1];
                result[i+2] = ys[2];
                result[i+3] = ys[3];
                i += 4;
            }
            while i < padded_n {
                result[i] = prp.forward(i);
                i += 1;
            }
            result
        }
        _ => {
            // ALF / others: sequential forward().
            (0..padded_n).map(|k| prp.forward(k)).collect()
        }
    };

    // Scatter-XOR into hints.
    let mut hints = vec![0u8; m * w];
    let mut non_empty = 0usize;

    for k in 0..padded_n {
        let seg = cell_of[k] / t;
        if k < n {
            let start = table_offset + k * w;
            let entry = &table_mmap[start..start + w];
            if !entry.iter().all(|&b| b == 0) { non_empty += 1; }
            let hint_start = seg * w;
            for (d, s) in hints[hint_start..hint_start + w].iter_mut().zip(entry.iter()) {
                *d ^= s;
            }
        }
    }

    (hints, non_empty)
}

/// Generate hints using inner rayon (batch_forward with par_iter inside).
/// Groups are processed sequentially; parallelism is within each group.
fn generate_hints_inner_rayon(
    backend: u8,
    master_key: &[u8; 16],
    group_id: u32,
    table_mmap: &[u8],
    header_size: usize,
    n: usize,
    w: usize,
    padded_n: usize,
    t: usize,
    m: usize,
    domain: usize,
    rounds: usize,
) -> (Vec<u8>, usize) {
    use harmonypir::prp::BatchPrp;

    let derived_key = derive_group_key(master_key, group_id);
    let actual_group = group_id as usize;
    let table_offset = header_size + actual_group * n * w;

    // Build PRP — same as before.
    // ALF arm removed 2026-05-12 — see harmonypir-wasm/src/lib.rs:36.
    let prp: Box<dyn BatchPrp> = match backend {
        PRP_HMR12 => {
            Box::new(HoangPrp::new(domain, rounds, &derived_key))
        }
        _ => {
            Box::new(HoangPrp::new(domain, rounds, &derived_key))
        }
    };

    // batch_forward() uses rayon internally (par_chunks_mut for HMR12, par_iter for ALF).
    let full_perm = prp.batch_forward();

    // Scatter-XOR into hints — same sequential loop.
    let mut hints = vec![0u8; m * w];
    let mut non_empty = 0usize;

    for k in 0..padded_n {
        let cell = full_perm[k];
        let seg = cell / t;
        if k < n {
            let start = table_offset + k * w;
            let entry = &table_mmap[start..start + w];
            if !entry.iter().all(|&b| b == 0) { non_empty += 1; }
            let hint_start = seg * w;
            for (d, s) in hints[hint_start..hint_start + w].iter_mut().zip(entry.iter()) {
                *d ^= s;
            }
        }
    }

    (hints, non_empty)
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  HarmonyPIR Hint Generation Benchmark — All INDEX Buckets  ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let key = [0x42u8; 16];
    let num_threads = rayon::current_num_threads();

    // Load INDEX cuckoo table.
    let idx_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let idx_mmap = unsafe { Mmap::map(&idx_file) }.expect("mmap");
    let (index_bins, _tag_seed) = read_cuckoo_header(&idx_mmap);
    let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE; // 4 × 13 = 52

    let n = index_bins;
    let t_raw = find_best_t(n as u32);
    let (padded_n, t_val) = pad_n_for_t(n as u32, t_raw);
    let pn = padded_n as usize;
    let t = t_val as usize;
    let domain = 2 * pn;
    let rounds = compute_rounds(padded_n);
    let params = Params::new(pn, index_w, t).unwrap();
    let m = params.m;

    println!("  Database:   {} ({:.2} GB)", CUCKOO_FILE,
        idx_mmap.len() as f64 / (1024.0*1024.0*1024.0));
    println!("  Buckets:    K={}", K);
    println!("  N={} bins, padded_N={}, T={}, M={} segments", n, pn, t, m);
    println!("  w={}B per bin, domain={}", index_w, domain);
    println!("  Rayon threads: {}\n", num_threads);

    let backends: Vec<(u8, &str)> = vec![
        (PRP_HMR12, "HMR12 (4-way AES, single-threaded per group)"),
        #[cfg(feature = "fastprp")]
        (PRP_FASTPRP, "FastPRP (batch_permute, single-threaded per group)"),
    ];

    for &(backend, backend_name) in &backends {
        println!("  ─── {} ───", backend_name);

        // ── Single group (group 0) for baseline ──
        let t0 = Instant::now();
        let (_hints, _ne) = generate_hints_single_group(
            backend, &key, 0,
            &idx_mmap, HEADER_SIZE, n, index_w,
            pn, t, m, domain, rounds,
        );
        let single = t0.elapsed();
        println!("    1 group (single-threaded):  {:.2?}", single);

        // ── All K groups, sequential ──
        let t0 = Instant::now();
        for b in 0..K as u32 {
            let _ = generate_hints_single_group(
                backend, &key, b,
                &idx_mmap, HEADER_SIZE, n, index_w,
                pn, t, m, domain, rounds,
            );
        }
        let sequential = t0.elapsed();
        println!("    {} groups (sequential):    {:.2?}", K, sequential);

        // ── All K groups, outer rayon ──
        let t0 = Instant::now();
        let _all_hints: Vec<_> = (0..K as u32)
            .into_par_iter()
            .map(|b| {
                generate_hints_single_group(
                    backend, &key, b,
                    &idx_mmap, HEADER_SIZE, n, index_w,
                    pn, t, m, domain, rounds,
                )
            })
            .collect();
        let parallel = t0.elapsed();

        let speedup = sequential.as_secs_f64() / parallel.as_secs_f64();
        println!("    {} groups (outer rayon):   {:.2?}  ({:.1}× speedup, {} threads)\n",
            K, parallel, speedup, num_threads);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Inner-only rayon comparison (HMR12 + ALF only — FastPRP has no inner rayon)
    // ═══════════════════════════════════════════════════════════════════
    println!("  ════════════════════════════════════════════");
    println!("  Inner-only rayon (sequential over groups, rayon inside batch_forward)\n");

    let inner_backends: Vec<(u8, &str)> = vec![
        (PRP_HMR12, "HMR12 (inner rayon par_chunks_mut(4))"),
    ];

    for &(backend, backend_name) in &inner_backends {
        println!("  ─── {} ───", backend_name);

        // ── 1 group with inner rayon ──
        let t0 = Instant::now();
        let _ = generate_hints_inner_rayon(
            backend, &key, 0,
            &idx_mmap, HEADER_SIZE, n, index_w,
            pn, t, m, domain, rounds,
        );
        let single_inner = t0.elapsed();
        println!("    1 group (inner rayon):      {:.2?}", single_inner);

        // ── 75 groups sequential, each with inner rayon ──
        let t0 = Instant::now();
        for b in 0..K as u32 {
            let _ = generate_hints_inner_rayon(
                backend, &key, b,
                &idx_mmap, HEADER_SIZE, n, index_w,
                pn, t, m, domain, rounds,
            );
        }
        let inner_sequential = t0.elapsed();
        println!("    {} groups (inner-only):     {:.2?}\n", K, inner_sequential);
    }

    println!("  Done.");
}
