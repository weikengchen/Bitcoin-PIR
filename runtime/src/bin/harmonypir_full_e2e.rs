//! HarmonyPIR FULL E2E: all 75 INDEX + 80 CHUNK groups on real Bitcoin UTXO data.
//!
//! Complete protocol pipeline:
//!   Phase 1 (offline): Generate hints for all 155 groups (outer rayon, ALF)
//!   Phase 2 (online):  For each INDEX group, query → decode → query CHUNK → verify
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_full_e2e --features "alf"

use build::common::*;
use harmonypir::params::Params;
#[cfg(feature = "alf")]
use harmonypir::prp::alf::AlfPrp;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir_wasm::{
    HarmonyGroup, PRP_ALF, PRP_HOANG,
    compute_rounds, derive_group_key, find_best_t, pad_n_for_t,
};

use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::time::Instant;

const MASTER_KEY: [u8; 16] = [0x42u8; 16];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 16 {
        hex(bytes)
    } else {
        format!("{}...{} ({} B)", hex(&bytes[..8]), hex(&bytes[bytes.len()-4..]), bytes.len())
    }
}

/// Decode a 13-byte index slot: [8B tag][4B start_chunk_id LE][1B num_chunks]
fn decode_index_slot(slot: &[u8]) -> (u64, u32, u8) {
    let tag = u64::from_le_bytes(slot[0..8].try_into().unwrap());
    let start_chunk = u32::from_le_bytes(slot[8..12].try_into().unwrap());
    let num_chunks = slot[12];
    (tag, start_chunk, num_chunks)
}

fn decode_chunk_slot(slot: &[u8]) -> (u32, &[u8]) {
    let chunk_id = u32::from_le_bytes(slot[0..4].try_into().unwrap());
    (chunk_id, &slot[4..])
}

fn choose_backend() -> (u8, &'static str) {
    #[cfg(feature = "alf")]
    { (PRP_ALF, "ALF") }
    #[cfg(not(feature = "alf"))]
    { (PRP_HOANG, "Hoang") }
}

/// Generate hints for one group (single-threaded, for outer rayon).
fn generate_hints_for_bucket(
    backend: u8,
    group_id: u32,
    table_mmap: &[u8],
    header_size: usize,
    actual_group: usize,
    n: usize,
    w: usize,
    padded_n: usize,
    t: usize,
    m: usize,
    domain: usize,
    rounds: usize,
) -> Vec<u8> {
    let derived_key = derive_group_key(&MASTER_KEY, group_id);
    let table_offset = header_size + actual_group * n * w;

    // Build PRP and compute cell assignments (single-threaded).
    let cell_of: Vec<usize> = match backend {
        #[cfg(feature = "alf")]
        PRP_ALF => {
            let prp = AlfPrp::new(&derived_key, domain, &derived_key, 0x4250_4952);
            (0..padded_n).map(|k| prp.forward(k)).collect()
        }
        _ => {
            let prp = HoangPrp::new(domain, rounds, &derived_key);
            let mut result = vec![0usize; padded_n];
            let mut i = 0;
            while i + 4 <= padded_n {
                let ys = prp.forward_4([i, i+1, i+2, i+3]);
                result[i] = ys[0]; result[i+1] = ys[1];
                result[i+2] = ys[2]; result[i+3] = ys[3];
                i += 4;
            }
            while i < padded_n { result[i] = prp.forward(i); i += 1; }
            result
        }
    };

    // Scatter-XOR into hints.
    let mut hints = vec![0u8; m * w];
    for k in 0..padded_n {
        let seg = cell_of[k] / t;
        if k < n {
            let start = table_offset + k * w;
            let entry = &table_mmap[start..start + w];
            let hint_start = seg * w;
            for (d, s) in hints[hint_start..hint_start + w].iter_mut().zip(entry.iter()) {
                *d ^= s;
            }
        }
    }

    hints
}

/// Simulate query server: look up sorted non-empty indices from the table.
fn simulate_query_server(
    req_bytes: &[u8],
    table_mmap: &[u8],
    table_offset: usize,
    n: usize,
    w: usize,
) -> Vec<u8> {
    let count = req_bytes.len() / 4;
    let mut response = Vec::with_capacity(count * w);
    for j in 0..count {
        let idx = u32::from_le_bytes(req_bytes[j*4..(j+1)*4].try_into().unwrap());
        if idx as usize >= n {
            response.extend(std::iter::repeat(0u8).take(w));
        } else {
            let s = table_offset + idx as usize * w;
            response.extend_from_slice(&table_mmap[s..s + w]);
        }
    }
    response
}

/// Find first non-empty, non-whale INDEX entry in a group.
/// Returns Some((bin, slot_idx, tag, start_chunk, num_chunks)).
fn find_target_in_index_group(
    table_mmap: &[u8],
    table_offset: usize,
    n: usize,
    w: usize,
) -> Option<(usize, usize, u64, u32, u8)> {
    for bin in 0..n {
        let bin_start = table_offset + bin * w;
        for slot in 0..INDEX_SLOTS_PER_BIN {
            let s = bin_start + slot * INDEX_SLOT_SIZE;
            let (tag, start_chunk, num_chunks) = decode_index_slot(&table_mmap[s..s + INDEX_SLOT_SIZE]);
            if tag != 0 && num_chunks > 0 && num_chunks < 50 {
                return Some((bin, slot, tag, start_chunk, num_chunks));
            }
        }
    }
    None
}

fn main() {
    let (backend, backend_name) = choose_backend();

    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║  HarmonyPIR FULL E2E: All {} INDEX + {} CHUNK Buckets — Real Bitcoin Data  ║", K, K_CHUNK);
    println!("║  PRP Backend: {:60}║", format!("{} (id={})", backend_name, backend));
    println!("╚═══════════════════════════════════════════════════════════════════════════╝\n");

    // ═══════════════════════════════════════════════════════════════════
    // LOAD DATABASES
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ PHASE 0: Load cuckoo tables ━━━\n");

    let idx_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let idx_mmap = unsafe { Mmap::map(&idx_file) }.expect("mmap index");
    let (index_bins, _tag_seed) = read_cuckoo_header(&idx_mmap);
    let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE; // 4 × 13 = 52

    let chunk_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_mmap = unsafe { Mmap::map(&chunk_file) }.expect("mmap chunk");
    let chunk_bins = read_chunk_cuckoo_header(&chunk_mmap);
    let chunk_w = CHUNK_SLOTS_PER_BIN * (4 + CHUNK_SIZE); // 3 × 44 = 132

    println!("  INDEX: {} bins × {}B, K={} groups", index_bins, index_w, K);
    println!("  CHUNK: {} bins × {}B, K={} groups\n", chunk_bins, chunk_w, K_CHUNK);

    // Precompute params for INDEX.
    let idx_t_raw = find_best_t(index_bins as u32);
    let (idx_padded_n, idx_t) = pad_n_for_t(index_bins as u32, idx_t_raw);
    let idx_pn = idx_padded_n as usize;
    let idx_t_usize = idx_t as usize;
    let idx_domain = 2 * idx_pn;
    let idx_rounds = compute_rounds(idx_padded_n);
    let idx_params = Params::new(idx_pn, index_w, idx_t_usize).unwrap();
    let idx_m = idx_params.m;

    println!("  INDEX params: padded_N={}, T={}, M={}, domain={}, max_queries={}",
        idx_pn, idx_t_usize, idx_m, idx_domain, idx_params.max_queries);

    // Precompute params for CHUNK.
    let chk_t_raw = find_best_t(chunk_bins as u32);
    let (chk_padded_n, chk_t) = pad_n_for_t(chunk_bins as u32, chk_t_raw);
    let chk_pn = chk_padded_n as usize;
    let chk_t_usize = chk_t as usize;
    let chk_domain = 2 * chk_pn;
    let chk_rounds = compute_rounds(chk_padded_n);
    let chk_params = Params::new(chk_pn, chunk_w, chk_t_usize).unwrap();
    let chk_m = chk_params.m;

    println!("  CHUNK params: padded_N={}, T={}, M={}, domain={}, max_queries={}",
        chk_pn, chk_t_usize, chk_m, chk_domain, chk_params.max_queries);

    let num_threads = rayon::current_num_threads();
    println!("  Rayon threads: {}\n", num_threads);

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 1: OFFLINE — Generate all hints (outer rayon)
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ PHASE 1: OFFLINE — Generate hints for all {} groups (outer rayon) ━━━\n", K + K_CHUNK);

    // ── Warmup: touch all mmap pages to measure without cold-cache penalty ──
    println!("  [Warmup] Touching INDEX mmap ({:.2} GB)...", idx_mmap.len() as f64 / (1024.0*1024.0*1024.0));
    let t_warm = Instant::now();
    {
        let mut _sum: u8 = 0;
        // Read one byte per 4KB page to fault all pages in.
        for i in (0..idx_mmap.len()).step_by(4096) {
            _sum = _sum.wrapping_add(idx_mmap[i]);
        }
        std::hint::black_box(_sum);
    }
    println!("    INDEX warmed in {:.2?}", t_warm.elapsed());

    println!("  [Warmup] Touching CHUNK mmap ({:.2} GB)...", chunk_mmap.len() as f64 / (1024.0*1024.0*1024.0));
    let t_warm = Instant::now();
    {
        let mut _sum: u8 = 0;
        for i in (0..chunk_mmap.len()).step_by(4096) {
            _sum = _sum.wrapping_add(chunk_mmap[i]);
        }
        std::hint::black_box(_sum);
    }
    println!("    CHUNK warmed in {:.2?}\n", t_warm.elapsed());

    // INDEX hints.
    let t0 = Instant::now();
    let index_hints: Vec<Vec<u8>> = (0..K as u32)
        .into_par_iter()
        .map(|b| {
            generate_hints_for_bucket(
                backend, b, &idx_mmap[..], HEADER_SIZE, b as usize,
                index_bins, index_w, idx_pn, idx_t_usize, idx_m, idx_domain, idx_rounds,
            )
        })
        .collect();
    let idx_hint_time = t0.elapsed();
    println!("  INDEX: {} groups in {:.2?} ({:.1?}/group)",
        K, idx_hint_time, idx_hint_time / K as u32);

    // CHUNK hints (run 1).
    let t0 = Instant::now();
    let chunk_hints: Vec<Vec<u8>> = (0..K_CHUNK as u32)
        .into_par_iter()
        .map(|b| {
            generate_hints_for_bucket(
                backend, K as u32 + b, &chunk_mmap[..], CHUNK_HEADER_SIZE, b as usize,
                chunk_bins, chunk_w, chk_pn, chk_t_usize, chk_m, chk_domain, chk_rounds,
            )
        })
        .collect();
    let chk_hint_time = t0.elapsed();
    println!("  CHUNK: {} groups in {:.2?} ({:.1?}/group)",
        K_CHUNK, chk_hint_time, chk_hint_time / K_CHUNK as u32);

    // CHUNK hints (run 2 — fully warm).
    let t0 = Instant::now();
    let _chunk_hints_2: Vec<Vec<u8>> = (0..K_CHUNK as u32)
        .into_par_iter()
        .map(|b| {
            generate_hints_for_bucket(
                backend, K as u32 + b, &chunk_mmap[..], CHUNK_HEADER_SIZE, b as usize,
                chunk_bins, chunk_w, chk_pn, chk_t_usize, chk_m, chk_domain, chk_rounds,
            )
        })
        .collect();
    let chk_hint_time_2 = t0.elapsed();
    println!("  CHUNK (run 2, warm): {} groups in {:.2?} ({:.1?}/group)",
        K_CHUNK, chk_hint_time_2, chk_hint_time_2 / K_CHUNK as u32);

    let total_hint_bytes: usize = index_hints.iter().map(|h| h.len()).sum::<usize>()
        + chunk_hints.iter().map(|h| h.len()).sum::<usize>();
    println!("  Total offline: {:.2?} (warm), {:.1} MB of hints\n",
        idx_hint_time + chk_hint_time_2,
        total_hint_bytes as f64 / (1024.0 * 1024.0));

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 2: Build HarmonyGroup instances from hints
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ PHASE 2: Build HarmonyGroup instances ━━━\n");

    let t0 = Instant::now();
    let mut index_groups: Vec<HarmonyGroup> = (0..K)
        .map(|b| {
            let mut group = HarmonyGroup::new_with_backend(
                index_bins as u32, index_w as u32, idx_t as u32,
                &MASTER_KEY, b as u32, backend,
            ).unwrap();
            group.load_hints(&index_hints[b]).unwrap();
            group
        })
        .collect();

    let mut chunk_groups: Vec<HarmonyGroup> = (0..K_CHUNK)
        .map(|b| {
            let mut group = HarmonyGroup::new_with_backend(
                chunk_bins as u32, chunk_w as u32, chk_t as u32,
                &MASTER_KEY, K as u32 + b as u32, backend,
            ).unwrap();
            group.load_hints(&chunk_hints[b]).unwrap();
            group
        })
        .collect();
    let group_build_time = t0.elapsed();
    println!("  {} INDEX + {} CHUNK groups built in {:.2?}\n", K, K_CHUNK, group_build_time);

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 3: ONLINE — Full INDEX → CHUNK pipeline for every INDEX group
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ PHASE 3: ONLINE — Query all {} INDEX groups → decode → query CHUNK ━━━\n", K);

    let overall_t0 = Instant::now();
    let mut total_index_queries = 0usize;
    let mut total_chunk_queries = 0usize;
    let mut total_index_req_bytes = 0usize;
    let mut total_index_resp_bytes = 0usize;
    let mut total_chunk_req_bytes = 0usize;
    let mut total_chunk_resp_bytes = 0usize;
    let mut total_index_dummy = 0usize;
    let mut total_chunk_dummy = 0usize;
    let mut chunk_groups_touched = vec![false; K_CHUNK];
    let mut all_pass = true;

    for ib in 0..K {
        let idx_table_offset = HEADER_SIZE + ib * index_bins * index_w;

        // Find a target entry in this INDEX group.
        let target = find_target_in_index_group(
            &idx_mmap[..], idx_table_offset, index_bins, index_w,
        );

        if target.is_none() {
            println!("  INDEX[{:>2}]: (no non-empty entry with chunks found, skipping)", ib);
            continue;
        }
        let (target_bin, _slot_idx, target_tag, start_chunk, num_chunks) = target.unwrap();

        // ── INDEX query (real) ──
        let req = index_groups[ib].build_request(target_bin as u32).unwrap();
        let req_bytes = req.request();
        let _idx_count = req_bytes.len() / 4;

        let response = simulate_query_server(
            &req_bytes, &idx_mmap[..], idx_table_offset, index_bins, index_w,
        );

        let answer = index_groups[ib].process_response(&response).unwrap();

        // ── INDEX dummy queries (K-1 other groups) ──
        for ob in 0..K {
            if ob == ib { continue; }
            let dummy_req = index_groups[ob].build_dummy_request().unwrap();
            let dummy_bytes = dummy_req.request();
            let ob_table_offset = HEADER_SIZE + ob * index_bins * index_w;
            let _dummy_resp = simulate_query_server(
                &dummy_bytes, &idx_mmap[..], ob_table_offset, index_bins, index_w,
            );
            // Client discards dummy response — no process_response, no hint consumed.
            total_index_dummy += 1;
        }

        // Verify INDEX answer.
        let expected_start = idx_table_offset + target_bin * index_w;
        let expected = &idx_mmap[expected_start..expected_start + index_w];
        let idx_ok = answer.as_slice() == expected;

        total_index_queries += 1;
        total_index_req_bytes += req_bytes.len();
        total_index_resp_bytes += response.len();

        if !idx_ok {
            println!("  INDEX[{:>2}]: bin={} tag=0x{:016x} → INDEX QUERY FAILED ✗", ib, target_bin, target_tag);
            all_pass = false;
            continue;
        }

        // ── Decode INDEX → find CHUNK group + bin ──
        let chunk_pbc_groups = derive_chunk_groups(start_chunk);
        let g = 0; // use first group
        let cb = chunk_pbc_groups[g];
        let chk_table_offset = CHUNK_HEADER_SIZE + cb * chunk_bins * chunk_w;

        // Scan all hash functions to find which bin holds start_chunk
        let mut target_chunk_bin = None;
        for ch in 0..CHUNK_CUCKOO_NUM_HASHES {
            let ckey = derive_chunk_cuckoo_key(cb, ch);
            let bin = cuckoo_hash_int(start_chunk, ckey, chunk_bins);
            let bin_off = chk_table_offset + bin * chunk_w;
            for slot in 0..CHUNK_SLOTS_PER_BIN {
                let s = bin_off + slot * (4 + CHUNK_SIZE);
                let cid = u32::from_le_bytes(chunk_mmap[s..s+4].try_into().unwrap());
                if cid == start_chunk {
                    target_chunk_bin = Some(bin);
                    break;
                }
            }
            if target_chunk_bin.is_some() { break; }
        }

        if target_chunk_bin.is_none() {
            println!("  INDEX[{:>2}] bin={:>6} → tag=0x{:016x} chunk={} n={} → CHUNK[{:>2}] NOT FOUND in any hash fn ✗",
                ib, target_bin, target_tag, start_chunk, num_chunks, cb);
            all_pass = false;
            continue;
        }
        let target_chunk_bin = target_chunk_bin.unwrap();

        chunk_groups_touched[cb] = true;

        // ── CHUNK query (real) ──
        let chk_req = chunk_groups[cb].build_request(target_chunk_bin as u32).unwrap();
        let chk_req_bytes = chk_req.request();
        let _chk_count = chk_req_bytes.len() / 4;
        let chk_response = simulate_query_server(
            &chk_req_bytes, &chunk_mmap[..], chk_table_offset, chunk_bins, chunk_w,
        );

        let chk_answer = chunk_groups[cb].process_response(&chk_response).unwrap();

        // ── CHUNK dummy queries (K_CHUNK-1 other groups) ──
        for ob in 0..K_CHUNK {
            if ob == cb { continue; }
            let dummy_req = chunk_groups[ob].build_dummy_request().unwrap();
            let dummy_bytes = dummy_req.request();
            let ob_table_offset = CHUNK_HEADER_SIZE + ob * chunk_bins * chunk_w;
            let _dummy_resp = simulate_query_server(
                &dummy_bytes, &chunk_mmap[..], ob_table_offset, chunk_bins, chunk_w,
            );
            total_chunk_dummy += 1;
        }

        // Verify CHUNK answer.
        let chk_expected_start = chk_table_offset + target_chunk_bin * chunk_w;
        let chk_expected = &chunk_mmap[chk_expected_start..chk_expected_start + chunk_w];
        let chk_ok = chk_answer.as_slice() == chk_expected;

        // Find the target chunk_id in the answer.
        let mut found_chunk = false;
        let mut chunk_data_hex = String::new();
        for slot in 0..CHUNK_SLOTS_PER_BIN {
            let s = slot * (4 + CHUNK_SIZE);
            let (cid, data) = decode_chunk_slot(&chk_answer[s..s + 4 + CHUNK_SIZE]);
            if cid == start_chunk {
                found_chunk = true;
                chunk_data_hex = hex_short(data);
            }
        }

        total_chunk_queries += 1;
        total_chunk_req_bytes += chk_req_bytes.len();
        total_chunk_resp_bytes += chk_response.len();

        let pass = idx_ok && chk_ok && found_chunk;
        if !pass { all_pass = false; }

        println!("  INDEX[{:>2}] bin={:>6} → tag=0x{:016x} chunk={} n={} → CHUNK[{:>2}] bin={:>7} → {} {}",
            ib, target_bin, target_tag, start_chunk, num_chunks,
            cb, target_chunk_bin,
            if found_chunk { &chunk_data_hex } else { "NOT FOUND" },
            if pass { "✓" } else { "✗" });
    }

    let online_time = overall_t0.elapsed();

    // ═══════════════════════════════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════════════════════════════
    let chunk_touched = chunk_groups_touched.iter().filter(|&&b| b).count();

    println!("\n━━━ SUMMARY ━━━\n");
    println!("  PRP backend:         {}", backend_name);
    println!("  INDEX groups:       {}/{} queried ({} dummy)", total_index_queries, K, total_index_dummy);
    println!("  CHUNK groups:       {}/{} touched ({} real + {} dummy)", chunk_touched, K_CHUNK, total_chunk_queries, total_chunk_dummy);

    println!("\n  ─── Offline (Hint Generation) ───");
    println!("    INDEX: {} groups in {:.2?}", K, idx_hint_time);
    println!("    CHUNK: {} groups in {:.2?}", K_CHUNK, chk_hint_time);
    println!("    Total: {:.2?}", idx_hint_time + chk_hint_time);
    println!("    Hint storage: {:.1} MB ({:.1} KB/INDEX + {:.1} KB/CHUNK)",
        total_hint_bytes as f64 / (1024.0 * 1024.0),
        index_hints[0].len() as f64 / 1024.0,
        chunk_hints[0].len() as f64 / 1024.0);

    println!("\n  ─── Online (Queries) ───");
    println!("    {} INDEX queries + {} CHUNK queries in {:.2?}", total_index_queries, total_chunk_queries, online_time);
    println!("    INDEX comms: {:.1} KB request + {:.1} KB response = {:.1} KB avg/query",
        total_index_req_bytes as f64 / 1024.0,
        total_index_resp_bytes as f64 / 1024.0,
        (total_index_req_bytes + total_index_resp_bytes) as f64 / total_index_queries as f64 / 1024.0);
    println!("    CHUNK comms: {:.1} KB request + {:.1} KB response = {:.1} KB avg/query",
        total_chunk_req_bytes as f64 / 1024.0,
        total_chunk_resp_bytes as f64 / 1024.0,
        (total_chunk_req_bytes + total_chunk_resp_bytes) as f64 / total_chunk_queries as f64 / 1024.0);
    let total_online = total_index_req_bytes + total_index_resp_bytes
        + total_chunk_req_bytes + total_chunk_resp_bytes;
    println!("    Total per UTXO lookup: ~{:.1} KB (INDEX) + ~{:.1} KB (CHUNK) = ~{:.1} KB",
        (total_index_req_bytes + total_index_resp_bytes) as f64 / total_index_queries as f64 / 1024.0,
        (total_chunk_req_bytes + total_chunk_resp_bytes) as f64 / total_chunk_queries as f64 / 1024.0,
        total_online as f64 / total_index_queries as f64 / 1024.0);

    // Max queries budget.
    println!("\n  ─── Query Budget ───");
    println!("    INDEX: {} max queries per group ({} used → {} remaining)",
        idx_params.max_queries, 1, idx_params.max_queries - 1);
    println!("    CHUNK: {} max queries per group ({} used in most-touched → {} remaining)",
        chk_params.max_queries, 1, chk_params.max_queries - 1);

    if all_pass {
        println!("\n╔═══════════════════════════════════════════════════════════════════════════╗");
        println!("║  FULL E2E: ALL {} INDEX → CHUNK PIPELINES PASSED ✓                        ║", total_index_queries);
        println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    } else {
        println!("\n╔═══════════════════════════════════════════════════════════════════════════╗");
        println!("║  FULL E2E: SOME QUERIES FAILED ✗                                         ║");
        println!("╚═══════════════════════════════════════════════════════════════════════════╝");
        std::process::exit(1);
    }
}
