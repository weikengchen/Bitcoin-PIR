//! HarmonyPIR full narrative E2E test on REAL Bitcoin UTXO cuckoo tables.
//!
//! Walks through the entire protocol with detailed intermediate logs:
//! - Hint generation (offline phase)
//! - State file serialization
//! - Query construction, server answer, answer recovery (online phase)
//! - Hint update after each query
//! - Decoded index entries (tag, start_chunk_id, num_chunks)
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_real_test

use build::common::*;
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
#[cfg(feature = "fastprp")]
use harmonypir::prp::fast::FastPrpWrapper;
#[cfg(feature = "alf")]
use harmonypir::prp::alf::AlfPrp;
use harmonypir::prp::Prp;
use harmonypir::relocation::RelocationDS;
use harmonypir_wasm::{
    HarmonyBucket, PRP_HOANG, PRP_FASTPRP, PRP_ALF,
    compute_rounds, derive_bucket_key, find_best_t, pad_n_for_t,
};

use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 20 {
        hex(bytes)
    } else {
        format!("{}...{} ({} B)", hex(&bytes[..10]), hex(&bytes[bytes.len()-4..]), bytes.len())
    }
}

/// Decode a 17-byte index slot: [8B tag][4B start_chunk_id LE][1B num_chunks][4B tree_loc LE]
fn decode_index_slot(slot: &[u8]) -> (u64, u32, u8, u32) {
    let tag = u64::from_le_bytes(slot[0..8].try_into().unwrap());
    let start_chunk = u32::from_le_bytes(slot[8..12].try_into().unwrap());
    let num_chunks = slot[12];
    let tree_loc = u32::from_le_bytes(slot[13..17].try_into().unwrap());
    (tag, start_chunk, num_chunks, tree_loc)
}

/// Decode a 44-byte chunk slot: [4B chunk_id LE][40B data]
fn decode_chunk_slot(slot: &[u8]) -> (u32, &[u8]) {
    let chunk_id = u32::from_le_bytes(slot[0..4].try_into().unwrap());
    (chunk_id, &slot[4..])
}

/// Build a boxed PRP for the given backend.
fn build_prp_box(backend: u8, key: &[u8; 16], domain: usize, rounds: usize) -> Box<dyn Prp> {
    match backend {
        PRP_HOANG => Box::new(HoangPrp::new(domain, rounds, key)),
        #[cfg(feature = "fastprp")]
        PRP_FASTPRP => Box::new(FastPrpWrapper::new(key, domain)),
        #[cfg(feature = "alf")]
        PRP_ALF => Box::new(AlfPrp::new(key, domain, key, 0x4250_4952)),
        _ => Box::new(HoangPrp::new(domain, rounds, key)),
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     HarmonyPIR Full Protocol Narrative — Real Bitcoin DB    ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let key = [0x42u8; 16];

    // ═══════════════════════════════════════════════════════════════════
    // LOAD DATABASE
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 0: Load cuckoo tables (shared by Hint Server + Query Server) ━━━\n");

    let idx_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let idx_mmap = unsafe { Mmap::map(&idx_file) }.expect("mmap");
    let (index_bins, tag_seed) = read_cuckoo_header(&idx_mmap);
    let index_w = CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE; // 4 × 13 = 52

    let chunk_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_mmap = unsafe { Mmap::map(&chunk_file) }.expect("mmap");
    let chunk_bins = read_chunk_cuckoo_header(&chunk_mmap);
    let chunk_w = CHUNK_CUCKOO_BUCKET_SIZE * (4 + CHUNK_SIZE); // 3 × 44 = 132

    println!("  Index cuckoo: {} ({:.2} GB)", CUCKOO_FILE,
        idx_mmap.len() as f64 / (1024.0*1024.0*1024.0));
    println!("    N={} bins, w={}B per bin ({} slots × {}B), tag_seed=0x{:016x}",
        index_bins, index_w, CUCKOO_BUCKET_SIZE, INDEX_SLOT_SIZE, tag_seed);
    println!("  Chunk cuckoo: {} ({:.2} GB)", CHUNK_CUCKOO_FILE,
        chunk_mmap.len() as f64 / (1024.0*1024.0*1024.0));
    println!("    N={} bins, w={}B per bin ({} slots × {}B)\n",
        chunk_bins, chunk_w, CHUNK_CUCKOO_BUCKET_SIZE, 4 + CHUNK_SIZE);

    // ═══════════════════════════════════════════════════════════════════
    // All PRP backends to test
    // ═══════════════════════════════════════════════════════════════════
    let backends: Vec<(u8, &str)> = vec![
        (PRP_HOANG, "Hoang PRP"),
        #[cfg(feature = "fastprp")]
        (PRP_FASTPRP, "FastPRP"),
        #[cfg(feature = "alf")]
        (PRP_ALF, "ALF PRP"),
    ];

    for &(backend, backend_name) in &backends {
        println!("\n\n======================================================================");
        println!("  PRP Backend: {} (id={})", backend_name, backend);
        println!("======================================================================\n");

        // INDEX BUCKET
        run_narrative(
            "INDEX", &key, 0,
            &idx_mmap, HEADER_SIZE, index_bins, index_w,
            INDEX_SLOT_SIZE, CUCKOO_BUCKET_SIZE, true,
            backend, backend_name,
        );

        println!();

        // CHUNK BUCKET
        run_narrative(
            "CHUNK", &key, K as u32,
            &chunk_mmap, CHUNK_HEADER_SIZE, chunk_bins, chunk_w,
            4 + CHUNK_SIZE, CHUNK_CUCKOO_BUCKET_SIZE, false,
            backend, backend_name,
        );
    }

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║          ALL BACKENDS × ALL BUCKETS PASSED ✓               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}

fn run_narrative(
    label: &str,
    master_key: &[u8; 16],
    bucket_id: u32,
    table_mmap: &[u8],
    header_size: usize,
    n: usize,
    w: usize,
    slot_size: usize,
    slots_per_bin: usize,
    is_index: bool,
    backend: u8,
    backend_name: &str,
) {
    let t_val = find_best_t(n as u32);
    let (padded_n, t_val) = pad_n_for_t(n as u32, t_val);
    let pn = padded_n as usize;
    let t = t_val as usize;
    let domain = 2 * pn;
    let r = compute_rounds(padded_n);
    let params = Params::new(pn, w, t).unwrap();
    let m = params.m;
    let derived_key = derive_bucket_key(master_key, bucket_id);
    let actual_bucket = if bucket_id >= K as u32 { (bucket_id - K as u32) as usize } else { bucket_id as usize };
    let table_offset = header_size + actual_bucket * n * w;

    println!("━━━ {label} BUCKET {actual_bucket}: FULL PROTOCOL NARRATIVE ━━━\n");

    // ═══════════════════════════════════════════════════════════════════
    // OFFLINE PHASE: HINT GENERATION
    // ═══════════════════════════════════════════════════════════════════
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  OFFLINE PHASE: Hint Server generates hints for client     │");
    println!("└─────────────────────────────────────────────────────────────┘\n");

    println!("  PRP:        {} (backend={})", backend_name, backend);
    println!("  Master key: {}", hex(master_key));
    println!("  Bucket key: {} (master ⊕ bucket_id={})", hex(&derived_key), bucket_id);
    println!("  Domain:     {} = 2 × padded_N", domain);
    println!("  Rounds:     {} = ceil(log2({})) + 40, rounded to mult of 4", r, domain);
    println!("  real_N:     {} (actual DB rows)", n);
    println!("  padded_N:   {} (+{} virtual empty rows)", pn, pn - n);
    println!("  T:          {} ≈ sqrt(2×{}) = {:.0}", t, pn, (2.0 * pn as f64).sqrt());
    println!("  M:          {} segments = 2×padded_N / T", m);
    println!("  max_queries: {} = padded_N / T\n", params.max_queries);

    let t_start = Instant::now();

    let prp: Box<dyn Prp> = build_prp_box(backend, &derived_key, domain, r);

    // Hint generation only needs P(v) for v in 0..padded_N to find each value's segment.
    // No RelocationDS needed — the relocation history is empty at init time.
    // Use batch_forward() when available (FastPRP, ALF), else sequential forward().
    println!("  [Hint Server] Computing cell assignments via P(v) for v in 0..{}...", pn);
    println!("    For each entry k: cell = P(k), segment = cell/T, H[segment] ^= DB[k]\n");

    // Build cell assignment: cell_of[v] = P(v) for all v in domain.
    // All backends implement BatchPrp: Hoang uses 4-way AES pipelining + rayon,
    // FastPRP uses O(N log N) radix-sort, ALF uses SIMD batch.
    let cell_of: Vec<usize> = {
        use harmonypir::prp::BatchPrp;
        // Downcast to concrete type to call batch_forward().
        match backend {
            #[cfg(feature = "fastprp")]
            PRP_FASTPRP => {
                println!("    Using FastPRP batch_forward() (O(N log N) radix-sort)...");
                let fp = prp.as_ref() as *const dyn Prp;
                let full = unsafe { &*(fp as *const FastPrpWrapper) }.batch_forward();
                full[..pn].to_vec()
            }
            #[cfg(feature = "alf")]
            PRP_ALF => {
                println!("    Using ALF batch_forward() (SIMD-parallel)...");
                let ap = prp.as_ref() as *const dyn Prp;
                let full = unsafe { &*(ap as *const AlfPrp) }.batch_forward();
                full[..pn].to_vec()
            }
            _ => {
                println!("    Using Hoang batch_forward() (4-way AES + rayon)...");
                let hp = prp.as_ref() as *const dyn Prp;
                let full = unsafe { &*(hp as *const HoangPrp) }.batch_forward();
                full[..pn].to_vec()
            }
        }
    };

    let prp_time = t_start.elapsed();
    println!("    PRP evaluation: {:.2?} for {} values", prp_time, pn);

    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();
    let mut entries_per_seg: Vec<usize> = vec![0; m];
    let mut non_empty = 0usize;

    for k in 0..pn {
        let seg = cell_of[k] / t;
        entries_per_seg[seg] += 1;
        if k < n {
            let start = table_offset + k * w;
            let entry = &table_mmap[start..start + w];
            if !entry.iter().all(|&b| b == 0) { non_empty += 1; }
            for (d, s) in hints[seg].iter_mut().zip(entry.iter()) { *d ^= s; }
        }
    }

    let hint_time = t_start.elapsed();
    let hints_bytes = m * w;

    println!("  [Hint Server] Hint generation complete.");
    println!("    Time:           {:.2?}", hint_time);
    println!("    Non-empty rows: {}/{} ({:.1}%)", non_empty, n, non_empty as f64 / n as f64 * 100.0);
    println!("    Segments:       {} (each covers T={} cells)", m, t);
    println!("    Entries/seg:    min={}, max={}, avg={:.0}",
        entries_per_seg.iter().min().unwrap(),
        entries_per_seg.iter().max().unwrap(),
        pn as f64 / m as f64);
    println!("    Total hints:    {} bytes ({:.1} KB)\n",
        hints_bytes, hints_bytes as f64 / 1024.0);
    println!("    Sample hints:");
    for s in 0..3.min(m) {
        println!("      H[{:>4}] = {} ({} entries XOR'd)", s, hex_short(&hints[s]), entries_per_seg[s]);
    }

    // ═══════════════════════════════════════════════════════════════════
    // CLIENT RECEIVES HINTS + SAVES STATE FILE
    // ═══════════════════════════════════════════════════════════════════
    println!("\n┌─────────────────────────────────────────────────────────────┐");
    println!("│  CLIENT: Receive hints, build local state, save to file    │");
    println!("└─────────────────────────────────────────────────────────────┘\n");

    let mut bucket = HarmonyBucket::new_with_backend(
        n as u32, w as u32, t as u32, master_key, bucket_id, backend,
    ).unwrap();
    let flat: Vec<u8> = hints.iter().flat_map(|h| h.iter().copied()).collect();
    bucket.load_hints(&flat).unwrap();

    println!("  Client created HarmonyBucket:");
    println!("    real_N={}, padded_N={}, w={}, T={}, M={}", bucket.real_n(), bucket.n(), w, t, m);
    println!("    Hints loaded: {} bytes", flat.len());

    let state_bytes = bucket.serialize();
    println!("  State file serialized: {} bytes ({:.1} KB)", state_bytes.len(), state_bytes.len() as f64 / 1024.0);
    println!("    Contents: params + 0 relocated segments + 0 PRP cache + {} hint bytes", hints_bytes);
    println!("    queries_remaining = {}\n", bucket.queries_remaining());

    // Deserialize to prove round-trip.
    let mut bucket = HarmonyBucket::deserialize(&state_bytes, master_key, bucket_id).unwrap();
    println!("  State file reloaded OK (simulating client restart).\n");

    // ═══════════════════════════════════════════════════════════════════
    // ONLINE PHASE: QUERIES
    // ═══════════════════════════════════════════════════════════════════
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│  ONLINE PHASE: Client queries, server answers              │");
    println!("└─────────────────────────────────────────────────────────────┘\n");

    // Pick targets: first 3 non-empty rows.
    let mut targets: Vec<usize> = Vec::new();
    for row in 0..n {
        if targets.len() >= 3 { break; }
        let start = table_offset + row * w;
        let entry = &table_mmap[start..start + w];
        if !entry.iter().all(|&b| b == 0) {
            targets.push(row);
        }
    }

    let prp_trace: Box<dyn Prp> = build_prp_box(backend, &derived_key, domain, r);
    let mut ds_trace = RelocationDS::new(pn, t, prp_trace).unwrap();

    for (qi, &q) in targets.iter().enumerate() {
        println!("  ════ Query #{} — row {} ════\n", qi + 1, q);

        // Show the ground truth entry.
        let expected_start = table_offset + q * w;
        let expected = &table_mmap[expected_start..expected_start + w];
        println!("    [Ground truth] DB[{}] = {}", q, hex_short(expected));

        if is_index {
            println!("    Decoded {} slots:", slots_per_bin);
            for s in 0..slots_per_bin {
                let slot = &expected[s * slot_size..(s + 1) * slot_size];
                let (tag, chunk_start, num_chunks, _tree_loc) = decode_index_slot(slot);
                let is_empty = tag == 0 && chunk_start == 0 && num_chunks == 0;
                if is_empty {
                    println!("      slot[{}]: (empty)", s);
                } else {
                    println!("      slot[{}]: tag=0x{:016x} start_chunk={} num_chunks={}{}",
                        s, tag, chunk_start, num_chunks,
                        if num_chunks == 0 { " [WHALE]" } else { "" });
                }
            }
        } else {
            println!("    Decoded {} slots:", slots_per_bin);
            for s in 0..slots_per_bin {
                let slot = &expected[s * slot_size..(s + 1) * slot_size];
                let (chunk_id, data) = decode_chunk_slot(slot);
                let is_empty = chunk_id == 0 && data.iter().all(|&b| b == 0);
                if is_empty {
                    println!("      slot[{}]: (empty)", s);
                } else {
                    println!("      slot[{}]: chunk_id={} data={}", s, chunk_id, hex_short(data));
                }
            }
        }

        // Step 1: Locate q in DS'.
        let cell = ds_trace.locate(q).unwrap();
        let seg = cell / t;
        let pos = cell % t;
        println!("\n    [Client] Step 1 — Locate(q={}) via PRP", q);
        println!("      cell = P({}) chain-walked → {}", q, cell);
        println!("      segment s = {} / {} = {}", cell, t, seg);
        println!("      position r = {} mod {} = {}", cell, t, pos);

        // Step 2: Build request (sorted non-empty indices, no dummy).
        println!("    [Client] Step 2 — Build request Q", );
        let hint_before = bucket.serialize(); // snapshot for comparison
        let req = bucket.build_request(q as u32).unwrap();
        let req_bytes = req.request();
        let count = req_bytes.len() / 4;

        println!("      Q has {} sorted non-empty indices (T={}, ~{:.0}% reduction)",
            count, t, (1.0 - count as f64 / t as f64) * 100.0);
        if count > 0 {
            let first_idx = u32::from_le_bytes(req_bytes[0..4].try_into().unwrap());
            let last_idx = u32::from_le_bytes(req_bytes[(count-1)*4..count*4].try_into().unwrap());
            println!("      Sorted range: [{}..{}]", first_idx, last_idx);
        }
        println!("      Position r={} (query target) omitted from request", pos);

        // Step 3: Server answers.
        println!("    [Query Server] Step 3 — Look up {} entries from cuckoo table", count);
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
        println!("      Response: {} bytes ({} entries × {}B)", response.len(), count, w);

        // Step 4: Client recovers answer.
        println!("    [Client] Step 4 — Recover answer: A = H[s={}] ⊕ Σ(R[i] for i≠r)", seg);
        println!("      H[{}] before = {}", seg, hex_short(&hints[seg]));

        let t_q = Instant::now();
        let answer = bucket.process_response(&response).unwrap();
        let query_time = t_q.elapsed();

        let correct = answer.as_slice() == expected;
        println!("      Answer     = {}", hex_short(&answer));
        println!("      Expected   = {}", hex_short(expected));
        println!("      Match: {} ({:.2?})", if correct { "YES ✓" } else { "NO ✗" }, query_time);

        if is_index {
            println!("\n    [Client] Decoded answer (3 index slots):");
            for s in 0..slots_per_bin {
                let slot = &answer[s * slot_size..(s + 1) * slot_size];
                let (tag, chunk_start, num_chunks, _tree_loc) = decode_index_slot(slot);
                let is_empty = tag == 0 && chunk_start == 0 && num_chunks == 0;
                if !is_empty {
                    println!("      slot[{}]: tag=0x{:016x} start_chunk={} num_chunks={}",
                        s, tag, chunk_start, num_chunks);
                }
            }
        } else {
            println!("\n    [Client] Decoded answer (2 chunk slots):");
            for s in 0..slots_per_bin {
                let slot = &answer[s * slot_size..(s + 1) * slot_size];
                let (chunk_id, data) = decode_chunk_slot(slot);
                if chunk_id != 0 || !data.iter().all(|&b| b == 0) {
                    println!("      slot[{}]: chunk_id={} data={}", s, chunk_id, hex_short(data));
                }
            }
        }

        // Step 5: Relocation + hint update.
        println!("\n    [Client] Step 5 — RelocateSegment(s={}) + update hints", seg);
        println!("      Segment {} values moved to random empty cells", seg);
        println!("      Hint parities updated for destination segments");

        // Compare serialized state to show growth.
        let state_after = bucket.serialize();
        let delta = state_after.len() as i64 - hint_before.len() as i64;
        println!("      State delta: +{} bytes (relocated segment ID stored)", delta);
        println!("      queries_used={}, queries_remaining={}\n",
            bucket.queries_used(), bucket.queries_remaining());

        ds_trace.relocate_segment(seg).unwrap();
        assert!(correct, "Query {} FAILED!", q);
    }

    // ═══════════════════════════════════════════════════════════════════
    // SAVE FINAL STATE
    // ═══════════════════════════════════════════════════════════════════
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │  Save final state (client can resume later)            │");
    println!("  └─────────────────────────────────────────────────────────┘\n");

    let final_state = bucket.serialize();
    println!("    Final state: {} bytes ({:.1} KB)", final_state.len(), final_state.len() as f64 / 1024.0);
    println!("    queries_used = {}, queries_remaining = {}",
        bucket.queries_used(), bucket.queries_remaining());
    println!("    {} relocated segments stored\n", bucket.queries_used());

    // Verify reload.
    let restored = HarmonyBucket::deserialize(&final_state, master_key, bucket_id).unwrap();
    assert_eq!(restored.queries_used(), bucket.queries_used());
    println!("    Reload verified: state survives serialize/deserialize ✓");
    println!("\n  [{label}] PASS ✓");
}
