//! HarmonyPIR E2E: INDEX → CHUNK pipeline on real Bitcoin UTXO data.
//!
//! Full protocol flow with verbose intermediate logs:
//!   1. Scan INDEX cuckoo table for a non-empty entry with chunks
//!   2. Generate hints for the INDEX bucket (offline phase)
//!   3. Query the INDEX bucket → decode start_chunk_id, num_chunks
//!   4. Determine CHUNK bucket + bin using hash function 0
//!   5. Generate hints for the CHUNK bucket (offline phase)
//!   6. Query the CHUNK bucket → retrieve 40-byte chunk data
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_index_to_chunk_e2e --features "alf"

use build::common::*;
use harmonypir::params::Params;
#[cfg(feature = "alf")]
use harmonypir::prp::alf::AlfPrp;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir_wasm::{
    HarmonyBucket, PRP_ALF, PRP_HOANG,
    compute_rounds, derive_bucket_key, find_best_t, pad_n_for_t,
};

use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

const MASTER_KEY: [u8; 16] = [0x42u8; 16];

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

/// Decode a 13-byte index slot: [8B tag][4B start_chunk_id LE][1B num_chunks]
fn decode_index_slot(slot: &[u8]) -> (u64, u32, u8) {
    let tag = u64::from_le_bytes(slot[0..8].try_into().unwrap());
    let start_chunk = u32::from_le_bytes(slot[8..12].try_into().unwrap());
    let num_chunks = slot[12];
    (tag, start_chunk, num_chunks)
}

/// Decode a 44-byte chunk slot: [4B chunk_id LE][40B data]
fn decode_chunk_slot(slot: &[u8]) -> (u32, &[u8]) {
    let chunk_id = u32::from_le_bytes(slot[0..4].try_into().unwrap());
    (chunk_id, &slot[4..])
}

/// Pick the PRP backend: ALF if available, else Hoang.
fn choose_backend() -> (u8, &'static str) {
    #[cfg(feature = "alf")]
    { (PRP_ALF, "ALF") }
    #[cfg(not(feature = "alf"))]
    { (PRP_HOANG, "Hoang") }
}

fn build_prp_box(backend: u8, key: &[u8; 16], domain: usize, rounds: usize) -> Box<dyn Prp> {
    match backend {
        #[cfg(feature = "alf")]
        PRP_ALF => Box::new(AlfPrp::new(key, domain, key, 0x4250_4952)),
        _ => Box::new(HoangPrp::new(domain, rounds, key)),
    }
}

/// Generate hints for one bucket and return a HarmonyBucket ready for queries.
fn generate_hints_for_bucket(
    label: &str,
    backend: u8,
    master_key: &[u8; 16],
    bucket_id: u32,
    table_mmap: &[u8],
    header_size: usize,
    n: usize,
    w: usize,
) -> HarmonyBucket {
    let t_val = find_best_t(n as u32);
    let (padded_n, t_val) = pad_n_for_t(n as u32, t_val);
    let pn = padded_n as usize;
    let t = t_val as usize;
    let domain = 2 * pn;
    let r = compute_rounds(padded_n);
    let params = Params::new(pn, w, t).unwrap();
    let m = params.m;
    let derived_key = derive_bucket_key(master_key, bucket_id);

    // Determine the actual table index (chunk buckets are offset by K).
    let actual_bucket = if bucket_id >= K as u32 {
        (bucket_id - K as u32) as usize
    } else {
        bucket_id as usize
    };
    let table_offset = header_size + actual_bucket * n * w;

    println!("    [Hint Server] Generating hints for {} bucket {} (actual table index {})", label, bucket_id, actual_bucket);
    println!("      real_N={}, padded_N={}, T={}, M={} segments, domain={}", n, pn, t, m, domain);

    let t0 = Instant::now();

    // Compute PRP forward mapping.
    let prp = build_prp_box(backend, &derived_key, domain, r);
    let cell_of: Vec<usize> = {
        use harmonypir::prp::BatchPrp;
        match backend {
            #[cfg(feature = "alf")]
            PRP_ALF => {
                let ap = prp.as_ref() as *const dyn Prp;
                let full = unsafe { &*(ap as *const AlfPrp) }.batch_forward();
                full[..pn].to_vec()
            }
            _ => {
                let hp = prp.as_ref() as *const dyn Prp;
                let full = unsafe { &*(hp as *const HoangPrp) }.batch_forward();
                full[..pn].to_vec()
            }
        }
    };

    // Scatter-XOR into hints.
    let mut hints_flat = vec![0u8; m * w];
    let mut non_empty = 0usize;
    for k in 0..pn {
        let seg = cell_of[k] / t;
        if k < n {
            let start = table_offset + k * w;
            let entry = &table_mmap[start..start + w];
            if !entry.iter().all(|&b| b == 0) { non_empty += 1; }
            let hint_start = seg * w;
            for (d, s) in hints_flat[hint_start..hint_start + w].iter_mut().zip(entry.iter()) {
                *d ^= s;
            }
        }
    }

    let elapsed = t0.elapsed();
    println!("      Hint generation: {:.2?}", elapsed);
    println!("      Non-empty rows: {}/{} ({:.1}%)", non_empty, n, non_empty as f64 / n as f64 * 100.0);
    println!("      Total hints: {} bytes ({:.1} KB)", hints_flat.len(), hints_flat.len() as f64 / 1024.0);

    // Build HarmonyBucket and load hints.
    let mut bucket = HarmonyBucket::new_with_backend(
        n as u32, w as u32, t as u32, master_key, bucket_id, backend,
    ).unwrap();
    bucket.load_hints(&hints_flat).unwrap();
    println!("      HarmonyBucket ready: max_queries={}\n", bucket.queries_remaining());

    bucket
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

fn main() {
    let (backend, backend_name) = choose_backend();

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  HarmonyPIR E2E: INDEX → CHUNK Pipeline on Real Bitcoin UTXO Data  ║");
    println!("║  PRP Backend: {:57}║", format!("{} (id={})", backend_name, backend));
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    // ═══════════════════════════════════════════════════════════════════
    // STEP 0: Load both cuckoo tables
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 0: Load cuckoo tables ━━━\n");

    let idx_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let idx_mmap = unsafe { Mmap::map(&idx_file) }.expect("mmap");
    let (index_bins, tag_seed) = read_cuckoo_header(&idx_mmap);
    let index_w = CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE; // 3 × 13 = 39

    let chunk_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_mmap = unsafe { Mmap::map(&chunk_file) }.expect("mmap");
    let chunk_bins = read_chunk_cuckoo_header(&chunk_mmap);
    let chunk_w = CHUNK_CUCKOO_BUCKET_SIZE * (4 + CHUNK_SIZE); // 2 × 44 = 88

    println!("  INDEX cuckoo: {} bins × {}B = {:.2} GB",
        index_bins, index_w, idx_mmap.len() as f64 / (1024.0*1024.0*1024.0));
    println!("    Slot layout: [8B tag][4B start_chunk_id][1B num_chunks] × 3 slots");
    println!("    tag_seed = 0x{:016x}", tag_seed);
    println!("  CHUNK cuckoo: {} bins × {}B = {:.2} GB",
        chunk_bins, chunk_w, chunk_mmap.len() as f64 / (1024.0*1024.0*1024.0));
    println!("    Slot layout: [4B chunk_id][40B data] × 2 slots");
    println!();

    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Scan INDEX table for a suitable target entry
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 1: Find a non-empty INDEX entry with chunks (not a whale) ━━━\n");

    // Scan INDEX bucket 0 for a bin with a non-empty slot that has num_chunks > 0 (not a whale).
    let index_bucket_id: u32 = 0;
    let index_table_offset = HEADER_SIZE + (index_bucket_id as usize) * index_bins * index_w;
    let mut target_bin: Option<usize> = None;
    let mut target_slot_idx = 0;
    let mut target_tag: u64 = 0;
    let mut target_start_chunk: u32 = 0;
    let mut target_num_chunks: u8 = 0;

    for bin in 0..index_bins {
        let bin_start = index_table_offset + bin * index_w;
        for slot in 0..CUCKOO_BUCKET_SIZE {
            let s = bin_start + slot * INDEX_SLOT_SIZE;
            let (tag, start_chunk, num_chunks) = decode_index_slot(&idx_mmap[s..s + INDEX_SLOT_SIZE]);
            if tag != 0 && num_chunks > 0 && num_chunks < 20 {
                // Valid non-whale entry with a reasonable number of chunks.
                target_bin = Some(bin);
                target_slot_idx = slot;
                target_tag = tag;
                target_start_chunk = start_chunk;
                target_num_chunks = num_chunks;
                break;
            }
        }
        if target_bin.is_some() { break; }
    }

    let target_bin = target_bin.expect("No suitable INDEX entry found!");

    println!("  Found target in INDEX bucket {}, bin {}:", index_bucket_id, target_bin);
    println!("    slot[{}]:", target_slot_idx);
    println!("      tag            = 0x{:016x}", target_tag);
    println!("      start_chunk_id = {}", target_start_chunk);
    println!("      num_chunks     = {}", target_num_chunks);

    // Show all 3 slots in the bin for context.
    println!("\n    Full bin {} contents (ground truth):", target_bin);
    let bin_data_start = index_table_offset + target_bin * index_w;
    let bin_data = &idx_mmap[bin_data_start..bin_data_start + index_w];
    for slot in 0..CUCKOO_BUCKET_SIZE {
        let s = slot * INDEX_SLOT_SIZE;
        let (tag, start_chunk, num_chunks) = decode_index_slot(&bin_data[s..s + INDEX_SLOT_SIZE]);
        if tag == 0 && start_chunk == 0 && num_chunks == 0 {
            println!("      slot[{}]: (empty)", slot);
        } else {
            println!("      slot[{}]: tag=0x{:016x} start_chunk={} num_chunks={}{}",
                slot, tag, start_chunk, num_chunks,
                if num_chunks == 0 { " [WHALE]" } else { "" });
        }
    }
    println!();

    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: OFFLINE PHASE — Generate INDEX hints
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 2: OFFLINE PHASE — Generate INDEX hints ━━━\n");

    let mut index_bucket = generate_hints_for_bucket(
        "INDEX", backend, &MASTER_KEY, index_bucket_id,
        &idx_mmap, HEADER_SIZE, index_bins, index_w,
    );

    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: ONLINE PHASE — Query INDEX bucket via HarmonyPIR
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 3: ONLINE PHASE — Query INDEX bin {} via HarmonyPIR ━━━\n", target_bin);

    println!("  [Client] Querying INDEX bin {} to retrieve {}-byte entry", target_bin, index_w);
    println!("  [Client] Step 3a — Locate bin {} in DS'", target_bin);

    let req = index_bucket.build_request(target_bin as u32).unwrap();
    let req_bytes = req.request();
    let idx_count = req_bytes.len() / 4;

    println!("  [Client] Step 3b — Build request Q");
    println!("    Q: {} sorted non-empty indices (T entries would be {}, ~{:.0}% reduction)",
        idx_count,
        {
            let t_val = find_best_t(index_bins as u32);
            let (_, t_final) = pad_n_for_t(index_bins as u32, t_val);
            t_final
        },
        {
            let t_val = find_best_t(index_bins as u32);
            let (_, t_final) = pad_n_for_t(index_bins as u32, t_val);
            (1.0 - idx_count as f64 / t_final as f64) * 100.0
        }
    );
    if idx_count > 0 {
        let first = u32::from_le_bytes(req_bytes[0..4].try_into().unwrap());
        let last = u32::from_le_bytes(req_bytes[(idx_count-1)*4..idx_count*4].try_into().unwrap());
        println!("    Sorted range: [{}..{}]", first, last);
    }
    println!("    Request wire size: {} bytes", req_bytes.len());

    println!("\n  [Query Server] Step 3c — Look up {} entries from INDEX cuckoo table", idx_count);
    let response = simulate_query_server(
        &req_bytes, &idx_mmap[..],
        index_table_offset, index_bins, index_w,
    );
    println!("    Server response: {} bytes ({} entries × {}B)", response.len(), idx_count, index_w);

    println!("\n  [Client] Step 3d — Recover answer: A = H[s] ⊕ XOR(server entries)");
    let answer = index_bucket.process_response(&response).unwrap();

    // Verify against ground truth.
    let correct = answer.as_slice() == bin_data;
    println!("    Answer  = {}", hex_short(&answer));
    println!("    Expected= {}", hex_short(bin_data));
    println!("    Match:    {} ✓", if correct { "YES" } else { "NO ✗" });
    assert!(correct, "INDEX query FAILED!");

    // Decode the recovered answer.
    println!("\n  [Client] Step 3e — Decode INDEX answer ({} slots × {}B):", CUCKOO_BUCKET_SIZE, INDEX_SLOT_SIZE);
    let mut found_entry = false;
    let mut decoded_start_chunk: u32 = 0;
    let mut decoded_num_chunks: u8 = 0;

    for slot in 0..CUCKOO_BUCKET_SIZE {
        let s = slot * INDEX_SLOT_SIZE;
        let slot_data = &answer[s..s + INDEX_SLOT_SIZE];
        let (tag, start_chunk, num_chunks) = decode_index_slot(slot_data);
        if tag == 0 && start_chunk == 0 && num_chunks == 0 {
            println!("    slot[{}]: (empty)", slot);
        } else {
            let whale = num_chunks == 0;
            println!("    slot[{}]: tag=0x{:016x} start_chunk={} num_chunks={}{}",
                slot, tag, start_chunk, num_chunks,
                if whale { " [WHALE]" } else { "" });
            if tag == target_tag && !whale {
                println!("             ← THIS is our target entry!");
                found_entry = true;
                decoded_start_chunk = start_chunk;
                decoded_num_chunks = num_chunks;
            }
        }
    }
    assert!(found_entry, "Target tag not found in decoded INDEX answer!");

    println!("\n  [Client] Decoded target entry:");
    println!("    start_chunk_id = {}", decoded_start_chunk);
    println!("    num_chunks     = {} (chunks {}..={})", decoded_num_chunks,
        decoded_start_chunk, decoded_start_chunk + decoded_num_chunks as u32 - 1);
    println!("    queries_remaining = {} (INDEX bucket)", index_bucket.queries_remaining());
    println!();

    // ═══════════════════════════════════════════════════════════════════
    // STEP 4: Determine CHUNK bucket + bin (using hash function 0)
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 4: Determine CHUNK bucket + bin ━━━\n");

    let chunk_buckets = derive_chunk_buckets(decoded_start_chunk);
    println!("  [Client] derive_chunk_buckets(start_chunk={}):", decoded_start_chunk);
    println!("    3 chunk groups: bucket[0]={}, bucket[1]={}, bucket[2]={}",
        chunk_buckets[0], chunk_buckets[1], chunk_buckets[2]);

    // For each chunk group, show how to find the bin (always using hash function 0).
    println!("\n  [Client] For each chunk group, compute cuckoo bin using hash fn 0:");
    for g in 0..3 {
        let bucket = chunk_buckets[g];
        let ckey = derive_chunk_cuckoo_key(bucket, 0);
        let bin = cuckoo_hash_int(decoded_start_chunk, ckey, chunk_bins);
        println!("    group[{}]: bucket={}, hash_fn=0, cuckoo_key=0x{:016x} → bin={}",
            g, bucket, ckey, bin);
    }

    // Pick the first group for the CHUNK query.
    let chunk_group = 0;
    let target_chunk_bucket = chunk_buckets[chunk_group];
    let target_chunk_ckey = derive_chunk_cuckoo_key(target_chunk_bucket, 0);
    let target_chunk_bin = cuckoo_hash_int(decoded_start_chunk, target_chunk_ckey, chunk_bins);

    println!("\n  → Using group[0]: CHUNK bucket={}, bin={}", target_chunk_bucket, target_chunk_bin);

    // Show ground truth for the target CHUNK bin.
    let chunk_table_offset = CHUNK_HEADER_SIZE + target_chunk_bucket * chunk_bins * chunk_w;
    let chunk_bin_start = chunk_table_offset + target_chunk_bin * chunk_w;
    let chunk_bin_data = &chunk_mmap[chunk_bin_start..chunk_bin_start + chunk_w];

    println!("\n  [Ground truth] CHUNK bin {} in bucket {} ({} bytes):", target_chunk_bin, target_chunk_bucket, chunk_w);
    for slot in 0..CHUNK_CUCKOO_BUCKET_SIZE {
        let s = slot * (4 + CHUNK_SIZE);
        let (chunk_id, data) = decode_chunk_slot(&chunk_bin_data[s..s + 4 + CHUNK_SIZE]);
        if chunk_id == 0 && data.iter().all(|&b| b == 0) {
            println!("    slot[{}]: (empty)", slot);
        } else {
            let is_target = chunk_id == decoded_start_chunk;
            println!("    slot[{}]: chunk_id={} data={}{}",
                slot, chunk_id, hex_short(data),
                if is_target { " ← TARGET" } else { "" });
        }
    }
    println!();

    // ═══════════════════════════════════════════════════════════════════
    // STEP 5: OFFLINE PHASE — Generate CHUNK hints
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 5: OFFLINE PHASE — Generate CHUNK hints ━━━\n");

    // CHUNK bucket IDs are offset by K (INDEX uses 0..K-1, CHUNK uses K..K+K_CHUNK-1).
    let chunk_bucket_id = K as u32 + target_chunk_bucket as u32;

    let mut chunk_bucket = generate_hints_for_bucket(
        "CHUNK", backend, &MASTER_KEY, chunk_bucket_id,
        &chunk_mmap, CHUNK_HEADER_SIZE, chunk_bins, chunk_w,
    );

    // ═══════════════════════════════════════════════════════════════════
    // STEP 6: ONLINE PHASE — Query CHUNK bucket via HarmonyPIR
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ STEP 6: ONLINE PHASE — Query CHUNK bin {} via HarmonyPIR ━━━\n", target_chunk_bin);

    println!("  [Client] Querying CHUNK bin {} to retrieve 88-byte entry (2 × 44B slots)", target_chunk_bin);
    println!("  [Client] Step 6a — Locate bin {} in DS'", target_chunk_bin);

    let req = chunk_bucket.build_request(target_chunk_bin as u32).unwrap();
    let req_bytes = req.request();
    let chunk_count = req_bytes.len() / 4;

    println!("  [Client] Step 6b — Build request Q");
    println!("    Q: {} sorted non-empty indices", chunk_count);
    {
        let t_val = find_best_t(chunk_bins as u32);
        let (_, t_final) = pad_n_for_t(chunk_bins as u32, t_val);
        println!("    (T={}, ~{:.0}% reduction)", t_final, (1.0 - chunk_count as f64 / t_final as f64) * 100.0);
    }
    println!("    Request wire size: {} bytes", req_bytes.len());

    println!("\n  [Query Server] Step 6c — Look up {} entries from CHUNK cuckoo table", chunk_count);
    let response = simulate_query_server(
        &req_bytes, &chunk_mmap[..],
        chunk_table_offset, chunk_bins, chunk_w,
    );
    println!("    Server response: {} bytes ({} entries × {}B)", response.len(), chunk_count, chunk_w);

    println!("\n  [Client] Step 6d — Recover answer: A = H[s] ⊕ XOR(server entries)");
    let answer = chunk_bucket.process_response(&response).unwrap();

    let correct = answer.as_slice() == chunk_bin_data;
    println!("    Answer  = {}", hex_short(&answer));
    println!("    Expected= {}", hex_short(chunk_bin_data));
    println!("    Match:    {} ✓", if correct { "YES" } else { "NO ✗" });
    assert!(correct, "CHUNK query FAILED!");

    // Decode the recovered CHUNK answer.
    println!("\n  [Client] Step 6e — Decode CHUNK answer ({} slots × {}B):", CHUNK_CUCKOO_BUCKET_SIZE, 4 + CHUNK_SIZE);
    let mut found_chunk = false;
    let mut chunk_data: Vec<u8> = Vec::new();

    for slot in 0..CHUNK_CUCKOO_BUCKET_SIZE {
        let s = slot * (4 + CHUNK_SIZE);
        let (chunk_id, data) = decode_chunk_slot(&answer[s..s + 4 + CHUNK_SIZE]);
        if chunk_id == 0 && data.iter().all(|&b| b == 0) {
            println!("    slot[{}]: (empty)", slot);
        } else {
            let is_target = chunk_id == decoded_start_chunk;
            println!("    slot[{}]: chunk_id={} data={}{}",
                slot, chunk_id, hex_short(data),
                if is_target { " ← TARGET" } else { "" });
            if is_target {
                found_chunk = true;
                chunk_data = data.to_vec();
            }
        }
    }
    assert!(found_chunk, "Target chunk_id {} not found in decoded CHUNK answer!", decoded_start_chunk);

    // ═══════════════════════════════════════════════════════════════════
    // STEP 7: RESULT — The 40-byte chunk data
    // ═══════════════════════════════════════════════════════════════════
    println!("\n━━━ STEP 7: FINAL RESULT ━━━\n");
    println!("  The client wanted to look up a UTXO identified by tag 0x{:016x}.", target_tag);
    println!("  Through the INDEX → CHUNK pipeline:\n");
    println!("  1. INDEX query (bin {}, bucket {}):", target_bin, index_bucket_id);
    println!("     → start_chunk_id={}, num_chunks={}",
        decoded_start_chunk, decoded_num_chunks);
    println!("  2. Chunk lookup: group[0] → CHUNK bucket {}, bin {}",
        target_chunk_bucket, target_chunk_bin);
    println!("  3. CHUNK query (bin {}, bucket {}):", target_chunk_bin, target_chunk_bucket);
    println!("     → chunk_id={}, 40 bytes of UTXO data:", decoded_start_chunk);
    println!();
    println!("     ┌──────────────────────────────────────────────────┐");
    println!("     │ chunk data: {}│", format!("{:<49}", hex(&chunk_data)));
    println!("     └──────────────────────────────────────────────────┘");
    println!();

    // If there are more chunks (num_chunks > 1), note them.
    if decoded_num_chunks > 1 {
        println!("  (This UTXO has {} total chunks: {}..={}. Only chunk {} was fetched.)",
            decoded_num_chunks,
            decoded_start_chunk,
            decoded_start_chunk + decoded_num_chunks as u32 - 1,
            decoded_start_chunk);
        println!("  The remaining chunks would require {} more CHUNK queries.\n", decoded_num_chunks - 1);
    }

    // Summary stats.
    println!("  ─── Communication Summary ───");
    let idx_req_size = idx_count * 4;
    let idx_resp_size = idx_count * index_w;
    let chk_req_size = chunk_count * 4;
    let chk_resp_size = chunk_count * chunk_w;
    println!("    INDEX request:  {} indices × 4B = {} bytes", idx_count, idx_req_size);
    println!("    INDEX response: {} entries × {}B = {} bytes ({:.1} KB)",
        idx_count, index_w, idx_resp_size, idx_resp_size as f64 / 1024.0);
    println!("    CHUNK request:  {} indices × 4B = {} bytes", chunk_count, chk_req_size);
    println!("    CHUNK response: {} entries × {}B = {} bytes ({:.1} KB)",
        chunk_count, chunk_w, chk_resp_size, chk_resp_size as f64 / 1024.0);
    let total = idx_req_size + idx_resp_size + chk_req_size + chk_resp_size;
    println!("    Total online:   {:.1} KB", total as f64 / 1024.0);

    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║              INDEX → CHUNK E2E PIPELINE: PASS ✓                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
}
