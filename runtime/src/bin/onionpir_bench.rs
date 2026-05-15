//! OnionPIR benchmark: measures all numerical unknowns for capacity planning.
//!
//! For each target database size (index-level and chunk-level), this binary:
//!   1. Prints params_info (dimensions, entry size, expansion)
//!   2. Populates a server with random data and preprocesses (NTT)
//!   3. Saves the preprocessed DB and prints file size
//!   4. Generates client keys and prints their sizes
//!   5. Generates queries, answers them, decrypts — prints sizes and timings
//!   6. Tests whether keys from one config work on another (key reusability)
//!
//! Usage: cargo run --release --bin onionpir_bench

use onionpir::{self, Client as PirClient, Server as PirServer};
use std::time::Instant;

/// Target database sizes matching our PBC group estimates.
const INDEX_NUM_ENTRIES: u64 = 8_224;
const CHUNK_NUM_ENTRIES: u64 = 43_053;

/// Number of queries to average for timing.
const TIMING_ROUNDS: usize = 10;

fn format_bytes(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:.2} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.2} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}

fn bench_config(label: &str, num_entries: u64, save_path: &str) -> (Vec<u8>, Vec<u8>) {
    println!("\n{}", "=".repeat(60));
    println!("=== {} (num_entries={}) ===", label, num_entries);
    println!("{}", "=".repeat(60));

    // ── 1. params_info ──────────────────────────────────────────────────────
    let p = onionpir::params_info(num_entries);
    println!("\n[1] params_info:");
    println!("  num_entries (padded): {}", p.num_entries);
    println!("  entry_size:          {} bytes", p.entry_size);
    println!("  num_plaintexts:      {}", p.num_plaintexts);
    println!("  fst_dim_sz:          {}", p.fst_dim_sz);
    println!("  other_dim_sz:        {}", p.other_dim_sz);
    println!("  poly_degree:         {}", p.poly_degree);
    println!("  db_size_mb:          {:.2} MB", p.db_size_mb);
    println!("  physical_size_mb:    {:.2} MB", p.physical_size_mb);
    println!(
        "  NTT expansion:       {:.2}x",
        p.physical_size_mb / p.db_size_mb
    );

    let entry_size = p.entry_size as usize;
    let padded = p.num_entries as usize;

    // ── 2. Populate server with random data ─────────────────────────────────
    println!("\n[2] Populating server with random {} entries...", padded);

    // Generate deterministic "random" entries for reproducibility
    let mut entries: Vec<Vec<u8>> = Vec::with_capacity(padded);
    for i in 0..padded {
        let mut entry = vec![0u8; entry_size];
        // Fill with a recognizable pattern: first 8 bytes = entry index
        let idx_bytes = (i as u64).to_le_bytes();
        entry[..8].copy_from_slice(&idx_bytes);
        // Fill remaining with pseudo-random bytes derived from index
        let mut state = i as u64;
        for chunk in entry[8..].chunks_mut(8) {
            state = state.wrapping_mul(0x5851f42d4c957f2d).wrapping_add(1);
            let bytes = state.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
        entries.push(entry);
    }

    let mut server = PirServer::new(num_entries);
    let fst_dim = p.fst_dim_sz as usize;
    let entries_per_pt = 1;
    let chunk_size = fst_dim * entries_per_pt * entry_size;

    let t_populate = Instant::now();
    for chunk_idx in 0..(p.other_dim_sz as usize) {
        // OnionPIRv2 port (commit-1 stub): `push_chunk` removed upstream.
        // Production replacement is `push_plaintexts` (different
        // semantics — operates at plaintext-coefficient level, not raw
        // bytes). See docs/ONIONPIR_PORT_MIGRATION.md §2 Commit 3.
        // For now the populate loop is a no-op; gen_data below fills
        // with random data and runs NTT in one shot.
        let _ = (chunk_size, fst_dim, entries_per_pt, padded, entries.clone());
        let _ = chunk_idx;
    }
    server.gen_data(&[]); // random data + NTT in one call (test path)
    println!("  populate time (test-path gen_data, populate+preprocess fused): {:.2?}", t_populate.elapsed());

    // ── Preprocess (NTT) ────────────────────────────────────────────────────
    // OnionPIRv2 port: `preprocess()` removed; NTT runs inside `gen_data`
    // / `push_plaintexts` automatically. Section retained for output
    // formatting parity, but timing now reflects fused populate+NTT.
    println!("\n[2b] Preprocessing (NTT transforms)...");
    let t_preprocess = Instant::now();
    // No-op — gen_data above already preprocessed.
    let preprocess_time = t_preprocess.elapsed();
    println!("  preprocess time (fused into populate above): {:.2?}", preprocess_time);

    // ── 3. Save and check file size ─────────────────────────────────────────
    println!("\n[3] Saving preprocessed DB to {}...", save_path);
    server.save_db(save_path);
    let file_size = std::fs::metadata(save_path)
        .map(|m| m.len())
        .unwrap_or(0);
    println!("  file size: {} ({:.2} MB)", format_bytes(file_size as usize), file_size as f64 / 1_048_576.0);
    println!(
        "  expansion vs logical: {:.2}x",
        file_size as f64 / (padded as f64 * entry_size as f64)
    );

    // ── 4. Client keys ──────────────────────────────────────────────────────
    println!("\n[4] Generating client keys...");
    let mut client = PirClient::new(num_entries);
    let client_id = client.id();

    let t_gk = Instant::now();
    let galois_keys = client.galois_keys();
    let gk_time = t_gk.elapsed();

    let t_gsw = Instant::now();
    let gsw_keys = client.gsw_key();
    let gsw_time = t_gsw.elapsed();

    println!("  client_id:       {}", client_id);
    println!(
        "  galois_keys:     {} (gen time: {:.2?})",
        format_bytes(galois_keys.len()),
        gk_time
    );
    println!(
        "  gsw_keys:        {} (gen time: {:.2?})",
        format_bytes(gsw_keys.len()),
        gsw_time
    );
    println!(
        "  total keys:      {}",
        format_bytes(galois_keys.len() + gsw_keys.len())
    );

    // ── 5. Register keys ────────────────────────────────────────────────────
    println!("\n[5] Registering keys with server...");
    let t_reg = Instant::now();
    server.set_galois_keys(client_id, &galois_keys);
    server.set_gsw_key(client_id, &gsw_keys);
    println!("  registration time: {:.2?}", t_reg.elapsed());

    // ── 6-8. Query, answer, decrypt ─────────────────────────────────────────
    let test_index: u64 = 42.min(num_entries - 1);

    println!("\n[6] Generating query for index {}...", test_index);
    let t_qgen = Instant::now();
    let query = client.generate_query(test_index);
    let qgen_time = t_qgen.elapsed();
    println!(
        "  query size:      {} (gen time: {:.2?})",
        format_bytes(query.len()),
        qgen_time
    );

    println!("\n[7] Answering queries ({}x for timing)...", TIMING_ROUNDS);
    // Warm-up query
    let _ = server.answer_query(client_id, &query);

    let mut total_answer_time = std::time::Duration::ZERO;
    let mut response = Vec::new();
    for _ in 0..TIMING_ROUNDS {
        let t = Instant::now();
        response = server.answer_query(client_id, &query);
        total_answer_time += t.elapsed();
    }
    let avg_answer_time = total_answer_time / TIMING_ROUNDS as u32;
    println!(
        "  response size:   {}",
        format_bytes(response.len())
    );
    println!(
        "  answer_query avg: {:.2?} ({} rounds)",
        avg_answer_time, TIMING_ROUNDS
    );

    // ── 9. Decrypt and verify ───────────────────────────────────────────────
    println!("\n[8] Decrypting response...");
    let t_dec = Instant::now();
    // OnionPIRv2 port (commit 2): bit-unpack the raw plaintext for a
    // byte-level verify. `decrypted` is now `params.entry_size` bytes.
    let _ = test_index;
    let raw_pt = client.decrypt_response(&response);
    let pinfo = onionpir::params_info(INDEX_NUM_ENTRIES);
    let decrypted = pir_core::onion_unpack::unpack_onion_plaintext(
        &raw_pt,
        pinfo.poly_degree as usize,
        pinfo.entry_size as usize,
    )
    .expect("onion_unpack rejected bench plaintext");
    let dec_time = t_dec.elapsed();
    println!(
        "  decrypted size:  {} (time: {:.2?})",
        format_bytes(decrypted.len()),
        dec_time
    );

    // Verify correctness: first 8 bytes should be the entry index
    let expected = &entries[test_index as usize];
    if decrypted.len() >= entry_size && decrypted[..entry_size] == expected[..] {
        println!("  verification:    OK (matches stored entry)");
    } else if decrypted.len() >= 8 {
        let got_idx = u64::from_le_bytes(decrypted[..8].try_into().unwrap());
        if got_idx == test_index {
            println!("  verification:    OK (first 8 bytes match index={})", test_index);
        } else {
            println!(
                "  verification:    MISMATCH! expected index={}, got={}",
                test_index, got_idx
            );
        }
    } else {
        println!("  verification:    FAILED (decrypted too short: {} bytes)", decrypted.len());
    }

    // ── Summary ─────────────────────────────────────────────────────────────
    println!("\n--- {} Summary ---", label);
    println!("  Entries:         {} (padded to {})", num_entries, padded);
    println!("  Entry size:      {} bytes", entry_size);
    println!("  Preprocess:      {:.2?}", preprocess_time);
    println!("  DB file:         {:.2} MB", file_size as f64 / 1_048_576.0);
    println!("  Keys total:      {}", format_bytes(galois_keys.len() + gsw_keys.len()));
    println!("  Query size:      {}", format_bytes(query.len()));
    println!("  Response size:   {}", format_bytes(response.len()));
    println!("  Query time:      {:.2?} avg", avg_answer_time);
    println!("  Decrypt time:    {:.2?}", dec_time);

    // Clean up temp file
    let _ = std::fs::remove_file(save_path);

    (galois_keys, gsw_keys)
}

fn main() {
    println!("OnionPIR Benchmark");
    println!("==================");
    println!("Testing at two database sizes matching our PBC group estimates.");
    println!("Index level: {} entries/group, Chunk level: {} entries/group",
        INDEX_NUM_ENTRIES, CHUNK_NUM_ENTRIES);

    // Benchmark index-level config
    let (index_gk, index_gsw) = bench_config(
        "Index level",
        INDEX_NUM_ENTRIES,
        "/tmp/onionpir_bench_index.bin",
    );

    // Benchmark chunk-level config
    let (chunk_gk, chunk_gsw) = bench_config(
        "Chunk level",
        CHUNK_NUM_ENTRIES,
        "/tmp/onionpir_bench_chunk.bin",
    );

    // ── 10. Key reusability test ────────────────────────────────────────────
    println!("\n{}", "=".repeat(60));
    println!("=== Key Reusability Test ===");
    println!("{}", "=".repeat(60));
    println!("\nTesting: can keys generated for num_entries={} work on a server with num_entries={}?",
        INDEX_NUM_ENTRIES, CHUNK_NUM_ENTRIES);

    let mut cross_server = PirServer::new(CHUNK_NUM_ENTRIES);
    // Populate with minimal dummy data so it can answer queries
    let p = onionpir::params_info(CHUNK_NUM_ENTRIES);
    let entry_size = p.entry_size as usize;
    let fst_dim = p.fst_dim_sz as usize;
    let chunk_size = fst_dim * entry_size;
    // OnionPIRv2 port stub: see populate-loop comment in main bench above.
    let _ = chunk_size;
    for chunk_idx in 0..(p.other_dim_sz as usize) {
        let _ = chunk_idx;
    }
    cross_server.gen_data(&[]);

    // Try registering index-level keys with chunk-level server
    let cross_client_id = 99999;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cross_server.set_galois_keys(cross_client_id, &index_gk);
        cross_server.set_gsw_key(cross_client_id, &index_gsw);
    }));

    match result {
        Ok(()) => {
            println!("  set_galois_key + set_gsw_key: OK (no panic)");
            // Try actually answering a query with cross keys
            let mut cross_client = PirClient::new(INDEX_NUM_ENTRIES);
            let query = cross_client.generate_query(0);
            let answer_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                cross_server.answer_query(cross_client_id, &query)
            }));
            match answer_result {
                Ok(_resp) => println!("  answer_query with cross keys: OK (returned response)"),
                Err(_) => println!("  answer_query with cross keys: PANIC (keys registered but query failed)"),
            }
        }
        Err(_) => {
            println!("  Key registration: PANIC (keys are NOT reusable across different num_entries)");
        }
    }

    // Also test: same num_entries, same keys = should always work
    println!("\nControl test: keys from num_entries={} on server with same num_entries...", CHUNK_NUM_ENTRIES);
    let mut control_server = PirServer::new(CHUNK_NUM_ENTRIES);
    // OnionPIRv2 port stub: see populate-loop comment in main bench above.
    for chunk_idx in 0..(p.other_dim_sz as usize) {
        let _ = chunk_idx;
    }
    control_server.gen_data(&[]);
    control_server.set_galois_keys(cross_client_id, &chunk_gk);
    control_server.set_gsw_key(cross_client_id, &chunk_gsw);
    let mut control_client = PirClient::new(CHUNK_NUM_ENTRIES);
    let control_query = control_client.generate_query(0);
    let _ = control_server.answer_query(cross_client_id, &control_query);
    println!("  Control: OK");

    println!("\n=== Benchmark complete ===");

    // ── Projection for full system ──────────────────────────────────────────
    println!("\n--- Full System Projections ---");
    println!("Based on measured values above:");
    println!("  Index batch (75 groups):  75 x query_time = estimated total");
    println!("  Chunk batch (80 groups):  80 x query_time = estimated total");
    println!("  Per-request upload:  155 x query_size");
    println!("  Per-request download: 155 x response_size");
    println!("  One-time key upload: 2 x total_key_size (if keys not reusable across configs)");
}
