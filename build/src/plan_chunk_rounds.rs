//! Simulate multi-round chunk PIR retrieval (unit-based).
//!
//! Takes the 50 queries from batch_pir_results.bin and simulates
//! fetching all their chunks in rounds, each round filling up to K_CHUNK=80
//! cuckoo-assigned bucket slots.
//!
//! A "unit" is CHUNKS_PER_UNIT consecutive 80-byte chunks (e.g. 10 = 800 bytes).
//! Each PIR query retrieves one unit.  The cuckoo table stores individual
//! chunk_ids; we query the *first* chunk_id of each unit.
//!
//! Algorithm per round:
//!   1. Each unfinished scriptpubkey contributes its next pending unit.
//!   2. If slots remain, scriptpubkeys with the most remaining contribute more.
//!   3. Cuckoo-assign candidates to 80 buckets (with eviction + rollback on fail).
//!   4. Successfully placed units are marked done.
//!   5. Repeat until all units are fetched.
//!
//! Adaptive max_kicks: when many rounds remain, use few kicks (failures are
//! cheap — just retry next round). Near the end, use more kicks to avoid
//! wasting rounds.
//!
//! Usage:
//!   cargo run --release -p build --bin gen_9_plan_chunk_rounds

mod common;

use common::*;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

// ─── Per-scriptpubkey state ──────────────────────────────────────────────────

struct SpkState {
    script_hash: [u8; SCRIPT_HASH_SIZE],
    start_chunk: u32,
    num_chunks: u32,
    num_units: usize,
    served: Vec<bool>,  // per unit
    cursor: usize,      // first potentially unserved unit
    remaining: usize,   // unserved units
}

impl SpkState {
    fn new(sh: [u8; SCRIPT_HASH_SIZE], start_chunk: u32, num_chunks: u32) -> Self {
        let nu = (num_chunks as usize + CHUNKS_PER_UNIT - 1) / CHUNKS_PER_UNIT;
        Self {
            script_hash: sh,
            start_chunk,
            num_chunks,
            num_units: nu,
            served: vec![false; nu],
            cursor: 0,
            remaining: nu,
        }
    }

    /// Chunk_id for the first chunk of unit `unit_idx`.
    fn unit_chunk_id(&self, unit_idx: usize) -> u32 {
        self.start_chunk + (unit_idx * CHUNKS_PER_UNIT) as u32
    }

    /// Return up to `max` unserved (unit_idx, unit_start_chunk_id) pairs.
    fn get_candidates(&self, max: usize) -> Vec<(usize, u32)> {
        let mut result = Vec::new();
        let mut idx = self.cursor;
        while idx < self.num_units && result.len() < max {
            if !self.served[idx] {
                result.push((idx, self.unit_chunk_id(idx)));
            }
            idx += 1;
        }
        result
    }

    fn mark_served(&mut self, unit_idx: usize) {
        if !self.served[unit_idx] {
            self.served[unit_idx] = true;
            self.remaining -= 1;
            while self.cursor < self.num_units && self.served[self.cursor] {
                self.cursor += 1;
            }
        }
    }
}

// ─── Adaptive max_kicks ─────────────────────────────────────────────────────

/// Compute max eviction kicks for this round based on estimated remaining rounds.
///
///   est_rounds_left = remaining_units / K_CHUNK
///
///   > 100 rounds left  →   3 kicks  (direct placement + minimal eviction)
///   10–100 rounds left →  20 kicks
///   2–10 rounds left   → 100 kicks
///   last round         → 500 kicks  (try hard, avoid an extra round)
fn adaptive_max_kicks(remaining: usize) -> usize {
    let est_rounds = remaining / K_CHUNK;
    if est_rounds > 100 {
        3
    } else if est_rounds > 10 {
        20
    } else if est_rounds > 1 {
        100
    } else {
        500
    }
}

// ─── Cuckoo placement with rollback ─────────────────────────────────────────

fn cuckoo_place(
    cand_buckets: &[[usize; NUM_HASHES]],
    buckets: &mut [Option<usize>; K_CHUNK],
    qi: usize,
    max_kicks: usize,
) -> bool {
    let cands = &cand_buckets[qi];

    // Try each candidate bucket directly
    for &c in cands {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }

    // Eviction
    let mut current_qi = qi;
    let mut current_bucket = cand_buckets[current_qi][0];

    for kick in 0..max_kicks {
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);

        let ev_cands = &cand_buckets[evicted_qi];

        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c == current_bucket {
                continue;
            }
            if buckets[c].is_none() {
                buckets[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_bucket = ev_cands[0];
        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c != current_bucket {
                next_bucket = c;
                break;
            }
        }
        current_qi = evicted_qi;
        current_bucket = next_bucket;
    }

    false
}

/// Try to place candidate `qi`. On failure, restore buckets to their prior state.
fn try_place(
    cand_buckets: &[[usize; NUM_HASHES]],
    buckets: &mut [Option<usize>; K_CHUNK],
    qi: usize,
    max_kicks: usize,
) -> bool {
    let saved = *buckets;
    if cuckoo_place(cand_buckets, buckets, qi, max_kicks) {
        true
    } else {
        *buckets = saved;
        false
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== Chunk PIR Multi-Round Simulation (unit-based) ===");
    println!("  CHUNKS_PER_UNIT = {} ({} bytes/unit)", CHUNKS_PER_UNIT, UNIT_DATA_SIZE);
    println!();

    let start = Instant::now();

    // ── 1. Load first-level PIR results ──────────────────────────────────
    println!("[1] Loading first-level PIR results: {}", BATCH_PIR_RESULTS_FILE);
    let results_data = std::fs::read(BATCH_PIR_RESULTS_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to read: {}", e);
        std::process::exit(1);
    });
    let num_first = results_data.len() / INDEX_ENTRY_SIZE;
    println!("  {} query results loaded", num_first);

    let mut spks: Vec<SpkState> = Vec::new();

    for i in 0..num_first {
        let base = i * INDEX_ENTRY_SIZE;
        let mut sh = [0u8; SCRIPT_HASH_SIZE];
        sh.copy_from_slice(&results_data[base..base + SCRIPT_HASH_SIZE]);
        let offset_half =
            u32::from_le_bytes(results_data[base + 20..base + 24].try_into().unwrap());
        let num_chunks =
            u32::from_le_bytes(results_data[base + 24..base + 28].try_into().unwrap());

        if num_chunks == 0 {
            continue;
        }

        let byte_offset = offset_half as u64 * 2;
        let start_chunk = (byte_offset / CHUNK_SIZE as u64) as u32;

        spks.push(SpkState::new(sh, start_chunk, num_chunks));
    }
    println!("  {} scriptpubkeys with chunks", spks.len());

    // ── 2. Add whale address (looked up from index) ───────────────────
    println!();
    println!("[2] Adding whale address...");
    let whale_sh: [u8; SCRIPT_HASH_SIZE] = [
        0x20, 0xd9, 0x20, 0x10, 0x3e, 0xcb, 0x72, 0x16, 0x38, 0xeb,
        0x43, 0xf3, 0xe7, 0xa2, 0x7c, 0x7b, 0x8e, 0xd3, 0x92, 0x5b,
    ];
    let whale_hex: String = whale_sh.iter().map(|b| format!("{:02x}", b)).collect();

    // Scan index file to find this address
    let index_data = std::fs::read(INDEX_FILE).expect("read index file");
    let num_index = index_data.len() / INDEX_ENTRY_SIZE;
    let mut whale_found = false;
    for i in 0..num_index {
        let base = i * INDEX_ENTRY_SIZE;
        if index_data[base..base + SCRIPT_HASH_SIZE] == whale_sh {
            let offset_half =
                u32::from_le_bytes(index_data[base + 20..base + 24].try_into().unwrap());
            let num_chunks =
                u32::from_le_bytes(index_data[base + 24..base + 28].try_into().unwrap());
            let byte_offset = offset_half as u64 * 2;
            let start_chunk = (byte_offset / CHUNK_SIZE as u64) as u32;

            let already = spks.iter().any(|s| s.script_hash == whale_sh);
            if already {
                println!("  Whale {} already in query set", whale_hex);
            } else {
                println!("  Whale: {} ({} chunks → {} units, start_chunk={})",
                    whale_hex, num_chunks,
                    (num_chunks as usize + CHUNKS_PER_UNIT - 1) / CHUNKS_PER_UNIT,
                    start_chunk);
                spks.push(SpkState::new(whale_sh, start_chunk, num_chunks));
                println!("  Added as scriptpubkey #{}", spks.len() - 1);
            }
            whale_found = true;
            break;
        }
    }
    if !whale_found {
        println!("  WARNING: whale {} not found in index (skipped by gen_1?)", whale_hex);
    }

    let num_spks = spks.len();
    let total_chunks: usize = spks.iter().map(|s| s.num_chunks as usize).sum();
    let total_units: usize = spks.iter().map(|s| s.num_units).sum();

    println!();
    println!("[3] Scriptpubkey summary:");
    println!(
        "  {:>4}  {:>8}  {:>6}  {:>12}  {}",
        "#", "Chunks", "Units", "Start", "Script Hash"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(4),
        "-".repeat(8),
        "-".repeat(6),
        "-".repeat(12),
        "-".repeat(42)
    );
    for (i, s) in spks.iter().enumerate() {
        let hex: String = s.script_hash.iter().map(|b| format!("{:02x}", b)).collect();
        println!(
            "  {:>4}  {:>8}  {:>6}  {:>12}  {}",
            i, s.num_chunks, s.num_units, s.start_chunk, hex
        );
    }
    println!();
    println!("  Total scriptpubkeys: {}", num_spks);
    println!("  Total chunks:        {}", total_chunks);
    println!("  Total units:         {}", total_units);
    println!("  Chunks per unit:     {}", CHUNKS_PER_UNIT);
    println!("  Buckets per round:   {}", K_CHUNK);
    println!(
        "  Theoretical min rounds: {} (ceil({}/{})) ",
        (total_units + K_CHUNK - 1) / K_CHUNK,
        total_units,
        K_CHUNK
    );
    println!();

    // ── 4. Simulate rounds ───────────────────────────────────────────────
    println!("[4] Simulating rounds...");
    println!(
        "  Adaptive max_kicks: >100 rounds left → 3, 10-100 → 20, 2-10 → 100, last → 500"
    );
    println!();
    let sim_start = Instant::now();

    let mut round = 0usize;
    let mut total_served = 0usize;
    let mut total_failed_placements = 0usize;

    // Collect per-round plan data: Vec of (unit_start_chunk_id, bucket_id)
    let mut plan_rounds: Vec<Vec<(u32, u8)>> = Vec::new();

    loop {
        let total_remaining: usize = spks.iter().map(|s| s.remaining).sum();
        if total_remaining == 0 {
            break;
        }
        round += 1;

        let max_kicks = adaptive_max_kicks(total_remaining);

        // ── Phase 1: one unit per unfinished scriptpubkey ────────────
        let mut candidates: Vec<(usize, usize, u32)> = Vec::new(); // (spk_idx, unit_idx, chunk_id)

        for si in 0..num_spks {
            if spks[si].remaining > 0 && candidates.len() < K_CHUNK {
                let cands = spks[si].get_candidates(1);
                if let Some(&(uid, cid)) = cands.first() {
                    candidates.push((si, uid, cid));
                }
            }
        }

        // ── Phase 2: fill candidates beyond K_CHUNK as backup ─────────
        let candidate_limit = K_CHUNK * 2;

        {
            let mut spk_contrib = vec![0usize; num_spks];
            for &(si, _, _) in &candidates {
                spk_contrib[si] += 1;
            }

            let mut order: Vec<usize> = (0..num_spks)
                .filter(|&i| spks[i].remaining > spk_contrib[i])
                .collect();
            order.sort_by(|&a, &b| {
                let ra = spks[a].remaining - spk_contrib[a];
                let rb = spks[b].remaining - spk_contrib[b];
                rb.cmp(&ra)
            });

            'fill: for &si in &order {
                let already = spk_contrib[si];
                let more = spks[si].get_candidates(candidate_limit);
                for (j, &(uid, cid)) in more.iter().enumerate() {
                    if j < already {
                        continue;
                    }
                    if candidates.len() >= candidate_limit {
                        break 'fill;
                    }
                    candidates.push((si, uid, cid));
                    spk_contrib[si] += 1;
                }
            }
        }

        // ── Cuckoo assignment with rollback ──────────────────────────
        let cand_buckets: Vec<[usize; NUM_HASHES]> = candidates
            .iter()
            .map(|&(_, _, cid)| derive_chunk_buckets(cid))
            .collect();

        let mut buckets: [Option<usize>; K_CHUNK] = [None; K_CHUNK];
        let mut placed: Vec<usize> = Vec::new();
        let mut failed = 0usize;

        for i in 0..candidates.len() {
            if placed.len() >= K_CHUNK {
                break;
            }
            if try_place(&cand_buckets, &mut buckets, i, max_kicks) {
                placed.push(i);
            } else {
                failed += 1;
            }
        }

        // Record this round's plan: extract (chunk_id, bucket_id) from buckets
        let mut round_entries: Vec<(u32, u8)> = Vec::new();
        for b in 0..K_CHUNK {
            if let Some(ci) = buckets[b] {
                let (_, _, chunk_id) = candidates[ci];
                round_entries.push((chunk_id, b as u8));
            }
        }
        plan_rounds.push(round_entries);

        // Mark placed units as served
        for &ci in &placed {
            let (si, uid, _) = candidates[ci];
            spks[si].mark_served(uid);
        }

        total_served += placed.len();
        total_failed_placements += failed;

        // Safety: if nothing was placed this round, we'd loop forever
        if placed.is_empty() {
            eprintln!(
                "  ERROR: Round {} placed 0 units out of {} candidates. Aborting.",
                round,
                candidates.len()
            );
            std::process::exit(1);
        }

        // Progress
        let new_remaining = total_remaining - placed.len();
        if round <= 5 || round % 100 == 0 || new_remaining == 0 {
            println!(
                "  Round {:>5}: placed {:>3}/{:>3}, failed {:>2}, kicks={:>3}, remaining {:>8}",
                round,
                placed.len(),
                candidates.len(),
                failed,
                max_kicks,
                new_remaining
            );
        }
    }

    let sim_elapsed = sim_start.elapsed();

    // ── 5. Write plan file ───────────────────────────────────────────────
    println!();
    println!("[5] Writing plan file: {}", CHUNK_PIR_PLAN_FILE);

    // Format:
    //   [8B PLAN_MAGIC]
    //   [4B num_spks] [4B num_rounds] [4B total_units_placed]
    //   Per spk: [20B script_hash][4B start_chunk][4B num_chunks]
    //   Per round: [1B num_placed] then num_placed × [4B chunk_id][1B bucket_id]
    let out_file = File::create(CHUNK_PIR_PLAN_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to create plan file: {}", e);
        std::process::exit(1);
    });
    let mut w = BufWriter::new(out_file);

    w.write_all(&PLAN_MAGIC.to_le_bytes()).unwrap();
    w.write_all(&(num_spks as u32).to_le_bytes()).unwrap();
    w.write_all(&(plan_rounds.len() as u32).to_le_bytes()).unwrap();
    w.write_all(&(total_served as u32).to_le_bytes()).unwrap();

    // SPK table
    for s in &spks {
        w.write_all(&s.script_hash).unwrap();
        w.write_all(&s.start_chunk.to_le_bytes()).unwrap();
        w.write_all(&s.num_chunks.to_le_bytes()).unwrap();
    }

    // Rounds
    for round_entries in &plan_rounds {
        w.write_all(&[round_entries.len() as u8]).unwrap();
        for &(chunk_id, bucket_id) in round_entries {
            w.write_all(&chunk_id.to_le_bytes()).unwrap();
            w.write_all(&[bucket_id]).unwrap();
        }
    }
    w.flush().unwrap();

    let plan_size = 8 + 12 + num_spks * 28
        + plan_rounds.iter().map(|r| 1 + r.len() * 5).sum::<usize>();
    println!(
        "  Written {} bytes ({:.1} KB), {} rounds",
        plan_size,
        plan_size as f64 / 1024.0,
        plan_rounds.len()
    );

    println!();
    println!("=== Summary ===");
    println!("  Script pubkeys:               {}", num_spks);
    println!("  Chunks per unit:              {}", CHUNKS_PER_UNIT);
    println!("  Total chunks:                 {}", total_chunks);
    println!("  Total units:                  {}", total_units);
    println!("  Total units fetched:          {}", total_served);
    println!("  Total rounds:                 {}", round);
    println!(
        "  Avg units per round:          {:.1}",
        total_served as f64 / round as f64
    );
    println!("  Total placement failures:     {}", total_failed_placements);
    if total_served + total_failed_placements > 0 {
        println!(
            "  Failure rate:                 {:.4}%",
            total_failed_placements as f64
                / (total_served + total_failed_placements) as f64
                * 100.0
        );
    }
    println!(
        "  Theoretical minimum rounds:   {}",
        (total_units + K_CHUNK - 1) / K_CHUNK
    );
    println!(
        "  Overhead vs theoretical:      {:.2}%",
        (round as f64 / ((total_units + K_CHUNK - 1) / K_CHUNK) as f64 - 1.0) * 100.0
    );
    println!("  Simulation time:              {:.2?}", sim_elapsed);
    println!("  Total time:                   {:.2?}", start.elapsed());
}
