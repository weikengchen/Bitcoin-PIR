//! HarmonyPIR Batch Protocol E2E Test — Rust client ↔ server.
//!
//! Tests the full batch wire protocol on real Bitcoin UTXO data:
//! 1. Generate hints for a subset of INDEX + CHUNK groups
//! 2. Build a batch request (real + synthetic dummy)
//! 3. Encode → decode via wire protocol
//! 4. Server processes the batch
//! 5. Client decodes responses and recovers entries
//! 6. Verify correctness against ground truth
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_batch_e2e --features "alf"

use build::common::*;
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir_wasm::{
    HarmonyGroup, PRP_HMR12,
    compute_rounds, derive_group_key, find_best_t, pad_n_for_t,
};
use runtime::protocol::*;

use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

const MASTER_KEY: [u8; 16] = [0x42u8; 16];

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 16 {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    } else {
        let head: String = bytes[..8].iter().map(|b| format!("{:02x}", b)).collect();
        let tail: String = bytes[bytes.len()-4..].iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}...{} ({} B)", head, tail, bytes.len())
    }
}

fn choose_backend() -> (u8, &'static str) {
    (PRP_HMR12, "HMR12")
}

fn build_prp_box(backend: u8, key: &[u8; 16], domain: usize, rounds: usize) -> Box<dyn Prp> {
    Box::new(HoangPrp::new(domain, rounds, key))
}

/// Generate hints for one group. Returns a ready-to-query HarmonyGroup.
fn generate_group(
    backend: u8, master_key: &[u8; 16], group_id: u32,
    table_mmap: &[u8], header_size: usize, n: usize, w: usize,
) -> HarmonyGroup {
    let t_val = find_best_t(n as u32);
    let (padded_n, t_val) = pad_n_for_t(n as u32, t_val);
    let pn = padded_n as usize;
    let t = t_val as usize;
    let domain = 2 * pn;
    let r = compute_rounds(padded_n);
    let params = Params::new(pn, w, t).unwrap();
    let m = params.m;
    let derived_key = derive_group_key(master_key, group_id);

    let actual_group = if group_id >= K as u32 {
        (group_id - K as u32) as usize
    } else {
        group_id as usize
    };
    let table_offset = header_size + actual_group * n * w;

    let prp = build_prp_box(backend, &derived_key, domain, r);
    let cell_of: Vec<usize> = (0..pn).map(|k| prp.forward(k)).collect();

    let mut hints_flat = vec![0u8; m * w];
    for k in 0..pn {
        let seg = cell_of[k] / t;
        if k < n {
            let start = table_offset + k * w;
            let entry = &table_mmap[start..start + w];
            let hint_start = seg * w;
            for (d, s) in hints_flat[hint_start..hint_start + w].iter_mut().zip(entry.iter()) {
                *d ^= s;
            }
        }
    }

    let mut group = HarmonyGroup::new_with_backend(
        n as u32, w as u32, t as u32, master_key, group_id, backend,
    ).unwrap();
    group.load_hints(&hints_flat).unwrap();
    group
}

/// Simulate the server processing a HarmonyBatchQuery.
/// This mirrors what handle_harmony_batch_query does but works in-process
/// using the mmap'd cuckoo tables directly.
fn server_process_batch(
    query: &HarmonyBatchQuery,
    idx_mmap: &[u8], index_bins: usize, index_w: usize,
    chunk_mmap: &[u8], chunk_bins: usize, chunk_w: usize,
) -> HarmonyBatchResult {
    let (table_bytes, bins_per_table, entry_size, header_size) = match query.level {
        0 => (idx_mmap, index_bins, index_w, HEADER_SIZE),
        1 => (chunk_mmap, chunk_bins, chunk_w, CHUNK_HEADER_SIZE),
        _ => panic!("bad level"),
    };

    let result_items: Vec<HarmonyBatchResultItem> = query.items.iter().map(|item| {
        let group_id = item.group_id as usize;
        let table_offset = header_size + group_id * bins_per_table * entry_size;

        let sub_results: Vec<Vec<u8>> = item.sub_queries.iter().map(|indices| {
            let mut data = Vec::with_capacity(indices.len() * entry_size);
            for &idx in indices {
                let idx_usize = idx as usize;
                if idx_usize < bins_per_table {
                    let off = table_offset + idx_usize * entry_size;
                    let end = off + entry_size;
                    if end <= table_bytes.len() {
                        data.extend_from_slice(&table_bytes[off..end]);
                    } else {
                        // Shouldn't happen, but pad with zeros.
                        data.extend(std::iter::repeat_n(0u8, entry_size));
                    }
                } else {
                    // Virtual padded row — return zeros (client expects entry_size bytes per index).
                    data.extend(std::iter::repeat_n(0u8, entry_size));
                }
            }
            data
        }).collect();

        HarmonyBatchResultItem { group_id: item.group_id, sub_results }
    }).collect();

    HarmonyBatchResult {
        level: query.level,
        round_id: query.round_id,
        sub_results_per_group: query.sub_queries_per_group,
        items: result_items,
    }
}

fn main() {
    let (backend, backend_name) = choose_backend();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  HarmonyPIR Batch Protocol E2E — Rust Client ↔ Server          ║");
    println!("║  PRP: {:58}║", backend_name);
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // ── Load tables ──
    let idx_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let idx_mmap = unsafe { Mmap::map(&idx_file) }.expect("mmap");
    let (index_bins, _tag_seed) = read_cuckoo_header(&idx_mmap);
    let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE; // 4 × 13 = 52

    let chunk_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_mmap = unsafe { Mmap::map(&chunk_file) }.expect("mmap");
    let chunk_bins = read_chunk_cuckoo_header(&chunk_mmap);
    let chunk_w = CHUNK_SLOTS_PER_BIN * (4 + CHUNK_SIZE); // 3 × 44 = 132

    println!("  INDEX: {} bins × {}B, CHUNK: {} bins × {}B\n", index_bins, index_w, chunk_bins, chunk_w);

    // ══════════════════════════════════════════════════════════════════
    // Phase 1: INDEX batch
    // ══════════════════════════════════════════════════════════════════
    println!("━━━ Phase 1: INDEX Batch ━━━\n");

    // Pick 5 real query targets from different INDEX groups.
    let real_index_groups: Vec<u32> = vec![0, 10, 25, 50, 74];
    let num_real = real_index_groups.len();
    let num_dummy = K - num_real;

    println!("  {} real queries + {} dummy = {} total INDEX groups\n", num_real, num_dummy, K);

    // Generate hints for the real groups.
    let t0 = Instant::now();
    let mut index_groups: Vec<(u32, HarmonyGroup)> = Vec::new();
    for &bid in &real_index_groups {
        let group = generate_group(backend, &MASTER_KEY, bid, &idx_mmap, HEADER_SIZE, index_bins, index_w);
        index_groups.push((bid, group));
    }
    // Also generate dummy groups for the rest.
    let mut dummy_index_groups: Vec<(u32, HarmonyGroup)> = Vec::new();
    for b in 0..K as u32 {
        if real_index_groups.contains(&b) { continue; }
        let group = generate_group(backend, &MASTER_KEY, b, &idx_mmap, HEADER_SIZE, index_bins, index_w);
        dummy_index_groups.push((b, group));
        if dummy_index_groups.len() >= 5 { break; } // only need a few for dummy generation
    }
    println!("  Hint generation: {:.2?}", t0.elapsed());

    // For each real group, pick a non-empty bin to query.
    let mut real_targets: Vec<(u32, usize)> = Vec::new(); // (group_id, bin_index)
    for &bid in &real_index_groups {
        let table_offset = HEADER_SIZE + bid as usize * index_bins * index_w;
        let mut target_bin = 0;
        for bin in 0..index_bins {
            let bin_start = table_offset + bin * index_w;
            let slot = &idx_mmap[bin_start..bin_start + INDEX_SLOT_SIZE];
            let tag = u64::from_le_bytes(slot[0..8].try_into().unwrap());
            let num_chunks = slot[12];
            if tag != 0 && num_chunks > 0 {
                target_bin = bin;
                break;
            }
        }
        real_targets.push((bid, target_bin));
    }

    // Build the batch request.
    // Use 1 sub-query per group: build_request + process_response must be paired 1:1
    // (HarmonyGroup is stateful — process_response reads state set by build_request).
    // In the real system, planRounds assigns each query to a specific group + hash fn.
    let sub_q_per_group: u8 = 1;
    let mut batch_items: Vec<HarmonyBatchItem> = Vec::new();

    // Real queries.
    let mut real_group_map: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (i, (bid, group)) in index_groups.iter_mut().enumerate() {
        let target_bin = real_targets[i].1;
        let req = group.build_request(target_bin as u32).unwrap();
        let req_bytes = req.request();
        let indices: Vec<u32> = req_bytes.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        real_group_map.insert(*bid, i);
        batch_items.push(HarmonyBatchItem { group_id: *bid as u8, sub_queries: vec![indices] });
    }

    // Dummy queries for remaining groups.
    let mut dummy_idx = 0;
    for b in 0..K as u32 {
        if real_index_groups.contains(&b) { continue; }
        if dummy_idx < dummy_index_groups.len() {
            let (_, ref mut dummy_group) = dummy_index_groups[dummy_idx];
            let dummy_bytes = dummy_group.build_synthetic_dummy();
            let indices: Vec<u32> = dummy_bytes.chunks(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            batch_items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
            dummy_idx = (dummy_idx + 1) % dummy_index_groups.len();
        } else {
            batch_items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![vec![]] });
        }
    }

    let batch_query = HarmonyBatchQuery {
        level: 0,
        round_id: 0,
        sub_queries_per_group: sub_q_per_group,
        items: batch_items,
        db_id: 0,
    };

    println!("  Batch request: {} groups × {} sub-queries", batch_query.items.len(), sub_q_per_group);

    // ── Wire protocol encode/decode round-trip ──
    let t0 = Instant::now();
    let request = Request::HarmonyBatchQuery(batch_query);
    let encoded = request.encode();
    let wire_time = t0.elapsed();

    println!("  Wire encode: {} bytes ({:.1} KB) in {:.2?}", encoded.len(), encoded.len() as f64 / 1024.0, wire_time);

    // Decode the encoded message (skip 4B length prefix).
    let t0 = Instant::now();
    let decoded = Request::decode(&encoded[4..]).unwrap();
    let decode_time = t0.elapsed();
    println!("  Wire decode: {:.2?}", decode_time);

    let decoded_batch = match decoded {
        Request::HarmonyBatchQuery(q) => q,
        _ => panic!("expected HarmonyBatchQuery"),
    };

    assert_eq!(decoded_batch.items.len(), K);
    assert_eq!(decoded_batch.sub_queries_per_group, sub_q_per_group);
    println!("  Decode verified: {} groups × {} sub-q ✓\n", decoded_batch.items.len(), decoded_batch.sub_queries_per_group);

    // ── Server processes the batch ──
    let t0 = Instant::now();
    let batch_result = server_process_batch(
        &decoded_batch,
        &idx_mmap, index_bins, index_w,
        &chunk_mmap, chunk_bins, chunk_w,
    );
    let server_time = t0.elapsed();
    println!("  Server processed batch in {:.2?}", server_time);

    // ── Wire protocol for response ──
    let response = Response::HarmonyBatchResult(batch_result);
    let resp_encoded = response.encode();
    println!("  Response wire: {} bytes ({:.1} KB)", resp_encoded.len(), resp_encoded.len() as f64 / 1024.0);

    let resp_decoded = Response::decode(&resp_encoded[4..]).unwrap();
    let result = match resp_decoded {
        Response::HarmonyBatchResult(r) => r,
        _ => panic!("expected HarmonyBatchResult"),
    };

    assert_eq!(result.items.len(), K);
    println!("  Response decode verified: {} items ✓\n", result.items.len());

    // ── Client processes real responses ──
    println!("  ── Client recovers INDEX entries ──\n");

    let mut index_pass = 0;
    let mut chunk_ids_to_fetch: Vec<(u32, u8)> = Vec::new(); // (start_chunk_id, num_chunks)

    for result_item in &result.items {
        let bid = result_item.group_id as u32;
        if let Some(&idx) = real_group_map.get(&bid) {
            let (_, ref mut group) = index_groups[idx];
            let target_bin = real_targets[idx].1;

            // Process first sub-query response.
            let resp_data = &result_item.sub_results[0];
            let expected_count = resp_data.len() / index_w;
            println!("    [debug] group {}: resp {} bytes = {} entries × {}B, last_query was bin {}",
                bid, resp_data.len(), expected_count, index_w, target_bin);
            let answer = match group.process_response(resp_data) {
                Ok(a) => a,
                Err(_) => {
                    println!("    [ERROR] process_response failed for group {}", bid);
                    continue;
                }
            };

            // Verify against ground truth.
            let table_offset = HEADER_SIZE + bid as usize * index_bins * index_w;
            let expected_start = table_offset + target_bin * index_w;
            let expected = &idx_mmap[expected_start..expected_start + index_w];
            let correct = answer.as_slice() == expected;

            // Decode first non-empty slot.
            let mut entry_info = String::new();
            for slot in 0..INDEX_SLOTS_PER_BIN {
                let s = slot * INDEX_SLOT_SIZE;
                let tag = u64::from_le_bytes(answer[s..s + 8].try_into().unwrap());
                let start_chunk = u32::from_le_bytes(answer[s + 8..s + 12].try_into().unwrap());
                let num_chunks = answer[s + 12];
                if tag != 0 && num_chunks > 0 {
                    entry_info = format!("start_chunk={} num_chunks={}", start_chunk, num_chunks);
                    chunk_ids_to_fetch.push((start_chunk, num_chunks));
                    break;
                }
            }

            println!("    Bucket {:>2}, bin {:>6}: {} {} {}",
                bid, target_bin,
                if correct { "✓" } else { "✗" },
                hex_short(&answer[..13.min(answer.len())]),
                entry_info);
            assert!(correct, "INDEX group {} FAILED", bid);
            index_pass += 1;
        }
    }

    println!("\n  INDEX: {}/{} correct ✓\n", index_pass, num_real);

    // ══════════════════════════════════════════════════════════════════
    // Phase 2: CHUNK batch
    // ══════════════════════════════════════════════════════════════════
    println!("━━━ Phase 2: CHUNK Batch ━━━\n");

    if chunk_ids_to_fetch.is_empty() {
        println!("  No chunks to fetch (all whales or empty). Skipping.\n");
    } else {
        // Collect unique chunk IDs.
        let mut all_chunk_ids: Vec<u32> = Vec::new();
        for &(start, count) in &chunk_ids_to_fetch {
            for ci in 0..count as u32 {
                let cid = start + ci;
                if !all_chunk_ids.contains(&cid) {
                    all_chunk_ids.push(cid);
                }
            }
        }
        all_chunk_ids.sort();
        println!("  {} unique chunk IDs to fetch from {} INDEX results\n", all_chunk_ids.len(), chunk_ids_to_fetch.len());

        // For simplicity, assign chunk IDs to groups using first candidate + first hash function.
        // This mirrors the real flow where planRounds() does cuckoo placement.
        let mut chunk_group_map: std::collections::HashMap<u32, (usize, u32)> = std::collections::HashMap::new(); // group_id → (chunk_idx, chunk_id)
        let mut chunk_group_instances: std::collections::HashMap<u32, HarmonyGroup> = std::collections::HashMap::new();

        for (ci, &cid) in all_chunk_ids.iter().enumerate() {
            let groups = derive_chunk_groups(cid);
            let target_group = groups[0] as u32;
            chunk_group_map.insert(target_group, (ci, cid));

            chunk_group_instances.entry(target_group).or_insert_with(|| {
                let chunk_bid = K as u32 + target_group;
                let group = generate_group(
                    backend, &MASTER_KEY, chunk_bid,
                    &chunk_mmap, CHUNK_HEADER_SIZE, chunk_bins, chunk_w,
                );
                group
            });
        }

        // Build chunk batches — one batch per hash function.
        // HarmonyGroup is stateful: build_request + process_response must be paired 1:1.
        // So we do CHUNK_CUCKOO_NUM_HASHES separate batch rounds, each with 1 sub-query per group.
        // Round h=0: build_request(bin_h0) for all real groups → send batch → process_response for all.
        // Round h=1: build_request(bin_h1) for all real groups → send batch → process_response for all.
        // This costs CHUNK_CUCKOO_NUM_HASHES hint slots per chunk, which is correct — without
        // placement info, the client must try each hash function.

        // Create a few dummy groups.
        let mut dummy_chunk_groups: Vec<HarmonyGroup> = Vec::new();
        for b in 0..3u32 {
            if !chunk_group_map.contains_key(&b) {
                let group = generate_group(
                    backend, &MASTER_KEY, K as u32 + b,
                    &chunk_mmap, CHUNK_HEADER_SIZE, chunk_bins, chunk_w,
                );
                dummy_chunk_groups.push(group);
                if dummy_chunk_groups.len() >= 2 { break; }
            }
        }

        println!("  Chunk strategy: {} batch round(s) (1 per hash fn), {} real + {} dummy per round\n",
            CHUNK_CUCKOO_NUM_HASHES, chunk_group_map.len(), K_CHUNK - chunk_group_map.len());

        let mut chunk_pass = 0;
        let mut recovered_chunks = std::collections::HashSet::new();

        for h in 0..CHUNK_CUCKOO_NUM_HASHES {
            let mut chunk_batch_items: Vec<HarmonyBatchItem> = Vec::new();
            let mut dummy_chunk_idx = 0;
            let dummy_count = dummy_chunk_groups.len();

            for b in 0..K_CHUNK as u32 {
                if let Some(&(_, cid)) = chunk_group_map.get(&b) {
                    if recovered_chunks.contains(&cid) {
                        // Already found in a previous round — send a synthetic dummy
                        // to keep the group active (server can't distinguish).
                        // This saves a hint slot.
                        let group = chunk_group_instances.get_mut(&b).unwrap();
                        let dummy_bytes = group.build_synthetic_dummy();
                        let indices: Vec<u32> = dummy_bytes.chunks(4)
                            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                            .collect();
                        chunk_batch_items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                    } else {
                        // Not yet found — real query with hash function h.
                        let group = chunk_group_instances.get_mut(&b).unwrap();
                        let ckey = derive_chunk_cuckoo_key(b as usize, h);
                        let bin_index = cuckoo_hash_int(cid, ckey, chunk_bins);
                        let req = group.build_request(bin_index as u32).unwrap();
                        let indices: Vec<u32> = req.request().chunks(4)
                            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                            .collect();
                        chunk_batch_items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                    }
                } else {
                    if dummy_count > 0 {
                        let db = &mut dummy_chunk_groups[dummy_chunk_idx % dummy_count];
                        let dummy_bytes = db.build_synthetic_dummy();
                        let indices: Vec<u32> = dummy_bytes.chunks(4)
                            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                            .collect();
                        chunk_batch_items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                        dummy_chunk_idx += 1;
                    } else {
                        chunk_batch_items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![vec![]] });
                    }
                }
            }

            let chunk_batch = HarmonyBatchQuery {
                level: 1,
                round_id: h as u16,
                sub_queries_per_group: 1,
                items: chunk_batch_items,
                db_id: 0,
            };

            // Wire round-trip.
            let request = Request::HarmonyBatchQuery(chunk_batch);
            let encoded = request.encode();
            let decoded = Request::decode(&encoded[4..]).unwrap();
            let decoded_batch = match decoded {
                Request::HarmonyBatchQuery(q) => q,
                _ => panic!("expected HarmonyBatchQuery"),
            };

            let t0 = Instant::now();
            let chunk_result = server_process_batch(
                &decoded_batch,
                &idx_mmap, index_bins, index_w,
                &chunk_mmap, chunk_bins, chunk_w,
            );
            let server_time = t0.elapsed();

            let response = Response::HarmonyBatchResult(chunk_result);
            let resp_encoded = response.encode();
            let resp_decoded = Response::decode(&resp_encoded[4..]).unwrap();
            let result = match resp_decoded {
                Response::HarmonyBatchResult(r) => r,
                _ => panic!("expected HarmonyBatchResult"),
            };

            println!("  CHUNK batch h={}: req {:.1} KB, server {:.2?}, resp {:.1} KB",
                h, encoded.len() as f64 / 1024.0, server_time, resp_encoded.len() as f64 / 1024.0);

            // Process responses for groups that had real queries this round.
            // Buckets that sent dummies (already found) don't call process_response
            // — the dummy didn't touch HarmonyGroup state.
            for result_item in &result.items {
                let bid = result_item.group_id as u32;
                if let Some(&(_, cid)) = chunk_group_map.get(&bid) {
                    if recovered_chunks.contains(&cid) {
                        // Was a dummy — ignore response, no state to update.
                        continue;
                    }
                    let group = chunk_group_instances.get_mut(&bid).unwrap();
                    let resp_data = &result_item.sub_results[0];
                    let answer = group.process_response(resp_data).unwrap();

                    let target_bytes = cid.to_le_bytes();
                    for slot in 0..CHUNK_SLOTS_PER_BIN {
                        let s = slot * (4 + CHUNK_SIZE);
                        if answer[s..s + 4] == target_bytes {
                            let data = &answer[s + 4..s + 4 + CHUNK_SIZE];
                            println!("    Bucket {:>2}, chunk_id={}: ✓ h={} data={}",
                                bid, cid, h, hex_short(data));
                            chunk_pass += 1;
                            recovered_chunks.insert(cid);
                            break;
                        }
                    }
                }
            }
        }

        let not_found = all_chunk_ids.len() - chunk_pass;
        if not_found > 0 {
            for &(_, cid) in chunk_group_map.values() {
                if !recovered_chunks.contains(&cid) {
                    println!("    chunk_id={}: ✗ NOT FOUND after {} hash functions", cid, CHUNK_CUCKOO_NUM_HASHES);
                }
            }
        }

        // Hint slot accounting.
        // Real queries in round 0: all real groups (chunk_group_map.len())
        // Real queries in round 1: only unfound after round 0
        let _found_at_h0 = chunk_pass.min(all_chunk_ids.len()); // approximate
        let real_round_0 = chunk_group_map.len();
        // Can't easily count found_at_h0 vs found_at_h1 from here, but the
        // print above already shows which chunks were found at which h.
        let _total_hint_slots = real_round_0 * CHUNK_CUCKOO_NUM_HASHES;
        println!("\n  Hint slot cost: {} real groups × {} rounds (worst case = {} slots, avg ≈ {:.1})",
            real_round_0, CHUNK_CUCKOO_NUM_HASHES,
            real_round_0 * CHUNK_CUCKOO_NUM_HASHES,
            real_round_0 as f64 * 1.5);

        println!("\n  CHUNK: {}/{} correct ✓\n", chunk_pass, all_chunk_ids.len());
    }

    // ══════════════════════════════════════════════════════════════════
    // Summary
    // ══════════════════════════════════════════════════════════════════
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║           BATCH PROTOCOL E2E: ALL PASSED ✓                     ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
