//! HarmonyPIR Batch Query — verbose protocol trace.
//!
//! Picks N real script hashes from the UTXO index, runs the full batch flow
//! (planRounds → INDEX batch → decode → CHUNK batch → reassemble) with
//! detailed intermediate logs at every step.
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_batch_trace --features "alf"

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
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::time::Instant;

const MASTER_KEY: [u8; 16] = [0x42u8; 16];
const NUM_ADDRESSES: usize = 8;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 16 { hex(bytes) }
    else {
        format!("{}...{} ({} B)", hex(&bytes[..8]), hex(&bytes[bytes.len()-4..]), bytes.len())
    }
}

fn choose_backend() -> (u8, &'static str) {
    (PRP_HMR12, "HMR12")
}

fn build_prp_box(backend: u8, key: &[u8; 16], domain: usize, rounds: usize) -> Box<dyn Prp> {
    Box::new(HoangPrp::new(domain, rounds, key))
}

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
    let actual_group = if group_id >= K as u32 { (group_id - K as u32) as usize } else { group_id as usize };
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
            for (d, s) in hints_flat[hint_start..hint_start + w].iter_mut().zip(entry.iter()) { *d ^= s; }
        }
    }
    let mut group = HarmonyGroup::new_with_backend(n as u32, w as u32, t as u32, master_key, group_id, backend).unwrap();
    group.load_hints(&hints_flat).unwrap();
    group
}

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
    let items: Vec<HarmonyBatchResultItem> = query.items.iter().map(|item| {
        let group_id = item.group_id as usize;
        let table_offset = header_size + group_id * bins_per_table * entry_size;
        let sub_results: Vec<Vec<u8>> = item.sub_queries.iter().map(|indices| {
            let mut data = Vec::with_capacity(indices.len() * entry_size);
            for &idx in indices {
                let i = idx as usize;
                if i < bins_per_table {
                    let off = table_offset + i * entry_size;
                    let end = off + entry_size;
                    if end <= table_bytes.len() {
                        data.extend_from_slice(&table_bytes[off..end]);
                    } else {
                        data.extend(std::iter::repeat_n(0u8, entry_size));
                    }
                } else {
                    data.extend(std::iter::repeat_n(0u8, entry_size));
                }
            }
            data
        }).collect();
        HarmonyBatchResultItem { group_id: item.group_id, sub_results }
    }).collect();
    HarmonyBatchResult { level: query.level, round_id: query.round_id, sub_results_per_group: query.sub_queries_per_group, items }
}

// PBC cuckoo placement and round planning use shared build::common::{pbc_cuckoo_place, pbc_plan_rounds}

fn main() {
    let (backend, backend_name) = choose_backend();
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║  HarmonyPIR Batch Query — Verbose Protocol Trace                    ║");
    println!("║  PRP: {:64}║", backend_name);
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");

    // ── Load data ──
    let idx_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let idx_mmap = unsafe { Mmap::map(&idx_file) }.expect("mmap");
    let (index_bins, tag_seed) = read_cuckoo_header(&idx_mmap);
    let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;

    let chunk_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_mmap = unsafe { Mmap::map(&chunk_file) }.expect("mmap");
    let chunk_bins = read_chunk_cuckoo_header(&chunk_mmap);
    let chunk_w = CHUNK_SLOTS_PER_BIN * (4 + CHUNK_SIZE);

    // Load real script hashes from the intermediate index file.
    let index_data_file = File::open(INDEX_FILE).expect("open index data");
    let index_data_mmap = unsafe { Mmap::map(&index_data_file) }.expect("mmap");
    let total_entries = index_data_mmap.len() / INDEX_RECORD_SIZE;

    println!("  INDEX cuckoo: {} bins × {}B, tag_seed=0x{:016x}", index_bins, index_w, tag_seed);
    println!("  CHUNK cuckoo: {} bins × {}B", chunk_bins, chunk_w);
    println!("  Source index:  {} entries × {}B\n", total_entries, INDEX_RECORD_SIZE);

    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Pick N real addresses (script hashes with num_chunks > 0)
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 1: Select {} addresses from UTXO index ━━━\n", NUM_ADDRESSES);

    let mut script_hashes: Vec<[u8; 20]> = Vec::new();
    let mut sh_metadata: Vec<(u32, u8)> = Vec::new(); // (start_chunk_id, num_chunks) ground truth

    // Sample evenly across the file.
    let step = total_entries / (NUM_ADDRESSES * 2);
    let mut pos = 0;
    while script_hashes.len() < NUM_ADDRESSES && pos < total_entries {
        let off = pos * INDEX_RECORD_SIZE;
        let sh = &index_data_mmap[off..off + 20];
        let start_chunk = u32::from_le_bytes(index_data_mmap[off + 20..off + 24].try_into().unwrap());
        let num_chunks = index_data_mmap[off + 24];
        if num_chunks > 0 && num_chunks < 10 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(sh);
            println!("  addr[{}]: sh={} start_chunk={} num_chunks={}",
                script_hashes.len(), hex(&arr), start_chunk, num_chunks);
            script_hashes.push(arr);
            sh_metadata.push((start_chunk, num_chunks));
        }
        pos += step;
    }
    let n_addr = script_hashes.len();
    println!();

    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Derive candidate INDEX groups + plan rounds
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 2: Derive candidate INDEX groups + planRounds ━━━\n");

    let index_cand_groups: Vec<Vec<usize>> = script_hashes.iter().map(|sh| {
        derive_groups(sh).to_vec()
    }).collect();

    for (qi, cands) in index_cand_groups.iter().enumerate() {
        println!("  addr[{}]: candidate INDEX groups = {:?}", qi, cands);
    }

    let index_rounds = pbc_plan_rounds(&index_cand_groups, K, NUM_HASHES, 500);
    println!("\n  planRounds result: {} round(s)", index_rounds.len());
    for (ri, round) in index_rounds.iter().enumerate() {
        println!("    round[{}]: {} assigned queries → {:?}", ri, round.len(),
            round.iter().map(|(qi, b)| format!("addr[{}]→group[{}]", qi, b)).collect::<Vec<_>>());
    }
    println!();

    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Offline — generate INDEX hints for all K groups
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 3: Offline — generate INDEX hints (K={} groups) ━━━\n", K);

    let t0 = Instant::now();
    let mut index_groups: HashMap<u32, HarmonyGroup> = HashMap::new();
    for b in 0..K as u32 {
        index_groups.insert(b, generate_group(backend, &MASTER_KEY, b, &idx_mmap, HEADER_SIZE, index_bins, index_w));
    }
    println!("  Generated hints for {} INDEX groups in {:.2?}\n", K, t0.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // STEP 4: Online — INDEX batch queries
    //   Same structure as CHUNK: for each placement round, always do
    //   INDEX_CUCKOO_NUM_HASHES hash-function rounds.  If the tag was
    //   already found at h=0 we send a fake query at h=1 (saves a hint
    //   slot; server still sees K queries per round).
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 4: Online — INDEX batch queries ({} hash-fn rounds per placement round) ━━━\n",
        INDEX_CUCKOO_NUM_HASHES);

    let mut index_results: HashMap<usize, (u32, u8)> = HashMap::new(); // qi → (start_chunk, num_chunks)
    let mut whale_set: HashSet<usize> = HashSet::new();

    for (ri, round) in index_rounds.iter().enumerate() {
        let group_to_query: HashMap<usize, usize> = round.iter().map(|&(qi, b)| (b, qi)).collect();
        let mut found_this_placement: HashSet<usize> = HashSet::new(); // qi already found

        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            println!("  ── INDEX placement round {}, hash fn h={} ──\n", ri, h);

            let mut items: Vec<HarmonyBatchItem> = Vec::new();
            let mut real_info: HashMap<u8, (usize, usize)> = HashMap::new(); // group_id → (qi, bin)

            for b in 0..K as u32 {
                let group = index_groups.get_mut(&b).unwrap();
                if let Some(&qi) = group_to_query.get(&(b as usize)) {
                    if found_this_placement.contains(&qi) || index_results.contains_key(&qi) || whale_set.contains(&qi) {
                        // Already found — send fake to preserve uniform traffic.
                        let dummy = group.build_synthetic_dummy();
                        let indices: Vec<u32> = dummy.chunks(4)
                            .map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
                        println!("    group[{:>2}]: FAKE (addr[{}] already found)", b, qi);
                        items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                    } else {
                        // Real query with hash function h.
                        let sh = &script_hashes[qi];
                        let ckey = derive_cuckoo_key(b as usize, h);
                        let bin = cuckoo_hash(sh, ckey, index_bins);

                        let req = group.build_request(bin as u32).unwrap();
                        let indices: Vec<u32> = req.request().chunks(4)
                            .map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();

                        println!("    group[{:>2}]: REAL addr[{}] → h={}, bin={} ({} indices)",
                            b, qi, h, bin, indices.len());

                        real_info.insert(b as u8, (qi, bin));
                        items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                    }
                } else {
                    // Bucket not assigned in this round — dummy.
                    let dummy = group.build_synthetic_dummy();
                    let indices: Vec<u32> = dummy.chunks(4)
                        .map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
                    items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                }
            }

            let batch = HarmonyBatchQuery {
                level: 0,
                round_id: (ri * INDEX_CUCKOO_NUM_HASHES + h) as u16,
                sub_queries_per_group: 1,
                items,
                db_id: 0,
            };

            // Wire round-trip + server.
            let req_enc = Request::HarmonyBatchQuery(batch).encode();
            let decoded = match Request::decode(&req_enc[4..]).unwrap() {
                Request::HarmonyBatchQuery(q) => q, _ => panic!(),
            };
            let t0 = Instant::now();
            let result = server_process_batch(&decoded, &idx_mmap, index_bins, index_w, &chunk_mmap, chunk_bins, chunk_w);
            let server_time = t0.elapsed();
            let resp_enc = Response::HarmonyBatchResult(result).encode();
            let result = match Response::decode(&resp_enc[4..]).unwrap() {
                Response::HarmonyBatchResult(r) => r, _ => panic!(),
            };

            println!("\n    Server: {} groups in {:.2?}, wire: req={:.1} KB resp={:.1} KB\n",
                K, server_time, req_enc.len() as f64 / 1024.0, resp_enc.len() as f64 / 1024.0);

            // Process responses for real queries only.
            for item in &result.items {
                if let Some(&(qi, bin)) = real_info.get(&item.group_id) {
                    let group = index_groups.get_mut(&(item.group_id as u32)).unwrap();
                    let answer = group.process_response(&item.sub_results[0]).unwrap();

                    // Verify ground truth.
                    let b = item.group_id as usize;
                    let table_off = HEADER_SIZE + b * index_bins * index_w;
                    let expected = &idx_mmap[table_off + bin * index_w..table_off + bin * index_w + index_w];
                    let correct = answer.as_slice() == expected;

                    // Search for matching tag.
                    let expected_tag = compute_tag(tag_seed, &script_hashes[qi]);
                    let mut tag_found = false;
                    for slot in 0..INDEX_SLOTS_PER_BIN {
                        let s = slot * INDEX_SLOT_SIZE;
                        let tag = u64::from_le_bytes(answer[s..s + 8].try_into().unwrap());
                        if tag == expected_tag {
                            let start_chunk = u32::from_le_bytes(answer[s + 8..s + 12].try_into().unwrap());
                            let num_chunks = answer[s + 12];
                            if num_chunks == 0 {
                                println!("    addr[{}] group[{}] bin={}: tag MATCH → WHALE (num_chunks=0)",
                                    qi, item.group_id, bin);
                                whale_set.insert(qi);
                            } else {
                                println!("    addr[{}] group[{}] bin={}: tag MATCH → start_chunk={} num_chunks={} {}",
                                    qi, item.group_id, bin, start_chunk, num_chunks,
                                    if correct { "✓" } else { "✗" });
                                index_results.insert(qi, (start_chunk, num_chunks));
                            }
                            found_this_placement.insert(qi);
                            tag_found = true;
                            break;
                        }
                    }
                    if !tag_found {
                        println!("    addr[{}] group[{}] bin={}: tag NOT FOUND at h={}",
                            qi, item.group_id, bin, h);
                    }
                }
            }
            println!();
        }
    }

    println!("  INDEX summary: {} found, {} whales, {} not found\n",
        index_results.len(), whale_set.len(),
        n_addr - index_results.len() - whale_set.len());

    // ═══════════════════════════════════════════════════════════════════
    // STEP 5: Collect all chunk IDs
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 5: Collect chunk IDs from INDEX results ━━━\n");

    let mut all_chunk_ids: Vec<u32> = Vec::new();
    for (&qi, &(start, count)) in &index_results {
        println!("  addr[{}]: chunks {}..={} ({} total)",
            qi, start, start + count as u32 - 1, count);
        for ci in 0..count as u32 {
            let cid = start + ci;
            if !all_chunk_ids.contains(&cid) { all_chunk_ids.push(cid); }
        }
    }
    all_chunk_ids.sort();
    println!("\n  {} unique chunk IDs to fetch\n", all_chunk_ids.len());

    // ═══════════════════════════════════════════════════════════════════
    // STEP 6: Plan CHUNK rounds
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 6: Plan CHUNK rounds (K_CHUNK={}, {} hash fns) ━━━\n", K_CHUNK, CHUNK_CUCKOO_NUM_HASHES);

    let chunk_cand_buckets: Vec<Vec<usize>> = all_chunk_ids.iter().map(|&cid| {
        derive_chunk_groups(cid).to_vec()
    }).collect();

    for (ci, cid) in all_chunk_ids.iter().enumerate() {
        println!("  chunk[{}] (id={}): candidate CHUNK groups = {:?}",
            ci, cid, chunk_cand_buckets[ci]);
    }

    let chunk_placement_rounds = pbc_plan_rounds(&chunk_cand_buckets, K_CHUNK, NUM_HASHES, 500);
    println!("\n  planRounds: {} placement round(s)", chunk_placement_rounds.len());
    for (ri, round) in chunk_placement_rounds.iter().enumerate() {
        println!("    placement_round[{}]: {:?}", ri,
            round.iter().map(|(ci, b)| format!("chunk[{}]→group[{}]", ci, b)).collect::<Vec<_>>());
    }
    println!();

    // ═══════════════════════════════════════════════════════════════════
    // STEP 7: Offline — generate CHUNK hints
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 7: Offline — generate CHUNK hints ━━━\n");

    // Only generate hints for groups we actually need.
    let needed_chunk_groups: HashSet<usize> = chunk_cand_buckets.iter().flat_map(|c| c.iter().copied()).collect();
    let t0 = Instant::now();
    let mut chunk_groups: HashMap<u32, HarmonyGroup> = HashMap::new();
    for &b in &needed_chunk_groups {
        let bid = K as u32 + b as u32;
        chunk_groups.insert(b as u32, generate_group(backend, &MASTER_KEY, bid, &chunk_mmap, CHUNK_HEADER_SIZE, chunk_bins, chunk_w));
    }
    // Also create a dummy group for unneeded groups.
    let mut dummy_chunk_bucket: Option<HarmonyGroup> = None;
    for b in 0..K_CHUNK as u32 {
        if !needed_chunk_groups.contains(&(b as usize)) {
            dummy_chunk_bucket = Some(generate_group(backend, &MASTER_KEY, K as u32 + b, &chunk_mmap, CHUNK_HEADER_SIZE, chunk_bins, chunk_w));
            break;
        }
    }
    println!("  Generated hints for {} CHUNK groups (+1 dummy) in {:.2?}\n",
        needed_chunk_groups.len(), t0.elapsed());

    // ═══════════════════════════════════════════════════════════════════
    // STEP 8: Online — CHUNK batch (NUM_HASHES rounds per placement round)
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 8: Online — CHUNK batch queries ━━━\n");

    let mut recovered_chunks: HashMap<u32, Vec<u8>> = HashMap::new();

    for (pri, placement_round) in chunk_placement_rounds.iter().enumerate() {
        let group_to_chunk: HashMap<usize, usize> = placement_round.iter().map(|&(ci, b)| (b, ci)).collect();
        let mut found_this_placement: HashSet<u32> = HashSet::new();

        for h in 0..CHUNK_CUCKOO_NUM_HASHES {
            println!("  ── Placement round {}, hash fn h={} ──\n", pri, h);

            let mut items: Vec<HarmonyBatchItem> = Vec::new();
            let mut real_info: HashMap<u8, (usize, u32, usize)> = HashMap::new(); // group_id → (ci, chunk_id, bin)

            for b in 0..K_CHUNK as u32 {
                if let Some(&ci) = group_to_chunk.get(&(b as usize)) {
                    let cid = all_chunk_ids[ci];
                    if found_this_placement.contains(&cid) || recovered_chunks.contains_key(&cid) {
                        // Already found — send fake.
                        if let Some(ref mut db) = dummy_chunk_bucket {
                            let dummy = db.build_synthetic_dummy();
                            let indices: Vec<u32> = dummy.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
                            items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                        } else if let Some(group) = chunk_groups.get_mut(&b) {
                            let dummy = group.build_synthetic_dummy();
                            let indices: Vec<u32> = dummy.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
                            items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                        } else {
                            items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![vec![]] });
                        }
                    } else {
                        // Real query.
                        let group = chunk_groups.get_mut(&b).unwrap();
                        let ckey = derive_chunk_cuckoo_key(b as usize, h);
                        let bin = cuckoo_hash_int(cid, ckey, chunk_bins);
                        let req = group.build_request(bin as u32).unwrap();
                        let indices: Vec<u32> = req.request().chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();

                        println!("    group[{:>2}]: REAL chunk[{}] (id={}) → h={} bin={} ({} indices)",
                            b, ci, cid, h, bin, indices.len());

                        real_info.insert(b as u8, (ci, cid, bin));
                        items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                    }
                } else {
                    // Not assigned — dummy.
                    if let Some(ref mut db) = dummy_chunk_bucket {
                        let dummy = db.build_synthetic_dummy();
                        let indices: Vec<u32> = dummy.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
                        items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![indices] });
                    } else {
                        items.push(HarmonyBatchItem { group_id: b as u8, sub_queries: vec![vec![]] });
                    }
                }
            }

            let batch = HarmonyBatchQuery { level: 1, round_id: (pri * CHUNK_CUCKOO_NUM_HASHES + h) as u16, sub_queries_per_group: 1, items, db_id: 0 };
            let req_enc = Request::HarmonyBatchQuery(batch).encode();
            let decoded = match Request::decode(&req_enc[4..]).unwrap() { Request::HarmonyBatchQuery(q) => q, _ => panic!() };
            let t0 = Instant::now();
            let result = server_process_batch(&decoded, &idx_mmap, index_bins, index_w, &chunk_mmap, chunk_bins, chunk_w);
            let server_time = t0.elapsed();
            let resp_enc = Response::HarmonyBatchResult(result).encode();
            let result = match Response::decode(&resp_enc[4..]).unwrap() { Response::HarmonyBatchResult(r) => r, _ => panic!() };

            println!("\n    Server: {:.2?}, wire: req={:.1} KB resp={:.1} KB\n",
                server_time, req_enc.len() as f64 / 1024.0, resp_enc.len() as f64 / 1024.0);

            // Process real responses.
            for item in &result.items {
                if let Some(&(ci, cid, _bin)) = real_info.get(&item.group_id) {
                    let group = chunk_groups.get_mut(&(item.group_id as u32)).unwrap();
                    let answer = group.process_response(&item.sub_results[0]).unwrap();

                    let target_bytes = cid.to_le_bytes();
                    for slot in 0..CHUNK_SLOTS_PER_BIN {
                        let s = slot * (4 + CHUNK_SIZE);
                        if answer[s..s + 4] == target_bytes {
                            let data = answer[s + 4..s + 4 + CHUNK_SIZE].to_vec();
                            println!("    chunk[{}] (id={}): ✓ FOUND at h={} → data={}",
                                ci, cid, h, hex_short(&data));
                            recovered_chunks.insert(cid, data);
                            found_this_placement.insert(cid);
                            break;
                        }
                    }
                }
            }
            println!();
        }
    }

    println!("  CHUNK summary: {}/{} recovered\n", recovered_chunks.len(), all_chunk_ids.len());

    // ═══════════════════════════════════════════════════════════════════
    // STEP 9: Reassemble per-address results
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Step 9: Reassemble UTXO data per address ━━━\n");

    let mut total_hint_slots_index = 0usize;
    let mut total_hint_slots_chunk = 0usize;

    for qi in 0..n_addr {
        let sh = &script_hashes[qi];
        println!("  addr[{}] sh={}", qi, hex(sh));

        if whale_set.contains(&qi) {
            println!("    → WHALE (excluded)\n");
            continue;
        }

        if let Some(&(start, count)) = index_results.get(&qi) {
            total_hint_slots_index += 1; // one INDEX query per address
            println!("    INDEX: start_chunk={}, num_chunks={}", start, count);
            let mut all_data = Vec::new();
            let mut all_found = true;
            for ci in 0..count as u32 {
                let cid = start + ci;
                if let Some(data) = recovered_chunks.get(&cid) {
                    println!("    CHUNK {}: {} ✓", cid, hex_short(data));
                    all_data.extend_from_slice(data);
                } else {
                    println!("    CHUNK {}: ✗ MISSING", cid);
                    all_found = false;
                }
            }
            // Hint slot cost for this address's chunks.
            // Each chunk costs 1 slot if found at h=0, 2 if found at h=1.
            // (Approximation — we logged the exact h above.)
            total_hint_slots_chunk += count as usize; // lower bound (best case all at h=0)

            if all_found {
                println!("    → {} bytes of UTXO data ✓", all_data.len());
            } else {
                println!("    → INCOMPLETE");
            }

            // Cross-check with ground truth.
            let (gt_start, gt_count) = sh_metadata[qi];
            if start == gt_start && count == gt_count {
                println!("    Ground truth: MATCH ✓");
            } else {
                println!("    Ground truth: MISMATCH! expected start={} count={}", gt_start, gt_count);
            }
        } else {
            println!("    → NOT FOUND in index (may need h=1 retry)");
        }
        println!();
    }

    // ═══════════════════════════════════════════════════════════════════
    // Summary
    // ═══════════════════════════════════════════════════════════════════
    println!("━━━ Summary ━━━\n");
    println!("  Addresses queried:    {}", n_addr);
    println!("  INDEX results:        {} found + {} whales", index_results.len(), whale_set.len());
    println!("  CHUNK results:        {}/{} recovered", recovered_chunks.len(), all_chunk_ids.len());
    println!("  INDEX hint slots:     ~{}", total_hint_slots_index);
    println!("  CHUNK hint slots:     ~{} (×{} hash fns ≈ {:.1} avg)",
        total_hint_slots_chunk, CHUNK_CUCKOO_NUM_HASHES, total_hint_slots_chunk as f64 * 1.5);
    println!("  INDEX batch rounds:   {}", index_rounds.len());
    println!("  CHUNK batch rounds:   {} (placement) × {} (hash fns) = {}",
        chunk_placement_rounds.len(), CHUNK_CUCKOO_NUM_HASHES,
        chunk_placement_rounds.len() * CHUNK_CUCKOO_NUM_HASHES);

    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║           BATCH TRACE COMPLETE ✓                                    ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
}
