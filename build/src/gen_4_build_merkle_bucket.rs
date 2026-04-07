//! Build per-bucket bin Merkle trees for INDEX and CHUNK cuckoo tables.
//!
//! Each PBC group (75 for INDEX, 80 for CHUNK) gets an arity-8 Merkle tree
//! over its cuckoo bins. Leaf[i] = SHA256(i_u32_LE || bin_content).
//!
//! Sibling tables are flat: each row is [8 × 32B child hashes] = 256B,
//! indexed directly by group_id (no cuckoo hashing for siblings).
//!
//! Output files:
//!   merkle_bucket_index_sib_L0.bin, L1.bin  — INDEX sibling levels
//!   merkle_bucket_chunk_sib_L0.bin, L1.bin  — CHUNK sibling levels
//!   merkle_bucket_tree_tops.bin             — 155 tree-top caches
//!   merkle_bucket_roots.bin                 — 155 × 32B roots
//!   merkle_bucket_root.bin                  — 32B super-root
//!
//! Usage: gen_4_build_merkle_bucket [--data-dir <dir>]

mod merkle_bucket_builder;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = "/Volumes/Bitcoin/data".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                data_dir = args[i + 1].clone();
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    merkle_bucket_builder::build_bucket_merkle(&data_dir);
}
