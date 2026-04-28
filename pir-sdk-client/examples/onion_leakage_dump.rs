//! Phase 2.3 cross-language diff: dump OnionPIR leakage profiles to JSON.
//!
//! Connects to an OnionPIR-enabled server, runs a fixed corpus of
//! script-hash queries through `OnionClient` while a
//! `BufferingLeakageRecorder` captures every wire-observable round, and
//! emits a JSON document on stdout. The vitest test
//! `web/src/__tests__/onion_leakage_diff.test.ts` (Phase 2.3 step D)
//! reads this JSON and asserts the standalone TypeScript
//! `OnionPirWebClient` produces a structurally equal profile for each
//! query — the operational form of "the two implementations leak the
//! same shape on the wire".
//!
//! Usage (default targets the public Hetzner deployment):
//!
//! ```bash
//! cargo run -p pir-sdk-client --features onion --example onion_leakage_dump -- \
//!     --output web/test/fixtures/onion_corpus.json
//! ```
//!
//! Override server with `--server <url>`, e.g. `ws://127.0.0.1:8091` for
//! a local `unified_server`. The output path is required because the
//! OnionPIR FFI (SEAL) prints diagnostic lines to stdout — JSON to a
//! file keeps the corpus parseable.
//!
//! Corpus shape: two distinct not-found script-hashes. Not-found is the
//! deterministic path — no CHUNK rounds, no per-query data dependence.
//! The TS port should produce byte-identical profiles for both.
//!
//! Output JSON shape:
//!
//! ```json
//! {
//!   "server_url": "wss://...",
//!   "queries": [
//!     { "script_hash_hex": "00...", "profile": { "backend": "onion", "rounds": [...] } },
//!     { "script_hash_hex": "01...", "profile": { ... } }
//!   ]
//! }
//! ```

use std::sync::Arc;

use pir_sdk::BufferingLeakageRecorder;
use pir_sdk_client::{OnionClient, PirClient, ScriptHash};

const DEFAULT_SERVER: &str = "wss://pir1.chenweikeng.com";

struct Args {
    server_url: String,
    output_path: String,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut server_url = DEFAULT_SERVER.to_string();
    let mut output_path: Option<String> = None;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--server" | "-s" => {
                i += 1;
                if i < argv.len() {
                    server_url = argv[i].clone();
                }
            }
            "--output" | "-o" => {
                i += 1;
                if i < argv.len() {
                    output_path = Some(argv[i].clone());
                }
            }
            "--help" | "-h" => {
                eprintln!("Usage: onion_leakage_dump --output <path> [--server <url>]");
                eprintln!();
                eprintln!("  --output, -o <path>  Path to write JSON corpus (required).");
                eprintln!("  --server, -s <url>   Server URL (default: {}).", DEFAULT_SERVER);
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    let output_path = output_path.unwrap_or_else(|| {
        eprintln!("Error: --output <path> is required (FFI prints to stdout).");
        eprintln!("Re-run with --help for usage.");
        std::process::exit(2);
    });
    Args { server_url, output_path }
}

/// Fixed corpus: two not-found script-hashes that must produce
/// structurally equal profiles. The bytes are arbitrary but deterministic
/// — the vitest port replays the same hex strings.
fn corpus() -> Vec<ScriptHash> {
    let mut a = [0u8; 20];
    let mut b = [0u8; 20];
    for i in 0..20 {
        a[i] = (i as u8).wrapping_mul(17);
        b[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    vec![a, b]
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(feature = "onion")]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    eprintln!("Connecting to {} ...", args.server_url);

    let mut entries: Vec<serde_json::Value> = Vec::new();

    for sh in corpus() {
        // Fresh recorder + fresh client per query so each profile starts
        // from the connect handshake. Connect cost is dominated by the
        // FHE key generation in the WASM module on the TS side; on
        // Rust this is a one-time setup.
        let recorder = Arc::new(BufferingLeakageRecorder::new());
        let mut client = OnionClient::new(&args.server_url);
        client.set_leakage_recorder(Some(recorder.clone()));

        client.connect().await?;
        let catalog = client.fetch_catalog().await?;
        let db_id = catalog.databases[0].db_id;
        eprintln!(
            "  query {} -> db_id={} (not-found path)",
            hex(&sh),
            db_id
        );
        let _ = client.query_batch(&[sh], db_id).await?;
        client.disconnect().await?;

        let profile = recorder.take_profile("onion");
        eprintln!(
            "    captured {} rounds: {:?}",
            profile.rounds.len(),
            profile
                .rounds
                .iter()
                .map(|r| format!("{:?}", r.kind))
                .collect::<Vec<_>>()
                .join(", "),
        );

        entries.push(serde_json::json!({
            "script_hash_hex": hex(&sh),
            "profile": profile,
        }));
    }

    let doc = serde_json::json!({
        "server_url": args.server_url,
        "queries": entries,
    });
    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(&args.output_path, json)?;
    eprintln!(
        "Wrote {} queries to {}",
        entries.len(),
        args.output_path,
    );
    Ok(())
}

#[cfg(not(feature = "onion"))]
fn main() {
    eprintln!(
        "This example requires the `onion` feature. Rebuild with:\n  \
         cargo run -p pir-sdk-client --features onion --example onion_leakage_dump"
    );
    std::process::exit(2);
}

#[cfg(feature = "onion")]
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
