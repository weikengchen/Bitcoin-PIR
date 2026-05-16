//! `bpir-admin attest` — fetch and verify a server's SEV-SNP report.
//!
//! Drives `pir_sdk_client::attest::attest()` and presents the result.
//! Optional `--expect-binary` and `--expect-manifest-roots` flags cross-
//! check the server's self-reported values against operator-published
//! expected values; mismatches exit non-zero so this can be wired into
//! CI.

use clap::Args;
use pir_sdk_client::attest::{attest, SevStatus};
use pir_sdk_client::WsConnection;

#[derive(Args, Debug)]
pub struct AttestArgs {
    /// WebSocket URL of the server to attest, e.g.
    /// `wss://weikeng2.bitcoinpir.org` or `ws://localhost:8092`.
    pub server: String,

    /// Expected hex of the server binary's SHA-256. If set, exit
    /// non-zero unless the server's self-reported `binary_sha256`
    /// matches.
    #[arg(long)]
    pub expect_binary: Option<String>,

    /// Comma-separated list of expected per-DB manifest roots (hex,
    /// in db_id order). If set, every position must match.
    #[arg(long, value_delimiter = ',')]
    pub expect_manifest_roots: Vec<String>,

    /// Expected SEV-SNP launch MEASUREMENT (96-char hex = 48 bytes).
    /// This is the value the operator publishes after uploading a UKI
    /// via VPSBG's Measured Boot UI and rebooting — it covers OVMF +
    /// the entire UKI bytes (kernel + initrd + cmdline). If set, exit
    /// non-zero on any mismatch. Implies the SEV report must be
    /// present (i.e., we're attesting against a SEV-SNP host, not a
    /// stock-Linux Hetzner-style fallback).
    #[arg(long)]
    pub expect_measurement: Option<String>,

    /// Override the connect+request timeout (seconds, default 30).
    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,
}

/// Run the attest subcommand, returning the process exit code.
pub async fn run(args: AttestArgs) -> Result<(), i32> {
    let mut conn = match connect(&args.server, args.timeout_seconds).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("attest: connect to {} failed: {}", args.server, e);
            return Err(1);
        }
    };

    let mut nonce = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut nonce) {
        eprintln!("attest: getrandom: {}", e);
        return Err(1);
    }

    let v = match attest(&mut conn, nonce).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("attest: server returned error: {}", e);
            return Err(1);
        }
    };

    println!("Server URL:        {}", args.server);
    println!("Nonce sent:        {}", hex::encode(nonce));
    println!();
    println!("== Self-reported (server-side) ==");
    println!("binary_sha256:     {}", hex::encode(v.response.binary_sha256));
    println!("git_rev:           {}", v.response.git_rev);
    // server_static_pub is the X25519 long-lived channel pubkey. All-zero
    // means the server hasn't enabled the encrypted-channel feature yet
    // (transitional — flag it so an operator who expects a key sees that
    // it's missing).
    if v.response.server_static_pub == [0u8; 32] {
        println!("channel pubkey:    <none>  (server has no X25519 channel key — encrypted-channel feature off)");
    } else {
        println!("channel pubkey:    {}  (X25519, V2-bound to REPORT_DATA)",
                 hex::encode(v.response.server_static_pub));
    }
    println!("manifest roots ({} DB{}):",
             v.response.manifest_roots.len(),
             if v.response.manifest_roots.len() == 1 { "" } else { "s" });
    for (i, root) in v.response.manifest_roots.iter().enumerate() {
        println!("  db_id={}: {}", i, hex::encode(root));
    }
    // Slice D.2: AMD VCEK chain bundled in AttestResult so the
    // browser can chain-validate the SEV-SNP report's signature
    // back to AMD's known root without talking to kdsintf.amd.com.
    let chain_present = !v.response.ark_pem.is_empty()
        && !v.response.ask_pem.is_empty()
        && !v.response.vcek_pem.is_empty();
    if chain_present {
        println!(
            "vcek chain:        bundled (ark={}B ask={}B vcek={}B)",
            v.response.ark_pem.len(),
            v.response.ask_pem.len(),
            v.response.vcek_pem.len(),
        );
    } else {
        println!(
            "vcek chain:        <none> (server has no VCEK chain loaded — \
             configure --vcek-dir on the server to enable browser-side \
             AMD-rooted chain validation)"
        );
    }
    println!();
    println!("== SEV-SNP attestation ==");
    println!("Report bytes:      {}", v.response.sev_snp_report.len());
    println!("Status:            {:?}", v.sev_status);
    println!("Expected REPORT_DATA[..32]: {}", hex::encode(v.expected_report_data_hash));
    if !v.response.sev_snp_report.is_empty() {
        // Pull the launch MEASUREMENT (offset 0x90, 48 bytes) for display.
        // (See AMD SEV-SNP ABI doc: report v2/v5 layout.)
        const MEASUREMENT_OFFSET: usize = 0x90;
        const MEASUREMENT_LEN: usize = 48;
        if v.response.sev_snp_report.len() >= MEASUREMENT_OFFSET + MEASUREMENT_LEN {
            let m = &v.response.sev_snp_report
                [MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN];
            println!("Launch MEASUREMENT: {}", hex::encode(m));
        }
    }

    let mut mismatch = false;

    // Cross-check sev status
    match v.sev_status {
        SevStatus::ReportDataMatch => {
            println!();
            println!("✓ SEV-SNP REPORT_DATA binding verified.");
        }
        SevStatus::NoSevHost => {
            println!();
            println!("⚠ Server is not running on a SEV-SNP host —");
            println!("   self-reported metadata is NOT hardware-backed.");
        }
        SevStatus::ReportDataMismatch => {
            println!();
            println!("✗ REPORT_DATA does not match recomputation —");
            println!("   server may be lying about its self-reported state.");
            mismatch = true;
        }
        SevStatus::MalformedReport => {
            println!();
            println!("✗ SEV report is malformed (too short for REPORT_DATA field).");
            mismatch = true;
        }
    }

    // Cross-check expected binary hash
    if let Some(expected_hex) = args.expect_binary {
        let actual_hex = hex::encode(v.response.binary_sha256);
        if !expected_hex.eq_ignore_ascii_case(&actual_hex) {
            println!();
            println!("✗ binary_sha256 mismatch:");
            println!("    expected: {}", expected_hex);
            println!("    got:      {}", actual_hex);
            mismatch = true;
        } else {
            println!();
            println!("✓ binary_sha256 matches expected.");
        }
    }

    // Cross-check expected MEASUREMENT (the operator-published launch
    // digest from the chip-signed report, NOT a recomputation).
    if let Some(expected_hex) = args.expect_measurement {
        const MEASUREMENT_OFFSET: usize = 0x90;
        const MEASUREMENT_LEN: usize = 48;
        if v.response.sev_snp_report.len() < MEASUREMENT_OFFSET + MEASUREMENT_LEN {
            println!();
            println!("✗ --expect-measurement set but server returned no SEV report");
            println!("    (host is not running on a SEV-SNP guest, or report is malformed)");
            mismatch = true;
        } else {
            let actual = &v.response.sev_snp_report
                [MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN];
            let actual_hex = hex::encode(actual);
            if !expected_hex.eq_ignore_ascii_case(&actual_hex) {
                println!();
                println!("✗ MEASUREMENT mismatch:");
                println!("    expected: {}", expected_hex);
                println!("    got:      {}", actual_hex);
                println!("    (different UKI loaded, or VPSBG OVMF version changed)");
                mismatch = true;
            } else {
                println!();
                println!("✓ Launch MEASUREMENT matches expected.");
            }
        }
    }

    // Cross-check expected manifest roots
    if !args.expect_manifest_roots.is_empty() {
        if args.expect_manifest_roots.len() != v.response.manifest_roots.len() {
            println!();
            println!(
                "✗ manifest root count mismatch: expected {}, got {}",
                args.expect_manifest_roots.len(),
                v.response.manifest_roots.len()
            );
            mismatch = true;
        } else {
            for (i, (exp, got)) in args
                .expect_manifest_roots
                .iter()
                .zip(v.response.manifest_roots.iter())
                .enumerate()
            {
                let got_hex = hex::encode(got);
                if !exp.eq_ignore_ascii_case(&got_hex) {
                    println!();
                    println!("✗ manifest_root[{}] mismatch:", i);
                    println!("    expected: {}", exp);
                    println!("    got:      {}", got_hex);
                    mismatch = true;
                }
            }
            if !mismatch {
                println!("✓ all manifest roots match expected.");
            }
        }
    }

    if mismatch {
        Err(2)
    } else {
        Ok(())
    }
}

async fn connect(url: &str, _timeout_secs: u64) -> Result<WsConnection, String> {
    // WsConnection::connect() applies DEFAULT_CONNECT_TIMEOUT (30s)
    // internally; per-request deadline is DEFAULT_REQUEST_TIMEOUT.
    // For an MVP CLI the defaults are fine; expose finer control later.
    WsConnection::connect(url).await.map_err(|e| e.to_string())
}
