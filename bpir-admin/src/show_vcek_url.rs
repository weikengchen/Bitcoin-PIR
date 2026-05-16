//! `bpir-admin show-vcek-url` — print the AMD KDS URLs the operator
//! needs to fetch for the connected server's per-chip VCEK certificate.
//!
//! Sequence:
//!   1. Connect to the server, run REQ_ATTEST.
//!   2. Parse the SNP report to extract `chip_id` (64 bytes) +
//!      `current_tcb` (bootloader / tee / snp / microcode SVNs).
//!   3. Print `cert_chain` URL (ARK + ASK, family-wide and stable
//!      across reboots) and the per-chip+TCB `vcek` URL.
//!
//! The operator then runs:
//!   curl -o cert_chain.pem '<chain url>'
//!   curl -o vcek.pem       '<vcek url>'
//! and drops both into the directory configured via `--vcek-dir` on
//! the unified_server side.

use clap::Args;
use pir_attest_verify::{parse_report, SnpReport};
use pir_sdk_client::attest::attest;
use pir_sdk_client::WsConnection;

#[derive(Args, Debug)]
pub struct ShowVcekUrlArgs {
    /// Server WebSocket URL (e.g. `wss://weikeng2.bitcoinpir.org`).
    pub server_url: String,
    /// AMD SoC family for KDS URL construction. Auto-detect by chip
    /// hint isn't done — the operator usually knows. Common values:
    /// `Milan` (Zen 3), `Genoa` (Zen 4), `Turin` (Zen 5).
    #[arg(long, default_value = "Turin")]
    pub family: String,
}

pub async fn run(args: ShowVcekUrlArgs) -> Result<(), i32> {
    let url = &args.server_url;
    println!("Server URL: {}", url);
    println!("Family:     {}", args.family);

    let mut conn = match WsConnection::connect(url).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect: {}", e);
            return Err(1);
        }
    };

    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("OS RNG must work");
    let v = match attest(&mut conn, nonce).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("attest: {}", e);
            return Err(2);
        }
    };

    if v.response.sev_snp_report.is_empty() {
        eprintln!(
            "server returned an empty SNP report — likely not a SEV-SNP host. \
             VCEK URLs only apply to SEV-SNP hosts; nothing to fetch."
        );
        return Err(3);
    }

    let report: SnpReport = match parse_report(&v.response.sev_snp_report) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("parse SNP report: {}", e);
            return Err(4);
        }
    };

    // Format chip_id as 128 hex chars (uppercase, no spaces — matches
    // the URL form AMD KDS expects).
    let chip_id_hex = report
        .chip_id
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();
    // The VCEK is bound to `reported_tcb`, NOT `current_tcb` — they
    // can differ when AMD wants to publish a VCEK for a TCB version
    // that's older (or newer) than what the guest is actually running.
    // Always use reported_tcb for the AMD KDS URL.
    let tcb = &report.reported_tcb;

    println!();
    println!("Chip ID:    {}", chip_id_hex);
    let fmc_str = match tcb.fmc {
        Some(fmc) => format!("fmc={} ", fmc),
        None => String::new(),
    };
    println!(
        "TCB (reported): {}bl={} tee={} snp={} microcode={}",
        fmc_str, tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
    );
    let signing_key = report.key_info.signing_key();
    let signing_key_name = match signing_key {
        0 => "VCEK (chip-specific, fetch from kdsintf.amd.com/vcek/v1/)",
        1 => "VLEK (cloud-loaded, fetch from kdsintf.amd.com/vlek/v1/)",
        _ => "RESERVED/NONE",
    };
    println!("Signing key:    {} (key_info.signing_key={})", signing_key_name, signing_key);
    if signing_key == 1 {
        println!();
        println!(
            "⚠ This chip uses VLEK, NOT VCEK. The cloud provider (VPSBG) loaded a custom\n  signing key. AMD KDS at /vcek/v1/ won't have a matching cert.\n  VLEK certs come from the same KDS host but at /vlek/v1/{{Family}}/{{ChipID}}\n  (ChipID is still the chip's hardware ID)."
        );
    }

    // Build the URLs. Turin's KDS endpoint also takes `fmcSPL` —
    // include it whenever fmc is present (Turin and later).
    let chain_url = format!("https://kdsintf.amd.com/vcek/v1/{}/cert_chain", args.family);
    let fmc_param = match tcb.fmc {
        Some(fmc) => format!("fmcSPL={}&", fmc),
        None => String::new(),
    };
    let vcek_url = format!(
        "https://kdsintf.amd.com/vcek/v1/{}/{}?{}blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        args.family, chip_id_hex, fmc_param, tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
    );
    println!();
    println!("Operator commands (run on the SEV-SNP host):");
    println!("  mkdir -p /home/pir/data/vcek && cd /home/pir/data/vcek");
    println!("  # cert_chain endpoint returns PEM (ASK + ARK concatenated)");
    println!("  curl -sS -o cert_chain.pem '{}'", chain_url);
    println!("  # VCEK endpoint returns DER regardless of Accept header — convert to PEM");
    println!("  curl -sS -o vcek.der       '{}'", vcek_url);
    println!("  openssl x509 -inform der -in vcek.der -out vcek.pem && rm vcek.der");
    println!();
    println!("Then add `--vcek-dir /home/pir/data/vcek` to the unified_server systemd unit");
    println!("and restart pir-vpsbg. Re-run `bpir-admin attest` and look for");
    println!("\"vcek chain: bundled\" to confirm.");
    println!();
    println!("Note: chip_id is full 64-byte SEV-SNP report field (AMD KDS accepts");
    println!("      the truncated form when only the leading bytes are non-zero, as");
    println!("      is common on production EPYC chips).");

    Ok(())
}
