# Bitcoin PIR — Private Bitcoin Wallet Lookups

Query the Bitcoin UTXO set without revealing which addresses you're interested in.

Today's light wallets leak every address you own to their server, enabling full surveillance of your balances, transactions, and spending habits. Bitcoin PIR uses **Private Information Retrieval** — a family of cryptographic protocols where the server(s) provably learn nothing about which records you look up — to give light wallets the same privacy as a full node, without the storage cost.

## Try It

A live demo runs at **[https://www.bitcoinpir.org/](https://www.bitcoinpir.org/)**. You can paste any Bitcoin address in the browser and watch it resolve to UTXOs privately. The servers run on a home machine and load data on demand, so the first query may be slow — please be patient.

## What It Does

- **Look up any Bitcoin address privately** — balance, UTXOs, and transaction history, with zero leakage to the server
- **Batch many addresses at once** — wallet sync performs dozens of lookups in a single round
- **Verify results cryptographically** — each result comes with an optional Merkle proof that ties it to a published root, so a malicious server can't silently return wrong data
- **Three privacy backends** for different trust and performance trade-offs
- **Works with existing wallets** via plugins and adapters — no need to build a wallet from scratch

## Privacy Backends

You can pick the backend that matches your threat model and performance needs:

| Backend | Trust Model | Best For |
|---------|-------------|----------|
| **DPF (2-server)** | Privacy holds as long as two servers don't collude | Fast, lightweight queries |
| **OnionPIR (1-server, FHE)** | Single server, cryptographic privacy from lattice hardness | Strongest single-server guarantee |
| **HarmonyPIR (1 or 2-server, stateful)** | Offline setup phase; deployed here as 2-server (query server + dedicated hint server) | Fast online queries after initial sync |

All three backends expose the same high-level API — clients can switch between them without changing their code.

## Supported Wallets and Clients

Bitcoin PIR plugs into the existing Bitcoin ecosystem rather than replacing it:

- **Web browser** — a TypeScript + WASM client runs entirely in-browser, no extension needed
- **Electrum** — a drop-in plugin for Electrum 4.7+ that replaces the normal Electrum server calls with private PIR queries
- **bitcoinjs ecosystem** — a drop-in replacement for `@bitcoinerlab/explorer`, so any bitcoinjs wallet can use PIR by swapping one import
- **Rust CLI** — a reference command-line client for testing and scripting

## Key Features

### Cryptographic result verification
Each UTXO lookup can be paired with a Merkle proof query that verifies the result against a published root hash. The server can refuse to answer, but it cannot lie about your balance. Verification is **batched** across all addresses in a wallet sync — one proof round covers the whole batch.

> **Privacy note on Merkle verification.** Within each PIR round, queries are padded to a fixed count (75 for index, 80 for chunk) so the server cannot tell which group is real. Every query — found, not-found, or whale — performs at least one CHUNK PIR round and at least one CHUNK-Merkle sibling pass, so a not-found query stays indistinguishable from a found one (the **round-presence** invariant). INDEX Merkle items are distributed across PBC groups so the per-level sibling-pass count does not depend on a batch's collision pattern (**INDEX Merkle Group-Symmetry**). **Trade-off (2026-05-17):** all three backends (DPF, HarmonyPIR, OnionPIR) no longer pad each query's CHUNK Merkle items to a fixed `M = 16`; a query now fetches and verifies its *real* chunk count, so the server learns the approximate UTXO count of a found address. This is an admitted leak — mild for the ~99% of addresses with a single chunk. See [docs/VERIFICATION_OVERVIEW.md](docs/VERIFICATION_OVERVIEW.md) for the full picture.

### Batch queries
Wallet sync typically touches dozens of addresses at once. Bitcoin PIR packs multiple addresses into a single PIR round using probabilistic batch codes, so syncing a wallet with 50 addresses takes roughly the same time as syncing one.

### Full UTXO dataset
The server hosts the complete Bitcoin UTXO set (~815K active script types at time of writing), filtered to exclude dust and very heavy addresses. Light wallets see the same data a full node would return.

### Open and self-hostable
Anyone can run their own PIR servers from a public Bitcoin Core snapshot. No trusted parties, no API keys, no rate limits.

## Project Layout

```
BitcoinPIR/
├── runtime/          PIR servers and reference CLI (Rust)
├── build/            Database generation pipeline (Rust)
├── web/              Browser client (TypeScript + WASM)
├── explorer/         bitcoinjs adapter
├── electrum_plugin/  Electrum plugin (Python)
├── doc/              Deployment and integration guides
└── pdf/              Research paper
```

## Getting Started

The full build pipeline requires a Bitcoin Core UTXO snapshot and takes a few hours to produce server-ready database files. Detailed instructions live in [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md).

For a quick taste:

1. **Clone and build**:
   ```bash
   git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git
   cd Bitcoin-PIR && cargo build --release
   ```
2. **Point clients at the live demo servers** (no database build needed) — see `web/` for the browser client or `electrum_plugin/` for the Electrum plugin.
3. **Or host your own**: generate the databases from a UTXO snapshot, then start the PIR servers. See [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md).

## Documentation

- [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md) — Production deployment guide
- [`doc/WEB.md`](doc/WEB.md) — Web client details
- [`doc/WALLET_INTEGRATION_ANALYSIS.md`](doc/WALLET_INTEGRATION_ANALYSIS.md) — How Bitcoin PIR integrates with existing wallets
- [`pdf/main.pdf`](pdf/main.pdf) — Research paper with full protocol descriptions and benchmarks

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Contributing

Contributions are welcome — please open a pull request or issue.
