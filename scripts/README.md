# Bitcoin PIR Scripts

Helper scripts for running and testing the PIR system.

## Scripts

### `start_pir_servers.sh`

Starts two Batch PIR WebSocket servers for UTXO lookups.

```bash
./scripts/start_pir_servers.sh
```

The script builds the `server` binary (`runtime` crate), kills any existing servers on ports 8091/8092, and starts two background server processes. Press Ctrl+C to stop both.

Server logs are written to `/tmp/pir_server1.log` and `/tmp/pir_server2.log`.

### `test_batch_pir_client.sh`

Tests the PIR client with a script hash query.

```bash
./scripts/test_batch_pir_client.sh [script_hash_hex]
```

Builds the `client` binary and runs a test query against servers at `ws://127.0.0.1:8091` and `ws://127.0.0.1:8092`.

### `get_random_hash.sh`

Samples random entries from the cuckoo hash table for debugging.

```bash
./scripts/get_random_hash.sh
```

### `build_full.sh`

Builds a complete full-snapshot UTXO PIR database (DPF + HarmonyPIR +
OnionPIR + all Merkle artifacts) from a Bitcoin Core dumptxoutset.
Single orchestrator that runs the full 10-stage pipeline.

```bash
./scripts/build_full.sh <dumptxoutset_file> <height>
```

Layout:
- Intermediate (raw UTXO + chunks; ~10–20 GB; safe to delete after build):
  `/Volumes/Bitcoin/data/intermediate/full_<H>/`
- Final checkpoint (~40 GB, ready for the server):
  `/Volumes/Bitcoin/data/checkpoints/<H>/`

The pipeline:
1. `gen_0_extract_utxo_set` — dumptxoutset → 68B flat UTXOs
2. `gen_1_build_utxo_chunks` — pack into 80B chunks + 25B index (no dust)
3. `build_cuckoo_generic index` — INDEX cuckoo (DPF/Harmony)
4. `build_cuckoo_generic chunk` — CHUNK cuckoo (DPF/Harmony)
5. `gen_4_build_merkle_bucket --data-dir` — per-bucket bin Merkle
6. `gen_1_onion` — pack UTXOs into 3840B OnionPIR entries
7. (move `onion_packed_entries.bin` + `onion_index.bin` into checkpoint dir)
8. `gen_2_onion --data-dir` — NTT store + chunk cuckoo + DATA bin hashes
9. `gen_3_onion --data-dir` — per-group INDEX PIR DBs (consolidated to `onion_index_all.bin`)
10. `gen_4_build_merkle_onion --data-dir` — per-bin OnionPIR Merkle (INDEX + DATA)

### `build_delta.sh`

Builds a complete delta UTXO database between two block heights, including
the per-bucket bin Merkle verification files. Runs the full pipeline:
`delta_gen_0` -> `delta_gen_1` -> `build_cuckoo_generic` (index + chunk) ->
`gen_4_build_merkle_bucket`.

```bash
./scripts/build_delta.sh <dumptxoutset_file> <bitcoin_datadir> <start_height> <end_height>
```

Output goes to `/Volumes/Bitcoin/data/deltas/<start>_<end>/`.

### `build_delta_onion.sh`

Builds the OnionPIR artifacts for an existing delta UTXO database, enabling
the 1-server OnionPIR backend on that delta. Must be run **after**
`build_delta.sh` for the same height range. Runs:
`delta_gen_1_onion` -> `gen_2_onion --data-dir` -> `gen_3_onion --data-dir`
-> `gen_4_build_merkle_onion --data-dir`.

```bash
./scripts/build_delta_onion.sh <start_height> <end_height>
```

Produces the `onion_*.bin` files and per-bin `merkle_onion_*.bin` Merkle trees
in the same `/Volumes/Bitcoin/data/deltas/<start>_<end>/` directory that
`build_delta.sh` wrote to. Once these exist, the server (re)started via
`start_pir_servers.sh` will automatically serve the delta via OnionPIR and the
web client's OnionPIR tab can query `db_id=1`.

---

## Regular database refresh runbook

Refresh production with a new full snapshot at height `B` plus a delta
from the previous full-snapshot height `A` to `B`. Keep the existing
checkpoint around as a backup until the new one is verified live.

Prerequisites: a local bitcoind synced to ≥ `B` with `txindex=1`, and
the previous dumptxoutset `utxo_<A>.dat` (kept from the last refresh).

```bash
# 1. Snapshot the chain at height B (≈5–15 min, locks the node briefly)
bitcoin-cli -datadir=/Volumes/Bitcoin/bitcoin -rpcclienttimeout=0 \
    -named dumptxoutset \
    path=/Volumes/Bitcoin/snapshots/utxo_<B>.dat \
    type=rollback rollback=<B>

# 2. Build the full snapshot at B (≈1–3 h)
./scripts/build_full.sh /Volumes/Bitcoin/snapshots/utxo_<B>.dat <B>

# 3. Build the delta A → B (≈10–30 min)
./scripts/build_delta.sh /Volumes/Bitcoin/snapshots/utxo_<A>.dat \
    /Volumes/Bitcoin/bitcoin <A> <B>
./scripts/build_delta_onion.sh <A> <B>

# 4. Hash every file under each new dir into a deterministic MANIFEST.toml
./scripts/build_db_manifest.sh /Volumes/Bitcoin/data/checkpoints/<B>
./scripts/build_db_manifest.sh /Volumes/Bitcoin/data/deltas/<A>_<B>

# 5. rsync to the Hetzner server (≈30–90 min depending on link)
rsync -aP /Volumes/Bitcoin/data/checkpoints/<B>/ \
    pir-hetzner:/home/pir/data/checkpoints/<B>/
rsync -aP /Volumes/Bitcoin/data/deltas/<A>_<B>/ \
    pir-hetzner:/home/pir/data/deltas/<A>_<B>/
ssh pir-hetzner "chown -R pir:pir /home/pir/data/checkpoints/<B> /home/pir/data/deltas/<A>_<B>"

# 6. Edit /home/pir/data/databases.toml on the host:
#       main:  height = <B>, path = "checkpoints/<B>"
#       delta: base_height = <A>, height = <B>, path = "deltas/<A>_<B>"
#    Restart and verify
ssh pir-hetzner "systemctl restart pir-primary pir-secondary"
ssh pir-hetzner 'journalctl -u pir-primary -n 50 --no-pager | grep -E "Loaded|height"'
```

After verifying live queries against `wss://pir1.chenweikeng.com`, you
can clean up the previous checkpoint dir on the host
(`/home/pir/data/checkpoints/<A>/`) and the local intermediate dir
(`/Volumes/Bitcoin/data/intermediate/full_<B>/`).
