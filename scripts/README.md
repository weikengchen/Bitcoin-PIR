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
