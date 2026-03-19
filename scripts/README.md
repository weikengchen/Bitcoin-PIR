# Bitcoin PIR Scripts

Helper scripts for running and testing the PIR system.

## Scripts

### `start_pir_servers.sh`

Starts two DPF-PIR WebSocket servers for UTXO lookups.

```bash
# Start servers on ports 8091 and 8092 (full database)
./scripts/start_pir_servers.sh

# Start with small database (whale addresses excluded)
./scripts/start_pir_servers.sh --small
```

The script builds the `server` binary, kills any existing servers on the configured ports, and starts two background server processes. Press Ctrl+C to stop both.

Server logs are written to `/tmp/pir_server1.log` and `/tmp/pir_server2.log`.

### `test_lookup_pir.sh`

Tests the PIR lookup client with example scriptPubKey queries.

```bash
./scripts/test_lookup_pir.sh
```

Builds the `lookup_pir` binary and runs a test query against servers at `ws://127.0.0.1:8091` and `ws://127.0.0.1:8092`.

### `get_random_hash.sh`

Samples random entries from the cuckoo hash table for debugging.

```bash
./scripts/get_random_hash.sh
```

Reads random 20-byte keys from the cuckoo database file at `/Volumes/Bitcoin/pir/utxo_chunks_cuckoo.bin`.
