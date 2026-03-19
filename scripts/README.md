# Bitcoin PIR Scripts

Helper scripts for running and testing the PIR system.

## Scripts

### `start_pir_servers.sh`

Starts two Batch PIR WebSocket servers for UTXO lookups.

```bash
./scripts/start_pir_servers.sh
```

The script builds the `server` binary (`runtime` crate), kills any existing servers on ports 8093/8094, and starts two background server processes. Press Ctrl+C to stop both.

Server logs are written to `/tmp/pir_server1.log` and `/tmp/pir_server2.log`.

### `test_batch_pir_client.sh`

Tests the PIR client with a script hash query.

```bash
./scripts/test_batch_pir_client.sh [script_hash_hex]
```

Builds the `client` binary and runs a test query against servers at `ws://127.0.0.1:8093` and `ws://127.0.0.1:8094`.

### `get_random_hash.sh`

Samples random entries from the cuckoo hash table for debugging.

```bash
./scripts/get_random_hash.sh
```
