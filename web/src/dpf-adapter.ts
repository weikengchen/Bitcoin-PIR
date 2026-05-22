/**
 * WASM-backed adapter that mimics the legacy `BatchPirClient` API shape.
 *
 * The old `web/src/client.ts` carried ~800 LOC of PIR wire-format logic
 * (encoding batched DPF queries, decoding responses, per-bucket Merkle
 * verification). Session 3 of the TS retirement plan replaced that with
 * this adapter, which delegates the actual PIR work to `WasmDpfClient`
 * from `pir-sdk-wasm` (which in turn wraps the native Rust `DpfClient`
 * via the `wasm_transport` layer in `pir-sdk-client`).
 *
 * What stays in TypeScript:
 *   * A pair of side-channel `ManagedWebSocket`s — the WASM client owns
 *     its own transport sockets internally, but those aren't exposed to
 *     the browser. The side-channel sockets are used for:
 *       - `REQ_GET_INFO_JSON` at connect time (to populate
 *         `serverInfo` so `hasMerkle` / `getMerkleRootHex` can answer
 *         synchronously without a roundtrip)
 *       - `REQ_GET_DB_CATALOG` at connect time (for the catalog
 *         accessors and the UI DB selector)
 *       - `REQ_RESIDENCY` via the residency panel in `web/index.html`
 *         (which iterates `getConnectedSockets()` across all backends
 *         and calls `fetchResidency(ws)`).
 *   * Translation between `WasmQueryResult` (the WASM-side opaque
 *     handle) and the legacy `QueryResult` shape consumed by the UI
 *     renderers + `sync-merge.ts`.
 *
 * What moves to WASM:
 *   * All PIR wire-format logic (INDEX + CHUNK batched queries).
 *   * Per-bucket bin-Merkle verification (`verifyMerkleBatch`).
 *   * Padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) —
 *     owned by the native `DpfClient`, not re-implementable here.
 *
 * 🔒 Privacy: the adapter cannot bypass padding, cannot short-circuit the
 * symmetric INDEX bin probing (`INDEX_CUCKOO_NUM_HASHES = 2`), and cannot
 * turn off Merkle verification — those live in native Rust code below the
 * WASM boundary.
 */

import { bytesToHex, hexToBytes } from './hash.js';
import {
  fetchDatabaseCatalog,
  fetchServerInfoJson,
  type BucketMerkleInfoJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
  type ServerInfoJson,
} from './server-info.js';
import {
  requireSdkWasm,
  type WasmAttestVerification,
  type WasmDpfClient,
  type WasmQueryResult,
} from './sdk-bridge.js';
import { getAmdTurinArkFingerprint } from './attest-pin.js';
import type { ConnectionState, QueryResult, UtxoEntry } from './types.js';
import { ManagedWebSocket } from './ws.js';

// ─── Config ──────────────────────────────────────────────────────────────────

/**
 * Per-server attestation snapshot, exposed via
 * `BatchPirClientAdapter.attestation` after `connect()` returns.
 *
 * `state`:
 *   - `'unattested'`: no attest call has succeeded for this server (or
 *     it's still in progress). Treat the channel as cleartext.
 *   - `'verified'`: attest returned `'reportDataMatch'` AND the server
 *     reported a non-zero X25519 channel pubkey AND the
 *     `upgradeToSecureChannel` call succeeded. Subsequent traffic is
 *     AEAD-sealed; cloudflared sees only ciphertext. The SEV-SNP
 *     report is internally consistent but its signature has NOT been
 *     chain-validated back to AMD's root.
 *   - `'verified-vcek'`: same as `'verified'` PLUS the AMD VCEK chain
 *     (ARK→ASK→VCEK) verified AND the report's ECDSA-P384 signature
 *     verified against the VCEK pubkey. Strongest browser-side
 *     guarantee — the report is provably signed by real AMD silicon
 *     whose root we operator-pinned at web-build time.
 *   - `'plaintext'`: attest succeeded but the server has no channel
 *     pubkey (legacy server). Subsequent traffic is plaintext through
 *     cloudflared — fine for development but not for production
 *     privacy.
 *   - `'mismatch'`: attest binding check failed. Self-reported fields
 *     should not be trusted; the connection is still alive but the
 *     adapter logs a warning and falls back to cleartext.
 */
export interface ServerAttestation {
  state: 'unattested' | 'verified' | 'verified-vcek' | 'plaintext' | 'mismatch';
  /** Raw SEV-SNP REPORT_DATA binding status from the attest call.
   *  Useful for surfacing the precise reason behind `mismatch`. */
  sevStatus?: string;
  /** Hex-encoded X25519 channel pubkey reported by the server. Empty
   *  on `unattested`; all-zero hex (`'00…00'`) on `plaintext`. */
  serverStaticPubHex?: string;
  /** SHA-256 of the running server binary (server-side self-report).
   *  Hex-encoded. Trusted only when `state === 'verified'` or
   *  `'verified-vcek'`. */
  binarySha256Hex?: string;
  /** Git commit baked into the running server binary. */
  gitRev?: string;
  /** Hex-encoded launch MEASUREMENT (96 chars / 48 bytes) — the
   *  digest AMD's PSP signs into every SEV-SNP report, covering OVMF
   *  + the loaded UKI bytes. Empty when not on a SEV-SNP host.
   *  Hardware-backed iff `sevStatus === 'reportDataMatch'`. */
  launchMeasurementHex?: string;
  /** When VCEK chain validation was attempted: 'pass' / 'fail' /
   *  'skipped' (server didn't bundle a chain — pre-Slice-D.2 server
   *  or `--vcek-dir` unset). Filled in by the adapter after the
   *  attest call resolves. */
  vcekChain?: 'pass' | 'fail' | 'skipped';
  /** When `vcekChain === 'fail'`, the diagnostic from
   *  `pir_attest_verify::VerifyError`. */
  vcekChainError?: string;
  /** Slice 3 build-time pin enforcement status:
   *   - `'no-pin'`: no pin configured for this server.
   *   - `'match'`: configured pin(s) matched the attested values.
   *   - `'measurement-mismatch'`: launchMeasurementHex didn't match.
   *   - `'binary-mismatch'`: binarySha256Hex didn't match.
   * On any mismatch, `state` is demoted to `'mismatch'` and
   * `pinError` carries a human-readable diagnostic. */
  pinStatus?: 'no-pin' | 'match' | 'measurement-mismatch' | 'binary-mismatch';
  pinError?: string;
}

export interface BatchPirClientConfig {
  server0Url: string;
  server1Url: string;
  /** Fires on every connection-state transition (from the adapter itself +
   * from the underlying `WasmDpfClient`). `disconnected` is also emitted on
   * errors during connect. */
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  /** Fires for adapter-level log events (connect messages, side-channel
   * errors). Audit events from the native client go to `console.log` —
   * we do not have an `onLog` hook on `WasmDpfClient` yet. */
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void;
  /**
   * If `true` (default), the adapter automatically attests both servers
   * after the WS connect completes and, when both report a valid
   * X25519 channel pubkey, upgrades both connections to the encrypted
   * channel. Subsequent PIR traffic flows through `pir_channel`'s
   * AEAD-sealed frames so cloudflared sees only ciphertext.
   *
   * Set `false` to keep the connection in cleartext (e.g. for
   * tcpdump-side debugging or testing against pre-V2 servers).
   */
  useSecureChannel?: boolean;
  /** Fires once per server after `connect()` resolves the per-server
   *  attestation result. Use to surface a "verified channel" badge in
   *  the UI. `serverIndex` is 0 (first URL) or 1 (second URL). */
  onAttestation?: (serverIndex: 0 | 1, info: ServerAttestation) => void;
  /**
   * Operator-pinned 32-byte SHA-256 fingerprint of the AMD ARK
   * (Root Key) certificate. When set AND the server bundles a VCEK
   * chain, the adapter calls `verifyVcekChain` and flips
   * `attestation.serverN.state` to `'verified-vcek'` on success. When
   * `null` (default), the chain isn't validated and state caps at
   * `'verified'` (V2 binding only).
   *
   * Pin this at web-build time (e.g. read from a `.env` constant) so a
   * malicious server can't substitute a forged "ARK". Compute via
   *   sha256(DER(ARK))
   * — for AMD's published ARK at https://kdsintf.amd.com/vcek/v1/{Family}/cert_chain
   * (the second PEM block).
   */
  expectedArkFingerprint?: Uint8Array | null;
  /**
   * Slice 3 build-time pins for the per-server attested values.
   * When a pin is set for a server, the adapter enforces it after
   * the SEV-SNP / VCEK chain checks pass: any mismatch on
   * `measurementHex` or `binarySha256Hex` demotes that server's
   * `state` to `'mismatch'` and carries a `pinError` diagnostic.
   *
   * Both fields are optional per server. Skipping a field skips
   * that check (e.g. omit `measurementHex` for non-SEV servers
   * like pir1 — they have no MEASUREMENT to compare).
   *
   * Pin values come from operator-published constants in
   * [`./attest-pin.ts`] — see `PIR2_TIER3_PIN` and `PIR1_PIN`.
   * Update those constants whenever the operator re-bakes + republishes.
   */
  expectedServer0Pin?: import('./attest-pin.js').ServerAttestPin;
  expectedServer1Pin?: import('./attest-pin.js').ServerAttestPin;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/**
 * Drop-in replacement for the pre-Session-3 `BatchPirClient`. Same
 * constructor config, same method names, same return shapes —
 * `web/index.html` changes its `new BatchPirClient(...)` call site to
 * `new BatchPirClientAdapter(...)` and nothing else.
 */
export class BatchPirClientAdapter {
  private readonly config: BatchPirClientConfig;
  private readonly ws0: ManagedWebSocket;
  private readonly ws1: ManagedWebSocket;
  private wasmClient: WasmDpfClient | null = null;
  private catalog: DatabaseCatalog | null = null;
  private serverInfo: ServerInfoJson | null = null;
  /**
   * Back-reference from translated `QueryResult` to its originating
   * `WasmQueryResult` handle. `WeakMap` so the pair can be collected once
   * the caller drops the translated result. `verifyMerkleBatch` reaches
   * here to round-trip each result through `toJson()` without having to
   * re-serialise by hand.
   */
  private readonly wasmHandles: WeakMap<QueryResult, WasmQueryResult> = new WeakMap();
  private connected = false;
  /**
   * Per-server attestation snapshot. Filled in by `connect()` if
   * `useSecureChannel` is enabled (default). Default `'unattested'`
   * until the post-connect attest call resolves. UI consumers should
   * read this after `connect()` returns or via the `onAttestation`
   * callback for live updates.
   */
  attestation: { server0: ServerAttestation; server1: ServerAttestation } = {
    server0: { state: 'unattested' },
    server1: { state: 'unattested' },
  };

  constructor(config: BatchPirClientConfig) {
    this.config = config;
    this.ws0 = new ManagedWebSocket({
      url: config.server0Url,
      label: 'DPF server0',
      onLog: config.onLog,
    });
    this.ws1 = new ManagedWebSocket({
      url: config.server1Url,
      label: 'DPF server1',
      onLog: config.onLog,
    });
  }

  // ── Connection lifecycle ──────────────────────────────────────────────

  async connect(): Promise<void> {
    this.setState('connecting');
    try {
      // Side-channels first — these carry small diagnostic frames, so
      // they're useful even before the PIR client comes up.
      await Promise.all([this.ws0.connect(), this.ws1.connect()]);

      // Fetch server info + catalog from server0 (the primary role)
      // so the Merkle / catalog accessors can return cached data.
      this.serverInfo = await fetchServerInfoJson(this.ws0);
      this.catalog = await fetchDatabaseCatalog(this.ws0);

      // Construct + wire the WASM client. `onStateChange` replays the
      // native-side transitions; we remap the plain-string payload onto
      // the web `ConnectionState` enum.
      const sdk = requireSdkWasm();
      this.wasmClient = new sdk.WasmDpfClient(
        this.config.server0Url,
        this.config.server1Url,
      );
      this.wasmClient.onStateChange((state: string) => {
        if (
          state === 'connected'
          || state === 'disconnected'
          || state === 'connecting'
          || state === 'reconnecting'
        ) {
          this.setState(state);
        }
      });

      await this.wasmClient.connect();

      // Optionally attest both servers and upgrade to the encrypted
      // channel BEFORE fetching the catalog (so the catalog request
      // itself goes through the channel — first frame cloudflared sees
      // is the handshake, everything after is ciphertext).
      if (this.config.useSecureChannel !== false) {
        await this.attestAndUpgrade();
      }

      // Populate the native-side catalog so subsequent `queryBatchRaw`
      // calls (which go through `query_batch_with_inspector`) have an
      // in-memory catalog to resolve `db_id` against. The side-channel
      // fetch above only populates the TS-side `this.catalog`.
      await this.wasmClient.fetchCatalog();
      this.connected = true;
      // Emit a final `connected` in case the native client's own
      // `onStateChange` fired before we registered the listener or got
      // coalesced out.
      this.setState('connected');
    } catch (e) {
      this.log(`Connect failed: ${(e as Error)?.message ?? e}`, 'error');
      this.teardown();
      this.setState('disconnected', (e as Error)?.message);
      throw e;
    }
  }

  disconnect(): void {
    this.teardown();
    this.setState('disconnected');
  }

  /**
   * `true` iff every piece of the stack is up:
   *   * both side-channel sockets are open,
   *   * the WASM client holds live transport sockets.
   */
  isConnected(): boolean {
    return (
      this.connected
      && this.ws0.isOpen()
      && this.ws1.isOpen()
      && !!this.wasmClient?.isConnected
    );
  }

  /**
   * Used by the residency panel in `web/index.html` to run `REQ_RESIDENCY`
   * across every connected server. Only the side-channel sockets are
   * returned — the WASM client's internal sockets are not addressable
   * from JS.
   */
  getConnectedSockets(): Array<{ label: string; ws: ManagedWebSocket }> {
    const out: Array<{ label: string; ws: ManagedWebSocket }> = [];
    if (this.ws0.isOpen()) {
      out.push({ label: `DPF server0 (${this.config.server0Url})`, ws: this.ws0 });
    }
    if (this.ws1.isOpen()) {
      out.push({ label: `DPF server1 (${this.config.server1Url})`, ws: this.ws1 });
    }
    return out;
  }

  // ── Catalog accessors ─────────────────────────────────────────────────

  getCatalog(): DatabaseCatalog | null {
    return this.catalog;
  }

  getCatalogEntry(dbId: number): DatabaseCatalogEntry | undefined {
    return this.catalog?.databases.find((d) => d.dbId === dbId);
  }

  // ── Merkle accessors (all read cached server info) ────────────────────

  hasMerkle(): boolean {
    const mb = this.serverInfo?.merkle_bucket;
    return !!(mb && mb.index_levels.length > 0);
  }

  hasMerkleForDb(dbId: number): boolean {
    const info = this.getMerkleInfoForDb(dbId);
    return !!(info && info.index_levels.length > 0);
  }

  getMerkleRootHex(): string | undefined {
    return this.serverInfo?.merkle_bucket?.super_root ?? this.serverInfo?.merkle?.root;
  }

  getMerkleRootHexForDb(dbId: number): string | undefined {
    return this.getMerkleInfoForDb(dbId)?.super_root;
  }

  private getMerkleInfoForDb(dbId: number): BucketMerkleInfoJson | undefined {
    // Main DB (db_id = 0) lives at the top level; non-zero DBs are under
    // the `databases` array. Mirrors the legacy `BatchPirClient` lookup.
    if (dbId === 0 && this.serverInfo?.merkle_bucket) {
      return this.serverInfo.merkle_bucket;
    }
    return this.serverInfo?.databases?.find((d) => d.db_id === dbId)?.merkle_bucket;
  }

  // ── Query paths ───────────────────────────────────────────────────────

  /**
   * Full-snapshot batch query. `scriptHashes` is an array of 20-byte
   * HASH160 outputs (as `Uint8Array`). Returns an array of the same
   * length, each slot either a `QueryResult` or `null` ("not found and
   * nothing to verify").
   *
   * The `onProgress` callback fires for step transitions only — the WASM
   * client doesn't yet expose fine-grained per-batch progress, so the
   * step names are coarser than in the pre-Session-3 client. This is an
   * accepted regression.
   */
  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  /**
   * Delta-database batch query. Same shape as `queryBatch` but every
   * non-null result carries `rawChunkData` — the encoded delta payload
   * that `sync-merge.ts::applyDeltaData` consumes to apply changes on
   * top of a cached snapshot.
   */
  async queryDelta(
    scriptHashes: Uint8Array[],
    dbId: number = 1,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  private async queryBatchInternal(
    scriptHashes: Uint8Array[],
    dbId: number,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    onProgress?.('Level 1', 'sending batched INDEX queries');

    const packed = packScriptHashes(scriptHashes);
    const wqrs = await this.wasmClient.queryBatchRaw(packed, dbId);
    onProgress?.('Decode', `translating ${wqrs.length} results`);

    const out: (QueryResult | null)[] = new Array(wqrs.length);
    for (let i = 0; i < wqrs.length; i++) {
      const wqr = wqrs[i];
      const qr = translateWasmResult(wqr);
      this.wasmHandles.set(qr, wqr);
      // The legacy BatchPirClient surfaced pure "not found" queries as
      // `null`. Preserve that contract for callers that do
      // `if (result) found++`. Queries that probed INDEX bins but found
      // no entries still carry verifiable absence-proof state, so we
      // keep the `QueryResult` for those — the UI filters with
      // `r && !r.isWhale && r.indexPbcGroup !== undefined` downstream.
      const hasInspectorState =
        (qr.allIndexBins?.length ?? 0) > 0 || qr.isWhale || qr.entries.length > 0;
      out[i] = hasInspectorState ? qr : null;
    }
    return out;
  }

  /**
   * Batch-verify per-bucket bin Merkle proofs for one or more
   * inspector-populated `QueryResult`s. `dbId` selects which database's
   * Merkle roots to verify against (0 = main, 1+ = delta).
   *
   * Each `QueryResult` is serialised to JSON via the stashed
   * `WasmQueryResult.toJson()` (or, for results that came from
   * elsewhere, via a manual `queryResultToJson` reconstruction) and
   * handed to `WasmDpfClient.verifyMerkleBatch`. The native verifier
   * drives the K-padded sibling-query rounds, parses the tree-tops
   * blob, walks every proof, and returns a `boolean[]` of verdicts.
   */
  async verifyMerkleBatch(
    results: QueryResult[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<boolean[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    onProgress?.('Merkle', `verifying ${results.length} items`);

    const jsonArr: any[] = results.map((r) => {
      const handle = this.wasmHandles.get(r);
      if (handle) return handle.toJson();
      return queryResultToJson(r);
    });

    const verdicts = await this.wasmClient.verifyMerkleBatch(jsonArr, dbId);
    const passed = verdicts.filter(Boolean).length;
    onProgress?.('Merkle', `done (${passed}/${verdicts.length} passed)`);
    return verdicts;
  }

  // ── Internal ──────────────────────────────────────────────────────────

  private teardown(): void {
    this.ws0.disconnect();
    this.ws1.disconnect();
    if (this.wasmClient) {
      // Best-effort async disconnect; `free()` is safe either way.
      this.wasmClient.disconnect().catch(() => { /* swallow */ });
      this.wasmClient.free();
      this.wasmClient = null;
    }
    this.connected = false;
  }

  private setState(state: ConnectionState, message?: string): void {
    this.config.onConnectionStateChange?.(state, message);
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(msg, level);
  }

  /**
   * Attest both servers and, if both report a valid V2 channel pubkey,
   * upgrade both connections to the encrypted channel. Called at the
   * tail of `connect()` when `useSecureChannel` is enabled (default).
   *
   * Failure modes (each leaves `attestation.serverN.state` set to a
   * descriptive value and logs but does NOT throw — the connection
   * stays alive in cleartext mode):
   *   - attest call rejects → state `'mismatch'` for that server
   *   - attest succeeds but `sevStatus !== 'reportDataMatch'` →
   *     state `'mismatch'`
   *   - attest succeeds but server reports all-zero pubkey (legacy
   *     server, no channel support) → state `'plaintext'`
   *   - both servers verified → call `upgradeToSecureChannel`; state
   *     becomes `'verified'` on each (or `'mismatch'` if the upgrade
   *     itself fails)
   */
  private async attestAndUpgrade(): Promise<void> {
    if (!this.wasmClient) return;

    const attestOne = async (idx: 0 | 1): Promise<WasmAttestVerification | null> => {
      try {
        return await this.wasmClient!.attest(idx);
      } catch (e) {
        this.log(
          `attest(server${idx}) failed: ${(e as Error)?.message ?? e}`,
          'error',
        );
        return null;
      }
    };

    // Run sequentially: both attests target the same WasmDpfClient
    // instance and the underlying `&mut self` Rust API serializes them
    // anyway. Using Promise.all here can leave the second future
    // wedged on the borrow when wasm-bindgen's async glue races.
    const att0 = await attestOne(0);
    const att1 = await attestOne(1);

    // Default behaviour: source the ARK fingerprint from WASM
    // (`getAmdTurinArkFingerprint`), which mirrors the Rust constant
    // `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256` and runs a
    // cross-check against `AMD_TURIN_ARK_FINGERPRINT_HEX` on first
    // call. Callers can still pass `null` explicitly to skip the
    // chain check (tests, pre-deploy debugging) or pass a different
    // fingerprint to override (e.g. for a future Milan migration —
    // they'd ship a custom Uint8Array).
    let expectedArkFp: Uint8Array | null;
    if (this.config.expectedArkFingerprint === null) {
      expectedArkFp = null;
    } else if (this.config.expectedArkFingerprint !== undefined) {
      expectedArkFp = this.config.expectedArkFingerprint;
    } else {
      try {
        expectedArkFp = getAmdTurinArkFingerprint();
      } catch (e) {
        // 'info' rather than 'error' because this is a fallback path
        // (skip chain validation) rather than an outright failure —
        // the connection still works, just without ARK pinning.
        this.log(
          `default ARK fingerprint unavailable (WASM not initialised?): ${(e as Error)?.message ?? e}`,
          'info',
        );
        expectedArkFp = null;
      }
    }

    // Strict production policy: VMPL 0, no debug, no migrate-MA, TCB-
    // monotonic. We deliberately do NOT pin MEASUREMENT here even when
    // a per-server pin is configured — the manual measurement check
    // below produces a more granular error message (which pin failed,
    // for which server) than the single-line WASM diagnostic.
    const sdk = requireSdkWasm();
    const policyReqs = new sdk.WasmPolicyRequirements();

    const summarise = (
      idx: 0 | 1,
      att: WasmAttestVerification | null,
    ): ServerAttestation => {
      if (!att) {
        return { state: 'mismatch' };
      }
      const allZero = att.serverStaticPub.every((b) => b === 0);
      const matched = att.sevStatus === 'reportDataMatch';
      const noSev = att.sevStatus === 'noSevHost';
      // For non-SEV hosts (e.g. Hetzner) we still allow the channel —
      // `noSevHost` means the binding can't be hardware-anchored but
      // the inner crypto is otherwise sound. Production `pir2` is on
      // SEV-SNP, so it should be `reportDataMatch`.
      const channelOk = matched || noSev;
      let state: ServerAttestation['state'];
      if (allZero) state = 'plaintext';
      else if (!channelOk) state = 'mismatch';
      else state = 'verified';

      const result: ServerAttestation = {
        state,
        sevStatus: att.sevStatus,
        serverStaticPubHex: att.serverStaticPubHex,
        binarySha256Hex: att.binarySha256Hex,
        gitRev: att.gitRev,
        launchMeasurementHex: att.launchMeasurementHex,
      };

      // Slice D.3+: AMD VCEK chain + policy validation. Only attempt
      // when the V2 binding already passed (otherwise the report is
      // suspect anyway), the server bundled a chain, AND we have an
      // operator-pinned ARK fingerprint to anchor trust.
      //
      // `verifyFull` runs:
      //   1. ARK fingerprint match + ARK→ASK→VCEK chain (RSA-PSS)
      //   2. SEV-SNP report ECDSA-P384 signature against VCEK
      //   3. Policy: VMPL ≤ max, no debug, no migrate-MA, TCB
      //      monotonicity + optional minimum / measurement / id pins
      // — and throws on the FIRST failure. Error message starts with
      // "chain:", "report-sig:" or "policy:" so the operator can
      // tell which step rejected.
      if (state === 'verified' && matched && att.hasVcekChain) {
        if (expectedArkFp) {
          try {
            att.verifyFull(expectedArkFp, policyReqs);
            result.state = 'verified-vcek';
            result.vcekChain = 'pass';
          } catch (e) {
            result.vcekChain = 'fail';
            result.vcekChainError = (e as Error)?.message ?? String(e);
            this.log(
              `verifyFull(server${idx}) failed: ${result.vcekChainError}`,
              'error',
            );
            // Demote to 'mismatch' on any failure — the operator's
            // pinning explicitly demanded chain + policy validation
            // and it didn't pass. Treat as a strong negative signal.
            result.state = 'mismatch';
          }
        } else {
          result.vcekChain = 'skipped';
        }
      } else if (state === 'verified' && matched && !att.hasVcekChain) {
        result.vcekChain = 'skipped';
      }

      // Slice 3 build-time pin enforcement. Runs AFTER chain
      // validation so the pin only kicks in when the report is
      // already internally consistent. A mismatch demotes state to
      // 'mismatch' regardless of how clean the chain validation was —
      // the operator pinned a specific (UKI, binary), and the server
      // is reporting something else.
      const pin =
        idx === 0 ? this.config.expectedServer0Pin : this.config.expectedServer1Pin;
      if (pin) {
        // Only enforce when state is verified-ish AND the report is
        // internally consistent. Skipping pin check on a 'mismatch'
        // would be misleading anyway — the channel is already broken.
        const stateOk = result.state === 'verified' || result.state === 'verified-vcek';
        if (stateOk) {
          if (
            pin.measurementHex &&
            att.launchMeasurementHex &&
            pin.measurementHex.toLowerCase() !== att.launchMeasurementHex.toLowerCase()
          ) {
            result.pinStatus = 'measurement-mismatch';
            result.pinError = `MEASUREMENT pin mismatch — expected ${pin.measurementHex.slice(0, 16)}…, got ${att.launchMeasurementHex.slice(0, 16)}…`;
            result.state = 'mismatch';
            this.log(`server${idx}: ${result.pinError}`, 'error');
          } else if (
            pin.binarySha256Hex &&
            att.binarySha256Hex &&
            pin.binarySha256Hex.toLowerCase() !== att.binarySha256Hex.toLowerCase()
          ) {
            result.pinStatus = 'binary-mismatch';
            result.pinError = `binary_sha256 pin mismatch — expected ${pin.binarySha256Hex.slice(0, 16)}…, got ${att.binarySha256Hex.slice(0, 16)}…`;
            result.state = 'mismatch';
            this.log(`server${idx}: ${result.pinError}`, 'error');
          } else {
            result.pinStatus = 'match';
          }
        }
      } else {
        result.pinStatus = 'no-pin';
      }
      return result;
    };

    const sum0 = summarise(0, att0);
    const sum1 = summarise(1, att1);
    this.attestation.server0 = sum0;
    this.attestation.server1 = sum1;
    this.config.onAttestation?.(0, sum0);
    this.config.onAttestation?.(1, sum1);

    // Only upgrade if BOTH servers cleared the channel-OK gate. A
    // half-encrypted setup gives no privacy benefit (the all-cleartext
    // server still leaks queries to cloudflared) and complicates UI.
    // Either 'verified' (V2 binding only) or 'verified-vcek' (full
    // AMD chain) qualifies — both prove the channel pubkey is bound
    // to a SEV-SNP report; the V2 binding is the gate that matters
    // for the channel itself.
    const channelReady = (s: ServerAttestation['state']) =>
      s === 'verified' || s === 'verified-vcek';
    if (channelReady(sum0.state) && channelReady(sum1.state) && att0 && att1) {
      try {
        await this.wasmClient.upgradeToSecureChannel(
          att0.serverStaticPub,
          att1.serverStaticPub,
        );
        this.log('Upgraded to encrypted channel (cloudflared sees only ciphertext)', 'success');
      } catch (e) {
        this.log(`upgradeToSecureChannel failed: ${(e as Error)?.message ?? e}`, 'error');
        // Mark both as mismatch since the channel didn't actually come
        // up despite the per-server attest being clean.
        this.attestation.server0 = { ...sum0, state: 'mismatch' };
        this.attestation.server1 = { ...sum1, state: 'mismatch' };
        this.config.onAttestation?.(0, this.attestation.server0);
        this.config.onAttestation?.(1, this.attestation.server1);
      }
    } else {
      this.log(
        `Channel left in cleartext (server0=${sum0.state}, server1=${sum1.state})`,
        'info',
      );
    }
    // Free the WasmAttestVerification handles to release the WASM-side
    // copies. We've already extracted the JS-side fields we need.
    att0?.free();
    att1?.free();
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Pack an `N`-entry `Uint8Array[]` of 20-byte HASH160 outputs into a
 * single `Uint8Array(20 * N)`, as expected by `WasmDpfClient.queryBatchRaw`.
 */
function packScriptHashes(hashes: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(hashes.length * 20);
  for (let i = 0; i < hashes.length; i++) {
    if (hashes[i].length !== 20) {
      throw new Error(
        `scriptHash[${i}] must be 20 bytes, got ${hashes[i].length}`,
      );
    }
    out.set(hashes[i], i * 20);
  }
  return out;
}

/**
 * Translate a `WasmQueryResult` (opaque handle from
 * `WasmDpfClient.queryBatchRaw`) into the legacy `QueryResult` shape.
 *
 * The two shapes differ in:
 *   * `entries`: WASM uses `{txid: hex, vout, amountSats}`; web uses
 *     `{txid: Uint8Array, vout, amount: bigint}` (hash.ts-style).
 *   * Inspector fields: WASM keeps all probed bins in `indexBins()` +
 *     `chunkBins()` with a separate `matchedIndexIdx()`; web keeps
 *     `indexPbcGroup`/`indexBinIndex`/`indexBinContent` for the matched
 *     bin plus an `allIndexBins` array for absence proofs. We derive
 *     both by indexing `indexBins[matchedIdx]`.
 *   * `chunkBinContents`: WASM hex, web raw bytes.
 */
function translateWasmResult(wqr: WasmQueryResult): QueryResult {
  const entries: UtxoEntry[] = [];
  for (let i = 0; i < wqr.entryCount; i++) {
    const e = wqr.getEntry(i);
    if (!e) continue;
    entries.push({
      txid: hexToBytes(e.txid),
      vout: Number(e.vout),
      amount: BigInt(e.amountSats ?? e.amount ?? 0),
    });
  }

  type WireBin = { pbcGroup: number; binIndex: number; binContent: string };
  const indexBinsRaw = (wqr.indexBins() as WireBin[]) ?? [];
  const chunkBinsRaw = (wqr.chunkBins() as WireBin[]) ?? [];
  const matchedIdxRaw = wqr.matchedIndexIdx();
  const matchedIdx = typeof matchedIdxRaw === 'number' ? matchedIdxRaw : undefined;
  const rawChunkData = wqr.rawChunkData();

  const allIndexBins = indexBinsRaw.map((b) => ({
    pbcGroup: b.pbcGroup,
    binIndex: b.binIndex,
    binContent: hexToBytes(b.binContent),
  }));
  // Primary match: prefer the explicitly matched bin, else fall back to
  // the first probed bin (legacy behaviour for not-found queries so
  // `indexPbcGroup !== undefined` still filters "verifiable" truthy).
  const primary = matchedIdx !== undefined ? allIndexBins[matchedIdx] : allIndexBins[0];

  return {
    entries,
    totalSats: wqr.totalBalance,
    // Display-only legacy fields — not read by any remaining consumer
    // for DPF results. Kept in the shape for type compatibility.
    startChunkId: 0,
    numChunks: chunkBinsRaw.length,
    numRounds: 0,
    isWhale: wqr.isWhale,
    merkleVerified: wqr.merkleVerified,
    rawChunkData: rawChunkData instanceof Uint8Array ? rawChunkData : undefined,
    indexPbcGroup: primary?.pbcGroup,
    indexBinIndex: primary?.binIndex,
    indexBinContent: primary?.binContent,
    allIndexBins: allIndexBins.length > 0 ? allIndexBins : undefined,
    chunkPbcGroups: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.pbcGroup) : undefined,
    chunkBinIndices: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.binIndex) : undefined,
    chunkBinContents:
      chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => hexToBytes(b.binContent)) : undefined,
  };
}

/**
 * Rebuild a `WasmQueryResult`-compatible JSON object from a hand-crafted
 * `QueryResult` (one that doesn't have a stashed WASM handle, e.g.
 * persisted through localStorage). Matches the field-name contract that
 * `parse_query_result_json` accepts in `pir-sdk-wasm`.
 */
function queryResultToJson(r: QueryResult): any {
  const entries = r.entries.map((e) => ({
    txid: bytesToHex(e.txid),
    vout: e.vout,
    // `parse_query_result_json` reads via `as_u64()`, so we must pass a
    // number (not a bigint) in JSON. The hex / decimal representation
    // doesn't matter — `JSON.stringify` handles bigints by conversion.
    amountSats: Number(e.amount),
  }));
  const obj: any = {
    entries,
    isWhale: r.isWhale,
    merkleVerified: r.merkleVerified ?? true,
  };
  if (r.allIndexBins && r.allIndexBins.length > 0) {
    obj.indexBins = r.allIndexBins.map((b) => ({
      pbcGroup: b.pbcGroup,
      binIndex: b.binIndex,
      binContent: bytesToHex(b.binContent),
    }));
    // Derive the matched-idx by scanning for the bin whose
    // (pbcGroup, binIndex) matches the primary-match fields. Only emit
    // when the result is an actual match — a not-found with
    // `indexPbcGroup === allIndexBins[0].pbcGroup` would otherwise be
    // miscategorised as a match.
    if (r.entries.length > 0 && r.indexPbcGroup !== undefined) {
      const idx = r.allIndexBins.findIndex(
        (b) => b.pbcGroup === r.indexPbcGroup && b.binIndex === r.indexBinIndex,
      );
      if (idx >= 0) obj.matchedIndexIdx = idx;
    }
  }
  if (r.chunkPbcGroups && r.chunkPbcGroups.length > 0) {
    obj.chunkBins = r.chunkPbcGroups.map((grp, i) => ({
      pbcGroup: grp,
      binIndex: r.chunkBinIndices?.[i] ?? 0,
      binContent: bytesToHex(r.chunkBinContents?.[i] ?? new Uint8Array()),
    }));
  }
  if (r.rawChunkData) {
    obj.rawChunkData = bytesToHex(r.rawChunkData);
  }
  return obj;
}
