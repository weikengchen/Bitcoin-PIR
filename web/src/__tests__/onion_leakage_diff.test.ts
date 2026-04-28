/**
 * Phase 2.3 step D: live cross-language leakage-profile diff.
 *
 * Loads the JSON corpus produced by the Rust `onion_leakage_dump`
 * example, drives the same script-hashes through the standalone
 * TypeScript `OnionPirWebClient`, and asserts the two profiles are
 * structurally equal — round-by-round, byte-by-byte.
 *
 * If this passes, the two implementations leak the same shape on the
 * wire for the corpus inputs. If it fails, the diff output points at
 * exactly which round (and which field) drifted.
 *
 * # Running
 *
 * Skip-by-default: this test only runs when `RUN_LIVE_DIFF=1` is set,
 * because it (a) opens a real WebSocket to a live PIR server and (b)
 * runs the OnionPIR FHE setup, which takes ~10-30 s per query.
 *
 * ```bash
 * # Regenerate the Rust fixture first (idempotent against a stable server):
 * cargo run --release -p pir-sdk-client --features onion --example onion_leakage_dump -- \
 *     --output web/test/fixtures/onion_corpus.json
 *
 * # Then run the live diff:
 * RUN_LIVE_DIFF=1 cd web && npx vitest run src/__tests__/onion_leakage_diff.test.ts
 * ```
 *
 * # Environment polyfills
 *
 * vitest runs in node, which on Node 18 lacks `WebSocket`. We polyfill
 * `globalThis.WebSocket` with the `ws` package, and load the
 * Emscripten OnionPIR module via CommonJS (`module.exports`) before
 * importing `OnionPirWebClient` so `(globalThis as any).createOnionPirModule`
 * is set when the client first asks for it.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

import {
  BufferingLeakageRecorder,
  type LeakageProfile,
  leakageProfilesEqual,
  roundProfilesEqual,
} from '../leakage.js';

// `__dirname` in ESM context — vitest runs as ESM by default.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const require = createRequire(import.meta.url);

const FIXTURE_PATH = resolve(__dirname, '../../test/fixtures/onion_corpus.json');
const WASM_JS_PATH = resolve(__dirname, '../../public/wasm/onionpir_client.js');

const RUN_LIVE = process.env.RUN_LIVE_DIFF === '1';

interface CorpusFile {
  server_url: string;
  queries: Array<{ script_hash_hex: string; profile: LeakageProfile }>;
}

function loadCorpus(): CorpusFile {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8')) as CorpusFile;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length !== 40) throw new Error(`expected 40 hex chars, got ${hex.length}`);
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const test = RUN_LIVE ? it : it.skip;

describe('OnionPIR cross-language leakage diff (Phase 2.3 step D)', () => {
  // Polyfills set up once for the whole describe block.
  beforeAll(async () => {
    if (!RUN_LIVE) return;

    // (1) WebSocket polyfill — Node 18 has no global WebSocket. The
    //     `ws` package's WebSocket exposes the same `binaryType`,
    //     event handlers, and `send` API the TS client uses.
    const wsModule = await import('ws');
    (globalThis as unknown as { WebSocket: unknown }).WebSocket = wsModule.WebSocket;

    // (2) OnionPIR WASM factory — Emscripten module supports node via
    //     `fs.readFileSync(...)` for the .wasm load. The TS client
    //     looks for `globalThis.createOnionPirModule`, so install it.
    const factory = require(WASM_JS_PATH);
    (globalThis as unknown as { createOnionPirModule: unknown }).createOnionPirModule = factory;
  });

  test('two not-found queries: TS profiles match the Rust corpus byte-for-byte', async () => {
    const corpus = loadCorpus();
    expect(corpus.queries.length).toBeGreaterThanOrEqual(2);

    // Lazy-import the client AFTER polyfills are installed — top-level
    // import would run the module's `import './ws'` etc. before
    // `globalThis.WebSocket` is set, breaking any module-init code that
    // captured the global early. (None today, but defensive.)
    const { OnionPirWebClient } = await import('../onionpir_client.js');

    const tsProfiles: LeakageProfile[] = [];
    for (const q of corpus.queries) {
      const sh = hexToBytes(q.script_hash_hex);
      const recorder = new BufferingLeakageRecorder();
      const client = new OnionPirWebClient({
        serverUrl: corpus.server_url,
        onLog: () => { /* swallow logs */ },
      });
      client.setLeakageRecorder(recorder);

      try {
        await client.connect();
        // queryBatch takes pre-computed scripthashes as Uint8Array,
        // so we feed our 20-byte fixture hash directly — no address
        // parsing or override hook needed.
        const results = await client.queryBatch([sh]);
        // Rust `query_batch` bundles Merkle verification; TS exposes it
        // as a separate `verifyMerkleBatch` call (production UI chains
        // them — see web/index.html). Chain it here so the captured
        // profile shape matches the Rust corpus.
        await client.verifyMerkleBatch(results);
      } finally {
        client.disconnect();
      }

      tsProfiles.push(recorder.takeProfile('onion'));
    }

    // Compare TS profile against the Rust corpus, query by query.
    expect(tsProfiles.length).toBe(corpus.queries.length);
    for (let i = 0; i < tsProfiles.length; i++) {
      const rustP = corpus.queries[i].profile;
      const tsP = tsProfiles[i];
      const equal = leakageProfilesEqual(rustP, tsP);
      if (!equal) {
        const rustKinds = rustP.rounds.map(
          (r) => r.kind + ('level' in r ? `:${r.level}` : ''),
        );
        const tsKinds = tsP.rounds.map(
          (r) => r.kind + ('level' in r ? `:${r.level}` : ''),
        );
        console.error(`query[${i}] rust kinds: ${rustKinds.join(', ')}`);
        console.error(`query[${i}]   ts kinds: ${tsKinds.join(', ')}`);
        // Build a focused diff to pinpoint the first divergent round.
        for (let r = 0; r < Math.min(rustP.rounds.length, tsP.rounds.length); r++) {
          if (!roundProfilesEqual(rustP.rounds[r], tsP.rounds[r])) {
            console.error(
              `query[${i}] round[${r}]: rust=${JSON.stringify(rustP.rounds[r])}` +
                ` ts=${JSON.stringify(tsP.rounds[r])}`,
            );
          }
        }
        if (rustP.rounds.length !== tsP.rounds.length) {
          console.error(
            `query[${i}] round counts differ: rust=${rustP.rounds.length} ts=${tsP.rounds.length}`,
          );
        }
      }
      expect(equal).toBe(true);
    }
  }, /* 5-minute timeout — FHE setup + 2 queries against a real server. */ 5 * 60 * 1000);

  // Skip-by-default skeleton always present so CI shows a clear "skipped"
  // line rather than silently dropping the test.
  if (!RUN_LIVE) {
    it.skip('LIVE diff (set RUN_LIVE_DIFF=1 to run)', () => {
      // body intentionally empty
    });
  }
});
