#!/usr/bin/env node
/**
 * Extract "example SPKs present in a delta database" and update
 * web/src/example_spks.json with a per-delta list.
 *
 * Usage:
 *   node scripts/extract_delta_examples.js <start_height> <end_height>
 *   node scripts/extract_delta_examples.js 940611 944000
 *
 * What it does:
 *   1. Loads the existing web/src/example_spks.json. Handles both the
 *      legacy flat-array shape and the new per-DB object shape.
 *   2. Computes hash160 = ripemd160(sha256(spk_bytes)) for each entry in
 *      the "main" list (the 1000 example scriptPubKeys).
 *   3. Streams /Volumes/Bitcoin/data/intermediate/delta_index_<A>_<B>.bin
 *      — a file of 25-byte records whose first 20 bytes are each delta
 *      scripthash — into a Set.
 *   4. Emits the intersection: scriptPubKeys whose scripthash is present in
 *      both the main UTXO set and the delta. These addresses will show
 *      visible delta results (spent or new UTXOs) in the web frontend's
 *      sync flow after the delta is applied.
 *   5. Writes the result back to web/src/example_spks.json under the key
 *      `delta_<A>_<B>`.
 *
 * Re-run this whenever a new delta database is built.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Args ────────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
if (argv.length !== 2) {
  console.error('Usage: node scripts/extract_delta_examples.js <start_height> <end_height>');
  process.exit(1);
}
const [startStr, endStr] = argv;
const startH = parseInt(startStr, 10);
const endH = parseInt(endStr, 10);
if (!Number.isFinite(startH) || !Number.isFinite(endH) || startH >= endH) {
  console.error(`Invalid height range: ${startStr}..${endStr}`);
  process.exit(1);
}

const deltaKey = `delta_${startH}_${endH}`;
const deltaIndexPath = `/Volumes/Bitcoin/data/intermediate/delta_index_${startH}_${endH}.bin`;
const examplesPath = path.join(__dirname, '..', 'web', 'src', 'example_spks.json');

// ─── Hash160 (must match web/src/hash.ts::scriptHash) ────────────────────────
function hash160(hex) {
  const buf = Buffer.from(hex, 'hex');
  const sha = crypto.createHash('sha256').update(buf).digest();
  return crypto.createHash('ripemd160').update(sha).digest().toString('hex');
}

// ─── Load existing example_spks.json (handle both old flat + new dict) ──────
const raw = JSON.parse(fs.readFileSync(examplesPath, 'utf8'));
let examples;
if (Array.isArray(raw)) {
  // Legacy format: flat array → wrap under "main".
  examples = { main: raw };
  console.log(`[info] Migrating example_spks.json from flat-array to per-DB format.`);
} else if (raw && typeof raw === 'object' && Array.isArray(raw.main)) {
  examples = raw;
} else {
  console.error('example_spks.json has unexpected structure; expected array or {main: [...]}');
  process.exit(1);
}
console.log(`[info] Loaded ${examples.main.length} main example SPKs`);

// ─── Read delta index file ──────────────────────────────────────────────────
if (!fs.existsSync(deltaIndexPath)) {
  console.error(`[error] Delta index not found: ${deltaIndexPath}`);
  console.error('        Run scripts/build_delta.sh for this height range first.');
  process.exit(1);
}
const idxBuf = fs.readFileSync(deltaIndexPath);
if (idxBuf.length % 25 !== 0) {
  console.error(`[error] Delta index size ${idxBuf.length} is not a multiple of 25 bytes`);
  process.exit(1);
}
const numRecords = idxBuf.length / 25;
console.log(`[info] Delta index: ${numRecords.toLocaleString()} scripthashes (${idxBuf.length.toLocaleString()} bytes)`);

const deltaHashes = new Set();
for (let off = 0; off < idxBuf.length; off += 25) {
  deltaHashes.add(idxBuf.slice(off, off + 20).toString('hex'));
}

// ─── Compute intersection ────────────────────────────────────────────────────
const intersection = [];
for (const spk of examples.main) {
  if (deltaHashes.has(hash160(spk))) {
    intersection.push(spk);
  }
}
console.log(`[info] Intersection: ${intersection.length} example SPKs present in both main and ${deltaKey}`);
if (intersection.length === 0) {
  console.error('[warn] Zero intersection — the delta has no entries matching any of the example SPKs.');
}

// ─── Write back ─────────────────────────────────────────────────────────────
examples[deltaKey] = intersection;

// Canonical key order: main first, then deltas sorted by start height.
const orderedKeys = ['main'];
const deltaKeys = Object.keys(examples).filter(k => k.startsWith('delta_'))
  .sort((a, b) => {
    const [, aStart] = a.split('_').map(Number);
    const [, bStart] = b.split('_').map(Number);
    return aStart - bStart;
  });
orderedKeys.push(...deltaKeys);
const ordered = {};
for (const k of orderedKeys) if (examples[k]) ordered[k] = examples[k];

fs.writeFileSync(examplesPath, JSON.stringify(ordered, null, 2) + '\n');
console.log(`[info] Updated ${examplesPath}`);
console.log(`[info] Keys now: ${Object.keys(ordered).join(', ')}`);
