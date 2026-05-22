/**
 * OnionPIR sharding — TypeScript helper tests.
 *
 * `validateShardRangeCoverage` is the tiling check used by
 * `OnionPirWebClient.assertShardCoverage`: explicit shard group ranges must
 * tile `0..K` / `0..K_CHUNK` exactly so the client can slice a positional
 * batch by range and concatenate per-shard responses into a complete result.
 * Mirrors the Rust `validate_shard_coverage` unit test.
 */
import { describe, it, expect } from 'vitest';
import { validateShardRangeCoverage } from '../onionpir_client.js';

describe('validateShardRangeCoverage', () => {
  it('accepts ranges that tile 0..total (any order)', () => {
    expect(validateShardRangeCoverage([[0, 25], [25, 50], [50, 75]], 75)).toBeNull();
    expect(validateShardRangeCoverage([[0, 75]], 75)).toBeNull();
    // Sorted internally → order-independent.
    expect(validateShardRangeCoverage([[50, 75], [0, 25], [25, 50]], 75)).toBeNull();
    // Uneven (K_CHUNK=80 across 3 shards).
    expect(validateShardRangeCoverage([[0, 27], [27, 54], [54, 80]], 80)).toBeNull();
  });

  it('rejects a gap', () => {
    expect(validateShardRangeCoverage([[0, 24], [25, 75]], 75)).not.toBeNull();
  });

  it('rejects an overlap', () => {
    expect(validateShardRangeCoverage([[0, 40], [25, 75]], 75)).not.toBeNull();
  });

  it('rejects incomplete coverage', () => {
    expect(validateShardRangeCoverage([[0, 25], [25, 50]], 75)).toMatch(/cover only/);
  });

  it('rejects an empty range', () => {
    expect(validateShardRangeCoverage([[0, 0], [0, 75]], 75)).toMatch(/empty/);
  });

  it('rejects out-of-bounds', () => {
    expect(validateShardRangeCoverage([[0, 80]], 75)).not.toBeNull();
  });
});
