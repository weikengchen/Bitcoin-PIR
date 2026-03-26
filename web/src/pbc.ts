/**
 * PBC (Probabilistic Batch Code) cuckoo placement utilities.
 *
 * Shared across all three PIR protocol clients (DPF, HarmonyPIR, OnionPIR).
 * These are pure functions with no protocol-specific dependencies.
 */

/**
 * Attempt to place item `qi` into `buckets` using cuckoo hashing with eviction.
 * Returns true if placed, false if maxKicks exceeded.
 */
export function cuckooPlace(
  candBuckets: number[][],
  buckets: (number | null)[],
  qi: number,
  maxKicks: number,
  numHashes: number,
): boolean {
  const cands = candBuckets[qi];

  // Try direct placement
  for (const c of cands) {
    if (buckets[c] === null) {
      buckets[c] = qi;
      return true;
    }
  }

  // Eviction loop
  let currentQi = qi;
  let currentBucket = candBuckets[currentQi][0];

  for (let kick = 0; kick < maxKicks; kick++) {
    const evictedQi = buckets[currentBucket]!;
    buckets[currentBucket] = currentQi;

    for (let offset = 0; offset < numHashes; offset++) {
      const c = candBuckets[evictedQi][(kick + offset) % numHashes];
      if (c === currentBucket) continue;
      if (buckets[c] === null) {
        buckets[c] = evictedQi;
        return true;
      }
    }

    let nextBucket = candBuckets[evictedQi][0];
    for (let offset = 0; offset < numHashes; offset++) {
      const c = candBuckets[evictedQi][(kick + offset) % numHashes];
      if (c !== currentBucket) {
        nextBucket = c;
        break;
      }
    }
    currentQi = evictedQi;
    currentBucket = nextBucket;
  }

  return false;
}

/**
 * Plan multi-round PBC placement for items with candidate buckets.
 * Returns rounds, each round is an array of [itemIndex, bucketId] pairs.
 */
export function planRounds(
  itemBuckets: number[][],
  numBuckets: number,
  numHashes: number,
  onError?: (msg: string) => void,
): [number, number][][] {
  let remaining = itemBuckets.map((_, i) => i);
  const rounds: [number, number][][] = [];

  while (remaining.length > 0) {
    const candBuckets = remaining.map(i => itemBuckets[i]);
    const bucketOwner: (number | null)[] = new Array(numBuckets).fill(null);
    const placedLocal: number[] = [];

    for (let li = 0; li < candBuckets.length; li++) {
      if (placedLocal.length >= numBuckets) break;
      const savedBuckets = [...bucketOwner];
      if (cuckooPlace(candBuckets, bucketOwner, li, 500, numHashes)) {
        placedLocal.push(li);
      } else {
        for (let b = 0; b < numBuckets; b++) bucketOwner[b] = savedBuckets[b];
      }
    }

    const roundEntries: [number, number][] = [];
    for (let b = 0; b < numBuckets; b++) {
      const localIdx = bucketOwner[b];
      if (localIdx !== null) {
        roundEntries.push([remaining[localIdx], b]);
      }
    }

    if (roundEntries.length === 0) {
      onError?.(`Could not place any items, ${remaining.length} remaining`);
      break;
    }

    const placedOrigIdx = new Set(placedLocal.map(li => remaining[li]));
    remaining = remaining.filter(i => !placedOrigIdx.has(i));
    rounds.push(roundEntries);
  }

  return rounds;
}
