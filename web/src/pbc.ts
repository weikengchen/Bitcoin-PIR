/**
 * PBC (Probabilistic Batch Code) cuckoo placement utilities.
 *
 * Shared across all three PIR protocol clients (DPF, HarmonyPIR, OnionPIR).
 * These are pure functions with no protocol-specific dependencies.
 */

import { sdkPlanRounds } from './sdk-bridge.js';

/**
 * Attempt to place item `qi` into `groups` using cuckoo hashing with eviction.
 * Returns true if placed, false if maxKicks exceeded.
 */
export function cuckooPlace(
  candGroups: number[][],
  groups: (number | null)[],
  qi: number,
  maxKicks: number,
  numHashes: number,
): boolean {
  const cands = candGroups[qi];

  // Try direct placement
  for (const c of cands) {
    if (groups[c] === null) {
      groups[c] = qi;
      return true;
    }
  }

  // Eviction loop
  let currentQi = qi;
  let currentGroup = candGroups[currentQi][0];

  for (let kick = 0; kick < maxKicks; kick++) {
    const evictedQi = groups[currentGroup]!;
    groups[currentGroup] = currentQi;

    for (let offset = 0; offset < numHashes; offset++) {
      const c = candGroups[evictedQi][(kick + offset) % numHashes];
      if (c === currentGroup) continue;
      if (groups[c] === null) {
        groups[c] = evictedQi;
        return true;
      }
    }

    let nextGroup = candGroups[evictedQi][0];
    for (let offset = 0; offset < numHashes; offset++) {
      const c = candGroups[evictedQi][(kick + offset) % numHashes];
      if (c !== currentGroup) {
        nextGroup = c;
        break;
      }
    }
    currentQi = evictedQi;
    currentGroup = nextGroup;
  }

  return false;
}

/**
 * Plan multi-round PBC placement for items with candidate groups.
 * Returns rounds, each round is an array of [itemIndex, groupId] pairs.
 *
 * WASM-first dispatch: when `pir-sdk-wasm` is loaded the Rust-native
 * `pir_core::pbc::pbc_plan_rounds` runs with the TS-hardcoded `maxKicks = 500`;
 * the pure-TS implementation below is the fallback. The WASM path cannot
 * invoke the `onError` callback — the underlying Rust function returns
 * silently — so the "could not place any remaining items" diagnostic only
 * fires when the WASM module failed to load.
 */
export function planRounds(
  itemGroups: number[][],
  numGroups: number,
  numHashes: number,
  onError?: (msg: string) => void,
): [number, number][][] {
  // Try WASM first; preserve the TS fallback so `onError` diagnostics still
  // surface when the WASM module failed to load.
  const viaSdk = sdkPlanRounds(itemGroups, numGroups, numHashes);
  if (viaSdk !== undefined) return viaSdk;

  let remaining = itemGroups.map((_, i) => i);
  const rounds: [number, number][][] = [];

  while (remaining.length > 0) {
    const candGroups = remaining.map(i => itemGroups[i]);
    const groupOwner: (number | null)[] = new Array(numGroups).fill(null);
    const placedLocal: number[] = [];

    for (let li = 0; li < candGroups.length; li++) {
      if (placedLocal.length >= numGroups) break;
      const savedGroups = [...groupOwner];
      if (cuckooPlace(candGroups, groupOwner, li, 500, numHashes)) {
        placedLocal.push(li);
      } else {
        for (let b = 0; b < numGroups; b++) groupOwner[b] = savedGroups[b];
      }
    }

    const roundEntries: [number, number][] = [];
    for (let b = 0; b < numGroups; b++) {
      const localIdx = groupOwner[b];
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
