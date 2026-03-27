package com.bitcoinpir.placement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * PBC (Probabilistic Batch Codes) cuckoo placement for round planning.
 * Ports planRounds / cuckooPlace from web/src/pbc.ts.
 *
 * Each query has NUM_HASHES candidate buckets. We pack as many queries as
 * possible into each round (one query per bucket), using cuckoo-style
 * eviction to maximize utilization.
 */
public final class PbcPlanner {
    private PbcPlanner() {}

    private static final int MAX_KICKS = 500;

    /**
     * Plan query rounds for batch PIR.
     *
     * @param itemBuckets  itemBuckets[i] = candidate bucket indices for item i
     * @param numBuckets   total number of buckets (K or K_CHUNK)
     * @return list of rounds; each round is a list of [itemIndex, bucketId] pairs
     */
    public static List<int[][]> planRounds(int[][] itemBuckets, int numBuckets) {
        List<Integer> remaining = new ArrayList<>();
        for (int i = 0; i < itemBuckets.length; i++) {
            remaining.add(i);
        }

        List<int[][]> rounds = new ArrayList<>();

        while (!remaining.isEmpty()) {
            int[] bucketOwner = new int[numBuckets];
            Arrays.fill(bucketOwner, -1);

            List<Integer> placedLocal = new ArrayList<>();
            int[][] candBuckets = new int[remaining.size()][];
            for (int li = 0; li < remaining.size(); li++) {
                candBuckets[li] = itemBuckets[remaining.get(li)];
            }

            for (int li = 0; li < candBuckets.length; li++) {
                if (placedLocal.size() >= numBuckets) break;

                int[] saved = Arrays.copyOf(bucketOwner, numBuckets);
                if (cuckooPlace(candBuckets, bucketOwner, li, numBuckets)) {
                    placedLocal.add(li);
                } else {
                    System.arraycopy(saved, 0, bucketOwner, 0, numBuckets);
                }
            }

            // Build round entries
            List<int[]> roundEntries = new ArrayList<>();
            for (int b = 0; b < numBuckets; b++) {
                if (bucketOwner[b] >= 0) {
                    int localIdx = bucketOwner[b];
                    roundEntries.add(new int[]{remaining.get(localIdx), b});
                }
            }

            if (roundEntries.isEmpty()) {
                // Could not place any items — give up to avoid infinite loop
                break;
            }

            // Remove placed items from remaining
            Set<Integer> placedOrigIdx = new HashSet<>();
            for (int li : placedLocal) {
                placedOrigIdx.add(remaining.get(li));
            }
            remaining.removeIf(placedOrigIdx::contains);

            rounds.add(roundEntries.toArray(new int[0][]));
        }

        return rounds;
    }

    /**
     * Try to place item {@code qi} into the bucket assignment, using cuckoo eviction.
     *
     * @param candBuckets  candidate buckets for all local items
     * @param buckets      current assignment (bucket → local item index, -1 = empty)
     * @param qi           local item index to place
     * @param numBuckets   total number of buckets
     * @return true if placed successfully
     */
    private static boolean cuckooPlace(int[][] candBuckets, int[] buckets, int qi, int numBuckets) {
        int current = qi;

        for (int kick = 0; kick < MAX_KICKS; kick++) {
            int[] cands = candBuckets[current];

            // Try to find an empty bucket
            for (int bucket : cands) {
                if (buckets[bucket] < 0) {
                    buckets[bucket] = current;
                    return true;
                }
            }

            // Evict a random occupant from one of our candidate buckets
            int evictBucket = cands[kick % cands.length];
            int evicted = buckets[evictBucket];
            buckets[evictBucket] = current;
            current = evicted;
        }

        return false;
    }
}
