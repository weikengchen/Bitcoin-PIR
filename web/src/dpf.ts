/**
 * DPF wrapper for libdpf (Batch PIR uses domain 2^20)
 */

import { Dpf } from 'libdpf';
import { DPF_N } from './constants.js';

export interface DpfKeyPair {
  key0: Uint8Array;
  key1: Uint8Array;
}

const dpf = Dpf.withDefaultKey();

/**
 * Generate DPF keys for a specific index in the 2^20 domain.
 * Returns (key0_for_server0, key1_for_server1).
 */
export async function genDpfKeys(index: number): Promise<DpfKeyPair> {
  const [k0, k1] = await dpf.gen(BigInt(index), DPF_N);
  return {
    key0: k0.toBytes(),
    key1: k1.toBytes(),
  };
}
