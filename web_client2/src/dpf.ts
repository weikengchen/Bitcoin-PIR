/**
 * DPF wrapper for libdpf
 *
 * Provides a simplified interface to the libdpf library
 */

import { Dpf, DpfKey } from 'libdpf';

/**
 * DPF key pair
 */
export interface DpfKeyPair {
  key1: Uint8Array;
  key2: Uint8Array;
}

/**
 * DPF wrapper class
 */
export class DpfWrapper {
  private dpf: Dpf;

  constructor() {
    this.dpf = Dpf.withDefaultKey();
  }

  /**
   * Generate DPF keys for a specific index (async)
   */
  async genKeys(index: number, n: number = 24): Promise<DpfKeyPair> {
    // Generate two keys that allow querying a specific index
    const [key0, key1] = await this.dpf.gen(BigInt(index), n);
    
    return {
      key1: key0.toBytes(),
      key2: key1.toBytes(),
    };
  }

  /**
   * Evaluate DPF key to get the result bitmap
   * Note: This is typically done on the server side
   */
  eval(key: Uint8Array, n: number = 24): Uint8Array {
    // This would evaluate the DPF key to produce the bitmap
    // In practice, we send the key to the server which evaluates it
    throw new Error('DPF evaluation is done server-side. Use sendKeysToServer() instead.');
  }
}

/**
 * Create a DPF instance
 */
export function createDpf(): DpfWrapper {
  return new DpfWrapper();
}