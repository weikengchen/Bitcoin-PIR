/**
 * Simple Binary Protocol (SBP) for PIR communication
 *
 * This is an application-specific binary format designed for simplicity and reliability:
 * - All integers are little-endian (native for JavaScript TypedArrays)
 * - Strings/bytes use 4-byte length prefix (u32, sufficient for all cases)
 * - Enum variants use 1-byte discriminant
 * - No nested type tags - the variant determines the exact structure
 *
 * ## Request Format:
 * [1 byte: variant] [variant-specific fields...]
 *
 * ## Response Format:
 * [1 byte: variant] [variant-specific fields...]
 */

import { KEY_SIZE } from './constants.js';

// ============================================================================
// Request Variant Constants
// ============================================================================

export const REQUEST_VARIANT = {
  QUERY: 0,
  QUERY_TWO_LOCATIONS: 1,
  QUERY_DATABASE: 2,
  QUERY_DATABASE_SINGLE: 3,
  LIST_DATABASES: 4,
  GET_DATABASE_INFO: 5,
  PING: 6,
} as const;

// ============================================================================
// Response Variant Constants
// ============================================================================

export const RESPONSE_VARIANT = {
  QUERY_RESULT: 0,
  QUERY_TWO_RESULTS: 1,
  DATABASE_LIST: 2,
  DATABASE_INFO: 3,
  ERROR: 4,
  PONG: 5,
} as const;

// ============================================================================
// Type Definitions
// ============================================================================

export interface DatabaseInfo {
  id: string;
  data_path: string;
  entry_size: number;
  bucket_size: number;
  num_buckets: number;
  num_locations: number;
  total_size: number;
}

export type Request =
  | { Ping: {} }
  | { Query: { bucket_index: number; dpf_key: Uint8Array } }
  | { QueryTwoLocations: { dpf_key1: Uint8Array; dpf_key2: Uint8Array } }
  | { QueryDatabase: { database_id: string; dpf_key1: Uint8Array; dpf_key2: Uint8Array } }
  | { QueryDatabaseSingle: { database_id: string; dpf_key: Uint8Array } }
  | { ListDatabases: {} }
  | { GetDatabaseInfo: { database_id: string } };

export type Response =
  | { Pong: {} }
  | { QueryResult: { data: Uint8Array } }
  | { QueryTwoResults: { data1: Uint8Array; data2: Uint8Array } }
  | { DatabaseList: { databases: DatabaseInfo[] } }
  | { DatabaseInfo: { info: DatabaseInfo } }
  | { Error: { message: string } };

// ============================================================================
// Encoder Class
// ============================================================================

class Encoder {
  private buffer: number[] = [];

  encodeU8(value: number): void {
    this.buffer.push(value & 0xff);
  }

  encodeU32(value: number): void {
    // Little-endian
    this.buffer.push(value & 0xff);
    this.buffer.push((value >> 8) & 0xff);
    this.buffer.push((value >> 16) & 0xff);
    this.buffer.push((value >> 24) & 0xff);
  }

  encodeU64(value: bigint | number): void {
    const v = typeof value === 'bigint' ? value : BigInt(value);
    // Little-endian: low 32 bits first, then high 32 bits
    const low = Number(v & 0xffffffffn);
    const high = Number((v >> 32n) & 0xffffffffn);
    this.encodeU32(low);
    this.encodeU32(high);
  }

  encodeBytes(data: Uint8Array): void {
    this.encodeU32(data.length);
    for (let i = 0; i < data.length; i++) {
      this.buffer.push(data[i]);
    }
  }

  encodeString(s: string): void {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(s);
    this.encodeBytes(bytes);
  }

  encodeRequest(request: Request): void {
    if ('Ping' in request) {
      this.encodeU8(REQUEST_VARIANT.PING);
    } else if ('Query' in request) {
      this.encodeU8(REQUEST_VARIANT.QUERY);
      this.encodeU64(request.Query.bucket_index);
      this.encodeBytes(request.Query.dpf_key);
    } else if ('QueryTwoLocations' in request) {
      this.encodeU8(REQUEST_VARIANT.QUERY_TWO_LOCATIONS);
      this.encodeBytes(request.QueryTwoLocations.dpf_key1);
      this.encodeBytes(request.QueryTwoLocations.dpf_key2);
    } else if ('QueryDatabase' in request) {
      this.encodeU8(REQUEST_VARIANT.QUERY_DATABASE);
      this.encodeString(request.QueryDatabase.database_id);
      this.encodeBytes(request.QueryDatabase.dpf_key1);
      this.encodeBytes(request.QueryDatabase.dpf_key2);
    } else if ('QueryDatabaseSingle' in request) {
      this.encodeU8(REQUEST_VARIANT.QUERY_DATABASE_SINGLE);
      this.encodeString(request.QueryDatabaseSingle.database_id);
      this.encodeBytes(request.QueryDatabaseSingle.dpf_key);
    } else if ('ListDatabases' in request) {
      this.encodeU8(REQUEST_VARIANT.LIST_DATABASES);
    } else if ('GetDatabaseInfo' in request) {
      this.encodeU8(REQUEST_VARIANT.GET_DATABASE_INFO);
      this.encodeString(request.GetDatabaseInfo.database_id);
    } else {
      throw new Error('Unknown request type');
    }
  }

  encodeDatabaseInfo(info: DatabaseInfo): void {
    this.encodeString(info.id);
    this.encodeString(info.data_path);
    this.encodeU64(info.entry_size);
    this.encodeU64(info.bucket_size);
    this.encodeU64(info.num_buckets);
    this.encodeU64(info.num_locations);
    this.encodeU64(info.total_size);
  }

  encodeResponse(response: Response): void {
    if ('Pong' in response) {
      this.encodeU8(RESPONSE_VARIANT.PONG);
    } else if ('QueryResult' in response) {
      this.encodeU8(RESPONSE_VARIANT.QUERY_RESULT);
      this.encodeBytes(response.QueryResult.data);
    } else if ('QueryTwoResults' in response) {
      this.encodeU8(RESPONSE_VARIANT.QUERY_TWO_RESULTS);
      this.encodeBytes(response.QueryTwoResults.data1);
      this.encodeBytes(response.QueryTwoResults.data2);
    } else if ('DatabaseList' in response) {
      this.encodeU8(RESPONSE_VARIANT.DATABASE_LIST);
      this.encodeU32(response.DatabaseList.databases.length);
      for (const db of response.DatabaseList.databases) {
        this.encodeDatabaseInfo(db);
      }
    } else if ('DatabaseInfo' in response) {
      this.encodeU8(RESPONSE_VARIANT.DATABASE_INFO);
      this.encodeDatabaseInfo(response.DatabaseInfo.info);
    } else if ('Error' in response) {
      this.encodeU8(RESPONSE_VARIANT.ERROR);
      this.encodeString(response.Error.message);
    } else {
      throw new Error('Unknown response type');
    }
  }

  toUint8Array(): Uint8Array {
    return new Uint8Array(this.buffer);
  }
}

// ============================================================================
// Decoder Class
// ============================================================================

class Decoder {
  private data: Uint8Array;
  private cursor: number = 0;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  decodeU8(): number {
    if (this.cursor + 1 > this.data.length) {
      throw new Error(`Not enough bytes for u8 at cursor ${this.cursor}`);
    }
    return this.data[this.cursor++];
  }

  decodeU32(): number {
    if (this.cursor + 4 > this.data.length) {
      throw new Error(`Not enough bytes for u32 at cursor ${this.cursor}`);
    }
    // Little-endian
    const value =
      this.data[this.cursor] |
      (this.data[this.cursor + 1] << 8) |
      (this.data[this.cursor + 2] << 16) |
      (this.data[this.cursor + 3] << 24);
    this.cursor += 4;
    return value >>> 0; // Ensure unsigned
  }

  decodeU64(): bigint {
    // Little-endian: low 32 bits first, then high 32 bits
    const low = this.decodeU32();
    const high = this.decodeU32();
    return (BigInt(high) << 32n) | BigInt(low);
  }

  decodeBytes(): Uint8Array {
    const len = this.decodeU32();
    if (this.cursor + len > this.data.length) {
      throw new Error(
        `Not enough bytes for data: need ${len}, have ${this.data.length - this.cursor}`
      );
    }
    const result = this.data.slice(this.cursor, this.cursor + len);
    this.cursor += len;
    return result;
  }

  decodeString(): string {
    const bytes = this.decodeBytes();
    const decoder = new TextDecoder();
    return decoder.decode(bytes);
  }

  decodeDatabaseInfo(): DatabaseInfo {
    return {
      id: this.decodeString(),
      data_path: this.decodeString(),
      entry_size: Number(this.decodeU64()),
      bucket_size: Number(this.decodeU64()),
      num_buckets: Number(this.decodeU64()),
      num_locations: Number(this.decodeU64()),
      total_size: Number(this.decodeU64()),
    };
  }

  decodeRequest(): Request {
    const variant = this.decodeU8();

    switch (variant) {
      case REQUEST_VARIANT.QUERY:
        return {
          Query: {
            bucket_index: Number(this.decodeU64()),
            dpf_key: this.decodeBytes(),
          },
        };

      case REQUEST_VARIANT.QUERY_TWO_LOCATIONS:
        return {
          QueryTwoLocations: {
            dpf_key1: this.decodeBytes(),
            dpf_key2: this.decodeBytes(),
          },
        };

      case REQUEST_VARIANT.QUERY_DATABASE:
        return {
          QueryDatabase: {
            database_id: this.decodeString(),
            dpf_key1: this.decodeBytes(),
            dpf_key2: this.decodeBytes(),
          },
        };

      case REQUEST_VARIANT.QUERY_DATABASE_SINGLE:
        return {
          QueryDatabaseSingle: {
            database_id: this.decodeString(),
            dpf_key: this.decodeBytes(),
          },
        };

      case REQUEST_VARIANT.LIST_DATABASES:
        return { ListDatabases: {} };

      case REQUEST_VARIANT.GET_DATABASE_INFO:
        return {
          GetDatabaseInfo: {
            database_id: this.decodeString(),
          },
        };

      case REQUEST_VARIANT.PING:
        return { Ping: {} };

      default:
        throw new Error(`Unknown request variant: ${variant}`);
    }
  }

  decodeResponse(): Response {
    const variant = this.decodeU8();

    switch (variant) {
      case RESPONSE_VARIANT.QUERY_RESULT:
        return {
          QueryResult: {
            data: this.decodeBytes(),
          },
        };

      case RESPONSE_VARIANT.QUERY_TWO_RESULTS:
        return {
          QueryTwoResults: {
            data1: this.decodeBytes(),
            data2: this.decodeBytes(),
          },
        };

      case RESPONSE_VARIANT.DATABASE_LIST: {
        const count = this.decodeU32();
        const databases: DatabaseInfo[] = [];
        for (let i = 0; i < count; i++) {
          databases.push(this.decodeDatabaseInfo());
        }
        return { DatabaseList: { databases } };
      }

      case RESPONSE_VARIANT.DATABASE_INFO:
        return {
          DatabaseInfo: {
            info: this.decodeDatabaseInfo(),
          },
        };

      case RESPONSE_VARIANT.ERROR:
        return {
          Error: {
            message: this.decodeString(),
          },
        };

      case RESPONSE_VARIANT.PONG:
        return { Pong: {} };

      default:
        throw new Error(`Unknown response variant: ${variant}`);
    }
  }
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Encode a request to bytes using SBP format
 */
export function encodeRequest(request: Request): Uint8Array {
  const encoder = new Encoder();
  encoder.encodeRequest(request);
  return encoder.toUint8Array();
}

/**
 * Decode a request from bytes using SBP format
 */
export function decodeRequest(data: Uint8Array): Request {
  const decoder = new Decoder(data);
  return decoder.decodeRequest();
}

/**
 * Encode a response to bytes using SBP format
 */
export function encodeResponse(response: Response): Uint8Array {
  const encoder = new Encoder();
  encoder.encodeResponse(response);
  return encoder.toUint8Array();
}

/**
 * Decode a response from bytes using SBP format
 */
export function decodeResponse(data: Uint8Array): Response {
  const decoder = new Decoder(data);
  return decoder.decodeResponse();
}

/**
 * Legacy Bincode-compatible class for backward compatibility
 * @deprecated Use encodeRequest/decodeResponse instead
 */
export class Bincode {
  static encode(value: any): Uint8Array {
    if (value && typeof value === 'object') {
      // Check if it's a request type
      if ('Ping' in value || 'Query' in value || 'QueryTwoLocations' in value ||
          'QueryDatabase' in value || 'QueryDatabaseSingle' in value ||
          'ListDatabases' in value || 'GetDatabaseInfo' in value) {
        return encodeRequest(value as Request);
      }
      // Check if it's a response type
      if ('Pong' in value || 'QueryResult' in value || 'QueryTwoResults' in value ||
          'DatabaseList' in value || 'DatabaseInfo' in value || 'Error' in value) {
        return encodeResponse(value as Response);
      }
    }
    throw new Error('Unknown value type for encoding');
  }

  static decode<T>(bytes: Uint8Array, typeHint?: string): T {
    if (typeHint === 'Request') {
      return decodeRequest(bytes) as T;
    }
    if (typeHint === 'Response') {
      return decodeResponse(bytes) as T;
    }
    // Try to decode as response by default (most common case)
    return decodeResponse(bytes) as T;
  }
}
