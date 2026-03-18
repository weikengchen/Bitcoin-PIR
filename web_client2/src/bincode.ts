/**
 * Simplified bincode serialization/deserialization
 * 
 * This is a minimal implementation that handles types needed for PIR protocol.
 * For production use, consider using a more complete bincode library.
 */

import { KEY_SIZE } from './constants.js';

export interface DatabaseInfo {
  id: string;
  data_path: string;
  entry_size: number;
  bucket_size: number;
  num_buckets: number;
  num_locations: number;
  total_size: number;
}

export class Bincode {
  /**
   * Encode a value to bytes
   */
  static encode(value: any): Uint8Array {
    const encoder = new BincodeEncoder();
    encoder.encodeValue(value);
    return encoder.toBytes();
  }

  /**
   * Decode bytes to a value
   */
  static decode<T>(bytes: Uint8Array, typeHint?: string): T {
    const decoder = new BincodeDecoder(bytes);
    return decoder.decodeValue(typeHint) as T;
  }
}

class BincodeEncoder {
  private buffer: number[] = [];

  encodeValue(value: any): void {
    if (value === null || value === undefined) {
      this.encodeU8(0);
    } else if (typeof value === 'object') {
      if (value instanceof Uint8Array) {
        this.encodeBytes(value);
      } else if (Array.isArray(value)) {
        this.encodeArray(value);
      } else if (this.isRequest(value) || this.isResponse(value)) {
        this.encodeEnum(value);
      } else {
        this.encodeObject(value);
      }
    } else if (typeof value === 'string') {
      this.encodeString(value);
    } else if (typeof value === 'number') {
      if (Number.isInteger(value)) {
        if (value >= 0 && value <= 255) {
          this.encodeU8(value);
        } else if (value >= 0 && value <= 65535) {
          this.encodeU16(value);
        } else if (value >= 0 && value <= 4294967295) {
          this.encodeU32(value);
        } else {
          this.encodeU64(BigInt(value));
        }
      } else {
        this.encodeF64(value);
      }
    } else if (typeof value === 'bigint') {
      this.encodeU64(value);
    }
  }

  isRequest(value: any): boolean {
    return 'Ping' in value || 'Query' in value || 'QueryTwoLocations' in value ||
           'QueryDatabase' in value || 'QueryDatabaseSingle' in value ||
           'ListDatabases' in value || 'GetDatabaseInfo' in value;
  }

  isResponse(value: any): boolean {
    return 'Pong' in value || 'QueryResult' in value || 'QueryTwoResults' in value ||
           'DatabaseList' in value || 'DatabaseInfo' in value || 'Error' in value;
  }

  encodeEnum(value: any): void {
    if ('Ping' in value) {
      this.encodeU8(6); // Ping variant (must match Rust enum order)
    } else if ('Query' in value) {
      this.encodeU8(0); // Query variant
      this.encodeU64(BigInt(value.Query.bucket_index));
      this.encodeBytes(value.Query.dpf_key);
    } else if ('QueryTwoLocations' in value) {
      this.encodeU8(1); // QueryTwoLocations variant
      this.encodeBytes(value.QueryTwoLocations.dpf_key1);
      this.encodeBytes(value.QueryTwoLocations.dpf_key2);
    } else if ('QueryDatabase' in value) {
      this.encodeU8(2); // QueryDatabase variant
      this.encodeString(value.QueryDatabase.database_id);
      this.encodeBytes(value.QueryDatabase.dpf_key1);
      this.encodeBytes(value.QueryDatabase.dpf_key2);
    } else if ('QueryDatabaseSingle' in value) {
      this.encodeU8(3); // QueryDatabaseSingle variant
      this.encodeString(value.QueryDatabaseSingle.database_id);
      this.encodeBytes(value.QueryDatabaseSingle.dpf_key);
    } else if ('ListDatabases' in value) {
      this.encodeU8(4); // ListDatabases variant
    } else if ('GetDatabaseInfo' in value) {
      this.encodeU8(5); // GetDatabaseInfo variant
      this.encodeString(value.GetDatabaseInfo.database_id);
    } else if ('Pong' in value) {
      this.encodeU8(5); // Pong variant (must match Rust enum order)
    } else if ('QueryResult' in value) {
      this.encodeU8(0); // QueryResult variant
      this.encodeBytes(value.QueryResult.data);
    } else if ('QueryTwoResults' in value) {
      this.encodeU8(1); // QueryTwoResults variant
      this.encodeBytes(value.QueryTwoResults.data1);
      this.encodeBytes(value.QueryTwoResults.data2);
    } else if ('DatabaseList' in value) {
      this.encodeU8(2); // DatabaseList variant
      this.encodeArray(value.DatabaseList.databases);
    } else if ('DatabaseInfo' in value) {
      this.encodeU8(3); // DatabaseInfo variant
      this.encodeDatabaseInfo(value.DatabaseInfo.info);
    } else if ('Error' in value) {
      this.encodeU8(4); // Error variant
      this.encodeString(value.Error.message);
    }
  }

  encodeDatabaseInfo(info: any): void {
    this.encodeString(info.id);
    this.encodeString(info.data_path);
    this.encodeU64(BigInt(info.entry_size));
    this.encodeU64(BigInt(info.bucket_size));
    this.encodeU64(BigInt(info.num_buckets));
    this.encodeU64(BigInt(info.num_locations));
    this.encodeU64(BigInt(info.total_size));
  }

  encodeU8(value: number): void {
    this.buffer.push(value & 0xFF);
  }

  encodeU16(value: number): void {
    this.buffer.push(value & 0xFF);
    this.buffer.push((value >> 8) & 0xFF);
  }

  encodeU32(value: number): void {
    // bincode uses big-endian encoding
    this.buffer.push((value >> 24) & 0xFF);
    this.buffer.push((value >> 16) & 0xFF);
    this.buffer.push((value >> 8) & 0xFF);
    this.buffer.push(value & 0xFF);
  }

  encodeU64(value: bigint): void {
    // bincode uses big-endian encoding
    const v = Number(value);
    this.encodeU32((v >> 32) & 0xFFFFFFFF);
    this.encodeU32(v & 0xFFFFFFFF);
  }

  encodeI64(value: bigint): void {
    const v = Number(value);
    this.encodeU32(v & 0xFFFFFFFF);
    this.encodeU32((v >> 32) & 0xFFFFFFFF);
  }

  encodeF64(value: number): void {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value, true); // little-endian
    for (let i = 0; i < 8; i++) {
      this.buffer.push(view.getUint8(i));
    }
  }

  encodeBytes(value: Uint8Array): void {
    this.encodeU64(BigInt(value.length));
    for (const byte of value) {
      this.buffer.push(byte);
    }
  }

  encodeString(value: string): void {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(value);
    this.encodeU64(BigInt(bytes.length));
    for (const byte of bytes) {
      this.buffer.push(byte);
    }
  }

  encodeArray(value: any[]): void {
    this.encodeU64(BigInt(value.length));
    for (const item of value) {
      this.encodeValue(item);
    }
  }

  encodeObject(value: { [key: string]: any }): void {
    const keys = Object.keys(value);
    this.encodeU64(BigInt(keys.length));
    for (const key of keys) {
      this.encodeString(key);
      this.encodeValue(value[key]);
    }
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.buffer);
  }
}

class BincodeDecoder {
  private offset = 0;

  constructor(private bytes: Uint8Array) {}

  decodeValue(typeHint?: string): any {
    if (this.offset >= this.bytes.length) {
      throw new Error('Unexpected end of data');
    }

    const firstByte = this.bytes[this.offset];

    // Handle specific type hints
    if (typeHint === 'Request' || typeHint === 'Response') {
      return this.decodeEnum(typeHint);
    }

    // Detect type based on context
    if (typeHint === 'string' || firstByte < 128) {
      return this.decodeString();
    } else if (typeHint === 'number') {
      return this.decodeU64();
    } else if (typeHint === 'Uint8Array') {
      return this.decodeBytes();
    } else if (typeHint === 'Array') {
      return this.decodeArray();
    } else if (typeHint === 'Object') {
      return this.decodeObject();
    } else {
      // Default: try to decode as enum first (for Request/Response)
      try {
        return this.decodeEnum();
      } catch {
        return this.decodeString();
      }
    }
  }

  decodeU8(): number {
    if (this.offset + 1 > this.bytes.length) {
      throw new Error('Unexpected end of data');
    }
    return this.bytes[this.offset++];
  }

  decodeU16(): number {
    if (this.offset + 2 > this.bytes.length) {
      throw new Error('Unexpected end of data');
    }
    const value = this.bytes[this.offset] | (this.bytes[this.offset + 1] << 8);
    this.offset += 2;
    return value;
  }

  decodeU32(): number {
    if (this.offset + 4 > this.bytes.length) {
      throw new Error('Unexpected end of data');
    }
    // bincode uses big-endian encoding
    const value =
      (this.bytes[this.offset] << 24) |
      (this.bytes[this.offset + 1] << 16) |
      (this.bytes[this.offset + 2] << 8) |
      this.bytes[this.offset + 3];
    this.offset += 4;
    return value >>> 0; // Ensure unsigned
  }

  decodeU64(): bigint {
    // bincode uses big-endian encoding
    const high = this.decodeU32();
    const low = this.decodeU32();
    return (BigInt(high) << 32n) | BigInt(low);
  }

  decodeI64(): bigint {
    const low = this.decodeU32();
    const high = this.decodeU32();
    return (BigInt(high << 32) | BigInt(low));
  }

  decodeF64(): number {
    if (this.offset + 8 > this.bytes.length) {
      throw new Error('Unexpected end of data');
    }
    const view = new DataView(this.bytes.buffer, this.offset, 8);
    const value = view.getFloat64(0, true); // little-endian
    this.offset += 8;
    return value;
  }

  decodeBytes(): Uint8Array {
    const len = Number(this.decodeU64());
    if (this.offset + len > this.bytes.length) {
      throw new Error('Unexpected end of data');
    }
    const value = this.bytes.slice(this.offset, this.offset + len);
    this.offset += len;
    return value;
  }

  decodeString(): string {
    const len = Number(this.decodeU64());
    if (this.offset + len > this.bytes.length) {
      throw new Error('Unexpected end of data');
    }
    const decoder = new TextDecoder();
    const value = decoder.decode(this.bytes.slice(this.offset, this.offset + len));
    this.offset += len;
    return value;
  }

  decodeArray(): any[] {
    const len = Number(this.decodeU64());
    const arr: any[] = [];
    for (let i = 0; i < len; i++) {
      arr.push(this.decodeValue());
    }
    return arr;
  }

  decodeObject(): { [key: string]: any } {
    const len = Number(this.decodeU64());
    const obj: { [key: string]: any } = {};
    for (let i = 0; i < len; i++) {
      const key = this.decodeString();
      obj[key] = this.decodeValue();
    }
    return obj;
  }

  decodeEnum(typeHint?: string): any {
    const variant = this.decodeU8();
    console.log(`[DEBUG] decodeEnum: typeHint=${typeHint}, variant=${variant}, offset=${this.offset}, bytes.length=${this.bytes.length}`);
    console.log(`[DEBUG] First 20 bytes:`, Array.from(this.bytes.slice(0, 20)));

    if (typeHint === 'Request') {
      switch (variant) {
        case 0: // Query
          return {
            Query: {
              bucket_index: Number(this.decodeU64()),
              dpf_key: this.decodeBytes(),
            },
          };
        case 1: // QueryTwoLocations
          return {
            QueryTwoLocations: {
              dpf_key1: this.decodeBytes(),
              dpf_key2: this.decodeBytes(),
            },
          };
        case 2: // QueryDatabase
          return {
            QueryDatabase: {
              database_id: this.decodeString(),
              dpf_key1: this.decodeBytes(),
              dpf_key2: this.decodeBytes(),
            },
          };
        case 3: // QueryDatabaseSingle
          return {
            QueryDatabaseSingle: {
              database_id: this.decodeString(),
              dpf_key: this.decodeBytes(),
            },
          };
        case 4: // ListDatabases
          return { ListDatabases: {} };
        case 5: // GetDatabaseInfo
          return {
            GetDatabaseInfo: {
              database_id: this.decodeString(),
            },
          };
        case 6: // Ping
          return { Ping: {} };
        default:
          throw new Error(`Unknown Request variant: ${variant}`);
      }
    } else if (typeHint === 'Response') {
      switch (variant) {
        case 0: // QueryResult
          return {
            QueryResult: {
              data: this.decodeBytes(),
            },
          };
        case 1: // QueryTwoResults
          return {
            QueryTwoResults: {
              data1: this.decodeBytes(),
              data2: this.decodeBytes(),
            },
          };
        case 2: // DatabaseList
          return {
            DatabaseList: {
              databases: this.decodeDatabaseInfoArray(),
            },
          };
        case 3: // DatabaseInfo
          return {
            DatabaseInfo: {
              info: this.decodeDatabaseInfo(),
            },
          };
        case 4: // Error
          return {
            Error: {
              message: this.decodeString(),
            },
          };
        case 5: // Pong
          return { Pong: {} };
        default:
          throw new Error(`Unknown Response variant: ${variant}`);
      }
    }

    throw new Error(`Unknown enum type: ${typeHint}`);
  }

  decodeDatabaseInfoArray(): DatabaseInfo[] {
    const len = Number(this.decodeU64());
    const arr: DatabaseInfo[] = [];
    for (let i = 0; i < len; i++) {
      arr.push(this.decodeDatabaseInfo());
    }
    return arr;
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
}