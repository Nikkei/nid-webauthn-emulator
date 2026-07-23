function appendCborTypeAndLength(out: number[], majorType: number, value: number): void {
  const prefix = majorType << 5;
  if (value < 24) {
    out.push(prefix | value);
    return;
  }
  if (value <= 0xff) {
    out.push(prefix | 24, value);
    return;
  }
  if (value <= 0xffff) {
    out.push(prefix | 25, value >> 8, value & 0xff);
    return;
  }
  if (value <= 0xffffffff) {
    out.push(prefix | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
    return;
  }

  const bigValue = BigInt(value);
  out.push(prefix | 27);
  for (let shift = 56n; shift >= 0n; shift -= 8n) {
    out.push(Number((bigValue >> shift) & 0xffn));
  }
}

function appendCborByteString(out: number[], data: Uint8Array): void {
  appendCborTypeAndLength(out, 2, data.byteLength);
  out.push(...data);
}

function objectKeyToCborMapKey(key: string): string | number {
  const numberKey = Number(key);
  return Number.isSafeInteger(numberKey) && String(numberKey) === key ? numberKey : key;
}

function appendCborValue(out: number[], value: unknown): void {
  if (value instanceof Uint8Array) {
    appendCborByteString(out, value);
    return;
  }
  if (value instanceof ArrayBuffer) {
    appendCborByteString(out, new Uint8Array(value));
    return;
  }
  if (Array.isArray(value)) {
    appendCborTypeAndLength(out, 4, value.length);
    for (const item of value) appendCborValue(out, item);
    return;
  }
  switch (typeof value) {
    case "number":
      if (!Number.isSafeInteger(value)) throw new Error("CBOR only supports safe integers");
      if (value >= 0) {
        appendCborTypeAndLength(out, 0, value);
      } else {
        appendCborTypeAndLength(out, 1, -1 - value);
      }
      return;
    case "string": {
      const encoded = new TextEncoder().encode(value);
      appendCborTypeAndLength(out, 3, encoded.byteLength);
      out.push(...encoded);
      return;
    }
    case "boolean":
      out.push(value ? 0xf5 : 0xf4);
      return;
    case "undefined":
      out.push(0xf7);
      return;
    case "object":
      if (value === null) {
        out.push(0xf6);
        return;
      }
      break;
    default:
      throw new Error(`Unsupported CBOR value type: ${typeof value}`);
  }

  const entries = Object.entries(value);
  appendCborTypeAndLength(out, 5, entries.length);
  for (const [k, v] of entries) {
    appendCborValue(out, objectKeyToCborMapKey(k));
    appendCborValue(out, v);
  }
}

export function encodeCbor(data: object): Uint8Array<ArrayBuffer> {
  const out: number[] = [];
  appendCborValue(out, data);
  return new Uint8Array(out);
}

class CborReader {
  private offset = 0;
  private readonly textDecoder = new TextDecoder("utf-8", { fatal: true });

  constructor(private readonly data: Uint8Array<ArrayBuffer>) {}

  read(): unknown {
    const value = this.readValue();
    if (this.offset !== this.data.byteLength) {
      throw new Error("Unexpected trailing CBOR data");
    }
    return value;
  }

  readWithRemainder(): { value: unknown; remainder: Uint8Array<ArrayBuffer> } {
    const value = this.readValue();
    return { value, remainder: this.data.slice(this.offset) };
  }

  private readValue(): unknown {
    const initialByte = this.readByte();
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    switch (majorType) {
      case 0:
        return this.readLength(additionalInfo);
      case 1:
        return -1 - this.readLength(additionalInfo);
      case 2:
        return this.readByteString(this.readLength(additionalInfo));
      case 3:
        return this.readTextString(this.readLength(additionalInfo));
      case 4:
        return this.readArray(this.readLength(additionalInfo));
      case 5:
        return this.readMap(this.readLength(additionalInfo));
      case 6:
        throw new Error("Unsupported CBOR tagged value");
      case 7:
        return this.readSimpleValue(additionalInfo);
    }
  }

  private readByte(): number {
    if (this.offset >= this.data.byteLength) {
      throw new Error("Insufficient data");
    }
    return this.data[this.offset++];
  }

  private readBytes(length: number): Uint8Array<ArrayBuffer> {
    if (this.offset + length > this.data.byteLength) {
      throw new Error("Insufficient data");
    }
    const bytes = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }

  private readLength(additionalInfo: number): number {
    if (additionalInfo < 24) return additionalInfo;
    if (additionalInfo === 24) return this.readByte();
    if (additionalInfo === 25) return (this.readByte() << 8) | this.readByte();
    if (additionalInfo === 26) {
      return this.readByte() * 0x1000000 + ((this.readByte() << 16) | (this.readByte() << 8) | this.readByte());
    }
    if (additionalInfo === 27) {
      let value = 0n;
      for (let i = 0; i < 8; i++) {
        value = (value << 8n) | BigInt(this.readByte());
      }
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("CBOR integer exceeds JavaScript safe integer range");
      }
      return Number(value);
    }
    throw new Error("Unsupported indefinite-length CBOR data");
  }

  private readByteString(length: number): Uint8Array<ArrayBuffer> {
    return this.readBytes(length);
  }

  private readTextString(length: number): string {
    return this.textDecoder.decode(this.readBytes(length));
  }

  private readArray(length: number): unknown[] {
    const values: unknown[] = [];
    for (let i = 0; i < length; i++) {
      values.push(this.readValue());
    }
    return values;
  }

  private readMap(length: number): Record<string | number, unknown> {
    const value: Record<string | number, unknown> = {};
    for (let i = 0; i < length; i++) {
      const key = this.readValue();
      if (typeof key !== "string" && typeof key !== "number") {
        throw new Error("Unsupported CBOR map key type");
      }
      value[key] = this.readValue();
    }
    return value;
  }

  private readSimpleValue(additionalInfo: number): unknown {
    switch (additionalInfo) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
        return null;
      case 23:
        return undefined;
      default:
        throw new Error(`Unsupported CBOR simple value: ${additionalInfo}`);
    }
  }
}

export function decodeCbor<T>(data: Uint8Array<ArrayBuffer>): T {
  return new CborReader(data).read() as T;
}

export function decodeCborWithRemainder<T>(data: Uint8Array<ArrayBuffer>): {
  value: T;
  remainder: Uint8Array<ArrayBuffer>;
} {
  const { value, remainder } = new CborReader(data).readWithRemainder();
  return { value: value as T, remainder };
}
