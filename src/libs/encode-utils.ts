import cbor from "cbor";

function encodeBase64Url(data: BufferSource): string {
  const buffer = bufferSourceToUint8Array(data);
  let binaryString = "";
  for (let i = 0; i < buffer.length; i++) {
    binaryString += String.fromCharCode(buffer[i]);
  }
  return btoa(binaryString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64Url(base64Url: string): Uint8Array<ArrayBuffer> {
  const binaryString = atob(base64Url.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function bufferSourceToUint8Array(data: BufferSource): Uint8Array<ArrayBuffer> {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
}

function strToUint8Array(data: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(data.split("").map((c) => c.charCodeAt(0)));
}

function encodeCbor(data: object): Uint8Array<ArrayBuffer> {
  function encoder(value: unknown): unknown {
    if (value instanceof Uint8Array) {
      return Buffer.from(value);
    }
    if (value instanceof ArrayBuffer) {
      return Buffer.from(value);
    }
    if (value instanceof Buffer) {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((v) => encoder(v));
    }
    if (typeof value === "object" && value !== null) {
      const encodedData = new Map<unknown, unknown>();
      for (const [k, v] of Object.entries(value)) {
        const ki = Number.parseInt(k);
        if (Number.isNaN(ki)) {
          encodedData.set(k, encoder(v));
        } else {
          encodedData.set(ki, encoder(v));
        }
      }
      return encodedData;
    }
    return value;
  }
  return new Uint8Array(cbor.encode(encoder(data)));
}

function decodeCbor<T>(data: Uint8Array<ArrayBuffer>): T {
  const canonicalData = cbor.decode(data) as Map<unknown, unknown>;
  function decoder(value: unknown): unknown {
    if (value instanceof Buffer) {
      return new Uint8Array(value);
    }
    if (Array.isArray(value)) {
      return value.map((v) => decoder(v));
    }
    if (value instanceof Map) {
      const decodedData = {};
      for (const [k, v] of value) {
        Object.assign(decodedData, { [k]: decoder(v) });
      }
      return decodedData;
    }
    if (typeof value === "object" && value !== null) {
      const decodedData = {};
      for (const [k, v] of Object.entries(value)) {
        Object.assign(decodedData, { [k]: decoder(v) });
      }
      return decodedData;
    }
    return value;
  }
  return decoder(canonicalData) as T;
}

const EncodeUtils = {
  strToUint8Array,
  bufferSourceToUint8Array,
  encodeBase64Url,
  decodeBase64Url,
  encodeCbor,
  decodeCbor,
};
export default EncodeUtils;
