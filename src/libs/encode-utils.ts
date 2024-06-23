import cbor from "cbor";

function encodeBase64Url(data: BufferSource): string {
  const buffer = bufferSourceToUint8Array(data);
  let binaryString = "";
  for (let i = 0; i < buffer.length; i++) {
    binaryString += String.fromCharCode(buffer[i]);
  }
  return btoa(binaryString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeBase64Url(base64Url: string): Uint8Array {
  const binaryString = atob(base64Url.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function bufferSourceToUint8Array(data: BufferSource): Uint8Array {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
}

function strToUint8Array(data: string): Uint8Array {
  return new Uint8Array(data.split("").map((c) => c.charCodeAt(0)));
}

function encodeCbor(data: Map<unknown, unknown>): Uint8Array {
  const canonicalData = new Map();
  for (const [key, value] of data) {
    if (value instanceof Map) {
      canonicalData.set(key, encodeCbor(value));
    } else if (value instanceof Uint8Array) {
      canonicalData.set(key, Buffer.from(value));
    } else {
      canonicalData.set(key, value);
    }
  }
  return new Uint8Array(cbor.encode(canonicalData));
}

function decodeCbor<T>(data: Uint8Array): T {
  return cbor.decode(data);
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
