import { decodeCbor, encodeCbor } from "./cbor";

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

const EncodeUtils = {
  strToUint8Array,
  bufferSourceToUint8Array,
  encodeBase64Url,
  decodeBase64Url,
  encodeCbor,
  decodeCbor,
};
export default EncodeUtils;
