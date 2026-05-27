import { describe, expect, test } from "@jest/globals";
import EncodeUtils from "../../src/libs/encode-utils";

describe("CBOR encode/decode edge cases", () => {
  test("round-trips primitive values and large integer encodings", () => {
    const encoded = EncodeUtils.encodeCbor({
      1: "one",
      nil: null,
      values: [false, true, undefined, -2, 24, 0x100, 0x1_0000, 0x1_0000_0000],
    });

    const decoded = EncodeUtils.decodeCbor<{
      1: string;
      nil: null;
      values: [boolean, boolean, undefined, number, number, number, number, number];
    }>(encoded);

    expect(decoded[1]).toBe("one");
    expect(decoded.nil).toBeNull();
    expect(decoded.values).toEqual([false, true, undefined, -2, 24, 0x100, 0x1_0000, 0x1_0000_0000]);
  });

  test("handles ArrayBuffer values within objects and arrays", () => {
    const ab = new Uint8Array([1, 2, 3]).buffer; // ArrayBuffer branch
    const ua = new Uint8Array([4, 5]);

    const obj = {
      v1: ab,
      v2: ua,
      arr: [ab, ua],
    };

    const encoded = EncodeUtils.encodeCbor(obj);
    const decoded = EncodeUtils.decodeCbor<{ v1: Uint8Array; v2: Uint8Array; arr: unknown[] }>(encoded);

    // ArrayBuffer is decoded back to Uint8Array
    expect(decoded.v1).toBeInstanceOf(Uint8Array);
    expect(Array.from(decoded.v1)).toEqual([1, 2, 3]);

    // Existing Uint8Array round-trips
    expect(Array.from(decoded.v2)).toEqual([4, 5]);

    // Mixed array elements preserved as Uint8Array
    expect(Array.isArray(decoded.arr)).toBe(true);
    const [a0, a1] = decoded.arr as Uint8Array[];
    expect(Array.from(a0)).toEqual([1, 2, 3]);
    expect(Array.from(a1)).toEqual([4, 5]);
  });

  test("handles Buffer values without conversion in encoder and to Uint8Array on decode", () => {
    const buf = Buffer.from([9, 8]);
    const obj = { b: buf } as unknown as Record<string, unknown>;

    const encoded = EncodeUtils.encodeCbor(obj);
    const decoded = EncodeUtils.decodeCbor<{ b: Uint8Array }>(encoded);

    expect(decoded.b).toBeInstanceOf(Uint8Array);
    expect(Array.from(decoded.b)).toEqual([9, 8]);
  });

  test("decodes tagged values and explicit integer widths", () => {
    expect(EncodeUtils.decodeCbor<number>(new Uint8Array([0xc1, 0x01]))).toBe(1);
    expect(EncodeUtils.decodeCbor<number>(new Uint8Array([0x1a, 0x00, 0x01, 0x00, 0x00]))).toBe(0x1_0000);
    expect(EncodeUtils.decodeCbor<number>(new Uint8Array([0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]))).toBe(
      0x1_0000_0000,
    );
    expect(EncodeUtils.decodeCbor<null>(new Uint8Array([0xf6]))).toBeNull();
  });

  test("rejects unsupported values and malformed input", () => {
    expect(() => EncodeUtils.encodeCbor(Symbol("unsupported") as unknown as object)).toThrow(
      "Unsupported CBOR value type: symbol",
    );
    expect(() => EncodeUtils.encodeCbor({ value: Number.NaN })).toThrow("CBOR only supports safe integers");
    expect(() => EncodeUtils.decodeCbor(new Uint8Array())).toThrow("Insufficient data");
    expect(() => EncodeUtils.decodeCbor(new Uint8Array([0x42, 0x01]))).toThrow("Insufficient data");
    expect(() => EncodeUtils.decodeCbor(new Uint8Array([0x5f]))).toThrow("Unsupported indefinite-length CBOR data");
    expect(() => EncodeUtils.decodeCbor(new Uint8Array([0x01, 0x02]))).toThrow("Unexpected trailing CBOR data");
    expect(() => EncodeUtils.decodeCbor(new Uint8Array([0xf8]))).toThrow("Unsupported CBOR simple value: 24");
    expect(() => EncodeUtils.decodeCbor(new Uint8Array([0xa1, 0x41, 0x01, 0x01]))).toThrow(
      "Unsupported CBOR map key type",
    );
    expect(() =>
      EncodeUtils.decodeCbor(new Uint8Array([0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
    ).toThrow("CBOR integer exceeds JavaScript safe integer range");
  });
});
