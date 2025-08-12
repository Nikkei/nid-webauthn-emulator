import { describe, expect, test } from "@jest/globals";
import EncodeUtils from "../../src/libs/encode-utils";

describe("EncodeUtils encodeCbor/decodeCbor edge cases", () => {
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
});
