import assert from "node:assert/strict";
import { describe, test } from "node:test";
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

    assert.equal(decoded[1], "one");
    assert.equal(decoded.nil, null);
    assert.deepEqual(decoded.values, [false, true, undefined, -2, 24, 0x100, 0x1_0000, 0x1_0000_0000]);
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
    assert.ok(decoded.v1 instanceof Uint8Array);
    assert.deepEqual(Array.from(decoded.v1), [1, 2, 3]);

    // Existing Uint8Array round-trips
    assert.deepEqual(Array.from(decoded.v2), [4, 5]);

    // Mixed array elements preserved as Uint8Array
    assert.equal(Array.isArray(decoded.arr), true);
    const [a0, a1] = decoded.arr as Uint8Array[];
    assert.deepEqual(Array.from(a0), [1, 2, 3]);
    assert.deepEqual(Array.from(a1), [4, 5]);
  });

  test("handles Buffer values without conversion in encoder and to Uint8Array on decode", () => {
    const buf = Buffer.from([9, 8]);
    const obj = { b: buf } as unknown as Record<string, unknown>;

    const encoded = EncodeUtils.encodeCbor(obj);
    const decoded = EncodeUtils.decodeCbor<{ b: Uint8Array }>(encoded);

    assert.ok(decoded.b instanceof Uint8Array);
    assert.deepEqual(Array.from(decoded.b), [9, 8]);
  });

  test("keeps non-exact integer object keys as text string map keys", () => {
    const decoded = EncodeUtils.decodeCbor<Record<string | number, boolean>>(
      EncodeUtils.encodeCbor({
        "1": false,
        "01": true,
        "1abc": true,
      }),
    );

    assert.equal(decoded[1], false);
    assert.equal(decoded["01"], true);
    assert.equal(decoded["1abc"], true);
  });

  test("decodes explicit integer widths", () => {
    assert.equal(EncodeUtils.decodeCbor<number>(new Uint8Array([0x1a, 0x00, 0x01, 0x00, 0x00])), 0x1_0000);
    assert.equal(
      EncodeUtils.decodeCbor<number>(new Uint8Array([0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])),
      0x1_0000_0000,
    );
    assert.equal(EncodeUtils.decodeCbor<null>(new Uint8Array([0xf6])), null);
  });

  test("decodeCborWithRemainder returns the first value and trailing bytes", () => {
    const first = EncodeUtils.encodeCbor({ 1: "a", [-2]: new Uint8Array([9, 9]) });
    const second = EncodeUtils.encodeCbor({ 2: "b" });
    const combined = new Uint8Array([...first, ...second]);

    const { value, remainder } = EncodeUtils.decodeCborWithRemainder<Record<string | number, unknown>>(combined);

    assert.equal(value[1], "a");
    assert.deepEqual(value[-2], new Uint8Array([9, 9]));
    assert.deepEqual(remainder, second);
  });

  test("rejects unsupported values and malformed input", () => {
    assert.throws(() => EncodeUtils.encodeCbor(Symbol("unsupported") as unknown as object), {
      message: "Unsupported CBOR value type: symbol",
    });
    assert.throws(() => EncodeUtils.encodeCbor({ value: Number.NaN }), { message: "CBOR only supports safe integers" });
    assert.throws(() => EncodeUtils.decodeCbor(new Uint8Array()), { message: "Insufficient data" });
    assert.throws(() => EncodeUtils.decodeCbor(new Uint8Array([0x42, 0x01])), { message: "Insufficient data" });
    assert.throws(() => EncodeUtils.decodeCbor(new Uint8Array([0x5f])), {
      message: "Unsupported indefinite-length CBOR data",
    });
    assert.throws(() => EncodeUtils.decodeCbor(new Uint8Array([0x01, 0x02])), {
      message: "Unexpected trailing CBOR data",
    });
    assert.throws(() => EncodeUtils.decodeCbor(new Uint8Array([0xc1, 0x01])), {
      message: "Unsupported CBOR tagged value",
    });
    assert.throws(() => EncodeUtils.decodeCbor(new Uint8Array([0xf8])), {
      message: "Unsupported CBOR simple value: 24",
    });
    assert.throws(() => EncodeUtils.decodeCbor(new Uint8Array([0xa1, 0x41, 0x01, 0x01])), {
      message: "Unsupported CBOR map key type",
    });
    assert.throws(
      () => EncodeUtils.decodeCbor(new Uint8Array([0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
      { message: "CBOR integer exceeds JavaScript safe integer range" },
    );
  });
});
