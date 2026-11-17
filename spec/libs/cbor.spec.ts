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

  test("decodes prototype-related keys as ordinary own properties", () => {
    const original = JSON.parse('{"__proto__":{"fmt":"none"},"constructor":1,"toString":2,"hasOwnProperty":3}');
    const decoded = EncodeUtils.decodeCbor<Record<string, unknown>>(EncodeUtils.encodeCbor(original));

    assert.equal(Object.getPrototypeOf(decoded), Object.prototype);
    assert.equal(Object.hasOwn(decoded, "__proto__"), true);
    assert.equal(decoded.fmt, undefined);
    assert.deepEqual(decoded, original);
    assert.deepEqual(EncodeUtils.encodeCbor(decoded), EncodeUtils.encodeCbor(original));
  });

  test("rejects duplicate keys, including different integer widths and nested maps", () => {
    for (const hex of [
      "a201010102", // {1: 1, 1: 2}
      "a2616101616102", // {"a": 1, "a": 2}
      "a20101180102", // The second 1 uses an extra integer byte.
      "a22001380002", // The second -1 uses an extra integer byte.
      "a26161f7616102", // The first value is undefined.
      "a16178a201010102", // {"x": {1: 1, 1: 2}}
      "81a201010102", // [{1: 1, 1: 2}]
    ]) {
      const encoded = Buffer.from(hex, "hex");
      for (const mapType of ["object", "map"] as const) {
        assert.throws(() => EncodeUtils.decodeCbor(encoded, { mapType }), /Duplicate CBOR map key/);
        assert.throws(
          () => EncodeUtils.decodeCborWithRemainder(Buffer.concat([encoded, Buffer.from([0])]), { mapType }),
          /Duplicate CBOR map key/,
        );
      }
    }
  });

  test("rejects distinct keys that would collide in an object", () => {
    for (const hex of ["a20101613102", "a26131020101", "a22001622d3102", "a2622d31022001"]) {
      const encoded = Buffer.from(hex, "hex");
      assert.throws(() => EncodeUtils.decodeCbor(encoded), /CBOR map keys collide in object representation/);
      assert.throws(
        () => EncodeUtils.decodeCborWithRemainder(encoded),
        /CBOR map keys collide in object representation/,
      );
    }
  });

  test("map mode preserves integer and text key types, including nested maps in arrays", () => {
    const encoded = Buffer.from("a401016131022003622d3104", "hex"); // {1: 1, "1": 2, -1: 3, "-1": 4}
    const expected = new Map<string | number, number>([
      [1, 1],
      ["1", 2],
      [-1, 3],
      ["-1", 4],
    ]);
    assert.deepEqual(EncodeUtils.decodeCbor(encoded, { mapType: "map" }), expected);

    const nested = Buffer.concat([Buffer.from("a1617881", "hex"), encoded]); // {"x": [encoded]}
    assert.deepEqual(EncodeUtils.decodeCbor(nested, { mapType: "map" }), new Map([["x", [expected]]]));
    const trailing = Buffer.from("a201010102", "hex"); // Intentionally invalid, but outside the first data item.
    assert.deepEqual(EncodeUtils.decodeCborWithRemainder(Buffer.concat([nested, trailing]), { mapType: "map" }), {
      value: new Map([["x", [expected]]]),
      remainder: trailing,
    });
    assert.throws(
      () => EncodeUtils.decodeCbor(Buffer.concat([nested, trailing]), { mapType: "map" }),
      /Unexpected trailing CBOR data/,
    );
  });

  test("map mode preserves __proto__ as an entry without changing the Map prototype", () => {
    const encoded = Buffer.from("a1695f5f70726f746f5f5fa163666d74646e6f6e65", "hex");
    const decoded = EncodeUtils.decodeCbor<Map<string, unknown>>(encoded, { mapType: "map" });
    assert.equal(Object.getPrototypeOf(decoded), Map.prototype);
    assert.deepEqual(decoded.get("__proto__"), new Map([["fmt", "none"]]));
    assert.equal(decoded.has("fmt"), false);
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
