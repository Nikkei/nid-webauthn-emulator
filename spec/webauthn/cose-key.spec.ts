import * as crypto from "node:crypto";
import { describe, expect, test } from "@jest/globals";
import { CoseKey } from "../../src";
import EncodeUtils from "../../src/libs/encode-utils";

describe("COSEKey Tests", () => {
  test("RSA Key test", () => {
    const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const coseKey1 = CoseKey.fromKeyObject(keys.publicKey);
    const coseKey2 = CoseKey.fromDer(coseKey1.toDer());
    const coseKey3 = CoseKey.fromBytes(coseKey1.toBytes());
    const coseKey4 = CoseKey.fromJwk(coseKey1.toJwk());

    expect(coseKey1.equals(coseKey2)).toBeTruthy();
    expect(coseKey1.equals(coseKey3)).toBeTruthy();
    expect(coseKey1.equals(coseKey4)).toBeTruthy();
  });

  test("P256 Key test", () => {
    const keys = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const coseKey1 = CoseKey.fromKeyObject(keys.publicKey);
    const coseKey2 = CoseKey.fromDer(coseKey1.toDer());
    const coseKey3 = CoseKey.fromBytes(coseKey1.toBytes());
    const coseKey4 = CoseKey.fromJwk(coseKey1.toJwk());

    expect(coseKey1.equals(coseKey2)).toBeTruthy();
    expect(coseKey1.equals(coseKey3)).toBeTruthy();
    expect(coseKey1.equals(coseKey4)).toBeTruthy();
  });

  test("Ed25519 Key test", () => {
    const keys = crypto.generateKeyPairSync("ed25519");
    const coseKey1 = CoseKey.fromKeyObject(keys.publicKey);
    const coseKey2 = CoseKey.fromDer(coseKey1.toDer());
    const coseKey3 = CoseKey.fromBytes(coseKey1.toBytes());
    const coseKey4 = CoseKey.fromJwk(coseKey1.toJwk());

    expect(coseKey1.equals(coseKey2)).toBeTruthy();
    expect(coseKey1.equals(coseKey3)).toBeTruthy();
    expect(coseKey1.equals(coseKey4)).toBeTruthy();
  });

  test("Unsupported key type test", () => {
    const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const unsupportedJwk = {
      ...CoseKey.fromKeyObject(keys.publicKey).toJwk(),
      kty: "unsupported",
    };
    expect(() => CoseKey.fromJwk(unsupportedJwk)).toThrow("Not supported key type");

    const unsupportedBytes = EncodeUtils.encodeCbor({ 1: 123, 3: 456 });
    expect(() => CoseKey.fromBytes(unsupportedBytes)).toThrow("Not supported key type");
  });
});
