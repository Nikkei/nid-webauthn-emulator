import { describe, expect, test } from "@jest/globals";
import { AuthenticatorEmulator } from "../../src/emulators/authenticator";
import { CoseKey } from "../../src/webauthn/cose-key";
import { RpId, unpackAuthenticatorData } from "../../src/webauthn/webauthn-model";

describe.each([-7, -8, -257])("CoseKey Test: %s", (alg) => {
  const getKey = () => {
    const authenticator = new AuthenticatorEmulator();
    const rpId = new RpId("example.com");
    const userHandle = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const credential = authenticator.authenticatorMakeCredential({
      rp: { id: rpId.value, name: "example" },
      user: { id: userHandle, name: "example", displayName: "example" },
      pubKeyCredParams: [{ alg, type: "public-key" }],
      clientDataHash: new Uint8Array(32),
    });
    return unpackAuthenticatorData(credential.authData).attestedCredentialData?.credentialPublicKey as CoseKey;
  };

  test("Der format _ serialize and deserialize test", async () => {
    const testCoseKey = getKey();
    const serialized = testCoseKey.toDer();
    const deserialized = CoseKey.fromDer(testCoseKey.toDer());
    const reSerialized = deserialized.toDer();

    expect(testCoseKey.alg).toEqual(alg);
    expect(testCoseKey).toEqual(deserialized);
    expect(serialized).toEqual(reSerialized);
  });

  test("Jwk format _ serialize and deserialize test", async () => {
    const testCoseKey = getKey();
    const serialized = testCoseKey.toJwk();
    const deserialized = CoseKey.fromJwk(testCoseKey.toJwk()).toJwk();
    const reSerialized = CoseKey.fromJwk(deserialized).toJwk();

    expect(testCoseKey.alg).toEqual(alg);
    expect(serialized).toEqual(deserialized);
    expect(serialized).toEqual(reSerialized);
  });

  test("KeyObject format _ serialize and deserialize test", async () => {
    const testCoseKey = getKey();
    const serialized = testCoseKey.toKeyObject();
    const deserialized = CoseKey.fromKeyObject(testCoseKey.toKeyObject()).toKeyObject();
    const reSerialized = CoseKey.fromKeyObject(deserialized).toKeyObject();

    expect(testCoseKey.alg).toEqual(alg);
    expect(serialized).toEqual(deserialized);
    expect(serialized).toEqual(reSerialized);
  });
});
