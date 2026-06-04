import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { AuthenticatorEmulator } from "../../src/authenticator/authenticator-emulator";
import { CoseKey } from "../../src/webauthn/cose-key";
import { RpId, unpackAuthenticatorData } from "../../src/webauthn/webauthn-model";

for (const alg of [-7, -8, -257]) {
  describe(`CoseKey Test: ${alg}`, () => {
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

      assert.deepEqual(testCoseKey.alg, alg);
      assert.deepEqual(testCoseKey, deserialized);
      assert.deepEqual(serialized, reSerialized);
    });

    test("Jwk format _ serialize and deserialize test", async () => {
      const testCoseKey = getKey();
      const serialized = testCoseKey.toJwk();
      const deserialized = CoseKey.fromJwk(testCoseKey.toJwk()).toJwk();
      const reSerialized = CoseKey.fromJwk(deserialized).toJwk();

      assert.deepEqual(testCoseKey.alg, alg);
      assert.deepEqual(serialized, deserialized);
      assert.deepEqual(serialized, reSerialized);
    });

    test("KeyObject format _ serialize and deserialize test", async () => {
      const testCoseKey = getKey();
      const serialized = testCoseKey.toKeyObject();
      const deserialized = CoseKey.fromKeyObject(testCoseKey.toKeyObject()).toKeyObject();
      const reSerialized = CoseKey.fromKeyObject(deserialized).toKeyObject();

      assert.deepEqual(testCoseKey.alg, alg);
      assert.deepEqual(serialized, deserialized);
      assert.deepEqual(serialized, reSerialized);
    });
  });
}
