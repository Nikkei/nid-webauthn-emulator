import { describe, expect, test } from "@jest/globals";
import EncodeUtils from "../../src/libs/encode-utils";
import { WebAuthnEmulator } from "../../src/webauthn/webauthn-api";
import { packAttestationObject, unpackAttestationObject } from "../../src/webauthn/webauthn-model";

describe("WebAuthn Model Test", () => {
  const webauthnEmulator = new WebAuthnEmulator();
  test("Attestation Object pack and unpack", async () => {
    const createResponse = webauthnEmulator.create("https://webauthn.io", {
      publicKey: {
        rp: { name: "webauthn.io", id: "webauthn.io" },
        user: { id: EncodeUtils.strToUint8Array("test-user"), name: "user", displayName: "user" },
        challenge: EncodeUtils.strToUint8Array("challenge"),
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      },
    });

    webauthnEmulator.authenticator.credentials[0].authenticatorData.signCount = 12;
    const testData = new Uint8Array(createResponse.response.attestationObject);
    const unpacked = unpackAttestationObject(testData);
    const rePacked = packAttestationObject(unpacked);
    const reUnpacked = unpackAttestationObject(rePacked);

    expect(rePacked).toEqual(testData);
    expect(reUnpacked).toEqual(unpacked);
  });
});
