import { describe, expect, test } from "@jest/globals";
import EncodeUtils from "../../src/libs/encode-utils";
import { WebAuthnEmulator } from "../../src/webauthn/webauthn-emulator";
import { packAttestationObject, unpackAttestationObject } from "../../src/webauthn/webauthn-model";

describe("WebAuthn Model Test", () => {
  const webauthnEmulator = new WebAuthnEmulator();
  test("Attestation Object pack and unpack", async () => {
    const createResponse = webauthnEmulator.create("https://test-rp.org", {
      publicKey: {
        rp: { name: "test-rp.org", id: "test-rp.org" },
        user: { id: EncodeUtils.strToUint8Array("test-user"), name: "user", displayName: "user" },
        challenge: EncodeUtils.strToUint8Array("challenge"),
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      },
    });

    const testData = new Uint8Array(createResponse.response.attestationObject);
    const unpacked = unpackAttestationObject(testData);
    const rePacked = packAttestationObject(unpacked);
    const reUnpacked = unpackAttestationObject(rePacked);

    expect(rePacked).toEqual(testData);
    expect(reUnpacked).toEqual(unpacked);
  });
});
