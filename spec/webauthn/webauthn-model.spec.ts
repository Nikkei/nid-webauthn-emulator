import { describe, expect, test } from "@jest/globals";
import EncodeUtils from "../../src/libs/encode-utils";
import { WebAuthnEmulator } from "../../src/webauthn/webauthn-emulator";
import {
  type AttestationObject,
  type PublicKeyCredentialSource,
  RpId,
  packAttestationObject,
  parsePublicKeyCredentialSourceFromJSON,
  toPublickeyCredentialSourceJSON,
  unpackAttestationObject,
} from "../../src/webauthn/webauthn-model";

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

  test("Attestation Object pack and unpack optional1", async () => {
    const testData: AttestationObject = {
      fmt: "none",
      authData: {
        flags: {
          userPresent: false,
          userVerified: false,
          backupEligibility: false,
          backupState: false,
          extensionData: true,
          attestedCredentialData: false,
        },
        rpIdHash: new Uint8Array(32),
        signCount: 0,
      },
      attStmt: { test: "test123" },
    };

    const packed = packAttestationObject(testData);
    const unpacked = unpackAttestationObject(packed);
    expect(unpacked).toEqual(testData);
  });

  test("Undefined User Handle serialize test", async () => {
    const testData: PublicKeyCredentialSource = {
      type: "public-key",
      id: new Uint8Array([116, 101, 115, 116, 45, 99]),
      privateKey: new Uint8Array([116, 101, 115, 116, 45, 99]),
      rpId: new RpId("test-rp.org"),
      userHandle: undefined,
    };
    const json = toPublickeyCredentialSourceJSON(testData);
    const model = parsePublicKeyCredentialSourceFromJSON(json);
    expect(model).toEqual(testData);
  });
});
