import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { AuthenticatorOptions } from "../../src";
import EncodeUtils from "../../src/libs/encode-utils";
import { WebAuthnEmulator } from "../../src/webauthn/webauthn-emulator";
import {
  type AttestationObject,
  type PublicKeyCredentialSource,
  packAttestationObject,
  parsePublicKeyCredentialSourceFromJSON,
  RpId,
  toFido2CreateOptions,
  toFido2RequestOptions,
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
    assert.deepEqual(rePacked, testData);
    assert.deepEqual(reUnpacked, unpacked);
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
        attestedCredentialData: undefined,
      },
      attStmt: { test: "test123" },
    };

    const packed = packAttestationObject(testData);
    const unpacked = unpackAttestationObject(packed);
    assert.deepEqual(unpacked, testData);
  });

  test("Undefined User Handle PublicKey serialize test", async () => {
    const testData: PublicKeyCredentialSource = {
      type: "public-key",
      id: new Uint8Array([116, 101, 115, 116, 45, 99]),
      privateKey: new Uint8Array([116, 101, 115, 116, 45, 99]),
      rpId: new RpId("test-rp.org"),
      userHandle: undefined,
    };
    const json = toPublickeyCredentialSourceJSON(testData);
    const model = parsePublicKeyCredentialSourceFromJSON(json);
    assert.deepEqual(model, testData);
  });

  const createOptionCases: [AuthenticatorSelectionCriteria, AuthenticatorOptions][] = [
    [
      { residentKey: "required", userVerification: "required" },
      { rk: true, uv: true, up: true },
    ],
    [
      { residentKey: "preferred", userVerification: "preferred" },
      { rk: true, uv: true, up: true },
    ],
    [
      { residentKey: "discouraged", userVerification: "discouraged" },
      { rk: false, uv: false, up: true },
    ],
    [
      { requireResidentKey: true, userVerification: "preferred" },
      { rk: true, uv: true, up: true },
    ],
    [
      { residentKey: "discouraged", userVerification: "preferred" },
      { rk: false, uv: true, up: true },
    ],
    [
      { requireResidentKey: false, userVerification: "preferred" },
      { rk: false, uv: true, up: true },
    ],
  ];

  for (const [criteria, expected] of createOptionCases) {
    test(`toFido2CreateOptions test: ${JSON.stringify(criteria)}`, () => {
      assert.deepEqual(toFido2CreateOptions(criteria), expected);
    });
  }

  const userVerificationCases: [UserVerificationRequirement | undefined, boolean][] = [
    ["required", true],
    ["preferred", true],
    ["discouraged", false],
    [undefined, false],
  ];

  for (const [criteria, expected] of userVerificationCases) {
    test(`UserVerificationRequirement test: ${criteria}`, () => {
      assert.deepEqual(toFido2RequestOptions(criteria).uv, expected);
    });
  }
});
