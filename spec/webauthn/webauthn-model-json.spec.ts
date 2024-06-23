import { describe, expect, test } from "@jest/globals";
import EncodeUtils from "../../src/libs/encode-utils";
import { WebAuthnEmulator } from "../../src/webauthn/webauthn-emulator";
import {
  parseAuthenticationResponseFromJSON,
  parseCreationOptionsFromJSON,
  parseRegistrationResponseFromJSON,
  parseRequestOptionsFromJSON,
  toAuthenticationResponseJSON,
  toCreationOptionsJSON,
  toRegistrationResponseJSON,
  toRequestOptionsJSON,
} from "../../src/webauthn/webauthn-model-json";

describe("WebAuthn JSON Model Test", () => {
  const creationOption: PublicKeyCredentialCreationOptions = {
    rp: { name: "test-rp.org", id: "test-rp.org" },
    user: { id: EncodeUtils.strToUint8Array("test-user"), name: "user", displayName: "user" },
    challenge: EncodeUtils.strToUint8Array("challenge"),
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
  };

  const requestOption: PublicKeyCredentialRequestOptions = {
    challenge: EncodeUtils.strToUint8Array("challenge"),
    allowCredentials: [{ id: EncodeUtils.strToUint8Array("test-credential"), type: "public-key" }],
    rpId: "test-rp.org",
    timeout: 60000,
    userVerification: "required",
  };

  const emulator = new WebAuthnEmulator();

  test("Create Option JSON Serialize Deserialize test", async () => {
    const json = toCreationOptionsJSON(creationOption);
    const model = parseCreationOptionsFromJSON(json);
    const reJson = toCreationOptionsJSON(model);

    expect(reJson).toEqual(json);
  });

  test("Create Response JSON Serialize Deserialize test", async () => {
    const response = emulator.create("https://test-rp.org", { publicKey: creationOption });

    const json = toRegistrationResponseJSON(response);
    const model = parseRegistrationResponseFromJSON(json);
    const reJson = toRegistrationResponseJSON(model);

    expect(reJson).toEqual(json);
  });

  test("Get Option JSON Serialize Deserialize test", async () => {
    const json = toRequestOptionsJSON(requestOption);
    const model = parseRequestOptionsFromJSON(json);
    const reJson = toRequestOptionsJSON(model);

    expect(reJson).toEqual(json);
  });

  test("Get Response JSON Serialize Deserialize test", async () => {
    const response = emulator.get("https://test-rp.org", {
      publicKey: { ...requestOption, allowCredentials: undefined },
    });
    const json = toAuthenticationResponseJSON(response);
    const model = parseAuthenticationResponseFromJSON(json);
    const reJson = toAuthenticationResponseJSON(model);
    expect(reJson).toEqual(json);
  });
});
