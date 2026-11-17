import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { AuthenticatorEmulator } from "../../src/authenticator/authenticator-emulator";
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
    excludeCredentials: [{ id: EncodeUtils.strToUint8Array("test-credential"), type: "public-key" }],
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

  const creationOptionPrf: PublicKeyCredentialCreationOptions = {
    ...creationOption,
    extensions: {
      prf: {
        eval: {
          first: EncodeUtils.strToUint8Array("prf-eval-first"),
          second: EncodeUtils.strToUint8Array("prf-eval-second"),
        },
      },
    },
  };

  const requestOptionPrf: PublicKeyCredentialRequestOptions = {
    ...requestOption,
    extensions: {
      prf: {
        eval: {
          first: EncodeUtils.strToUint8Array("prf-eval-first"),
          second: EncodeUtils.strToUint8Array("prf-eval-second"),
        },
      },
    },
  };

  test("rejects malformed base64url throughout registration and authentication options with EncodingError", () => {
    const creation = toCreationOptionsJSON(creationOption);
    const request = toRequestOptionsJSON(requestOption);
    for (const invalid of ["!", "a", "YQ==", "Y Q", "YQ\n", "+w", "/w"]) {
      const creationCases: PublicKeyCredentialCreationOptionsJSON[] = [
        { ...creation, challenge: invalid },
        { ...creation, user: { ...creation.user, id: invalid } },
        { ...creation, excludeCredentials: [{ type: "public-key", id: invalid }] },
        { ...creation, extensions: { prf: { eval: { first: invalid } } } },
        { ...creation, extensions: { prf: { eval: { first: "YQ", second: invalid } } } },
      ];
      const requestCases: PublicKeyCredentialRequestOptionsJSON[] = [
        { ...request, challenge: invalid },
        { ...request, allowCredentials: [{ type: "public-key", id: invalid }] },
        { ...request, extensions: { prf: { eval: { first: invalid } } } },
        { ...request, extensions: { prf: { eval: { first: "YQ", second: invalid } } } },
        { ...request, extensions: { prf: { evalByCredential: { YQ: { first: invalid } } } } },
        { ...request, extensions: { prf: { evalByCredential: { YQ: { first: "YQ", second: invalid } } } } },
      ];
      for (const options of creationCases) {
        assert.throws(() => parseCreationOptionsFromJSON(options), { name: "EncodingError" });
      }
      for (const options of requestCases) {
        assert.throws(() => parseRequestOptionsFromJSON(options), { name: "EncodingError" });
      }
    }
  });

  test("decodes unpadded base64url and empty PRF inputs without changing the JSON input", () => {
    const json: PublicKeyCredentialRequestOptionsJSON = {
      challenge: "-_8",
      allowCredentials: [{ type: "public-key", id: "YQ" }],
      extensions: { prf: { eval: { first: "", second: "YWI" }, evalByCredential: { YQ: { first: "YWJj" } } } },
    };
    const before = JSON.stringify(json);
    const options = parseRequestOptionsFromJSON(json);
    assert.deepEqual(new Uint8Array(options.challenge as ArrayBuffer), Uint8Array.of(251, 255));
    assert.deepEqual(new Uint8Array(options.allowCredentials?.[0].id as ArrayBuffer), Uint8Array.of(97));
    assert.deepEqual(options.extensions?.prf?.eval, {
      first: new ArrayBuffer(0),
      second: Uint8Array.of(97, 98).buffer,
    });
    assert.deepEqual(options.extensions?.prf?.evalByCredential?.YQ.first, Uint8Array.of(97, 98, 99).buffer);
    assert.equal(JSON.stringify(json), before);
  });

  test("Create Option JSON Serialize Deserialize test", async () => {
    for (const option of [creationOption, creationOptionPrf]) {
      const json = toCreationOptionsJSON(option);
      const model = parseCreationOptionsFromJSON(json);
      const reJson = toCreationOptionsJSON(model);
      assert.deepEqual(reJson, json);
    }
  });

  test("Create Response JSON Serialize Deserialize test", async () => {
    const cases = [
      { emulator: new WebAuthnEmulator(), option: creationOption },
      {
        emulator: new WebAuthnEmulator(new AuthenticatorEmulator({ hmacSecret: "hmac-secret-mc" })),
        option: creationOptionPrf,
      },
    ];
    for (const { emulator, option } of cases) {
      const response = emulator.create("https://test-rp.org", { publicKey: option });
      const json = toRegistrationResponseJSON(response);
      const model = parseRegistrationResponseFromJSON(json);
      const reJson = toRegistrationResponseJSON(model);
      assert.deepEqual(reJson, json);
    }
  });

  test("Get Option JSON Serialize Deserialize test", async () => {
    for (const option of [requestOption, requestOptionPrf]) {
      const json = toRequestOptionsJSON(option);
      const model = parseRequestOptionsFromJSON(json);
      const reJson = toRequestOptionsJSON(model);
      assert.deepEqual(reJson, json);
    }
  });

  test("Get Response JSON Serialize Deserialize test", async () => {
    const cases = [
      { emulator: new WebAuthnEmulator(), createOption: creationOption, getOption: requestOption },
      {
        emulator: new WebAuthnEmulator(new AuthenticatorEmulator({ hmacSecret: "hmac-secret-mc" })),
        createOption: creationOptionPrf,
        getOption: requestOptionPrf,
      },
    ];
    for (const { emulator, createOption, getOption } of cases) {
      emulator.create("https://test-rp.org", { publicKey: createOption });
      const response = emulator.get("https://test-rp.org", {
        publicKey: { ...getOption, allowCredentials: undefined },
      });
      const json = toAuthenticationResponseJSON(response);
      const model = parseAuthenticationResponseFromJSON(json);
      const reJson = toAuthenticationResponseJSON(model);
      assert.deepEqual(reJson, json);
    }
  });

  test("Create Response JSON optional test", async () => {
    const emulator = new WebAuthnEmulator();
    const customOption = { publicKey: { ...creationOption, excludeCredentials: undefined } };
    const json = emulator.createJSON("https://test-rp.org", toCreationOptionsJSON(customOption.publicKey));
    const customJson: RegistrationResponseJSON = {
      ...json,
      authenticatorAttachment: "platform",
      response: { ...json.response, publicKey: undefined, publicKeyAlgorithm: -1 },
    };
    const model = parseRegistrationResponseFromJSON(customJson);
    assert.deepEqual(model.authenticatorAttachment, customJson.authenticatorAttachment);
    assert.equal(model.response.getPublicKey(), null);
    assert.deepEqual(model.response.getPublicKeyAlgorithm(), -1);
    assert.deepEqual(toRegistrationResponseJSON(model), customJson);
    assert.deepEqual(model.toJSON(), customJson);
  });

  test("Get Response JSON optional test", async () => {
    const emulator = new WebAuthnEmulator();
    const customOption = { publicKey: { ...requestOption, allowCredentials: undefined } };
    const json = emulator.getJSON("https://test-rp.org", toRequestOptionsJSON(customOption.publicKey));
    const customJson: AuthenticationResponseJSON = {
      ...json,
      authenticatorAttachment: "platform",
      response: { ...json.response, userHandle: undefined },
    };
    const model = parseAuthenticationResponseFromJSON(customJson);
    assert.equal(model.response.userHandle, null);
    assert.deepEqual(toAuthenticationResponseJSON(model), customJson);
    assert.deepEqual(model.toJSON(), customJson);
  });

  test("Parse Authentication Response with User Handle JSON test", async () => {
    const testData: AuthenticationResponseJSON = {
      type: "public-key",
      id: "AAAAAA",
      rawId: "AAAAAA",
      response: {
        clientDataJSON: "BBBBBB",
        authenticatorData: "CCCCCC",
        signature: "DDDDDD",
        userHandle: "EEEEEE",
      },
      clientExtensionResults: {},
    };
    const model = parseAuthenticationResponseFromJSON(testData);
    const json = model.toJSON();
    assert.deepEqual(json, testData);
  });
});
