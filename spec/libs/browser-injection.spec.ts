import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { AuthenticatorEmulator } from "../../src/authenticator/authenticator-emulator";
import EncodeUtils from "../../src/libs/encode-utils";
import { HookWebAuthnApis } from "../../src/test-utils/browser-injection";
import { WebAuthnEmulator } from "../../src/webauthn/webauthn-emulator";

describe("Browser Injection Test", () => {
  test("Browser Injection Test", async () => {
    const window = { navigator: { credentials: { create: undefined, get: undefined } } };
    const PublicKeyCredential = {
      isConditionalMediationAvailable: async () => false,
      signalUnknownCredential: undefined,
    };

    // biome-ignore lint/security/noGlobalEval: This is a test code.
    eval(HookWebAuthnApis);

    assert.ok(await PublicKeyCredential.isConditionalMediationAvailable());
    assert.notEqual(window.navigator.credentials.create, undefined);
    assert.notEqual(window.navigator.credentials.get, undefined);
    assert.notEqual(PublicKeyCredential.signalUnknownCredential, undefined);
  });

  // The hooked create/get run in-page, so every helper they reach must be exported.
  test("hooked create and get round-trip prf through the emulator", async () => {
    const origin = "https://test-rp.org";
    const emulator = new WebAuthnEmulator(new AuthenticatorEmulator({ hmacSecret: "hmac-secret-mc" }));

    const window: {
      navigator: {
        credentials: {
          create?: (options: { publicKey: unknown }) => Promise<PublicKeyCredential>;
          get?: (options: { publicKey: unknown }) => Promise<PublicKeyCredential>;
        };
      };
      webAuthnEmulatorCreate: (
        optionsJSON: PublicKeyCredentialCreationOptionsJSON,
      ) => Promise<RegistrationResponseJSON>;
      webAuthnEmulatorGet: (optionsJSON: PublicKeyCredentialRequestOptionsJSON) => Promise<AuthenticationResponseJSON>;
    } = {
      navigator: { credentials: { create: undefined, get: undefined } },
      webAuthnEmulatorCreate: async (optionsJSON) => emulator.createJSON(origin, optionsJSON),
      webAuthnEmulatorGet: async (optionsJSON) => emulator.getJSON(origin, optionsJSON),
    };
    const PublicKeyCredential = { isConditionalMediationAvailable: async () => false };

    // biome-ignore lint/security/noGlobalEval: This is a test code.
    eval(HookWebAuthnApis);
    assert.ok(await PublicKeyCredential.isConditionalMediationAvailable());

    const first = EncodeUtils.strToUint8Array("prf-input-first");
    const create = window.navigator.credentials.create;
    assert.ok(create);
    const created = await create({
      publicKey: {
        rp: { id: "test-rp.org", name: "rp" },
        user: { id: EncodeUtils.strToUint8Array("user"), name: "user", displayName: "user" },
        challenge: EncodeUtils.strToUint8Array("challenge"),
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        extensions: { prf: { eval: { first } } },
      },
    });
    const createdPrf = created.getClientExtensionResults().prf?.results?.first;
    assert.ok(createdPrf instanceof ArrayBuffer);
    assert.equal(createdPrf.byteLength, 32);

    const get = window.navigator.credentials.get;
    assert.ok(get);
    const asserted = await get({
      publicKey: {
        rpId: "test-rp.org",
        challenge: EncodeUtils.strToUint8Array("challenge-2"),
        extensions: { prf: { eval: { first } } },
      },
    });
    const assertedPrf = asserted.getClientExtensionResults().prf?.results?.first;
    assert.ok(assertedPrf instanceof ArrayBuffer);
    assert.deepEqual(new Uint8Array(assertedPrf), new Uint8Array(createdPrf));
  });
});
