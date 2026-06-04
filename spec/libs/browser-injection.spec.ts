import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { HookWebAuthnApis } from "../../src/test-utils/browser-injection";

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
});
