import { describe, expect, test } from "@jest/globals";
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

    expect(await PublicKeyCredential.isConditionalMediationAvailable()).toBeTruthy();
    expect(window.navigator.credentials.create).toBeDefined();
    expect(window.navigator.credentials.get).toBeDefined();
    expect(PublicKeyCredential.signalUnknownCredential).toBeDefined();
  });
});
