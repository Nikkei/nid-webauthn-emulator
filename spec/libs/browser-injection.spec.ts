import { describe, expect, test } from "@jest/globals";
import { HookWebAuthnApis } from "../../src/libs/browser-injection";

describe("Browser Injection Test", () => {
  test("Browser Injection Test", async () => {
    const window = { navigator: { credentials: { create: undefined, get: undefined } } };
    const PublicKeyCredential = { isConditionalMediationAvailable: async () => false };

    // biome-ignore lint/security/noGlobalEval: This is a test code.
    eval(HookWebAuthnApis);

    expect(await PublicKeyCredential.isConditionalMediationAvailable()).toBeTruthy();
    expect(window.navigator.credentials.create).toBeDefined();
    expect(window.navigator.credentials.get).toBeDefined();
  });
});
