import { describe, test } from "@jest/globals";
import { expect } from "@jest/globals";
import { AuthenticatorEmulator } from "../../src";
import { type CTAPAuthenticatorRequest, CTAP_COMMAND } from "../../src/authenticator/ctap-model";

describe("Authenticator Emulator Exceptional Test", () => {
  // Success case has been tested in the webauthn-emulator.spec.ts

  test("Unknown command _ CTAP Error", async () => {
    const testRequest: CTAPAuthenticatorRequest = {
      command: CTAP_COMMAND.authenticatorReset,
    };
    const authenticator = new AuthenticatorEmulator();
    expect(() => {
      authenticator.command(testRequest);
    }).toThrowError("CTAP error: CTAP1_ERR_INVALID_COMMAND (1)");
  });
});
