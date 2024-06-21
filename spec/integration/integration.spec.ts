import { describe, test } from "@jest/globals";
import WebAuthnApiEmulator from "../../src/index";
import { WebAuthnIO } from "./webauthn-io";

describe("Passkeys Integration Test by webauthn.io", () => {
  test("Registration Ceremony and Authentication Ceremony", async () => {
    const origin = "https://webauthn.io";
    const webAuthnApiEmulator = new WebAuthnApiEmulator();
    const webauthnIO = await WebAuthnIO.create();

    // Create passkey.
    const creationOptions = await webauthnIO.getRegistrationOptions();
    console.log("Registration options", creationOptions);
    const creationCredential = webAuthnApiEmulator.createJSON(origin, creationOptions);
    console.log("Registration credential", creationCredential);
    await webauthnIO.getRegistrationVerification(creationCredential);
    console.log("Registration verification completed");

    // Authenticate passkey.
    const requestOptions = await webauthnIO.getAuthenticationOptions();
    console.log("Authentication options", requestOptions);
    const requestCredential = webAuthnApiEmulator.getJSON(origin, requestOptions);
    console.log("Authentication credential", requestCredential);
    await webauthnIO.getAuthenticationVerification(requestCredential);
    console.log("Authentication verification completed");
  }, 60000);
});
