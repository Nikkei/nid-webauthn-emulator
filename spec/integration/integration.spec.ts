import { describe, test } from "@jest/globals";
import WebAuthnApiEmulator from "../../src/index";
import { parseCreationOptionsFromJSON, parseRequestOptionsFromJSON } from "../../src/webauthn/webauthn-model-json";
import { WebAuthnIO } from "./webauthn-io";

describe("Passkeys Integration Test by webauthn.io", () => {
  test("Registration Ceremony and Authentication Ceremony", async () => {
    const origin = "https://webauthn.io";
    const webAuthnApiEmulator = new WebAuthnApiEmulator();
    const webauthnIO = await WebAuthnIO.create();

    // Create passkey.
    const creationOptions = { publicKey: parseCreationOptionsFromJSON(await webauthnIO.getRegistrationOptions()) };
    console.log("Registration options", creationOptions);
    const creationCredential = await webAuthnApiEmulator.create(origin, creationOptions);
    console.log("Registration credential", creationCredential.toJSON());
    await webauthnIO.getRegistrationVerification(creationCredential.toJSON());
    console.log("Registration verification completed");

    // Authenticate passkey.
    const requestOptions = { publicKey: parseRequestOptionsFromJSON(await webauthnIO.getAuthenticationOptions()) };
    console.log("Authentication options", requestOptions);
    const requestCredential = await webAuthnApiEmulator.get(origin, requestOptions);
    console.log("Authentication credential", requestCredential.toJSON());
    await webauthnIO.getAuthenticationVerification(requestCredential.toJSON());
    console.log("Authentication verification completed");
  }, 60000);
});
