import { describe, test } from "@jest/globals";
import { PasskeysTestAuthenticator } from "./passkeys-test-authenticator";
import { authenticationCeremony, registrationCeremony } from "./test-utils/passkeys-ceremony";
import { WebAuthnIO } from "./webauthn-io";

describe("webauthn.io を利用した Passkeys の登録とログイン", () => {
  test("Registration Ceremony and Authentication Ceremony", async () => {
    const authenticator = new PasskeysTestAuthenticator("https://webauthn.io");
    const webauthnIO = await WebAuthnIO.create();

    await registrationCeremony(authenticator, webauthnIO);
    await authenticationCeremony(authenticator, webauthnIO);
  });
});
