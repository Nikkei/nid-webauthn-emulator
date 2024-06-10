import { describe, test } from "@jest/globals";
import { PasskeysTestAuthenticator } from "./passkeys-test-authenticator";
import { WebAuthnIO } from "./webauthn-io";
import { authenticationCeremony, registrationCeremony } from "./test-utils/passkeys-ceremony";

describe("webauthn.io を利用した Passkeys の登録とログイン", () => {
  test("Registration Ceremony and Authentication Ceremony", async () => {
    const authenticator = new PasskeysTestAuthenticator("https://webauthn.io");
    const webauthnIO = await WebAuthnIO.create();

    await registrationCeremony(authenticator, webauthnIO);
    await authenticationCeremony(authenticator, webauthnIO);
  });
});
