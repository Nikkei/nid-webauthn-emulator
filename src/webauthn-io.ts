import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "./libs/json";
import type { PasskeysApiClient } from "./test-utils/passkeys-api-client";

export class WebAuthnIO implements PasskeysApiClient {
  private constructor(private sessionId: string) {}

  public static async create(): Promise<WebAuthnIO> {
    const sessionId = await WebAuthnIO.getSessionId();
    return new WebAuthnIO(sessionId);
  }

  public async getRegistrationOptions(): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const optionsRequest = {
      username: "test-user",
      user_verification: "preferred",
      attestation: "none",
      attachment: "all",
      algorithms: ["es256", "rs256"],
      discoverable_credential: "preferred",
      hints: [],
    };

    const options = await fetch("https://webauthn.io/registration/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(optionsRequest),
    });
    const optionsJson = await options.json();
    return optionsJson;
  }

  public async getRegistrationVerification(response: RegistrationResponseJSON): Promise<void> {
    const verificationRequest = {
      response: response,
      username: "test-user",
    };

    const verification = await fetch("https://webauthn.io/registration/verification", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verificationRequest),
    });
    const verificationJson = await verification.json();
    if (!verificationJson.verified) {
      throw new Error(`Verification failed: ${JSON.stringify(verificationJson)}`);
    }
  }

  public async getAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const optionsRequest = {
      user_verification: "preferred",
    };
    const options = await fetch("https://webauthn.io/authentication/options", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `sessionid=${this.sessionId}` },
      body: JSON.stringify(optionsRequest),
    });
    const optionsJson = await options.json();
    return optionsJson;
  }

  public async getAuthenticationVerification(response: AuthenticationResponseJSON): Promise<void> {
    const verificationRequest = {
      response: response,
      username: "",
    };
    const verification = await fetch("https://webauthn.io/authentication/verification", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `sessionid=${this.sessionId}` },
      body: JSON.stringify(verificationRequest),
    });
    const verificationJson = await verification.json();
    if (!verificationJson.verified) {
      throw new Error(`Verification failed: ${JSON.stringify(verificationJson)}`);
    }
  }

  private static async getSessionId(): Promise<string> {
    const home = await fetch("https://webauthn.io/");
    return home.headers.get("set-cookie")?.split(";")[0].split("=")[1] ?? "";
  }
}
