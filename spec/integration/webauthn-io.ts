import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "../../src/webauthn/webauthn-model-json";
import type { PasskeysApiClient, PasskeysUser } from "./passkeys-api-client";

/**
 * Passkeys Api Client implementation for webauthn.io
 */
export class WebAuthnIO implements PasskeysApiClient {
  private constructor(private sessionId: string) {}

  public static async create(): Promise<WebAuthnIO> {
    const sessionId = await WebAuthnIO.getSessionId();
    return new WebAuthnIO(sessionId);
  }

  public getUser(): PasskeysUser {
    return { username: `user-${this.sessionId}`, id: this.sessionId };
  }

  /**
   * Get a passkey registration options by https://webauthn.io/registration/options
   * @returns PublicKeyCredentialCreationOptionsJSON
   */
  public async getRegistrationOptions(user: PasskeysUser): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const optionsRequest = {
      username: user.username,
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

  /**
   * Register your passkey account by https://webauthn.io/registration/verification
   * @param response RegistrationResponseJSON
   */
  public async getRegistrationVerification(user: PasskeysUser, response: RegistrationResponseJSON): Promise<void> {
    const verificationRequest = {
      response: response,
      username: user.username,
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

  /**
   * Get a passkey authentication options by https://webauthn.io/authentication/options
   * @returns PublicKeyCredentialRequestOptionsJSON
   */
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

  /**
   * Authenticate your passkey account by https://webauthn.io/authentication/verification
   * @param response AuthenticationResponseJSON
   */
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
