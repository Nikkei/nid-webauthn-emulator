import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "../../src";
import type { PasskeysApiClient, PasskeysUser } from "../integration/passkeys-api-client";

type UserModel = {
  id: string;
  username: string;
};

type CredentialRecord = {
  id: string;
  publicKey: Uint8Array<ArrayBuffer>;
  user: UserModel;
  webauthnUserID: string;
  counter: number;
  backedUp: boolean;
  transports?: AuthenticatorTransport[];
};

export const TEST_RP_ORIGIN = "https://test-rp.com";
export const TEST_RP_ID = "test-rp.com";

export class WebAuthnTestServer implements PasskeysApiClient {
  private challenges: Set<string> = new Set();
  private credentials: CredentialRecord[] = [];

  constructor(
    public origin = TEST_RP_ORIGIN,
    public rpID = TEST_RP_ID,
  ) {}

  async getRegistrationOptions(user: PasskeysUser): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const options = await generateRegistrationOptions({
      rpName: "Test RP",
      rpID: this.rpID,
      userName: user.username,
      attestationType: "none",
      excludeCredentials: this.credentials.map((cred) => ({
        id: cred.id,
        type: "public-key",
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
        authenticatorAttachment: "platform",
      },
    });
    options.user.id;
    this.challenges.add(options.challenge);
    return options;
  }

  async getRegistrationVerification(user: PasskeysUser, response: RegistrationResponseJSON): Promise<void> {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: (challenge) => this.challenges.has(challenge),
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
    });

    if (!verification.verified || !verification.registrationInfo) throw new Error("Registration verification failed");
    const registrationInfo = verification.registrationInfo;
    this.credentials.push({
      id: response.id,
      publicKey: registrationInfo.credential.publicKey as Uint8Array<ArrayBuffer>,
      user,
      webauthnUserID: user.id,
      counter: registrationInfo.credential.counter,
      backedUp: false,
      transports: undefined,
    });
  }

  async getAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const options = await generateAuthenticationOptions({
      rpID: this.rpID,
      allowCredentials: this.credentials.map((cred) => ({
        id: cred.id,
        type: "public-key",
      })),
    });
    this.challenges.add(options.challenge);
    return options;
  }

  async getAuthenticationVerification(response: AuthenticationResponseJSON): Promise<void> {
    const credential = this.credentials.find((cred) => cred.id === response.id);
    if (!credential) throw new Error("Credential not found");

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: (challenge) => this.challenges.has(challenge),
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      credential: {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      },
    });
    if (!verification.verified) throw new Error("Authentication verification failed");
  }
}
