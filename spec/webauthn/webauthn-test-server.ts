import { randomBytes } from "node:crypto";
import {
  type VerifiedCredential,
  verifyAuthentication,
  verifyRegistration,
  WebAuthnVerificationError,
} from "../../src";
import type { PasskeysApiClient, PasskeysUser } from "../integration/passkeys-api-client";

export const TEST_RP_ORIGIN = "https://test-rp.com";
export const TEST_RP_ID = "test-rp.com";

/** In-memory test RP, limited to the emulator's none attestation and ES256/EdDSA/RS256 keys. */
export class WebAuthnTestServer implements PasskeysApiClient {
  // Tests intentionally reuse options to exercise multiple responses to the same challenge.
  private registrationChallenges = new Map<string, string>();
  private authenticationChallenge?: string;
  private credentials = new Map<string, VerifiedCredential>();

  constructor(
    public origin = TEST_RP_ORIGIN,
    public rpID = TEST_RP_ID,
  ) {}

  async getRegistrationOptions(user: PasskeysUser): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const challenge = randomBytes(32).toString("base64url");
    this.registrationChallenges.set(user.id, challenge);
    return {
      challenge,
      rp: { name: "Test RP", id: this.rpID },
      user: { id: randomBytes(32).toString("base64url"), name: user.username, displayName: "" },
      pubKeyCredParams: [-8, -7, -257].map((alg) => ({ type: "public-key", alg })),
      timeout: 60_000,
      attestation: "none",
      excludeCredentials: this.credentialDescriptors(),
      authenticatorSelection: {
        residentKey: "preferred",
        requireResidentKey: false,
        userVerification: "preferred",
        authenticatorAttachment: "platform",
      },
      extensions: { credProps: true },
    };
  }

  async getRegistrationVerification(user: PasskeysUser, response: RegistrationResponseJSON): Promise<void> {
    const expectedChallenge = this.registrationChallenges.get(user.id);
    if (!expectedChallenge) throw new WebAuthnVerificationError("INVALID_OPTIONS", "Registration options are required");
    const { credential } = verifyRegistration({
      response,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      expectedChallenge,
      supportedAlgorithmIDs: [-8, -7, -257],
    });
    this.credentials.set(credential.id, credential);
  }

  async getAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const challenge = randomBytes(32).toString("base64url");
    this.authenticationChallenge = challenge;
    return {
      rpId: this.rpID,
      challenge,
      allowCredentials: this.credentialDescriptors(),
      timeout: 60_000,
      userVerification: "preferred",
    };
  }

  async getAuthenticationVerification(response: AuthenticationResponseJSON): Promise<void> {
    const credential = this.credentials.get(response.id);
    if (!credential) throw new Error("Credential not found");
    if (!this.authenticationChallenge)
      throw new WebAuthnVerificationError("INVALID_OPTIONS", "Authentication options are required");
    const result = verifyAuthentication({
      response,
      credential,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      expectedChallenge: this.authenticationChallenge,
    });
    credential.counter = result.newCounter;
    credential.backupState = result.backupState;
  }

  private credentialDescriptors(): PublicKeyCredentialDescriptorJSON[] {
    return [...this.credentials.keys()].map((id) => ({ id, type: "public-key" }));
  }
}
