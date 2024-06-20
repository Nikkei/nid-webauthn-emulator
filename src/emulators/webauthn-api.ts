import EncodeUtils from "../libs/encode-utils";
import {
  type AuthenticationPublicKeyCredential,
  type RegistrationPublicKeyCredential,
  toAuthenticationResponseJson,
  toRegistrationResponseJson,
} from "../webauthn/webauthn-model-json";
import { AuthenticatorEmulator } from "./authenticator";

import {
  type AttestationObject,
  type AuthenticatorData,
  type CollectedClientData,
  RpId,
  packAttestationObject,
  packAuthenticatorData,
} from "../webauthn/webauthn-model";

/**
 * WebAuthn API emulator
 */
export class WebAuthnApiEmulator {
  public authenticator = new AuthenticatorEmulator();

  /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
  public async get(origin: string, options: CredentialRequestOptions): Promise<AuthenticationPublicKeyCredential> {
    if (!options.publicKey) throw new Error("PublicKeyCredentialCreationOptions are required");
    const rpId = new RpId(options.publicKey.rpId || "");
    if (!rpId.validate(origin)) throw new Error(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);
    const credential = this.authenticator.getCredential(rpId);

    const authenticatorData: AuthenticatorData = {
      rpIdHash: rpId.hash,
      flags: {
        backupEligibility: true,
        backupState: false,
        userPresent: true,
        userVerified: true,
      },
      signCount: 0,
      attestedCredentialData: credential.attestedCredentialData,
    };

    const clientData: CollectedClientData = {
      type: "webauthn.get",
      challenge: EncodeUtils.encodeBase64Url(new Uint8Array(options.publicKey.challenge as ArrayBuffer)),
      origin,
      crossOrigin: false,
    };

    const signature = this.authenticator.sign(rpId, authenticatorData, clientData);

    const publicKeyCredential: AuthenticationPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(credential.attestedCredentialData.credentialId),
      type: "public-key",
      rawId: credential.attestedCredentialData.credentialId,
      response: {
        clientDataJSON: EncodeUtils.toUint8Array(JSON.stringify(clientData)),
        authenticatorData: packAuthenticatorData(authenticatorData),
        signature,
        userHandle: credential.publicKeyCredentialSource.userHandle || null,
      },
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      toJSON: () => toAuthenticationResponseJson(publicKeyCredential),
    };

    return publicKeyCredential;
  }

  /** @see https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create */
  public async create(origin: string, options: CredentialCreationOptions): Promise<RegistrationPublicKeyCredential> {
    if (!options.publicKey) throw new Error("PublicKeyCredentialCreationOptions are required");

    const rpId = new RpId(options.publicKey.rp.id || "");
    if (!rpId.validate(origin)) throw new Error(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);

    const credential = this.authenticator.generateCredential(rpId, options.publicKey.pubKeyCredParams);

    const authData: AuthenticatorData = {
      rpIdHash: rpId.hash,
      flags: {
        backupEligibility: true,
        backupState: false,
        userPresent: true,
        userVerified: true,
      },
      signCount: 0,
      attestedCredentialData: credential.attestedCredentialData,
    };

    const attestationObject: AttestationObject = {
      fmt: "none",
      attStmt: {},
      authData: authData,
    };

    const clientData: CollectedClientData = {
      challenge: EncodeUtils.encodeBase64Url(new Uint8Array(options.publicKey.challenge as ArrayBuffer)),
      origin,
      type: "webauthn.create",
      crossOrigin: false,
    };

    const response: AuthenticatorAttestationResponse = {
      attestationObject: packAttestationObject(attestationObject),
      clientDataJSON: EncodeUtils.toUint8Array(JSON.stringify(clientData)),

      getAuthenticatorData: () => packAuthenticatorData(authData),
      getPublicKey: () => credential.attestedCredentialData.credentialPublicKey.toDer(),
      getPublicKeyAlgorithm: () => credential.attestedCredentialData.credentialPublicKey.alg,
      getTransports: () => credential.publicKeyCredentialDescriptor.transports || [],
    };

    const publicKeyCredential: RegistrationPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(credential.attestedCredentialData.credentialId),
      type: "public-key",
      rawId: credential.attestedCredentialData.credentialId,
      response,
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      toJSON: () => toRegistrationResponseJson(publicKeyCredential),
    };

    return publicKeyCredential;
  }
}
