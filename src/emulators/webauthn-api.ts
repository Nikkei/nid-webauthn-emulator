import EncodeUtils from "../libs/encode-utils";
import {
  type AuthenticationResponseJSON,
  type CreatePublicKeyCredential,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  type RequestPublicKeyCredential,
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
  toAuthenticationResponseJSON,
  toRegistrationResponseJSON,
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

  public getJSON(origin: string, optionsJSON: PublicKeyCredentialRequestOptionsJSON): AuthenticationResponseJSON {
    const options = parseRequestOptionsFromJSON(optionsJSON);
    const response = this.get(origin, { publicKey: options });
    return toAuthenticationResponseJSON(response);
  }

  public createJSON(origin: string, optionsJSON: PublicKeyCredentialCreationOptionsJSON): RegistrationResponseJSON {
    const options = parseCreationOptionsFromJSON(optionsJSON);
    const response = this.create(origin, { publicKey: options });
    return toRegistrationResponseJSON(response);
  }

  /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
  public get(origin: string, options: CredentialRequestOptions): RequestPublicKeyCredential {
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
      challenge: EncodeUtils.encodeBase64Url(EncodeUtils.bufferSourceToUint8Array(options.publicKey.challenge)),
      origin,
      crossOrigin: false,
    };

    const signature = this.authenticator.sign(rpId, authenticatorData, clientData);

    const publicKeyCredential: RequestPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(credential.attestedCredentialData.credentialId),
      type: "public-key",
      rawId: credential.attestedCredentialData.credentialId,
      response: {
        clientDataJSON: EncodeUtils.strToUint8Array(JSON.stringify(clientData)),
        authenticatorData: packAuthenticatorData(authenticatorData),
        signature,
        userHandle: credential.publicKeyCredentialSource.userHandle || null,
      },
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      toJSON: () => toAuthenticationResponseJSON(publicKeyCredential),
    };

    return publicKeyCredential;
  }

  /** @see https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create */
  public create(origin: string, options: CredentialCreationOptions): CreatePublicKeyCredential {
    if (!options.publicKey) throw new Error("PublicKeyCredentialCreationOptions are required");

    const rpId = new RpId(options.publicKey.rp.id || "");
    if (!rpId.validate(origin)) throw new Error(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);

    const credential = this.authenticator.generateCredential(
      rpId,
      options.publicKey.pubKeyCredParams,
      EncodeUtils.bufferSourceToUint8Array(options.publicKey.user.id),
    );

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
      challenge: EncodeUtils.encodeBase64Url(EncodeUtils.bufferSourceToUint8Array(options.publicKey.challenge)),
      origin,
      type: "webauthn.create",
      crossOrigin: false,
    };

    const response: AuthenticatorAttestationResponse = {
      attestationObject: packAttestationObject(attestationObject),
      clientDataJSON: EncodeUtils.strToUint8Array(JSON.stringify(clientData)),

      getAuthenticatorData: () => packAuthenticatorData(authData),
      getPublicKey: () => credential.attestedCredentialData.credentialPublicKey.toDer(),
      getPublicKeyAlgorithm: () => credential.attestedCredentialData.credentialPublicKey.alg,
      getTransports: () => credential.publicKeyCredentialDescriptor.transports || [],
    };

    const publicKeyCredential: CreatePublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(credential.attestedCredentialData.credentialId),
      type: "public-key",
      rawId: credential.attestedCredentialData.credentialId,
      response,
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      toJSON: () => toRegistrationResponseJSON(publicKeyCredential),
    };

    return publicKeyCredential;
  }
}
