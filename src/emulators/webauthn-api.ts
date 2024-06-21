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
  type AttestedCredentialData,
  type CollectedClientData,
  RpId,
  packAttestationObject,
  packAuthenticatorData,
} from "../webauthn/webauthn-model";

/**
 * WebAuthn API emulator
 */
export class WebAuthnApiEmulator {
  constructor(public authenticator: AuthenticatorEmulator = new AuthenticatorEmulator()) {}

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
    const rpId = new RpId(options.publicKey.rpId ?? "");
    if (!rpId.validate(origin)) throw new Error(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);

    const clientData: CollectedClientData = {
      type: "webauthn.get",
      challenge: EncodeUtils.encodeBase64Url(EncodeUtils.bufferSourceToUint8Array(options.publicKey.challenge)),
      origin,
      crossOrigin: false,
    };
    const signResponse = this.authenticator.sign(rpId, clientData, options.publicKey.allowCredentials ?? []);

    const authData = signResponse.authenticatorData;
    const id = EncodeUtils.bufferSourceToUint8Array(signResponse.publicKeyCredentialDescriptor.id);

    const publicKeyCredential: RequestPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(id),
      type: "public-key",
      rawId: id,
      response: {
        clientDataJSON: EncodeUtils.strToUint8Array(JSON.stringify(clientData)),
        authenticatorData: packAuthenticatorData(authData),
        signature: signResponse.signature,
        userHandle: signResponse.userHandle ?? null,
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

    const rpId = new RpId(options.publicKey.rp.id ?? "");
    if (!rpId.validate(origin)) throw new Error(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);

    const credential = this.authenticator.generateCredential(
      rpId,
      options.publicKey.pubKeyCredParams,
      options.publicKey.excludeCredentials ?? [],
      EncodeUtils.bufferSourceToUint8Array(options.publicKey.user.id),
    );

    const authData = credential.authenticatorData;
    const attestedCredentialData = authData.attestedCredentialData as AttestedCredentialData;

    const attestationObject: AttestationObject = {
      fmt: "none",
      attStmt: {},
      authData,
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
      getPublicKey: () => attestedCredentialData.credentialPublicKey.toDer(),
      getPublicKeyAlgorithm: () => attestedCredentialData.credentialPublicKey.alg,
      getTransports: () => credential.publicKeyCredentialDescriptor.transports ?? [],
    };

    const publicKeyCredential: CreatePublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(attestedCredentialData.credentialId),
      type: "public-key",
      rawId: attestedCredentialData.credentialId,
      response,
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      toJSON: () => toRegistrationResponseJSON(publicKeyCredential),
    };

    return publicKeyCredential;
  }
}
