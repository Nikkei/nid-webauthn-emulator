import { AuthenticatorEmulator } from "../authenticator/authenticator";
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
} from "./webauthn-model-json";

import { createHash } from "node:crypto";
import {
  CTAP_COMMAND,
  packGetAssertionRequest,
  packMakeCredentialRequest,
  unpackGetAssertionResponse,
  unpackGetInfoResponse,
  unpackMakeCredentialResponse,
} from "../authenticator/ctap-model";
import {
  type AttestationObject,
  type AttestedCredentialData,
  type CollectedClientData,
  RpId,
  packAttestationObject,
  packAuthenticatorData,
  unpackAuthenticatorData,
} from "./webauthn-model";

export type AuthenticatorInfo = {
  version: string;
  aaguid: string;
  options: {
    rk: boolean;
    uv: boolean;
  };
};

/**
 * WebAuthn emulator
 */
export class WebAuthnEmulator {
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

  public getAuthenticatorInfo(): AuthenticatorInfo {
    const authenticatorInfo = unpackGetInfoResponse(
      this.authenticator.command({ command: CTAP_COMMAND.authenticatorGetInfo }),
    );
    return {
      version: authenticatorInfo.versions.join(", "),
      aaguid: EncodeUtils.encodeBase64Url(authenticatorInfo.aaguid),
      options: {
        rk: authenticatorInfo.options?.rk ?? false,
        uv: authenticatorInfo.options?.uv ?? false,
      },
    };
  }

  /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
  public get(origin: string, options: CredentialRequestOptions): RequestPublicKeyCredential {
    if (!options.publicKey) throw new Error("PublicKeyCredentialCreationOptions are required");
    const rpId = new RpId(options.publicKey.rpId ?? "");
    if (!rpId.validate(origin)) throw new Error(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);

    const clientData: CollectedClientData = {
      type: "webauthn.get",
      challenge: EncodeUtils.encodeBase64Url(options.publicKey.challenge),
      origin,
      crossOrigin: false,
    };

    const authenticatorRequest = packGetAssertionRequest({
      rpId: rpId.value,
      clientDataHash: createHash("sha256").update(JSON.stringify(clientData)).digest(),
      allowList: options.publicKey.allowCredentials,
    });
    const authenticatorResponse = unpackGetAssertionResponse(this.authenticator.command(authenticatorRequest));

    const responseId = authenticatorResponse.credential?.id ?? options.publicKey.allowCredentials?.[0]?.id;
    if (!responseId) throw new Error("No credential ID found");
    const authData = unpackAuthenticatorData(authenticatorResponse.authData);
    const rawId = EncodeUtils.bufferSourceToUint8Array(responseId);

    const publicKeyCredential: RequestPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(rawId),
      type: "public-key",
      rawId,
      response: {
        clientDataJSON: EncodeUtils.strToUint8Array(JSON.stringify(clientData)),
        authenticatorData: packAuthenticatorData(authData),
        signature: authenticatorResponse.signature,
        userHandle: EncodeUtils.bufferSourceToUint8Array(authenticatorResponse.user.id),
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

    const clientData: CollectedClientData = {
      challenge: EncodeUtils.encodeBase64Url(options.publicKey.challenge),
      origin,
      type: "webauthn.create",
      crossOrigin: false,
    };
    const clientDataJSON = JSON.stringify(clientData);

    const authenticatorRequest = packMakeCredentialRequest({
      clientDataHash: createHash("sha256").update(clientDataJSON).digest(),
      rp: options.publicKey.rp,
      user: options.publicKey.user,
      pubKeyCredParams: options.publicKey.pubKeyCredParams,
      excludeList: options.publicKey.excludeCredentials,
      options: {
        rk: options.publicKey.authenticatorSelection?.requireResidentKey,
        uv: options.publicKey.authenticatorSelection?.userVerification !== "discouraged",
      },
    });
    const authenticatorResponse = unpackMakeCredentialResponse(this.authenticator.command(authenticatorRequest));

    const authData = unpackAuthenticatorData(authenticatorResponse.authData);
    const attestedCredentialData = authData.attestedCredentialData as AttestedCredentialData;

    const attestationObject: AttestationObject = {
      fmt: "none",
      attStmt: {},
      authData,
    };

    const response: AuthenticatorAttestationResponse = {
      attestationObject: packAttestationObject(attestationObject),
      clientDataJSON: EncodeUtils.strToUint8Array(clientDataJSON),

      getAuthenticatorData: () => packAuthenticatorData(authData),
      getPublicKey: () => attestedCredentialData.credentialPublicKey.toDer(),
      getPublicKeyAlgorithm: () => attestedCredentialData.credentialPublicKey.alg,
      getTransports: () => this.authenticator.params.transports,
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
