import Base64 from "./base64";
import type { Base64urlString } from "./base64";

type AuthenticationExtensionsClientInputsJSON = object;
type AuthenticationExtensionsClientOutputsJSON = object;

// options for navigator.credentials.create() serialization
// @see https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON

export interface PublicKeyCredentialCreationOptionsJSON {
  readonly rp: PublicKeyCredentialRpEntity;
  readonly user: PublicKeyCredentialUserEntityJSON;
  readonly challenge: Base64urlString;
  readonly pubKeyCredParams: PublicKeyCredentialParameters[];
  readonly timeout?: number;
  readonly excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  readonly authenticatorSelection?: AuthenticatorSelectionCriteria;
  readonly hints?: string[];
  readonly attestation?: string;
  readonly attestationFormats?: string[];
  readonly extensions?: AuthenticationExtensionsClientInputsJSON;
}

interface PublicKeyCredentialUserEntityJSON {
  readonly id: Base64urlString;
  readonly name: string;
  readonly displayName: string;
}

interface PublicKeyCredentialDescriptorJSON {
  readonly id: Base64urlString;
  readonly type: string;
  transports?: string[];
}

export function parseCreationOptionsFromJSON(
  options: PublicKeyCredentialCreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  return {
    rp: options.rp,
    user: { ...options.user, id: Base64.base64urlToBuffer(options.user.id) },
    challenge: Base64.base64urlToBuffer(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      id: Base64.base64urlToBuffer(cred.id),
      type: cred.type as PublicKeyCredentialType,
      transports: cred.transports as AuthenticatorTransport[],
    })),
    authenticatorSelection: options.authenticatorSelection,
    attestation: options.attestation as AttestationConveyancePreference,
    extensions: options.extensions,
  };
}

// options for navigator.credentials.get() serialization
// @see https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON

export interface PublicKeyCredentialRequestOptionsJSON {
  readonly challenge: Base64urlString;
  readonly timeout?: number;
  readonly rpId?: string;
  readonly allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  readonly userVerification?: string;
  readonly hints?: string[];
  readonly attestation?: string;
  readonly attestationFormats?: string[];
  readonly extensions?: AuthenticationExtensionsClientInputsJSON;
}

export function parseRequestOptionsFromJSON(
  options: PublicKeyCredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: Base64.base64urlToBuffer(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      id: Base64.base64urlToBuffer(cred.id),
      transports: cred.transports as AuthenticatorTransport[],
      type: cred.type as PublicKeyCredentialType,
    })),
    userVerification: options.userVerification as UserVerificationRequirement,
    extensions: options.extensions,
  };
}

// response for navigator.credentials.create() serialization
// @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

export interface RegistrationPublicKeyCredential extends PublicKeyCredential {
  response: AuthenticatorAttestationResponse;
}

export interface RegistrationResponseJSON {
  readonly id: Base64urlString;
  readonly rawId: Base64urlString;
  readonly response: AuthenticatorAttestationResponseJSON;
  readonly authenticatorAttachment?: string;
  readonly clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
  readonly type: string;
}

interface AuthenticatorAttestationResponseJSON {
  readonly clientDataJSON: Base64urlString;
  readonly authenticatorData: Base64urlString;
  readonly transports: string[];
  readonly publicKey?: Base64urlString;
  readonly publicKeyAlgorithm?: number;
  readonly attestationObject: Base64urlString;
}

// response for navigator.credentials.get() serialization
// @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

export interface AuthenticationPublicKeyCredential extends PublicKeyCredential {
  response: AuthenticatorAssertionResponse;
}

export interface AuthenticationResponseJSON {
  readonly id: Base64urlString;
  readonly rawId: Base64urlString;
  readonly response: AuthenticatorAssertionResponseJSON;
  readonly authenticatorAttachment?: string;
  readonly clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
  readonly type: string;
}

interface AuthenticatorAssertionResponseJSON {
  readonly clientDataJSON: Base64urlString;
  readonly authenticatorData: Base64urlString;
  readonly signature: Base64urlString;
  readonly userHandle?: Base64urlString;
  readonly attestationObject?: Base64urlString;
}

/** @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson */
export function toRegistrationResponseJson(credential: PublicKeyCredential): RegistrationResponseJSON {
  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  const publicKey = attestationResponse.getPublicKey();
  const responseJSON = {
    clientDataJSON: Base64.bufferToBase64url(attestationResponse.clientDataJSON),
    authenticatorData: Base64.bufferToBase64url(attestationResponse.getAuthenticatorData()),
    transports: attestationResponse.getTransports(),
    publicKey: publicKey ? Base64.bufferToBase64url(publicKey) : undefined,
    publicKeyAlgorithm: attestationResponse.getPublicKeyAlgorithm(),
    attestationObject: Base64.bufferToBase64url(attestationResponse.attestationObject),
  };

  return {
    id: credential.id,
    rawId: credential.id,
    response: responseJSON,
    authenticatorAttachment:
      credential.authenticatorAttachment === null ? undefined : credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputsJSON,
    type: credential.type as PublicKeyCredentialType,
  };
}

/** @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson */
export function toAuthenticationResponseJson(credential: PublicKeyCredential): AuthenticationResponseJSON {
  const assertionResponse = credential.response as AuthenticatorAssertionResponse;
  const responseJson = {
    clientDataJSON: Base64.bufferToBase64url(assertionResponse.clientDataJSON),
    authenticatorData: Base64.bufferToBase64url(assertionResponse.authenticatorData),
    signature: Base64.bufferToBase64url(assertionResponse.signature),
    userHandle: assertionResponse.userHandle ? Base64.bufferToBase64url(assertionResponse.userHandle) : undefined,
  };
  return {
    id: credential.id,
    rawId: credential.id,
    response: responseJson,
    authenticatorAttachment:
      credential.authenticatorAttachment === null ? undefined : credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputsJSON,
    type: credential.type as PublicKeyCredentialType,
  };
}
