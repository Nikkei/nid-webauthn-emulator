type Base64urlString = string;
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
    user: { ...options.user, id: decodeBase64Url(options.user.id) },
    challenge: decodeBase64Url(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      id: decodeBase64Url(cred.id),
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
    challenge: decodeBase64Url(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      id: decodeBase64Url(cred.id),
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
  toJSON(): RegistrationResponseJSON;
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
  toJSON(): AuthenticationResponseJSON;
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
    clientDataJSON: encodeBase64Url(attestationResponse.clientDataJSON),
    authenticatorData: encodeBase64Url(attestationResponse.getAuthenticatorData()),
    transports: attestationResponse.getTransports(),
    publicKey: publicKey ? encodeBase64Url(publicKey) : undefined,
    publicKeyAlgorithm: attestationResponse.getPublicKeyAlgorithm(),
    attestationObject: encodeBase64Url(attestationResponse.attestationObject),
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
    clientDataJSON: encodeBase64Url(assertionResponse.clientDataJSON),
    authenticatorData: encodeBase64Url(assertionResponse.authenticatorData),
    signature: encodeBase64Url(assertionResponse.signature),
    userHandle: assertionResponse.userHandle ? encodeBase64Url(assertionResponse.userHandle) : undefined,
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

function encodeBase64Url(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function decodeBase64Url(base64Url: string): ArrayBuffer {
  const base64 = base64Url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(base64Url.length + ((4 - (base64Url.length % 4)) % 4), "=");

  const binaryString = atob(base64);

  const byteArray = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    byteArray[i] = binaryString.charCodeAt(i);
  }
  return byteArray.buffer;
}
