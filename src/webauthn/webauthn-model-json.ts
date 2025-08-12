// Do not import anything here, it should be a standalone file

type Base64urlString = string;
type AuthenticationExtensionsClientInputsJSON = object;
type AuthenticationExtensionsClientOutputsJSON = object;

// options for navigator.credentials.create() serialization
// @see https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptionsjson */
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

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentityjson */
export interface PublicKeyCredentialUserEntityJSON {
  readonly id: Base64urlString;
  readonly name: string;
  readonly displayName: string;
}

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptorjson */
export interface PublicKeyCredentialDescriptorJSON {
  readonly id: Base64urlString;
  readonly type: string;
  transports?: string[];
}

/** @see https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON */
export function parseCreationOptionsFromJSON(
  optionsJSON: PublicKeyCredentialCreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  return {
    rp: optionsJSON.rp,
    user: parsePublicKeyCredentialUserEntityFromJSON(optionsJSON.user),
    challenge: decodeBase64Url(optionsJSON.challenge),
    pubKeyCredParams: optionsJSON.pubKeyCredParams,
    timeout: optionsJSON.timeout,
    excludeCredentials: optionsJSON.excludeCredentials?.map(parsePublicKeyCredentialDescriptorFromJSON),
    authenticatorSelection: optionsJSON.authenticatorSelection,
    attestation: optionsJSON.attestation as AttestationConveyancePreference,
    extensions: optionsJSON.extensions,
  };
}

// options for navigator.credentials.get() serialization
// @see https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptionsjson */
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

/** @see https://www.w3.org/TR/webauthn-3/#sctn-parseRequestOptionsFromJSON */
export function parseRequestOptionsFromJSON(
  optionsJSON: PublicKeyCredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: decodeBase64Url(optionsJSON.challenge),
    timeout: optionsJSON.timeout,
    rpId: optionsJSON.rpId,
    allowCredentials: optionsJSON.allowCredentials?.map(parsePublicKeyCredentialDescriptorFromJSON),
    userVerification: optionsJSON.userVerification as UserVerificationRequirement,
    extensions: optionsJSON.extensions,
  };
}

// response for navigator.credentials.create() serialization
// @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

export interface CreatePublicKeyCredential extends PublicKeyCredential {
  response: AuthenticatorAttestationResponse;
  toJSON(): RegistrationResponseJSON;
}

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson */
export interface RegistrationResponseJSON {
  readonly id: Base64urlString;
  readonly rawId: Base64urlString;
  readonly response: AuthenticatorAttestationResponseJSON;
  readonly authenticatorAttachment?: AuthenticatorAttachment;
  readonly clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
  readonly type: PublicKeyCredentialType;
}

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson */
interface AuthenticatorAttestationResponseJSON {
  readonly clientDataJSON: Base64urlString;
  readonly authenticatorData: Base64urlString;
  readonly transports: AuthenticatorTransport[];
  readonly publicKey?: Base64urlString;
  readonly publicKeyAlgorithm?: number;
  readonly attestationObject: Base64urlString;
}

// response for navigator.credentials.get() serialization
// @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

export interface RequestPublicKeyCredential extends PublicKeyCredential {
  response: AuthenticatorAssertionResponse;
  toJSON(): AuthenticationResponseJSON;
}

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson */
export interface AuthenticationResponseJSON {
  readonly id: Base64urlString;
  readonly rawId: Base64urlString;
  readonly response: AuthenticatorAssertionResponseJSON;
  readonly authenticatorAttachment?: AuthenticatorAttachment;
  readonly clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
  readonly type: PublicKeyCredentialType;
}

/** @see https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorassertionresponsejson */
interface AuthenticatorAssertionResponseJSON {
  readonly clientDataJSON: Base64urlString;
  readonly authenticatorData: Base64urlString;
  readonly signature: Base64urlString;
  readonly userHandle?: Base64urlString;
  readonly attestationObject?: Base64urlString;
}

// Not standard mapping functions

export function toRegistrationResponseJSON(credential: PublicKeyCredential): RegistrationResponseJSON {
  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  const publicKey = attestationResponse.getPublicKey();
  const algorithm = attestationResponse.getPublicKeyAlgorithm();
  const responseJSON = {
    clientDataJSON: encodeBase64Url(attestationResponse.clientDataJSON),
    authenticatorData: encodeBase64Url(attestationResponse.getAuthenticatorData()),
    transports: attestationResponse.getTransports() as AuthenticatorTransport[],
    publicKey: publicKey ? encodeBase64Url(publicKey) : undefined,
    publicKeyAlgorithm: algorithm === -1 ? undefined : algorithm,
    attestationObject: encodeBase64Url(attestationResponse.attestationObject),
  };

  return {
    id: credential.id,
    rawId: credential.id,
    response: responseJSON,
    authenticatorAttachment:
      credential.authenticatorAttachment === null
        ? undefined
        : (credential.authenticatorAttachment as AuthenticatorAttachment),
    clientExtensionResults: credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputsJSON,
    type: credential.type as PublicKeyCredentialType,
  };
}

export function toAuthenticationResponseJSON(credential: PublicKeyCredential): AuthenticationResponseJSON {
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
      credential.authenticatorAttachment === null
        ? undefined
        : (credential.authenticatorAttachment as AuthenticatorAttachment),
    clientExtensionResults: credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputsJSON,
    type: credential.type as PublicKeyCredentialType,
  };
}

export function toCreationOptionsJSON(
  options: PublicKeyCredentialCreationOptions,
): PublicKeyCredentialCreationOptionsJSON {
  return {
    rp: options.rp,
    user: toPublicKeyCredentialUserEntityJSON(options.user),
    challenge: encodeBase64Url(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    excludeCredentials: options.excludeCredentials?.map(toPublicKeyCredentialDescriptorJSON),
    authenticatorSelection: options.authenticatorSelection,
    attestation: options.attestation,
    extensions: options.extensions,
  };
}

export function toRequestOptionsJSON(
  options: PublicKeyCredentialRequestOptions,
): PublicKeyCredentialRequestOptionsJSON {
  return {
    challenge: encodeBase64Url(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map(toPublicKeyCredentialDescriptorJSON),
    userVerification: options.userVerification,
    extensions: options.extensions,
  };
}

export function parseRegistrationResponseFromJSON(options: RegistrationResponseJSON): CreatePublicKeyCredential {
  return {
    id: options.id,
    rawId: decodeBase64Url(options.rawId),
    response: {
      clientDataJSON: decodeBase64Url(options.response.clientDataJSON),
      getAuthenticatorData: () => decodeBase64Url(options.response.authenticatorData),
      getTransports: () => options.response.transports,
      getPublicKey: () => (options.response.publicKey ? decodeBase64Url(options.response.publicKey) : null),
      getPublicKeyAlgorithm: () => options.response.publicKeyAlgorithm ?? -1,
      attestationObject: decodeBase64Url(options.response.attestationObject),
    },
    authenticatorAttachment: options.authenticatorAttachment ?? null,
    getClientExtensionResults: () => options.clientExtensionResults,
    toJSON: () => options,
    type: options.type,
  };
}

export interface UnknownCredentialOptionsJSON {
  rpId: string;
  credentialId: Base64urlString;
}

export interface AllAcceptedCredentialsOptionsJSON {
  rpId: string;
  userId: Base64urlString;
  allAcceptedCredentialIds: Base64urlString[];
}

export interface CurrentUserDetailsOptionsJSON {
  rpId: string;
  userId: Base64urlString;
  name: string;
  displayName: string;
}

export function parseAuthenticationResponseFromJSON(options: AuthenticationResponseJSON): RequestPublicKeyCredential {
  return {
    id: options.id,
    rawId: decodeBase64Url(options.rawId),
    response: {
      clientDataJSON: decodeBase64Url(options.response.clientDataJSON),
      authenticatorData: decodeBase64Url(options.response.authenticatorData),
      signature: decodeBase64Url(options.response.signature),
      userHandle: options.response.userHandle ? decodeBase64Url(options.response.userHandle) : null,
    },
    authenticatorAttachment: options.authenticatorAttachment ?? null,
    getClientExtensionResults: () => options.clientExtensionResults,
    toJSON: () => options,
    type: options.type,
  };
}

export function toPublicKeyCredentialDescriptorJSON(
  credential: PublicKeyCredentialDescriptor,
): PublicKeyCredentialDescriptorJSON {
  return {
    id: encodeBase64Url(credential.id),
    type: credential.type,
    transports: credential.transports,
  };
}

export function parsePublicKeyCredentialDescriptorFromJSON(
  credential: PublicKeyCredentialDescriptorJSON,
): PublicKeyCredentialDescriptor {
  return {
    id: decodeBase64Url(credential.id),
    type: credential.type as PublicKeyCredentialType,
    transports: credential.transports as AuthenticatorTransport[],
  };
}

export function toPublicKeyCredentialUserEntityJSON(
  user: PublicKeyCredentialUserEntity,
): PublicKeyCredentialUserEntityJSON {
  return { ...user, id: encodeBase64Url(user.id) };
}

export function parsePublicKeyCredentialUserEntityFromJSON(
  user: PublicKeyCredentialUserEntityJSON,
): PublicKeyCredentialUserEntity {
  return { ...user, id: decodeBase64Url(user.id) };
}

// Helper functions

export function encodeBase64Url(buffer: BufferSource): string {
  const toArrayBuffer = (bufferSource: BufferSource): ArrayBuffer => {
    if (bufferSource instanceof ArrayBuffer) {
      return bufferSource;
    }
    return bufferSource.buffer.slice(bufferSource.byteOffset, bufferSource.byteOffset + bufferSource.byteLength);
  };
  return btoa(String.fromCharCode(...new Uint8Array<ArrayBuffer>(toArrayBuffer(buffer))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function decodeBase64Url(base64Url: string): ArrayBuffer {
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
