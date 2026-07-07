// Do not import anything here, it should be a standalone file

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
    extensions: parseExtensionsFromJSON(optionsJSON.extensions),
  };
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
    extensions: parseExtensionsFromJSON(optionsJSON.extensions),
  };
}

// response for navigator.credentials.create() serialization
// @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

export interface CreatePublicKeyCredential extends PublicKeyCredential {
  readonly response: AuthenticatorAttestationResponse;
  toJSON(): RegistrationResponseJSON;
}

// response for navigator.credentials.get() serialization
// @see https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-tojson

export interface RequestPublicKeyCredential extends PublicKeyCredential {
  readonly response: AuthenticatorAssertionResponse;
  toJSON(): AuthenticationResponseJSON;
}

// Not standard mapping functions

export function toRegistrationResponseJSON(credential: PublicKeyCredential): RegistrationResponseJSON {
  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  const publicKey = attestationResponse.getPublicKey();
  const algorithm = attestationResponse.getPublicKeyAlgorithm();
  const responseJSON = {
    clientDataJSON: encodeBase64Url(attestationResponse.clientDataJSON),
    authenticatorData: encodeBase64Url(attestationResponse.getAuthenticatorData()),
    transports: attestationResponse.getTransports(),
    publicKey: publicKey ? encodeBase64Url(publicKey) : undefined,
    publicKeyAlgorithm: algorithm,
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
    clientExtensionResults: toExtensionResultsJSON(credential.getClientExtensionResults()),
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
    clientExtensionResults: toExtensionResultsJSON(credential.getClientExtensionResults()),
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
    extensions: options.extensions as AuthenticationExtensionsClientInputsJSON | undefined,
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
    extensions: options.extensions as AuthenticationExtensionsClientInputsJSON | undefined,
  };
}

export function parseRegistrationResponseFromJSON(options: RegistrationResponseJSON): CreatePublicKeyCredential {
  return {
    id: options.id,
    rawId: decodeBase64Url(options.rawId),
    response: {
      clientDataJSON: decodeBase64Url(options.response.clientDataJSON),
      getAuthenticatorData: () => decodeBase64Url(options.response.authenticatorData),
      getTransports: () => options.response.transports as AuthenticatorTransport[],
      getPublicKey: () => (options.response.publicKey ? decodeBase64Url(options.response.publicKey) : null),
      getPublicKeyAlgorithm: () => options.response.publicKeyAlgorithm ?? -1,
      attestationObject: decodeBase64Url(options.response.attestationObject),
    },
    authenticatorAttachment: options.authenticatorAttachment ?? null,
    getClientExtensionResults: () => options.clientExtensionResults as AuthenticationExtensionsClientOutputs,
    toJSON: () => options,
    type: options.type,
  };
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
    getClientExtensionResults: () => options.clientExtensionResults as AuthenticationExtensionsClientOutputs,
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

function parsePRFValuesFromJSON(values: AuthenticationExtensionsPRFValuesJSON): AuthenticationExtensionsPRFValues {
  const parsed: AuthenticationExtensionsPRFValues = { first: decodeBase64Url(values.first) };
  if (values.second !== undefined) {
    parsed.second = decodeBase64Url(values.second);
  }
  return parsed;
}

function parsePRFInputsFromJSON(prf: AuthenticationExtensionsPRFInputsJSON): AuthenticationExtensionsPRFInputs {
  const parsed: AuthenticationExtensionsPRFInputs = {};
  if (prf.eval) {
    parsed.eval = parsePRFValuesFromJSON(prf.eval);
  }
  if (prf.evalByCredential) {
    parsed.evalByCredential = Object.fromEntries(
      Object.entries(prf.evalByCredential).map(
        ([credentialId, values]) => [credentialId, parsePRFValuesFromJSON(values)] as const,
      ),
    );
  }
  return parsed;
}

// Decodes each supported extension's JSON-encoded inputs into their non-json form.
// Only prf is decoding today, future extension with encoded inputs should add code here
function parseExtensionsFromJSON(
  extensionsJSON: AuthenticationExtensionsClientInputsJSON | undefined,
): AuthenticationExtensionsClientInputs | undefined {
  if (!extensionsJSON) {
    return undefined;
  }
  const parsed = { ...extensionsJSON } as AuthenticationExtensionsClientInputs;
  if (extensionsJSON.prf) {
    parsed.prf = parsePRFInputsFromJSON(extensionsJSON.prf);
  }
  return parsed;
}

function toPRFValuesJSON(values: AuthenticationExtensionsPRFValues): AuthenticationExtensionsPRFValuesJSON {
  const json: AuthenticationExtensionsPRFValuesJSON = { first: encodeBase64Url(values.first) };
  if (values.second !== undefined) {
    json.second = encodeBase64Url(values.second);
  }
  return json;
}

// Encodes each supported extension's outputs into their json form.
// Only prf is encoding today, future extension with encoded outputs should add code here
function toExtensionResultsJSON(
  results: AuthenticationExtensionsClientOutputs,
): AuthenticationExtensionsClientOutputsJSON {
  const json = { ...results } as AuthenticationExtensionsClientOutputsJSON;
  if (results.prf?.results) {
    json.prf = { ...results.prf, results: toPRFValuesJSON(results.prf.results) };
  }
  return json;
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
