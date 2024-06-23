/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialRequest {
  clientDataHash: Uint8Array;
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  excludeList?: PublicKeyCredentialDescriptor[];
  extensions?: Map<string, unknown>;
  options?: Map<string, unknown>;
  pinAuth?: Uint8Array;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialResponse {
  fmt: string;
  authData: Uint8Array;
  attStmt: Map<string, unknown>;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionRequest {
  rpId: string;
  clientDataHash: Uint8Array;
  allowList?: PublicKeyCredentialDescriptor[];
  extensions?: Map<string, unknown>;
  options?: Map<string, unknown>;
  pinAuth?: Uint8Array;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionResponse {
  credential?: PublicKeyCredentialDescriptor;
  authData: Uint8Array;
  signature: Uint8Array;
  user: PublicKeyCredentialUserEntity;
  numberOfCredentials: number;
}
