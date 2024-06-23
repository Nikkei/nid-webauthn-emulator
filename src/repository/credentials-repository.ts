import EncodeUtils from "../libs/encode-utils";
import {
  type AuthenticatorData,
  type PublicKeyCredentialSource,
  type PublicKeyCredentialSourceJSON,
  packAuthenticatorData,
  parsePublicKeyCredentialSourceFromJSON,
  toPublickeyCredentialSourceJSON,
  unpackAuthenticatorData,
} from "../webauthn/webauthn-model";

import {
  type PublicKeyCredentialDescriptorJSON,
  type PublicKeyCredentialUserEntityJSON,
  parsePublicKeyCredentialDescriptorFromJSON,
  parsePublicKeyCredentialUserEntityFromJSON,
  toPublicKeyCredentialDescriptorJSON,
  toPublicKeyCredentialUserEntityJSON,
} from "../webauthn/webauthn-model-json";

export type PasskeyCredential = {
  readonly publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor;
  readonly publicKeyCredentialSource: PublicKeyCredentialSource;
  readonly authenticatorData: AuthenticatorData;
  readonly user: PublicKeyCredentialUserEntity | undefined;
};

export type PasskeyCredentialJSON = {
  publicKeyCredentialDescriptor: PublicKeyCredentialDescriptorJSON;
  publicKeyCredentialSource: PublicKeyCredentialSourceJSON;
  authenticatorData: string;
  user?: PublicKeyCredentialUserEntityJSON;
};

/**
 * Passkey credentials repository
 */
export interface PasskeysCredentialsRepository {
  saveCredential(credential: PasskeyCredential): void;
  deleteCredential(credential: PasskeyCredential): void;
  loadCredentials(): PasskeyCredential[];
}

/**
 * Get the ID of a credential
 * @param credential Credential
 */
export function getRepositoryId(credential: PasskeyCredential): string {
  return EncodeUtils.encodeBase64Url(credential.publicKeyCredentialDescriptor.id);
}

/**
 * Serialize a credential to a JSON string
 * @param credential Credential
 * @returns { id: Credential ID; data: JSON Credential }
 */
export function serializeCredential(credential: PasskeyCredential): string {
  const serialized = {
    publicKeyCredentialDescriptor: toPublicKeyCredentialDescriptorJSON(credential.publicKeyCredentialDescriptor),
    publicKeyCredentialSource: toPublickeyCredentialSourceJSON(credential.publicKeyCredentialSource),
    authenticatorData: EncodeUtils.encodeBase64Url(packAuthenticatorData(credential.authenticatorData)),
    user: credential.user ? toPublicKeyCredentialUserEntityJSON(credential.user) : undefined,
  };
  return JSON.stringify(serialized, null, 2);
}

/**
 * Deserialize a credential from a JSON string
 * @param data JSON string
 * @returns Credential
 */
export function deserializeCredential(data: string): PasskeyCredential {
  const serialized = JSON.parse(data) as PasskeyCredentialJSON;
  return {
    publicKeyCredentialDescriptor: parsePublicKeyCredentialDescriptorFromJSON(serialized.publicKeyCredentialDescriptor),
    publicKeyCredentialSource: parsePublicKeyCredentialSourceFromJSON(serialized.publicKeyCredentialSource),
    authenticatorData: unpackAuthenticatorData(EncodeUtils.decodeBase64Url(serialized.authenticatorData)),
    user: serialized.user ? parsePublicKeyCredentialUserEntityFromJSON(serialized.user) : undefined,
  };
}
