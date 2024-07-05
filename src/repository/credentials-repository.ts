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

export type PasskeyDiscoverableCredential = {
  readonly publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor;
  readonly publicKeyCredentialSource: PublicKeyCredentialSource;
  readonly authenticatorData: AuthenticatorData;
  readonly user: PublicKeyCredentialUserEntity;
};

export type PasskeyDiscoverableCredentialJSON = {
  publicKeyCredentialDescriptor: PublicKeyCredentialDescriptorJSON;
  publicKeyCredentialSource: PublicKeyCredentialSourceJSON;
  authenticatorData: string;
  user: PublicKeyCredentialUserEntityJSON;
};

/**
 * Passkey credentials repository
 */
export interface PasskeysCredentialsRepository {
  saveCredential(credential: PasskeyDiscoverableCredential): void;
  deleteCredential(credential: PasskeyDiscoverableCredential): void;
  loadCredentials(): PasskeyDiscoverableCredential[];
}

/**
 * Get the ID of a credential
 * @param credential Credential
 */
export function getRepositoryId(credential: PasskeyDiscoverableCredential): string {
  return EncodeUtils.encodeBase64Url(credential.publicKeyCredentialDescriptor.id);
}

/**
 * Serialize a credential to a JSON string
 * @param credential Credential
 * @returns { id: Credential ID; data: JSON Credential }
 */
export function serializeCredential(credential: PasskeyDiscoverableCredential): string {
  const serialized = {
    publicKeyCredentialDescriptor: toPublicKeyCredentialDescriptorJSON(credential.publicKeyCredentialDescriptor),
    publicKeyCredentialSource: toPublickeyCredentialSourceJSON(credential.publicKeyCredentialSource),
    authenticatorData: EncodeUtils.encodeBase64Url(packAuthenticatorData(credential.authenticatorData)),
    user: toPublicKeyCredentialUserEntityJSON(credential.user),
  };
  return JSON.stringify(serialized, null, 2);
}

/**
 * Deserialize a credential from a JSON string
 * @param data JSON string
 * @returns Credential
 */
export function deserializeCredential(data: string): PasskeyDiscoverableCredential {
  const serialized = JSON.parse(data) as PasskeyDiscoverableCredentialJSON;
  return {
    publicKeyCredentialDescriptor: parsePublicKeyCredentialDescriptorFromJSON(serialized.publicKeyCredentialDescriptor),
    publicKeyCredentialSource: parsePublicKeyCredentialSourceFromJSON(serialized.publicKeyCredentialSource),
    authenticatorData: unpackAuthenticatorData(EncodeUtils.decodeBase64Url(serialized.authenticatorData)),
    user: parsePublicKeyCredentialUserEntityFromJSON(serialized.user),
  };
}
