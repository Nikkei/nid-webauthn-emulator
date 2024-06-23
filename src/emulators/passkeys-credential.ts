import EncodeUtils from "../libs/encode-utils";
import type { AuthenticatorData, PublicKeyCredentialSource } from "../webauthn/webauthn-model";

export type PasskeyCredential = {
  readonly publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor;
  readonly publicKeyCredentialSource: PublicKeyCredentialSource;
  readonly authenticatorData: AuthenticatorData;
  readonly user: PublicKeyCredentialUserEntity;
};

/**
 * Serialize a credential to a JSON string
 * @param credential Credential
 * @returns JSON string
 */
export function serializeCredential(credential: PasskeyCredential): string {
  const replacer = (_: string, value: unknown) => {
    if (value instanceof Uint8Array) {
      return EncodeUtils.encodeBase64Url(value);
    }
    return value;
  };
  return JSON.stringify(credential, replacer);
}

/**
 * Deserialize a credential from a JSON string
 * @param data JSON string
 * @returns Credential
 */
export function deserializeCredential(data: string): PasskeyCredential {
  const reviver = (_: string, value: unknown) => {
    if (typeof value === "string") {
      return EncodeUtils.decodeBase64Url(value);
    }
    return value;
  };
  return JSON.parse(data, reviver);
}
