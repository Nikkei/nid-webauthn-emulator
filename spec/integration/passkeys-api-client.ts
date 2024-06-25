import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "../../src/webauthn/webauthn-model-json";

export interface PasskeysUser {
  username: string;
  id: string;
}

export interface PasskeysApiClient {
  getRegistrationOptions(user: PasskeysUser): Promise<PublicKeyCredentialCreationOptionsJSON>;
  getRegistrationVerification(user: PasskeysUser, response: RegistrationResponseJSON): Promise<void>;
  getAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON>;
  getAuthenticationVerification(response: AuthenticationResponseJSON): Promise<void>;
}
