import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "../../src/webauthn/webauthn-model-json";

export interface PasskeysApiClient {
  getRegistrationOptions(): Promise<PublicKeyCredentialCreationOptionsJSON>;
  getRegistrationVerification(response: RegistrationResponseJSON): Promise<void>;
  getAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON>;
  getAuthenticationVerification(response: AuthenticationResponseJSON): Promise<void>;
}
