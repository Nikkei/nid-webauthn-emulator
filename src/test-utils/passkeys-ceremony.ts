import {
  parseCreationOptionsFromJSON,
  toRegistrationResponseJson,
  parseRequestOptionsFromJSON,
  toAuthenticationResponseJson,
} from "../libs/json";
import type { PasskeysTestAuthenticator } from "../passkeys-test-authenticator";
import type { PasskeysApiClient } from "./passkeys-api-client";

export async function registrationCeremony(
  authenticator: PasskeysTestAuthenticator,
  passkeysApiClient: PasskeysApiClient,
) {
  const optionsJson = await passkeysApiClient.getRegistrationOptions();
  const options = { publicKey: parseCreationOptionsFromJSON(optionsJson) };
  console.log("Registration options", options);

  const credential = await authenticator.create(options);
  const credentialJson = toRegistrationResponseJson(credential);
  console.log("Registration credential", credentialJson);
  await passkeysApiClient.getRegistrationVerification(credentialJson);
  console.log("Registration verification completed");
}

export async function authenticationCeremony(
  authenticator: PasskeysTestAuthenticator,
  passkeysApiClient: PasskeysApiClient,
) {
  const optionsJson = await passkeysApiClient.getAuthenticationOptions();
  const options = { publicKey: parseRequestOptionsFromJSON(optionsJson) };
  console.log("Authentication options", options);

  const credential = await authenticator.get(options);
  const credentialJson = toAuthenticationResponseJson(credential);
  console.log("Authentication credential", credentialJson);
  await passkeysApiClient.getAuthenticationVerification(credentialJson);
  console.log("Authentication verification completed");
}
