import type { WebAuthnApiEmulator } from "../../src/emulators/webauthn-api";
import {
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
  toAuthenticationResponseJson,
  toRegistrationResponseJson,
} from "../../src/webauthn/webauthn-model-json";
import type { PasskeysApiClient } from "./passkeys-api-client";

export async function registrationCeremony(
  origin: string,
  webAuthnApiEmulator: WebAuthnApiEmulator,
  passkeysApiClient: PasskeysApiClient,
) {
  const optionsJson = await passkeysApiClient.getRegistrationOptions();
  const options = { publicKey: parseCreationOptionsFromJSON(optionsJson) };
  console.log("Registration options", options);

  const credential = await webAuthnApiEmulator.create(origin, options);
  const credentialJson = toRegistrationResponseJson(credential);
  console.log("Registration credential", credentialJson);
  await passkeysApiClient.getRegistrationVerification(credentialJson);
  console.log("Registration verification completed");
}

export async function authenticationCeremony(
  origin: string,
  webAuthnApiEmulator: WebAuthnApiEmulator,
  passkeysApiClient: PasskeysApiClient,
) {
  const optionsJson = await passkeysApiClient.getAuthenticationOptions();
  const options = { publicKey: parseRequestOptionsFromJSON(optionsJson) };
  console.log("Authentication options", options);

  const credential = await webAuthnApiEmulator.get(origin, options);
  const credentialJson = toAuthenticationResponseJson(credential);
  console.log("Authentication credential", credentialJson);
  await passkeysApiClient.getAuthenticationVerification(credentialJson);
  console.log("Authentication verification completed");
}
