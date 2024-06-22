import {
  decodeBase64Url,
  encodeBase64Url,
  parseAuthenticationResponseFromJSON,
  parseRegistrationResponseFromJSON,
  toCreationOptionsJSON,
  toRequestOptionsJSON,
} from "../webauthn/webauthn-model-json";

export const WebAuthnEmulatorGet = "webAuthnEmulatorGet";
export const WebAuthnEmulatorCreate = "webAuthnEmulatorCreate";
export const HookWebAuthnApis = `
(function () {
  ${encodeBase64Url.toString()}
  ${decodeBase64Url.toString()}
  ${toCreationOptionsJSON.toString()}
  ${parseRegistrationResponseFromJSON.toString()}
  ${toRequestOptionsJSON.toString()}
  ${parseAuthenticationResponseFromJSON.toString()}

  window.navigator.credentials.create = async (options) => {
    if (!options.publicKey) return undefined;
    const optionsJSON = toCreationOptionsJSON(options.publicKey);
    const responseJSON = await window.${WebAuthnEmulatorCreate}(optionsJSON);
    return parseRegistrationResponseFromJSON(responseJSON);
  }

  window.navigator.credentials.get = async (options) => {
    if (!options.publicKey) return undefined;
    const optionsJSON = toRequestOptionsJSON(options.publicKey);
    const responseJSON = await window.${WebAuthnEmulatorGet}(optionsJSON);
    return parseAuthenticationResponseFromJSON(responseJSON);
  }
  PublicKeyCredential.isConditionalMediationAvailable = async () => true;
})();
`;
