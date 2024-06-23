import * as Model from "../webauthn/webauthn-model-json";

export const WebAuthnEmulatorGet = "webAuthnEmulatorGet";
export const WebAuthnEmulatorCreate = "webAuthnEmulatorCreate";
export const HookWebAuthnApis = `
(function () {
  ${Model.encodeBase64Url.toString()}
  ${Model.decodeBase64Url.toString()}
  ${Model.toPublicKeyCredentialUserEntityJSON.toString()}
  ${Model.toPublicKeyCredentialDescriptorJSON.toString()}
  ${Model.toCreationOptionsJSON.toString()}
  ${Model.toRequestOptionsJSON.toString()}
  ${Model.parseRegistrationResponseFromJSON.toString()}
  ${Model.parseAuthenticationResponseFromJSON.toString()}

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
