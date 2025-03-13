import * as Model from "../webauthn/webauthn-model-json";

export const WebAuthnEmulatorGet = "webAuthnEmulatorGet";
export const WebAuthnEmulatorCreate = "webAuthnEmulatorCreate";
export const WebAuthnEmulatorSignalUnknownCredential = "webAuthnEmulatorSignalUnknownCredential";
export const WebAuthnEmulatorSignalAllAcceptedCredentials = "webAuthnEmulatorSignalAllAcceptedCredentials";
export const WebAuthnEmulatorSignalCurrentUserDetails = "webAuthnEmulatorSignalCurrentUserDetails";

const webAuthnModelExports = Object.values(Model)
  .map((m) => m.toString())
  .join("\n  ");

export const HookWebAuthnApis = `
(function () {
  ${webAuthnModelExports}

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
  
  PublicKeyCredential.signalUnknownCredential = async (options) => {
    if (!options || !options.rpId || !options.credentialId) return;
    await window.${WebAuthnEmulatorSignalUnknownCredential}(options);
  }

  PublicKeyCredential.signalAllAcceptedCredentials = async (options) => {
    if (!options || !options.rpId || !options.userId || !options.allAcceptedCredentialIds) return;
    await window.${WebAuthnEmulatorSignalAllAcceptedCredentials}(options);
  }

  PublicKeyCredential.signalCurrentUserDetails = async (options) => {
    if (!options || !options.rpId || !options.userId) return;
    await window.${WebAuthnEmulatorSignalCurrentUserDetails}(options);
  }
})();
`;
