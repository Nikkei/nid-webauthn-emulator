import {
  HookWebAuthnApis,
  WebAuthnEmulatorCreate,
  WebAuthnEmulatorGet,
  WebAuthnEmulatorSignalUnknownCredential,
} from "./test-utils/browser-injection";
import { WebAuthnEmulator } from "./webauthn/webauthn-emulator";

export default WebAuthnEmulator;

export * from "./authenticator/authenticator-emulator";
export * from "./authenticator/ctap-model";
export * from "./repository/credentials-file-repository";
export * from "./repository/credentials-memory-repository";
export * from "./repository/credentials-repository";
export * from "./webauthn/cose-key";
export * from "./webauthn/webauthn-emulator";
export * from "./webauthn/webauthn-model";
export * from "./webauthn/webauthn-model-json";

export const BrowserInjection = {
  WebAuthnEmulatorGet,
  WebAuthnEmulatorCreate,
  WebAuthnEmulatorSignalUnknownCredential,
  HookWebAuthnApis,
};
