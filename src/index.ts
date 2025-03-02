import {
  HookWebAuthnApis,
  WebAuthnEmulatorCreate,
  WebAuthnEmulatorGet,
  WebAuthnEmulatorSignalUnknownCredential,
} from "./test-utils/browser-injection";
import { WebAuthnEmulator } from "./webauthn/webauthn-emulator";

export default WebAuthnEmulator;

export * from "./webauthn/webauthn-model-json";
export * from "./webauthn/webauthn-model";
export * from "./webauthn/webauthn-emulator";
export * from "./webauthn/cose-key";

export * from "./authenticator/authenticator-emulator";
export * from "./authenticator/ctap-model";

export * from "./repository/credentials-repository";
export * from "./repository/credentials-file-repository";
export * from "./repository/credentials-memory-repository";

export const BrowserInjection = {
  WebAuthnEmulatorGet,
  WebAuthnEmulatorCreate,
  WebAuthnEmulatorSignalUnknownCredential,
  HookWebAuthnApis,
};
