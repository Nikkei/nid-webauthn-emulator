import { HookWebAuthnApis, WebAuthnEmulatorCreate, WebAuthnEmulatorGet } from "./libs/browser-injection";
import { WebAuthnEmulator } from "./webauthn/webauthn-api";

export default WebAuthnEmulator;

export const BrowserInjection = {
  WebAuthnEmulatorGet,
  WebAuthnEmulatorCreate,
  HookWebAuthnApis,
};
