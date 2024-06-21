import { WebAuthnApiEmulator } from "./emulators/webauthn-api";
import { HookWebAuthnApis, WebAuthnEmulatorCreate, WebAuthnEmulatorGet } from "./libs/browser-injection";

export default WebAuthnApiEmulator;

export const BrowserInjection = {
  WebAuthnEmulatorGet,
  WebAuthnEmulatorCreate,
  HookWebAuthnApis,
};
