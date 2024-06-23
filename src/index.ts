import { HookWebAuthnApis, WebAuthnEmulatorCreate, WebAuthnEmulatorGet } from "./libs/browser-injection";
import { WebAuthnApiEmulator } from "./webauthn/webauthn-api";

export default WebAuthnApiEmulator;

export const BrowserInjection = {
  WebAuthnEmulatorGet,
  WebAuthnEmulatorCreate,
  HookWebAuthnApis,
};
