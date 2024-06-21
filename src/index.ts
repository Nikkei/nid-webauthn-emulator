import { WebAuthnApiEmulator } from "./emulators/webauthn-api";
import { InjectWebAuthnEmulatorCode, WebAuthnEmulatorCreate, WebAuthnEmulatorGet } from "./libs/browser-injection";

export default WebAuthnApiEmulator;

export const BrowserInjection = {
  WebAuthnEmulatorGet,
  WebAuthnEmulatorCreate,
  InjectWebAuthnEmulatorCode,
};
