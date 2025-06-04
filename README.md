# NID WebAuthn Emulator

[![CI Status](https://github.com/Nikkei/nid-webauthn-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/Nikkei/nid-webauthn-emulator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[English](README.md) | [日本語](README.ja.md)

`NID WebAuthn Emulator` is a library that provides both a [FIDO2/CTAP Authenticator emulator](src/authenticator/authenticator-emulator.ts) and a [WebAuthn API emulator](src/webauthn/webauthn-emulator.ts) built on top of it. Each component is implemented according to the WebAuthn API and CTAP specifications respectively. This module runs on Node.js and is designed for local integration testing of Passkeys.

For detailed specifications of each emulator, please refer to the following:

- [FIDO2/CTAP Authenticator Emulator Detailed Specification for Developers](docs/authenticator-emulator.en.md)
- [WebAuthn API Emulator Detailed Specification for Developers](docs/webauthn-emulator.en.md)

## Usage

```bash
npm install nid-webauthn-emulator
```

Basic usage involves creating a `WebAuthnEmulator` class and using the `create` and `get` methods to emulate `navigator.credentials.create` and `navigator.credentials.get` from the WebAuthn API.

```TypeScript
import WebAuthnEmulator from "nid-webauthn-emulator";

const emulator = new WebAuthnEmulator();
const origin = "https://example.com";

emulator.create(origin, creationOptions);
emulator.get(origin, requestOptions);
```

You can also use the `createJSON` and `getJSON` methods to perform emulation with JSON data based on the WebAuthn API specification.

```TypeScript
emulator.createJSON(origin, creationOptionsJSON);
emulator.getJSON(origin, requestOptionsJSON);
```

These JSON specifications are defined as standard specification data in the following:

- <https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson>
- <https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson>

The `WebAuthnEmulator` class emulates the following FIDO2/CTAP Authenticator by default:

- Automatically performs User Verification (sets the `uv` flag)
- Supports ES256, RS256, and EdDSA algorithms
- Emulates a USB-connected CTAP2 device
- AAGUID is `NID-AUTH-3141592`
- Increments the Sign Counter by `1` during authentication

These settings can be changed by creating an `AuthenticatorEmulator` class and passing it to the `WebAuthnEmulator` class to modify the Authenticator behavior as follows:

```TypeScript
import WebAuthnEmulator, { AuthenticatorEmulator } from "nid-webauthn-emulator";

const authenticator = new AuthenticatorEmulator({
  algorithmIdentifiers: ["ES256"],
  verifications: {
    userVerified: false,
    userPresent: false,
  },
  signCounterIncrement: 0,
});

const webAuthnEmulator = new WebAuthnEmulator(authenticator);
```

`AuthenticatorEmulator` implements the following commands from the FIDO2/CTAP specification:

- `authenticatorMakeCredential` (CTAP2): Creating credentials
- `authenticatorGetAssertion` (CTAP2): Retrieving credentials
- `authenticatorGetInfo` (CTAP2): Getting authenticator information

These are typically not used directly, but are called internally by the `WebAuthnEmulator` class according to the CTAP protocol as follows:

```TypeScript
const authenticatorRequest = packMakeCredentialRequest({
  clientDataHash: createHash("sha256").update(clientDataJSON).digest(),
  rp: options.publicKey.rp,
  user: options.publicKey.user,
  pubKeyCredParams: options.publicKey.pubKeyCredParams,
  excludeList: options.publicKey.excludeCredentials,
  options: {
    rk: options.publicKey.authenticatorSelection?.requireResidentKey,
    uv: options.publicKey.authenticatorSelection?.userVerification !== "discouraged",
  },
});
const authenticatorResponse = unpackMakeCredentialResponse(this.authenticator.command(authenticatorRequest));
```

## Example with [WebAuthn.io](https://webauthn.io/)

Here's an example of usage with [webauthn.io](https://webauthn.io/), a well-known WebAuthn demo site. You can find working test code examples in the [integration tests](spec/integration/integration.spec.ts).

```TypeScript
// Initialize the Origin and WebAuthn API emulator
// Here we use https://webauthn.io as the Origin
const origin = "https://webauthn.io";
const emulator = new WebAuthnEmulator();
const webauthnIO = await WebAuthnIO.create();
const user = webauthnIO.getUser();

// Display Authenticator information
console.log("Authenticator Information", emulator.getAuthenticatorInfo());

// Create passkey using WebAuthn API Emulator
const creationOptions = await webauthnIO.getRegistrationOptions(user);
const creationCredential = emulator.createJSON(origin, creationOptions);
await webauthnIO.getRegistrationVerification(user, creationCredential);

// Verify authentication with webauthn.io
const requestOptions = await webauthnIO.getAuthenticationOptions();
const requestCredential = emulator.getJSON(origin, requestOptions);
await webauthnIO.getAuthenticationVerification(requestCredential);
```

## Automated Testing with Playwright

This library is intended for use in Passkeys E2E testing, particularly with Playwright. For Playwright testing, you can easily use the WebAuthn API emulator with the utility class `BrowserInjection`. Here's how to use it:

```TypeScript
import WebAuthnEmulator, {
  BrowserInjection,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "nid-webauthn-emulator";

async function startWebAuthnEmulator(page: Page, origin: string, debug = false, relatedOrigins: string[] = []) {
  const emulator = new WebAuthnEmulator();

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorCreate,
    async (optionsJSON: PublicKeyCredentialCreationOptionsJSON) => {
      const response = emulator.createJSON(origin, optionsJSON, relatedOrigins);
      return response;
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorGet,
    async (optionsJSON: PublicKeyCredentialRequestOptionsJSON) => {
      const response = emulator.getJSON(origin, optionsJSON, relatedOrigins);
      return response;
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorSignalUnknownCredential,
    async (options: UnknownCredentialOptionsJSON) => {
      emulator.signalUnknownCredential(options);
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorSignalAllAcceptedCredentials,
    async (options: AllAcceptedCredentialsOptionsJSON) => {
      emulator.signalAllAcceptedCredentials(options);
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorSignalCurrentUserDetails,
    async (options: CurrentUserDetailsOptionsJSON) => {
      emulator.signalCurrentUserDetails(options);
    },
  );
}

test.describe("Passkeys Tests", { tag: ["@daily"] }, () => {
  test("Passkeys login test", async ({ page }) => {
    // Exposed functions defined once per page initially
    // Related origins can be specified as needed
    const relatedOrigins = ["https://sub.example.com", "https://alt.example.com"];
    await startWebAuthnEmulator(page, env, true, relatedOrigins);
    await page.goto("https://example.com/passkeys/login");

    // Start hooking Passkeys WebAuthn API
    // Must be executed after page navigation
    await page.evaluate(BrowserInjection.HookWebAuthnApis);
  });
});
```

`startWebAuthnEmulator` uses Playwright's `exposeFunction` to inject the `WebAuthnEmulator`'s `createJSON` and `getJSON` methods into the browser context. This makes the `WebAuthnEmulator` class's `get` and `create` APIs available under the `window` object in the Playwright test context.

- `window.webAuthnEmulatorGet`: Exposed Function for `WebAuthnEmulator.getJSON`
- `window.webAuthnEmulatorCreate`: Exposed Function for `WebAuthnEmulator.createJSON`
- `window.webAuthnEmulatorSignalUnknownCredential`: Exposed Function for `WebAuthnEmulator.signalUnknownCredential`
- `window.webAuthnEmulatorSignalAllAcceptedCredentials`: Exposed Function for `WebAuthnEmulator.signalAllAcceptedCredentials`
- `window.webAuthnEmulatorSignalCurrentUserDetails`: Exposed Function for `WebAuthnEmulator.signalCurrentUserDetails`

Additionally, the `startWebAuthnEmulator` function supports a `relatedOrigins` parameter. This allows requests from different origins to use the same RP ID. This is useful when using Passkeys in multi-domain environments (such as `example.com` and `sub.example.com`). The value of `relatedOrigins` is the same as the content of `/.well-known/webauthn` hosted on the domain specified by the RP ID.

These are defined globally per Page, so they need to be defined only once per Page instance.

Next, to hook WebAuthn APIs like `navigator.credentials.get`, evaluate `BrowserInjection.HookWebAuthnApis` in the test context.

```TypeScript
await page.evaluate(BrowserInjection.HookWebAuthnApis);
```

`BrowserInjection.HookWebAuthnApis` is a serialized string of a JavaScript function that, when evaluated, performs the following operations:

- Overrides the definition of `navigator.credentials.get` to call `window.webAuthnEmulatorGet`
- Overrides the definition of `navigator.credentials.create` to call `window.webAuthnEmulatorCreate`
- Adds the definition of `PublicKeyCredential.signalUnknownCredential` to call `window.webAuthnEmulatorSignalUnknownCredential`

This ensures that the `WebAuthnEmulator` methods defined earlier with `exposeFunction` are executed when `navigator.credentials.get` and `navigator.credentials.create` are called. These processes include serialization and deserialization of data for communication between the test context and Playwright context.

## License

MIT License

Copyright (C) 2024 Nikkei Inc.