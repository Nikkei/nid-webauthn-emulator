# WebAuthn API Emulator - Detailed Specification for Developers

## Overview

The [WebAuthn Emulator](../src//webauthn/webauthn-emulator.ts) is a tool for simulating authentication processes based on the WebAuthn specification. It is primarily intended for testing and development purposes.

## Main Classes

### WebAuthnEmulator

A class that mimics the main functionality of the WebAuthn protocol.

#### Key Methods

1. `getJSON(origin: string, optionsJSON: PublicKeyCredentialRequestOptionsJSON): AuthenticationResponseJSON`

   - Processes authentication requests and returns responses in JSON format.

2. `createJSON(origin: string, optionsJSON: PublicKeyCredentialCreationOptionsJSON): RegistrationResponseJSON`

   - Processes credential creation requests and returns responses in JSON format.

3. `getAuthenticatorInfo(): AuthenticatorInfo`

   - Retrieves authenticator information.

4. `signalUnknownCredential(options: UnknownCredentialOptionsJSON): void`

   - Signals unknown credentials and removes them from the authenticator.

5. `get(origin: string, options: CredentialRequestOptions): RequestPublicKeyCredential`

   - Simulates the authentication process.

6. `create(origin: string, options: CredentialCreationOptions): CreatePublicKeyCredential`
   - Simulates the process of creating new credentials.

## Key Features

1. **Credential Creation**: Uses the `create` method to simulate the creation of new public key credentials.

2. **Authentication**: Uses the `get` method to simulate authentication processes using existing credentials.

3. **JSON Compatibility**: The `getJSON` and `createJSON` methods enable processing of requests and responses in JSON format.

4. **Authenticator Information**: The `getAuthenticatorInfo` method allows you to obtain detailed information about the Authenticator.

## Security Considerations

- Relying Party ID validation: Performs proper RPID validation and generates errors for invalid RPIDs.
- Challenge processing: Includes challenges in client data and processes them with proper hashing.

## Error Handling

Custom error classes are defined:

- `WebAuthnEmulatorError`: General emulator error
- `NoPublicKeyError`: Error when no public key options are provided
- `InvalidRpIdError`: Error when an invalid Relying Party ID is detected

## Important Notes

1. This emulator is not a complete replacement for actual WebAuthn. Use only for testing and development purposes.

2. Actual implementations may require more stringent security checks and production-appropriate settings.

3. This emulator covers the basic functionality of the WebAuthn specification, but does not support all advanced features or extensions.

## Usage Example

```javascript
const emulator = new WebAuthnEmulator();

// Credential creation
const creationOptions = {
  /* ... */
};
const credential = emulator.createJSON(origin, creationOptions);

// Authentication
const requestOptions = {
  /* ... */
};
const assertion = emulator.getJSON(origin, requestOptions);
```

This document provides an overview of the main functionality and usage of the provided code. Actual implementations may require more detailed configuration and error handling.