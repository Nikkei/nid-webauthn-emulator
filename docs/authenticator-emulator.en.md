# FIDO2/CTAP Authenticator Emulator - Detailed Specification for Developers

## Overview

The [Authenticator Emulator](../src/authenticator/authenticator-emulator.ts) is a tool for software simulation of FIDO2-compliant Authenticators. It is primarily intended for testing and development of WebAuthn implementations.

## Main Classes

### AuthenticatorEmulator

A class that emulates the main functionality of an Authenticator based on the CTAP protocol.

#### Key Methods

1. `command(request: CTAPAuthenticatorRequest): CTAPAuthenticatorResponse`

   - Receives CTAP commands and returns appropriate responses.

2. `authenticatorGetInfo(): AuthenticatorGetInfoResponse`

   - Returns information about the Authenticator.

3. `authenticatorMakeCredential(request: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse`

   - Creates new credentials.

4. `authenticatorGetAssertion(request: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse`
   - Performs authentication using existing credentials.

## Key Features

1. **Credential Creation**: Uses the `authenticatorMakeCredential` method to simulate the creation of new public key credentials.

2. **Authentication**: Uses the `authenticatorGetAssertion` method to simulate authentication processes using existing credentials.

3. **Authenticator Information Retrieval**: The `authenticatorGetInfo` method allows you to obtain detailed information about the Authenticator.

4. **CTAP Command Processing**: The `command` method processes commands based on the CTAP protocol.

5. **Customizable Parameters**: Various parameters can be customized, including AAGUID, supported algorithms, and user operation simulation.

6. **Stateless Mode**: Processes each command independently without maintaining Authenticator state.

## Security Considerations

- Exclude list and allow list processing: Performs appropriate credential filtering during credential creation and authentication.
- Signature counter management: Increases the signature counter with each authentication to prevent replay attacks.

## Error Handling

Uses the `AuthenticationEmulatorError` class to return error codes based on the CTAP protocol.

## Important Notes

1. This emulator is not a complete replacement for actual hardware Authenticators. Use only for testing and development purposes.

2. Actual implementations may require more stringent security checks and production-appropriate settings.

3. This emulator covers the basic functionality of the FIDO2/WebAuthn specification, but does not support all advanced features or extensions.

## Customization

Using `AuthenticatorParameters`, you can customize the following items:

- AAGUID
- Supported transport protocols
- Supported cryptographic algorithms
- Signature counter increment
- User verification and presence confirmation simulation
- User interaction simulation
- Credential storage method
- Stateless mode activation

## Usage Example

```javascript
const emulator = new AuthenticatorEmulator({
  aaguid: new Uint8Array([
    /* Custom AAGUID */
  ]),
  algorithmIdentifiers: ["ES256", "RS256"],
  // Other custom parameters
});

// Processing MakeCredential command
const makeCredentialRequest = {
  /* ... */
};
const credentialResponse = emulator.command({
  command: CTAP_COMMAND.authenticatorMakeCredential,
  request: makeCredentialRequest,
});

// Processing GetAssertion command
const getAssertionRequest = {
  /* ... */
};
const assertionResponse = emulator.command({
  command: CTAP_COMMAND.authenticatorGetAssertion,
  request: getAssertionRequest,
});
```

This document provides an overview of the main functionality and usage of the provided CTAP-based Authenticator emulator code. Actual implementations may require more detailed configuration, error handling, and security considerations.