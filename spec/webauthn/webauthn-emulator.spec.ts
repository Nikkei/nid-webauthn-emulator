import { describe, expect, test } from "@jest/globals";
import WebAuthnEmulator, {
  AuthenticationEmulatorError,
  CTAP_STATUS_CODE,
  AuthenticatorEmulator,
  InvalidRpIdError,
  NoPublicKeyError,
} from "../../src";
import { TEST_RP_ORIGIN, WebAuthnTestServer } from "./webauthn-test-server";

describe("WebAuthnEmulator Registration Passkeys Test", () => {
  const user = { username: "test", id: "test" };
  test("Create Passkeys test _ OK", async () => {
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();

    const options = await testServer.getRegistrationOptions(user);
    const credential = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential);
  });

  test("Create Passkeys with an illegal origin _ failed to response", async () => {
    const illegalOrigin = `${TEST_RP_ORIGIN}_illegal`;
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();

    const options = await testServer.getRegistrationOptions(user);

    await expect(async () => {
      emulator.createJSON(illegalOrigin, options);
    }).rejects.toThrow(InvalidRpIdError);
  });

  test("Create Passkeys with no public key credential parameters _ failed to response", async () => {
    const emulator = new WebAuthnEmulator();
    await expect(async () => {
      emulator.create(TEST_RP_ORIGIN, {});
    }).rejects.toThrow(NoPublicKeyError);
  });

  test("Found in the exclude List _ CTAP Error", async () => {
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);
    const credential = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential);
    const options2 = await testServer.getRegistrationOptions(user);
    await expect(async () => {
      emulator.createJSON(TEST_RP_ORIGIN, options2);
    }).rejects.toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_CREDENTIAL_EXCLUDED));
  });

  test("Invalid algorithm _ CTAP Error", async () => {
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);
    const illegalOptions = { ...options, pubKeyCredParams: [{ type: "public-key", alg: 99 } as const] };
    await expect(async () => {
      emulator.createJSON(TEST_RP_ORIGIN, illegalOptions);
    }).rejects.toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_UNSUPPORTED_ALGORITHM));
  });

  test("User registration operation failed _ CTAP Error", async () => {
    const authenticator = new AuthenticatorEmulator({
      userMakeCredentialInteraction: () => undefined,
    });
    const emulator = new WebAuthnEmulator(authenticator);
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);
    await expect(async () => {
      emulator.createJSON(TEST_RP_ORIGIN, options);
    }).rejects.toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED));
  });
});

describe("WebAuthnEmulator Authentication Passkeys Test", () => {
  const user = { username: "test", id: "test" };
  const createCredential = async (
    authenticator?: AuthenticatorEmulator,
  ): Promise<[WebAuthnEmulator, WebAuthnTestServer]> => {
    const emulator = new WebAuthnEmulator(authenticator);
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);
    const credential = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential);
    return [emulator, testServer];
  };

  test("Create and Authenticate Passkeys test _ OK", async () => {
    const [emulator, testServer] = await createCredential();
    const options = await testServer.getAuthenticationOptions();
    const credential = emulator.getJSON(TEST_RP_ORIGIN, options);
    await testServer.getAuthenticationVerification(credential);
  });

  test("Authenticate Passkeys with an illegal origin _ failed to response", async () => {
    const [emulator, testServer] = await createCredential();
    const illegalOrigin = `${TEST_RP_ORIGIN}_illegal`;
    const options = await testServer.getAuthenticationOptions();
    await expect(async () => {
      emulator.getJSON(illegalOrigin, options);
    }).rejects.toThrow(InvalidRpIdError);
  });

  test("Request Passkeys with no public key credential parameters _ failed to response", async () => {
    const emulator = new WebAuthnEmulator();
    await expect(async () => {
      emulator.get(TEST_RP_ORIGIN, {});
    }).rejects.toThrow(NoPublicKeyError);
  });

  test("Not found in allow list _ CTAP Error", async () => {
    const [emulator, testServer] = await createCredential();
    const options = await testServer.getAuthenticationOptions();
    await expect(async () => {
      emulator.getJSON(TEST_RP_ORIGIN, {
        ...options,
        allowCredentials: [{ id: "AAAAAA", type: "public-key" }],
      });
    }).rejects.toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS));
  });

  test("User authentication operation failed _ CTAP Error", async () => {
    const authenticator = new AuthenticatorEmulator({
      userGetAssertionInteraction: () => undefined,
    });
    const [emulator, testServer] = await createCredential(authenticator);
    const options = await testServer.getAuthenticationOptions();
    await expect(async () => {
      emulator.getJSON(TEST_RP_ORIGIN, options);
    }).rejects.toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED));
  });
});

describe("WebAuthnEmulator getAuthenticatorInfo Test", () => {
  test("Get Authenticator Information _ OK", () => {
    const emulator = new WebAuthnEmulator();
    const info = emulator.getAuthenticatorInfo();
    expect(info).toEqual({
      version: "FIDO_2_0",
      aaguid: "TklELUFVVEgtMzE0MTU5Mg",
      options: { rk: true, uv: true },
    });
  });
});
