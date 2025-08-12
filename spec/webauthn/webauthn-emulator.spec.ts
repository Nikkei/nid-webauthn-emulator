import { describe, expect, test } from "@jest/globals";
import WebAuthnEmulator, {
  AuthenticationEmulatorError,
  AuthenticatorEmulator,
  CTAP_COMMAND,
  CTAP_STATUS_CODE,
  type CTAPAuthenticatorRequest,
  type CTAPAuthenticatorResponse,
  InvalidRpIdError,
  NoPublicKeyError,
  type PasskeysCredentialsRepository,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  packCredentialManagementResponse,
  parseRequestOptionsFromJSON,
  toPublicKeyCredentialDescriptorJSON,
  unpackAuthenticatorData,
} from "../../src";
import EncodeUtils from "../../src/libs/encode-utils";
import { PasskeysCredentialsMemoryRepository } from "../../src/repository/credentials-memory-repository";
import { TEST_RP_ORIGIN, WebAuthnTestServer } from "./webauthn-test-server";

describe("WebAuthnEmulator Registration Passkeys Test", () => {
  const user = { username: "test", id: "test" };
  test("Create Passkeys test _ OK", async () => {
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();

    const options = await testServer.getRegistrationOptions(user);
    const credential1 = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential1);

    const credential2 = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential2);

    // Last Credentials only
    const credentialRecords = emulator.authenticator.params.credentialsRepository?.loadCredentials() ?? [];
    expect(credentialRecords.length).toBe(1);
    expect(EncodeUtils.encodeBase64Url(credentialRecords[0].publicKeyCredentialSource.id)).toBe(credential2.id);
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

  test("Create Passkeys without RP ID _ OK", async () => {
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();

    const options = await testServer.getRegistrationOptions(user);
    const customOptions: PublicKeyCredentialCreationOptionsJSON = {
      ...options,
      rp: { name: "test" },
    };
    const credential1 = emulator.createJSON(TEST_RP_ORIGIN, customOptions);
    await testServer.getRegistrationVerification(user, credential1);
  });
});

describe("WebAuthnEmulator Authentication Passkeys Test", () => {
  const user = { username: "test", id: "test" };
  const createCredential = async (
    authenticator?: AuthenticatorEmulator,
  ): Promise<[WebAuthnEmulator, WebAuthnTestServer]> => {
    const testServer1 = new WebAuthnTestServer();
    const testServer2 = new WebAuthnTestServer("https://test-rp2.com", "test-rp2.com");
    const emulator = new WebAuthnEmulator(authenticator);

    const options1 = await testServer1.getRegistrationOptions(user);
    const credential1 = emulator.createJSON(testServer1.origin, options1);
    await testServer1.getRegistrationVerification(user, credential1);

    const options2 = await testServer2.getRegistrationOptions(user);
    const customOptions2: PublicKeyCredentialCreationOptionsJSON = {
      ...options2,
      authenticatorSelection: { residentKey: "discouraged" },
    };
    const credential2 = emulator.createJSON(testServer2.origin, customOptions2);
    await testServer2.getRegistrationVerification(user, credential2);

    return [emulator, testServer1];
  };

  test("Create and Authenticate Passkeys test _ OK", async () => {
    const [emulator, testServer] = await createCredential();
    const options = await testServer.getAuthenticationOptions();
    const credential = emulator.getJSON(TEST_RP_ORIGIN, options);
    await testServer.getAuthenticationVerification(credential);
  });

  test("EdDSA Algorithm Passkeys test _ OK", async () => {
    const authenticator = new AuthenticatorEmulator({ algorithmIdentifiers: ["EdDSA"] });
    const [emulator, testServer] = await createCredential(authenticator);
    const options = await testServer.getAuthenticationOptions();
    const credential = emulator.getJSON(TEST_RP_ORIGIN, options);
    await testServer.getAuthenticationVerification(credential);
  });

  test("RS256 Algorithm Passkeys test _ OK", async () => {
    const authenticator = new AuthenticatorEmulator({ algorithmIdentifiers: ["RS256"] });
    const [emulator, testServer] = await createCredential(authenticator);
    const options = await testServer.getAuthenticationOptions();
    const credential = emulator.getJSON(TEST_RP_ORIGIN, options);
    await testServer.getAuthenticationVerification(credential);
  });

  test("SignCounter Increment test _ OK", async () => {
    const authenticator = new AuthenticatorEmulator({ signCounterIncrement: 13 });
    const [emulator, testServer] = await createCredential(authenticator);
    const options1 = await testServer.getAuthenticationOptions();
    const credential1 = emulator.getJSON(TEST_RP_ORIGIN, options1);

    const authData = unpackAuthenticatorData(EncodeUtils.decodeBase64Url(credential1.response.authenticatorData));
    expect(authData.signCount).toBe(13);

    const options2 = await testServer.getAuthenticationOptions();
    const credential2 = emulator.getJSON(TEST_RP_ORIGIN, options2);
    const authData2 = unpackAuthenticatorData(EncodeUtils.decodeBase64Url(credential2.response.authenticatorData));
    expect(authData2.signCount).toBe(26);
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

  test("Only one credential is allowed and RP ID is undefined _ credential is undefined and OK", async () => {
    const [emulator, testServer] = await createCredential();
    const options = await testServer.getAuthenticationOptions();
    const credential = (emulator.authenticator.params.credentialsRepository?.loadCredentials() ?? [])[0];
    emulator.getJSON(TEST_RP_ORIGIN, {
      ...options,
      rpId: undefined,

      allowCredentials: [toPublicKeyCredentialDescriptorJSON(credential.publicKeyCredentialDescriptor)],
    } as PublicKeyCredentialRequestOptionsJSON);
  });

  test("Stateless Authenticator Test _ OK", async () => {
    const authenticator = new AuthenticatorEmulator({ stateless: true });
    const [emulator, testServer] = await createCredential(authenticator);
    const options = await testServer.getAuthenticationOptions();
    const credential = emulator.getJSON(TEST_RP_ORIGIN, options);
    await testServer.getAuthenticationVerification(credential);

    const credentialRecords = emulator.authenticator.params.credentialsRepository?.loadCredentials() ?? [];
    const authData = unpackAuthenticatorData(EncodeUtils.decodeBase64Url(credential.response.authenticatorData));
    expect(credentialRecords.length).toBe(0);
    expect(authData.signCount).toBe(0);
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

describe("WebAuthnEmulator signalUnknownCredential Test", () => {
  test("Signal Unknown Credential _ OK", async () => {
    const user = { username: "test-signal", id: "test-signal" };
    // Create a new emulator with a clean repository
    const repository = new PasskeysCredentialsMemoryRepository();
    const authenticator = new AuthenticatorEmulator({
      credentialsRepository: repository,
    });
    const emulator = new WebAuthnEmulator(authenticator);
    const testServer = new WebAuthnTestServer();

    // Create a credential
    const options = await testServer.getRegistrationOptions(user);
    const credential = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential);

    // Verify the credential exists
    const credentialsBefore = repository.loadCredentials();
    expect(credentialsBefore.length).toBe(1);

    // Signal unknown credential
    emulator.signalUnknownCredential({
      rpId: TEST_RP_ORIGIN.replace("https://", ""),
      credentialId: credential.id,
    });

    // Verify the credential was deleted
    const credentialsAfter = repository.loadCredentials();
    expect(credentialsAfter.length).toBe(0);
  });
});

describe("WebAuthnEmulator signalAllAcceptedCredentials Test", () => {
  test("Signal All Accepted Credentials _ OK", async () => {
    // Create users
    const user = { username: "user1", id: "user1-id" };

    // Create a new emulator with a clean repository
    const repository = new PasskeysCredentialsMemoryRepository();
    const authenticator = new AuthenticatorEmulator({
      credentialsRepository: repository,
    });
    const emulator = new WebAuthnEmulator(authenticator);
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);

    // Create credential1 for user
    const credential1 = emulator.createJSON(TEST_RP_ORIGIN, options);
    const backupCredential1 = repository.loadCredentials()[0];

    // Create credential2 for user (credential1 is overwritten)
    const credential2 = emulator.createJSON(TEST_RP_ORIGIN, options);

    // restore credential1
    repository.saveCredential(backupCredential1);

    // Verify all credentials exist
    const credentialsBefore = repository.loadCredentials();
    expect(credentialsBefore.length).toBe(2);

    // Get the user1 credentials
    const user1Credentials = credentialsBefore.filter((cred) => cred.user.name === user.username);

    // Get the actual user ID from the credential
    const actualUserId = EncodeUtils.encodeBase64Url(user1Credentials[0].user.id);

    // Get the IDs of all credentials
    const allCredentialIds = credentialsBefore.map((cred) =>
      EncodeUtils.encodeBase64Url(cred.publicKeyCredentialSource.id),
    );

    // Signal that only the first credential is accepted for user1
    emulator.signalAllAcceptedCredentials({
      rpId: TEST_RP_ORIGIN.replace("https://", ""),
      userId: actualUserId,
      allAcceptedCredentialIds: [credential1.id],
    });

    // Verify that one credential was deleted
    const credentialsAfter = repository.loadCredentials();
    expect(credentialsAfter.length).toBe(1);

    // Check that credential1 and credential3 still exist
    const remainingIds = credentialsAfter.map((cred) => EncodeUtils.encodeBase64Url(cred.publicKeyCredentialSource.id));
    expect(remainingIds).toContain(credential1.id);
    expect(remainingIds).not.toContain(credential2.id);

    // Verify one credential was deleted
    expect(remainingIds.length).toBe(1);
    expect(allCredentialIds.length).toBe(2);
    const deletedIds = allCredentialIds.filter((id) => !remainingIds.includes(id));
    expect(deletedIds.length).toBe(1);
  });

  test("Signal All Accepted Credentials with empty list _ Delete all user credentials", async () => {
    // Create user
    const user = { username: "user-test", id: "user-test-id" };

    // Create a new emulator with a clean repository
    const repository = new PasskeysCredentialsMemoryRepository();
    const authenticator = new AuthenticatorEmulator({
      credentialsRepository: repository,
    });
    const emulator = new WebAuthnEmulator(authenticator);
    const testServer = new WebAuthnTestServer();

    // Create a credential for the user
    const options = await testServer.getRegistrationOptions(user);
    const credential1 = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential1);

    // Verify credentials exist
    const credentialsBefore = repository.loadCredentials();
    expect(credentialsBefore.length).toBe(1);

    // Get the actual user ID from the credential
    const actualUserId = EncodeUtils.encodeBase64Url(credentialsBefore[0].user.id);

    // Signal empty accepted credentials list
    emulator.signalAllAcceptedCredentials({
      rpId: TEST_RP_ORIGIN.replace("https://", ""),
      userId: actualUserId,
      allAcceptedCredentialIds: [],
    });

    // Verify all user credentials were deleted
    const userCredentialsAfter = repository
      .loadCredentials()
      .filter((cred) => EncodeUtils.encodeBase64Url(cred.user.id) === actualUserId);

    expect(userCredentialsAfter.length).toBe(0);
  });
});

describe("WebAuthnEmulator relatedOrigins Test", () => {
  test("Get with relatedOrigins _ OK with origin not matching rpId", async () => {
    const user = { username: "test-related", id: "test-related" };
    const emulator = new WebAuthnEmulator();

    // Origin is different from the RP ID
    const testServer = new WebAuthnTestServer("https://test-rp.com", "test-rp2.com");

    const relatedOrigins = ["https://test-rp-a.com", "https://test-rp-b.com", "https://test-rp.com"];

    // Register a credential
    const regOptions = await testServer.getRegistrationOptions(user);
    const credential = emulator.createJSON(testServer.origin, regOptions, relatedOrigins);
    await testServer.getRegistrationVerification(user, credential);

    // Create authentication options
    const authOptions = await testServer.getAuthenticationOptions();

    // Standard RP ID validation only
    await expect(async () => {
      emulator.getJSON(testServer.origin, authOptions);
    }).rejects.toThrow(InvalidRpIdError);

    // Related origins validation
    const authResponse = emulator.getJSON(testServer.origin, authOptions, relatedOrigins);
    expect(authResponse).toBeDefined();
    expect(authResponse.id).toBe(credential.id);
  });
});

describe("WebAuthnEmulator signalCurrentUserDetails Test", () => {
  test("Signal Current User Details _ OK", async () => {
    // Create user
    const user = { username: "user-details", id: "user-details-id" };

    // Create a new emulator with a clean repository
    const repository = new PasskeysCredentialsMemoryRepository();
    const authenticator = new AuthenticatorEmulator({
      credentialsRepository: repository,
    });
    const emulator = new WebAuthnEmulator(authenticator);
    const testServer = new WebAuthnTestServer();

    // Create a credential
    const options = await testServer.getRegistrationOptions(user);
    const credential = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential);

    // Verify the credential exists with original user details
    const credentialsBefore = repository.loadCredentials();
    expect(credentialsBefore.length).toBe(1);
    expect(credentialsBefore[0].user.name).toBe(user.username);
    // Note: We don't check displayName as it's not consistently set by the test server

    // Get the actual user ID from the credential
    const actualUserId = EncodeUtils.encodeBase64Url(credentialsBefore[0].user.id);

    // Update user details using the actual user ID from the credential
    const updatedName = "Updated User Name";
    const updatedDisplayName = "Updated Display Name";

    emulator.signalCurrentUserDetails({
      rpId: TEST_RP_ORIGIN.replace("https://", ""),
      userId: actualUserId,
      name: updatedName,
      displayName: updatedDisplayName,
    });

    // Verify the user details were updated
    const credentialsAfter = repository.loadCredentials();
    expect(credentialsAfter.length).toBe(1);
    expect(credentialsAfter[0].user.name).toBe(updatedName);
    expect(credentialsAfter[0].user.displayName).toBe(updatedDisplayName);

    // Verify the credential ID and user ID remain unchanged
    expect(EncodeUtils.encodeBase64Url(credentialsAfter[0].publicKeyCredentialSource.id)).toBe(credential.id);
    expect(EncodeUtils.encodeBase64Url(credentialsAfter[0].user.id)).toBe(actualUserId);
  });

  test("Signal Current User Details with non-existent user _ Error", async () => {
    // Create a new emulator with a clean repository
    const repository = new PasskeysCredentialsMemoryRepository();
    const authenticator = new AuthenticatorEmulator({
      credentialsRepository: repository,
    });
    const emulator = new WebAuthnEmulator(authenticator);

    // Try to update non-existent user
    const nonExistentUserId = "non-existent-user-id";

    expect(() => {
      emulator.signalCurrentUserDetails({
        rpId: TEST_RP_ORIGIN.replace("https://", ""),
        userId: EncodeUtils.encodeBase64Url(EncodeUtils.strToUint8Array(nonExistentUserId)),
        name: "New Name",
        displayName: "New Display Name",
      });
    }).toThrow(); // Should throw CTAP2_ERR_NO_CREDENTIALS
  });
});

describe("WebAuthnEmulator getClientExtensionResults.rk coverage", () => {
  test("rk=true when discoverable credential (user present)", async () => {
    const emulator = new WebAuthnEmulator(new AuthenticatorEmulator());
    const testServer = new WebAuthnTestServer();

    const user = { username: "ext-user", id: "ext-user" };
    const regOptions = await testServer.getRegistrationOptions(user);
    const regResp = emulator.createJSON(TEST_RP_ORIGIN, regOptions);
    await testServer.getRegistrationVerification(user, regResp);

    const reqOptions = await testServer.getAuthenticationOptions();
    const parsed = parseRequestOptionsFromJSON(reqOptions);
    const cred = emulator.get(TEST_RP_ORIGIN, { publicKey: parsed });

    const ext = cred.getClientExtensionResults();
    expect("credProps" in ext && ext.credProps).toBeTruthy();
    if ("credProps" in ext && ext.credProps) {
      expect(ext.credProps.rk).toBe(true);
    }
  });

  test("rk=false with stateless + single allowCredential (no user)", async () => {
    const emulator = new WebAuthnEmulator(new AuthenticatorEmulator({ stateless: true }));
    const testServer = new WebAuthnTestServer();

    const user = { username: "ext-user2", id: "ext-user2" };
    const regOptions = await testServer.getRegistrationOptions(user);
    const regResp = emulator.createJSON(TEST_RP_ORIGIN, regOptions);
    await testServer.getRegistrationVerification(user, regResp);

    const reqOptions = await testServer.getAuthenticationOptions();
    const singleAllow: PublicKeyCredentialRequestOptionsJSON = {
      ...reqOptions,
      allowCredentials: [{ type: "public-key", id: regResp.id }],
    };

    const parsed = parseRequestOptionsFromJSON(singleAllow);
    const cred = emulator.get(TEST_RP_ORIGIN, { publicKey: parsed });
    const ext = cred.getClientExtensionResults();
    expect("credProps" in ext && ext.credProps).toBeTruthy();
    if ("credProps" in ext && ext.credProps) {
      expect(ext.credProps.rk).toBe(false);
    }
  });

  test("signalAllAcceptedCredentials skips credentials when userId mismatches", async () => {
    // repository-backed authenticator with isolated repository
    const emulator = new WebAuthnEmulator(
      new AuthenticatorEmulator({ credentialsRepository: new PasskeysCredentialsMemoryRepository() }),
    );
    const testServer = new WebAuthnTestServer();

    const user = { username: "ext-user3", id: "ext-user3" };
    const regOptions = await testServer.getRegistrationOptions(user);
    const regResp = emulator.createJSON(TEST_RP_ORIGIN, regOptions);
    const repository = emulator.authenticator.params.credentialsRepository as PasskeysCredentialsRepository;
    await testServer.getRegistrationVerification(user, regResp);

    // credentials exist
    const before = repository.loadCredentials();
    expect(before.length).toBe(1);
    const existingId = before.map((c) => EncodeUtils.encodeBase64Url(c.publicKeyCredentialSource.id))[0];
    const actualUserId = EncodeUtils.encodeBase64Url(before[0].user.id);
    // ensure mismatch by altering actualUserId
    const wrongUserId = `${actualUserId}-mismatch`;
    emulator.signalAllAcceptedCredentials({
      rpId: TEST_RP_ORIGIN.replace("https://", ""),
      userId: wrongUserId,
      allAcceptedCredentialIds: [], // even though empty, mismatch should skip deletion
    });

    const after = repository.loadCredentials();
    const remainingIds = after.map((c) => EncodeUtils.encodeBase64Url(c.publicKeyCredentialSource.id));
    expect(remainingIds).toContain(existingId); // original credential remains
    expect(after.length).toBe(1); // unchanged
  });

  test("signalAllAcceptedCredentials handles undefined totalCredentials (defaults to 0)", async () => {
    class BeginNoTotalAuthenticator extends AuthenticatorEmulator {
      override command(request: CTAPAuthenticatorRequest): CTAPAuthenticatorResponse {
        if (request.command === CTAP_COMMAND.authenticatorCredentialManagement) {
          return packCredentialManagementResponse({});
        }
        return super.command(request);
      }
    }

    const emulator = new WebAuthnEmulator(new BeginNoTotalAuthenticator());
    expect(() =>
      emulator.signalAllAcceptedCredentials({
        rpId: TEST_RP_ORIGIN.replace("https://", ""),
        userId: "any-user",
        allAcceptedCredentialIds: [],
      }),
    ).not.toThrow();
  });
});
