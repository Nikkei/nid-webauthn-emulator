import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, test } from "node:test";
import WebAuthnEmulator, {
  AuthenticationEmulatorError,
  AuthenticatorEmulator,
  type CreatePublicKeyCredential,
  CTAP_COMMAND,
  CTAP_STATUS_CODE,
  type CTAPAuthenticatorRequest,
  type CTAPAuthenticatorResponse,
  type PasskeysCredentialsRepository,
  packCredentialManagementResponse,
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
  type RequestPublicKeyCredential,
  toPublicKeyCredentialDescriptorJSON,
  unpackAuthenticatorData,
} from "../../src";
import EncodeUtils from "../../src/libs/encode-utils";
import { PasskeysCredentialsFileRepository } from "../../src/repository/credentials-file-repository";
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
    assert.equal(credentialRecords.length, 1);
    assert.equal(EncodeUtils.encodeBase64Url(credentialRecords[0].publicKeyCredentialSource.id), credential2.id);
  });

  test("Create Passkeys with an illegal origin _ failed to response", async () => {
    const illegalOrigin = `${TEST_RP_ORIGIN}_illegal`;
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();

    const options = await testServer.getRegistrationOptions(user);
    const call = () => emulator.createJSON(illegalOrigin, options);
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "SecurityError");
    }
  });

  test("Create Passkeys with no public key credential parameters _ failed to response", async () => {
    const emulator = new WebAuthnEmulator();
    const call = () => emulator.create(TEST_RP_ORIGIN, {});
    assert.throws(call, TypeError);
  });

  test("Found in the exclude List _ CTAP Error", async () => {
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);
    const credential = emulator.createJSON(TEST_RP_ORIGIN, options);
    await testServer.getRegistrationVerification(user, credential);
    const options2 = await testServer.getRegistrationOptions(user);
    const call = () => emulator.createJSON(TEST_RP_ORIGIN, options2);
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "NotAllowedError");
    }
  });

  test("Invalid algorithm _ CTAP Error", async () => {
    const emulator = new WebAuthnEmulator();
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);
    const illegalOptions = { ...options, pubKeyCredParams: [{ type: "public-key", alg: 99 } as const] };
    const call = () => emulator.createJSON(TEST_RP_ORIGIN, illegalOptions);
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "NotSupportedError");
    }
  });

  test("User registration operation failed _ CTAP Error", async () => {
    const authenticator = new AuthenticatorEmulator({
      userMakeCredentialInteraction: () => undefined,
    });
    const emulator = new WebAuthnEmulator(authenticator);
    const testServer = new WebAuthnTestServer();
    const options = await testServer.getRegistrationOptions(user);
    const call = () => emulator.createJSON(TEST_RP_ORIGIN, options);
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "NotAllowedError");
    }
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
    assert.equal(authData.signCount, 13);

    const options2 = await testServer.getAuthenticationOptions();
    const credential2 = emulator.getJSON(TEST_RP_ORIGIN, options2);
    const authData2 = unpackAuthenticatorData(EncodeUtils.decodeBase64Url(credential2.response.authenticatorData));
    assert.equal(authData2.signCount, 26);
  });

  test("Authenticate Passkeys with an illegal origin _ failed to response", async () => {
    const [emulator, testServer] = await createCredential();
    const illegalOrigin = `${TEST_RP_ORIGIN}_illegal`;
    const options = await testServer.getAuthenticationOptions();
    const call = () => emulator.getJSON(illegalOrigin, options);
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "SecurityError");
    }
  });

  test("Request Passkeys with no public key credential parameters _ failed to response", async () => {
    const emulator = new WebAuthnEmulator();
    const call = () => emulator.get(TEST_RP_ORIGIN, {} as CredentialRequestOptions);
    assert.throws(call, TypeError);
  });

  test("Not found in allow list _ CTAP Error", async () => {
    const [emulator, testServer] = await createCredential();
    const options = await testServer.getAuthenticationOptions();
    const call = () =>
      emulator.getJSON(TEST_RP_ORIGIN, {
        ...options,
        allowCredentials: [{ id: "AAAAAA", type: "public-key" }],
      });
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "NotAllowedError");
    }
  });

  test("User authentication operation failed _ CTAP Error", async () => {
    const authenticator = new AuthenticatorEmulator({
      userGetAssertionInteraction: () => undefined,
    });
    const [emulator, testServer] = await createCredential(authenticator);
    const options = await testServer.getAuthenticationOptions();
    const call = () => emulator.getJSON(TEST_RP_ORIGIN, options);
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "NotAllowedError");
    }
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
    assert.equal(credentialRecords.length, 0);
    assert.equal(authData.signCount, 0);
  });
});

describe("WebAuthnEmulator getAuthenticatorInfo Test", () => {
  test("Get Authenticator Information _ OK", () => {
    const emulator = new WebAuthnEmulator();
    const info = emulator.getAuthenticatorInfo();
    assert.deepEqual(info, {
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
    assert.equal(credentialsBefore.length, 1);

    // Signal unknown credential
    emulator.signalUnknownCredential({
      rpId: TEST_RP_ORIGIN.replace("https://", ""),
      credentialId: credential.id,
    });

    // Verify the credential was deleted
    const credentialsAfter = repository.loadCredentials();
    assert.equal(credentialsAfter.length, 0);
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
    assert.equal(credentialsBefore.length, 2);

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
    assert.equal(credentialsAfter.length, 1);

    // Check that credential1 and credential3 still exist
    const remainingIds = credentialsAfter.map((cred) => EncodeUtils.encodeBase64Url(cred.publicKeyCredentialSource.id));
    assert.ok(remainingIds.includes(credential1.id));
    assert.ok(!remainingIds.includes(credential2.id));

    // Verify one credential was deleted
    assert.equal(remainingIds.length, 1);
    assert.equal(allCredentialIds.length, 2);
    const deletedIds = allCredentialIds.filter((id) => !remainingIds.includes(id));
    assert.equal(deletedIds.length, 1);
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
    assert.equal(credentialsBefore.length, 1);

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

    assert.equal(userCredentialsAfter.length, 0);
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
    const invalidCall = () => emulator.getJSON(testServer.origin, authOptions);
    assert.throws(invalidCall, DOMException as unknown as ErrorConstructor);
    try {
      invalidCall();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "SecurityError");
    }

    // Related origins validation
    const authResponse = emulator.getJSON(testServer.origin, authOptions, relatedOrigins);
    assert.notEqual(authResponse, undefined);
    assert.equal(authResponse.id, credential.id);
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
    assert.equal(credentialsBefore.length, 1);
    assert.equal(credentialsBefore[0].user.name, user.username);
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
    assert.equal(credentialsAfter.length, 1);
    assert.equal(credentialsAfter[0].user.name, updatedName);
    assert.equal(credentialsAfter[0].user.displayName, updatedDisplayName);

    // Verify the credential ID and user ID remain unchanged
    assert.equal(EncodeUtils.encodeBase64Url(credentialsAfter[0].publicKeyCredentialSource.id), credential.id);
    assert.equal(EncodeUtils.encodeBase64Url(credentialsAfter[0].user.id), actualUserId);
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

    assert.throws(() => {
      emulator.signalCurrentUserDetails({
        rpId: TEST_RP_ORIGIN.replace("https://", ""),
        userId: EncodeUtils.encodeBase64Url(EncodeUtils.strToUint8Array(nonExistentUserId)),
        name: "New Name",
        displayName: "New Display Name",
      });
    }); // Should throw CTAP2_ERR_NO_CREDENTIALS
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
    assert.ok("credProps" in ext && ext.credProps);
    if ("credProps" in ext && ext.credProps) {
      assert.equal(ext.credProps.rk, true);
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
    assert.ok("credProps" in ext && ext.credProps);
    if ("credProps" in ext && ext.credProps) {
      assert.equal(ext.credProps.rk, false);
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
    assert.equal(before.length, 1);
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
    assert.ok(remainingIds.includes(existingId)); // original credential remains
    assert.equal(after.length, 1); // unchanged
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
    assert.doesNotThrow(() =>
      emulator.signalAllAcceptedCredentials({
        rpId: TEST_RP_ORIGIN.replace("https://", ""),
        userId: "any-user",
        allAcceptedCredentialIds: [],
      }),
    );
  });
});

describe("WebAuthnEmulator DOMException mapping coverage", () => {
  test("signalCurrentUserDetails with invalid parameter → DataError", () => {
    const emulator = new WebAuthnEmulator(new AuthenticatorEmulator());
    const userId = EncodeUtils.encodeBase64Url(EncodeUtils.strToUint8Array("uid"));

    const call = () =>
      (emulator as unknown as { signalCurrentUserDetails: (o: unknown) => void }).signalCurrentUserDetails({
        // Force rpId to be undefined to trigger CTAP1_ERR_INVALID_PARAMETER inside authenticator
        rpId: undefined,
        userId,
        name: "n",
        displayName: "d",
      });

    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "DataError");
    }
  });

  test("getAuthenticatorInfo with invalid CBOR → DataError", () => {
    class BadCborAuthenticator extends AuthenticatorEmulator {
      override command(): CTAPAuthenticatorResponse {
        return { status: CTAP_STATUS_CODE.CTAP2_OK, data: new Uint8Array([0xff]) } as CTAPAuthenticatorResponse;
      }
    }
    const emulator = new WebAuthnEmulator(new BadCborAuthenticator());

    const call = () => emulator.getAuthenticatorInfo();
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "DataError");
    }
  });

  test("getAuthenticatorInfo with invalid command → UnknownError", () => {
    class InvalidCommandAuthenticator extends AuthenticatorEmulator {
      override command(): CTAPAuthenticatorResponse {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND);
      }
    }
    const emulator = new WebAuthnEmulator(new InvalidCommandAuthenticator());

    const call = () => emulator.getAuthenticatorInfo();
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "UnknownError");
    }
  });
});

describe("WebAuthnEmulator credential management error mapping", () => {
  test("signalUnknownCredential on stateless authenticator → NotAllowedError", () => {
    const emulator = new WebAuthnEmulator(new AuthenticatorEmulator({ stateless: true }));
    const call = () =>
      emulator.signalUnknownCredential({
        rpId: "example.com",
        credentialId: EncodeUtils.encodeBase64Url(EncodeUtils.strToUint8Array("nope")),
      });
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "NotAllowedError");
    }
  });

  test("signalUnknownCredential for non-existent credential → NotAllowedError", async () => {
    const repository = new PasskeysCredentialsMemoryRepository();
    const authenticator = new AuthenticatorEmulator({ credentialsRepository: repository });
    const emulator = new WebAuthnEmulator(authenticator);
    const call = () =>
      emulator.signalUnknownCredential({
        rpId: "example.com",
        credentialId: EncodeUtils.encodeBase64Url(EncodeUtils.strToUint8Array("missing")),
      });
    assert.throws(call, DOMException as unknown as ErrorConstructor);
    try {
      call();
      throw new Error("Expected DOMException");
    } catch (e: unknown) {
      assert.ok(e instanceof DOMException);
      assert.equal((e as DOMException).name, "NotAllowedError");
    }
  });
});

describe("WebAuthnEmulator invalid CBOR mapping on create/get", () => {
  test("create path invalid CBOR → DataError", () => {
    class BadCreateCborAuthenticator extends AuthenticatorEmulator {
      override command(request: CTAPAuthenticatorRequest): CTAPAuthenticatorResponse {
        if (request.command === CTAP_COMMAND.authenticatorMakeCredential) {
          return { status: CTAP_STATUS_CODE.CTAP2_OK, data: new Uint8Array([0xff]) } as CTAPAuthenticatorResponse;
        }
        return super.command(request);
      }
    }
    const emulator = new WebAuthnEmulator(new BadCreateCborAuthenticator());
    const user = { username: "bad-cbor", id: "bad-cbor" };
    const server = new WebAuthnTestServer();
    return server.getRegistrationOptions(user).then((opts) => {
      const call = () => emulator.createJSON(TEST_RP_ORIGIN, opts);
      assert.throws(call, DOMException as unknown as ErrorConstructor);
      try {
        call();
        throw new Error("Expected DOMException");
      } catch (e: unknown) {
        assert.ok(e instanceof DOMException);
        assert.equal((e as DOMException).name, "DataError");
      }
    });
  });

  test("get path invalid CBOR → DataError", () => {
    class BadGetCborAuthenticator extends AuthenticatorEmulator {
      override command(request: CTAPAuthenticatorRequest): CTAPAuthenticatorResponse {
        if (request.command === CTAP_COMMAND.authenticatorGetAssertion) {
          return { status: CTAP_STATUS_CODE.CTAP2_OK, data: new Uint8Array([0xff]) } as CTAPAuthenticatorResponse;
        }
        return super.command(request);
      }
    }

    const emulator = new WebAuthnEmulator(new BadGetCborAuthenticator());
    const server = new WebAuthnTestServer();
    const user = { username: "bad-cbor2", id: "bad-cbor2" };
    return server.getRegistrationOptions(user).then((reg) => {
      const regResp = emulator.createJSON(TEST_RP_ORIGIN, reg);
      return server.getRegistrationVerification(user, regResp).then(async () => {
        const req = await server.getAuthenticationOptions();
        const call = () => emulator.getJSON(TEST_RP_ORIGIN, req);
        assert.throws(call, DOMException as unknown as ErrorConstructor);
        try {
          call();
          throw new Error("Expected DOMException");
        } catch (e: unknown) {
          assert.ok(e instanceof DOMException);
          assert.equal((e as DOMException).name, "DataError");
        }
      });
    });
  });
});

describe("handleAuthenticatorCall other error path", () => {
  test("getAuthenticatorInfo rethrows non-CTAP errors as-is", () => {
    class ThrowingAuthenticator extends AuthenticatorEmulator {
      override command(): CTAPAuthenticatorResponse {
        throw new Error("Non-CTAP failure");
      }
    }
    const emulator = new WebAuthnEmulator(new ThrowingAuthenticator());

    try {
      emulator.getAuthenticatorInfo();
      throw new Error("Expected Error to be thrown");
    } catch (e: unknown) {
      // Should not be mapped to DOMException; should be the original error
      assert.ok(!(e instanceof DOMException));
      assert.ok(e instanceof Error);
      assert.equal((e as Error).message, "Non-CTAP failure");
    }
  });
});

describe("WebAuthnEmulator PRF extension", () => {
  const rpOrigin = "https://test-rp.org";
  const rpId = "test-rp.org";
  const user = { id: EncodeUtils.strToUint8Array("prf-user"), name: "user", displayName: "User" };
  const challenge = EncodeUtils.strToUint8Array("prf-challenge");
  const pubKeyCredParams = [{ type: "public-key" as const, alg: -7 }];
  const inputA = EncodeUtils.strToUint8Array("prf-input-a");
  const inputB = EncodeUtils.strToUint8Array("prf-input-b");

  function prfEmulator(
    hmacSecret: "none" | "hmac-secret" | "hmac-secret-mc",
    repository?: PasskeysCredentialsRepository,
  ): WebAuthnEmulator {
    const credentialsRepository = repository ?? new PasskeysCredentialsMemoryRepository();
    return new WebAuthnEmulator(new AuthenticatorEmulator({ hmacSecret, credentialsRepository }));
  }

  function createCredential(
    emulator: WebAuthnEmulator,
    extensions: AuthenticationExtensionsClientInputs,
    credUser: PublicKeyCredentialUserEntity = user,
  ): CreatePublicKeyCredential {
    return emulator.create(rpOrigin, {
      publicKey: { rp: { id: rpId, name: rpId }, user: credUser, challenge, pubKeyCredParams, extensions },
    });
  }

  function assertCredential(
    emulator: WebAuthnEmulator,
    credentialId: BufferSource,
    extensions: AuthenticationExtensionsClientInputs,
  ): RequestPublicKeyCredential {
    return emulator.get(rpOrigin, {
      publicKey: { rpId, challenge, allowCredentials: [{ type: "public-key", id: credentialId }], extensions },
    });
  }

  function prfResults(credential: PublicKeyCredential): AuthenticationExtensionsPRFValues {
    const results = credential.getClientExtensionResults().prf?.results;
    assert.ok(results);
    assert.ok(results.first instanceof ArrayBuffer);
    assert.equal(results.first.byteLength, 32);
    if (results.second) {
      assert.ok(results.second instanceof ArrayBuffer);
      assert.equal(results.second.byteLength, 32);
    }
    return results;
  }

  test("hmac-secret-mc emulator create and get results match", () => {
    const emulator = prfEmulator("hmac-secret-mc");
    const credential = createCredential(emulator, { prf: { eval: { first: inputA, second: inputB } } });
    assert.equal(credential.getClientExtensionResults().prf?.enabled, true);
    const createResults = prfResults(credential);
    assert.ok(createResults.second);

    const credentialId = credential.rawId;
    const assertion = assertCredential(emulator, credentialId, { prf: { eval: { first: inputA, second: inputB } } });
    assert.deepEqual(prfResults(assertion), createResults);
  });

  test("assertCredential produces the same output with and without hmac-secret-mc", () => {
    const repository = new PasskeysCredentialsMemoryRepository();
    const credential = createCredential(prfEmulator("hmac-secret-mc", repository), {
      prf: { eval: { first: inputA } },
    });
    const createResults = prfResults(credential);
    const credentialId = credential.rawId;

    const evalInputs = { prf: { eval: { first: inputA, second: inputB } } };
    const withMc = prfResults(assertCredential(prfEmulator("hmac-secret-mc", repository), credentialId, evalInputs));
    const withoutMc = prfResults(assertCredential(prfEmulator("hmac-secret", repository), credentialId, evalInputs));

    assert.ok(withMc.second);
    assert.deepEqual(withMc.first, createResults.first);
    assert.deepEqual(withMc, withoutMc);
  });

  test("hmac-secret only returns results during get", () => {
    const emulator = prfEmulator("hmac-secret");
    const credential = createCredential(emulator, { prf: {} });
    const createResults = credential.getClientExtensionResults();
    assert.equal(createResults.prf?.enabled, true);
    assert.equal(createResults.prf?.results, undefined);

    const credentialId = credential.rawId;
    const assertResults = prfResults(
      assertCredential(emulator, credentialId, { prf: { eval: { first: inputA, second: inputB } } }),
    );
    assert.ok(assertResults.second);
  });

  test("hmac-secret create with eval returns no key results", () => {
    const emulator = prfEmulator("hmac-secret");
    const credential = createCredential(emulator, { prf: { eval: { first: inputA } } });
    const createResults = credential.getClientExtensionResults();
    assert.equal(createResults.prf?.enabled, true);
    assert.equal(createResults.prf?.results, undefined);

    prfResults(assertCredential(emulator, credential.rawId, { prf: { eval: { first: inputA } } }));
  });

  test("two eval inputs produce two distinct outputs", () => {
    const emulator = prfEmulator("hmac-secret");
    const credentialId = createCredential(emulator, { prf: {} }).rawId;
    const assertResults = prfResults(
      assertCredential(emulator, credentialId, { prf: { eval: { first: inputA, second: inputB } } }),
    );
    assert.ok(assertResults.second);
    assert.notDeepEqual(assertResults.first, assertResults.second);
  });

  test("no PRF result with no hmac-secret extension", () => {
    const emulator = prfEmulator("none");
    const credential = createCredential(emulator, { prf: {} });
    assert.equal(credential.getClientExtensionResults().prf?.enabled, false);

    const credentialId = credential.rawId;
    const assertion = assertCredential(emulator, credentialId, { prf: { eval: { first: inputA } } });
    assert.equal(assertion.getClientExtensionResults().prf, undefined);
  });

  test("PRF resolves for a discoverable credential without an allow list", () => {
    const emulator = prfEmulator("hmac-secret-mc");
    const createResults = prfResults(createCredential(emulator, { prf: { eval: { first: inputA, second: inputB } } }));

    // no allowCredentials
    const assertion = emulator.get(rpOrigin, {
      publicKey: { rpId, challenge, extensions: { prf: { eval: { first: inputA, second: inputB } } } },
    });
    assert.deepEqual(prfResults(assertion), createResults);
  });

  test("evalByCredential returns each credential's result and nothing on a mismatch", () => {
    const emulator = prfEmulator("hmac-secret-mc");
    const userA = { id: EncodeUtils.strToUint8Array("prf-user-a"), name: "a", displayName: "A" };
    const userB = { id: EncodeUtils.strToUint8Array("prf-user-b"), name: "b", displayName: "B" };

    const credentialA = createCredential(emulator, { prf: { eval: { first: inputA } } }, userA);
    const credentialB = createCredential(emulator, { prf: { eval: { first: inputB } } }, userB);
    const resultsA = prfResults(credentialA);
    const resultsB = prfResults(credentialB);
    const idAB64 = EncodeUtils.encodeBase64Url(credentialA.rawId);
    const idBB64 = EncodeUtils.encodeBase64Url(credentialB.rawId);

    const assertedA = assertCredential(emulator, credentialA.rawId, {
      prf: { evalByCredential: { [idAB64]: { first: inputA } } },
    });
    const assertedB = assertCredential(emulator, credentialB.rawId, {
      prf: { evalByCredential: { [idBB64]: { first: inputB } } },
    });
    assert.deepEqual(prfResults(assertedA), resultsA);
    assert.deepEqual(prfResults(assertedB), resultsB);

    const mismatchedA = assertCredential(emulator, credentialA.rawId, {
      prf: { evalByCredential: { [idBB64]: { first: inputB } } },
    });
    const mismatchedB = assertCredential(emulator, credentialB.rawId, {
      prf: { evalByCredential: { [idAB64]: { first: inputA } } },
    });
    assert.equal(mismatchedA.getClientExtensionResults().prf, undefined);
    assert.equal(mismatchedB.getClientExtensionResults().prf, undefined);
  });

  test("evalByCredential without allowCredentials throws NotSupportedError", () => {
    const emulator = prfEmulator("hmac-secret");
    assert.throws(
      () =>
        emulator.get(rpOrigin, {
          publicKey: { rpId, challenge, extensions: { prf: { evalByCredential: { AAAA: { first: inputA } } } } },
        }),
      { name: "NotSupportedError" },
    );
  });

  test("credRandom persists to a file repository across emulator instances", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prf-file-credentials-"));
    try {
      const created = prfEmulator("hmac-secret-mc", new PasskeysCredentialsFileRepository(dir));
      const credential = createCredential(created, { prf: { eval: { first: inputA, second: inputB } } });
      const createResults = prfResults(credential);
      const credentialId = credential.rawId;

      const loaded = prfEmulator("hmac-secret-mc", new PasskeysCredentialsFileRepository(dir));
      const assertResults = prfResults(
        assertCredential(loaded, credentialId, { prf: { eval: { first: inputA, second: inputB } } }),
      );
      assert.deepEqual(assertResults, createResults);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("hmac-secret-mc PRF works with WebAuthnTestServer", async () => {
    const emulator = prfEmulator("hmac-secret-mc");
    const testServer = new WebAuthnTestServer();
    const prfUser = { username: "prf", id: "prf" };

    const regOptions = await testServer.getRegistrationOptions(prfUser);
    const credential = emulator.create(testServer.origin, {
      publicKey: {
        ...parseCreationOptionsFromJSON(regOptions),
        extensions: { prf: { eval: { first: inputA, second: inputB } } },
      },
    });
    await testServer.getRegistrationVerification(prfUser, credential.toJSON());
    const createResults = prfResults(credential);

    const authOptions = await testServer.getAuthenticationOptions();
    const assertion = emulator.get(testServer.origin, {
      publicKey: {
        ...parseRequestOptionsFromJSON(authOptions),
        extensions: { prf: { eval: { first: inputA, second: inputB } } },
      },
    });
    // Verifies the signature over authenticatorData, which now carries the hmac-secret extension.
    await testServer.getAuthenticationVerification(assertion.toJSON());
    assert.deepEqual(prfResults(assertion), createResults);
  });
});
