import { beforeEach, describe, expect, test } from "@jest/globals";
import { AuthenticatorEmulator } from "../../src";
import {
  AuthenticationEmulatorError,
  type AuthenticatorCredentialManagementRequest,
  type AuthenticatorCredentialManagementResponse,
  CREDENTIAL_MANAGEMENT_SUBCOMMAND,
  CTAP_COMMAND,
  CTAP_STATUS_CODE,
  type CTAPAuthenticatorRequest,
  packCredentialManagementRequest,
} from "../../src/authenticator/ctap-model";
import EncodeUtils from "../../src/libs/encode-utils";
import { PasskeysCredentialsMemoryRepository } from "../../src/repository/credentials-memory-repository";

describe("Authenticator Emulator Exceptional Test", () => {
  // Success case has been tested in the webauthn-emulator.spec.ts

  test("Unknown command _ CTAP Error", async () => {
    const testRequest: CTAPAuthenticatorRequest = {
      command: CTAP_COMMAND.authenticatorReset,
    };
    const authenticator = new AuthenticatorEmulator();
    expect(() => {
      authenticator.command(testRequest);
    }).toThrow("CTAP error: CTAP1_ERR_INVALID_COMMAND (1)");
  });
});

describe("Authenticator Credential Management Tests", () => {
  let authenticator: AuthenticatorEmulator;
  let repository: PasskeysCredentialsMemoryRepository;

  // Test data
  const rpId1 = "example.com";
  const rpId2 = "test.com";

  const user1 = {
    id: EncodeUtils.strToUint8Array("user1-id"),
    name: "user1",
    displayName: "User One",
  };

  const user2 = {
    id: EncodeUtils.strToUint8Array("user2-id"),
    name: "user2",
    displayName: "User Two",
  };

  const user3 = {
    id: EncodeUtils.strToUint8Array("user3-id"),
    name: "user3",
    displayName: "User Three",
  };

  beforeEach(() => {
    // Create a new repository for each test
    repository = new PasskeysCredentialsMemoryRepository();

    // Create authenticator with the repository
    authenticator = new AuthenticatorEmulator({
      credentialsRepository: repository,
    });

    // Create test credentials
    createTestCredential(rpId1, user1);
    createTestCredential(rpId1, user2);
    createTestCredential(rpId2, user3);
  });

  // Helper function to create a test credential
  function createTestCredential(rpId: string, user: PublicKeyCredentialUserEntity) {
    const clientDataHash = new Uint8Array(32).fill(1);
    const makeCredentialRequest = {
      clientDataHash,
      rp: { id: rpId, name: rpId },
      user,
      pubKeyCredParams: [{ type: "public-key" as const, alg: -7 }],
    };

    authenticator.authenticatorMakeCredential(makeCredentialRequest);
  }

  describe("enumerateCredentialsBegin", () => {
    test("should return the total number of credentials for a specific RP", () => {
      // Create request for enumerateCredentialsBegin
      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
        subCommandParams: {
          rpId: rpId1,
        },
      };

      // Execute the command
      const response = authenticator.authenticatorCredentialManagement(request);

      // Verify the response
      expect(response.totalCredentials).toBe(2); // We created 2 credentials for rpId1
    });

    test("should throw an error if rpId is not provided", () => {
      // Create request without rpId
      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
      };

      // Execute the command and expect an error
      expect(() => {
        authenticator.authenticatorCredentialManagement(request);
      }).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER));
    });

    test("should return 0 credentials for an RP with no credentials", () => {
      // Create request for a non-existent RP
      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
        subCommandParams: {
          rpId: "nonexistent.com",
        },
      };

      // Execute the command
      const response = authenticator.authenticatorCredentialManagement(request);

      // Verify the response
      expect(response.totalCredentials).toBe(0);
    });
  });

  describe("enumerateCredentialsGetNextCredential", () => {
    test("should return credentials one by one", () => {
      // First, call enumerateCredentialsBegin
      const beginRequest = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
        subCommandParams: {
          rpId: rpId1,
        },
      };

      authenticator.authenticatorCredentialManagement(beginRequest);

      // Now call enumerateCredentialsGetNextCredential twice to get both credentials
      const getNextRequest = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential,
      };

      // Get first credential
      const response1 = authenticator.authenticatorCredentialManagement(getNextRequest);
      expect(response1.user).toBeDefined();
      expect(response1.credentialID).toBeDefined();
      expect(response1.publicKey).toBeDefined();

      // Get second credential
      const response2 = authenticator.authenticatorCredentialManagement(getNextRequest);
      expect(response2.user).toBeDefined();
      expect(response2.credentialID).toBeDefined();
      expect(response2.publicKey).toBeDefined();

      // Verify we got different credentials
      if (response1.credentialID && response2.credentialID) {
        expect(EncodeUtils.encodeBase64Url(response1.credentialID)).not.toBe(
          EncodeUtils.encodeBase64Url(response2.credentialID),
        );
      }

      // Verify we can't get more credentials
      expect(() => {
        authenticator.authenticatorCredentialManagement(getNextRequest);
      }).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS));
    });

    test("should throw an error if called without calling enumerateCredentialsBegin first", () => {
      const getNextRequest = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential,
      };

      expect(() => {
        authenticator.authenticatorCredentialManagement(getNextRequest);
      }).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS));
    });
  });

  describe("updateUserInformation", () => {
    test("should update user information for all credentials of a user", () => {
      // Create updated user information
      const updatedUser = {
        id: user1.id, // Same ID
        name: "user1-updated",
        displayName: "Updated User One",
      };

      // Create request for updateUserInformation
      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
        subCommandParams: {
          rpId: rpId1,
          user: updatedUser,
        },
      };

      // Execute the command
      authenticator.authenticatorCredentialManagement(request);

      // Verify the user information was updated by enumerating credentials
      const beginRequest = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
        subCommandParams: {
          rpId: rpId1,
        },
      };

      authenticator.authenticatorCredentialManagement(beginRequest);

      const getNextRequest = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential,
      };

      // Get credentials and check if user info was updated
      const nextResponse = authenticator.authenticatorCredentialManagement(getNextRequest);

      // Find the credential for user1
      if (
        nextResponse.user &&
        EncodeUtils.encodeBase64Url(nextResponse.user.id) === EncodeUtils.encodeBase64Url(user1.id)
      ) {
        expect(nextResponse.user.name).toBe(updatedUser.name);
        expect(nextResponse.user.displayName).toBe(updatedUser.displayName);
      }
    });

    test("should throw an error if rpId is not provided", () => {
      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
        subCommandParams: {
          user: user1,
        },
      };

      expect(() => {
        authenticator.authenticatorCredentialManagement(request);
      }).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER));
    });

    test("should throw an error if user is not provided", () => {
      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
        subCommandParams: {
          rpId: rpId1,
        },
      };

      expect(() => {
        authenticator.authenticatorCredentialManagement(request);
      }).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER));
    });

    test("should throw an error if no credentials exist for the user", () => {
      const nonExistentUser = {
        id: EncodeUtils.strToUint8Array("nonexistent-id"),
        name: "nonexistent",
        displayName: "Non Existent User",
      };

      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
        subCommandParams: {
          rpId: rpId1,
          user: nonExistentUser,
        },
      };

      expect(() => {
        authenticator.authenticatorCredentialManagement(request);
      }).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS));
    });
  });

  describe("authenticatorCredentialManagement with stateless authenticator", () => {
    test("should throw an error if authenticator is stateless", () => {
      // Create a stateless authenticator
      const statelessAuthenticator = new AuthenticatorEmulator({
        stateless: true,
      });

      // Create request for enumerateCredentialsBegin
      const request = {
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
        subCommandParams: {
          rpId: rpId1,
        },
      };

      // Execute the command and expect an error
      expect(() => {
        statelessAuthenticator.authenticatorCredentialManagement(request);
      }).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED));
    });
  });

  describe("Authenticator Credential Management additional error coverage", () => {
    test("dispatch default branch throws invalid command", () => {
      const authenticator = new AuthenticatorEmulator();
      // Build a CTAP request with an unknown subCommand to hit default branch
      const data = EncodeUtils.encodeCbor({ "1": -1 });
      expect(() => authenticator.command({ command: CTAP_COMMAND.authenticatorCredentialManagement, data })).toThrow(
        new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND),
      );
    });

    test("enumerateCredentialsBegin without repository throws not allowed", () => {
      const authenticator = new AuthenticatorEmulator({ stateless: true });
      const req = packCredentialManagementRequest({
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
        subCommandParams: { rpId: "example.com" },
      });
      expect(() => authenticator.command(req)).toThrow(
        new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED),
      );
    });

    test("updateUserInformation without repository throws not allowed", () => {
      const authenticator = new AuthenticatorEmulator({ stateless: true });
      const req = packCredentialManagementRequest({
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
        subCommandParams: { rpId: "example.com", user: { id: new Uint8Array([1]), name: "n", displayName: "d" } },
      });
      expect(() => authenticator.command(req)).toThrow(
        new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED),
      );
    });

    test("deleteCredential without repository throws not allowed", () => {
      const authenticator = new AuthenticatorEmulator({ stateless: true });
      const req = packCredentialManagementRequest({ subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential });
      expect(() => authenticator.command(req)).toThrow(
        new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED),
      );
    });

    test("deleteCredential without credentialId throws invalid parameter", () => {
      const authenticator = new AuthenticatorEmulator();
      const req = packCredentialManagementRequest({ subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential });
      expect(() => authenticator.command(req)).toThrow(
        new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER),
      );
    });

    test("deleteCredential for non-existent id throws no credentials", () => {
      const authenticator = new AuthenticatorEmulator();
      const credentialId = EncodeUtils.strToUint8Array("non-existent-id");
      const req = packCredentialManagementRequest({
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential,
        subCommandParams: { credentialId },
      });
      expect(() => authenticator.command(req)).toThrow(
        new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS),
      );
    });

    test("private enumerateCredentialsBegin guard throws not allowed when repository missing", () => {
      const authenticator = new AuthenticatorEmulator({ stateless: true });
      const target = (
        authenticator as unknown as {
          authenticatorEnumerateCredentialsBegin: (
            this: AuthenticatorEmulator,
            request: AuthenticatorCredentialManagementRequest,
          ) => AuthenticatorCredentialManagementResponse;
        }
      ).authenticatorEnumerateCredentialsBegin.bind(authenticator);
      const call = () =>
        target({
          subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
          subCommandParams: { rpId: "x" },
        });
      expect(call).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED));
    });

    test("private updateUserInformation guard throws not allowed when repository missing", () => {
      const authenticator = new AuthenticatorEmulator({ stateless: true });
      const target = (
        authenticator as unknown as {
          authenticatorUpdateUserInformation: (
            this: AuthenticatorEmulator,
            request: AuthenticatorCredentialManagementRequest,
          ) => AuthenticatorCredentialManagementResponse;
        }
      ).authenticatorUpdateUserInformation.bind(authenticator);
      const call = () =>
        target({
          subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
          subCommandParams: { rpId: "x", user: { id: new Uint8Array([1]), name: "n", displayName: "d" } },
        });
      expect(call).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED));
    });

    test("private deleteCredential guard throws not allowed when repository missing", () => {
      const authenticator = new AuthenticatorEmulator({ stateless: true });
      const target = (
        authenticator as unknown as {
          authenticatorDeleteCredential: (
            this: AuthenticatorEmulator,
            request: AuthenticatorCredentialManagementRequest,
          ) => AuthenticatorCredentialManagementResponse;
        }
      ).authenticatorDeleteCredential.bind(authenticator);
      const call = () => target({ subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential });
      expect(call).toThrow(new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED));
    });
  });
});
