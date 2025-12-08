import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "@jest/globals";
import { AuthenticatorEmulator } from "../../src/authenticator/authenticator-emulator";
import EncodeUtils from "../../src/libs/encode-utils";
import { createPasskeysEmulator } from "../../src/test-utils/unit-test";
import {
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
  type RequestPublicKeyCredential,
} from "../../src/webauthn/webauthn-model-json";

type GlobalTestOverrides = typeof globalThis & {
  location?: Location;
  btoa?: (data: string) => string;
  atob?: (data: string) => string;
};

const globalScope = globalThis as GlobalTestOverrides;
const originalLocation = globalScope.location;
const originalBtoa = globalScope.btoa;
const originalAtob = globalScope.atob;

beforeAll(() => {
  if (!globalScope.btoa) {
    globalScope.btoa = (data: string) => Buffer.from(data, "binary").toString("base64");
  }
  if (!globalScope.atob) {
    globalScope.atob = (base64: string) => Buffer.from(base64, "base64").toString("binary");
  }
});

const clearDefaultRepository = () => {
  const repository = new AuthenticatorEmulator().params.credentialsRepository;
  repository?.loadCredentials().forEach((credential) => {
    repository.deleteCredential(credential);
  });
};

beforeEach(() => {
  clearDefaultRepository();
});

afterEach(() => {
  globalScope.location = originalLocation;
  clearDefaultRepository();
});

afterAll(() => {
  globalScope.location = originalLocation;
  globalScope.btoa = originalBtoa;
  globalScope.atob = originalAtob;
});

describe("createPasskeysEmulator", () => {
  test("exposes default passkeys-like interfaces", async () => {
    const emulator = createPasskeysEmulator();

    expect(await emulator.methods.publicKeyCredentials.isConditionalMediationAvailable?.()).toBe(true);
    expect(await emulator.methods.publicKeyCredentials.getClientCapabilities()).toEqual({ conditionalGet: true });
    expect(await emulator.methods.publicKeyCredentials.isUserVerifyingPlatformAuthenticatorAvailable()).toBe(true);
    expect(emulator.methods.publicKeyCredentials.parseCreationOptionsFromJSON).toBe(parseCreationOptionsFromJSON);
    expect(emulator.methods.publicKeyCredentials.parseRequestOptionsFromJSON).toBe(parseRequestOptionsFromJSON);
  });

  test("addPasskey stores credentials for custom rpId and allows authentication", async () => {
    globalScope.location = { origin: "https://example.com" } as unknown as Location;

    const emulator = createPasskeysEmulator({ origin: "https://example.com", rpId: "example.com" });
    emulator.addPasskey("user-123");

    const repository = emulator.instance.authenticator.params.credentialsRepository;
    const credentials = repository?.loadCredentials() ?? [];
    expect(credentials).toHaveLength(1);
    expect(credentials[0].publicKeyCredentialSource.rpId.value).toBe("example.com");

    const credentialId = EncodeUtils.encodeBase64Url(credentials[0].publicKeyCredentialSource.id);
    const requestOptions = emulator.methods.publicKeyCredentials.parseRequestOptionsFromJSON({
      challenge: EncodeUtils.encodeBase64Url(Buffer.from("challenge")),
      rpId: "example.com",
      allowCredentials: [{ type: "public-key", id: credentialId }],
    });

    const assertion = (await emulator.methods.credentialsContainer.get({
      publicKey: requestOptions,
    })) as RequestPublicKeyCredential;

    expect(assertion.id).toBe(credentialId);
    const userHandle = assertion.response.userHandle;
    expect(EncodeUtils.encodeBase64Url(new Uint8Array(userHandle ?? new ArrayBuffer(0)))).toBe(
      EncodeUtils.encodeBase64Url(Buffer.from("user-123")),
    );
  });

  test("creationException bubbles up as DOMException", async () => {
    globalScope.location = { origin: "http://localhost" } as unknown as Location;

    const emulator = createPasskeysEmulator({ creationException: "AbortError" });
    const creationOptions = emulator.methods.publicKeyCredentials.parseCreationOptionsFromJSON({
      challenge: EncodeUtils.encodeBase64Url(Buffer.from("challenge")),
      rp: { name: "Test RP", id: "localhost" },
      user: {
        id: EncodeUtils.encodeBase64Url(Buffer.from("creation-user")),
        name: "creation-user",
        displayName: "",
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    });
    const createCall = emulator.methods.credentialsContainer.create({ publicKey: creationOptions });

    await expect(createCall).rejects.toThrow(DOMException as unknown as ErrorConstructor);
    await expect(createCall).rejects.toMatchObject({ name: "AbortError" });
  });

  test("requestException is thrown when fetching assertions", async () => {
    globalScope.location = { origin: "http://localhost" } as unknown as Location;

    const emulator = createPasskeysEmulator({ requestException: "InvalidStateError" });
    emulator.addPasskey("auth-user");

    const repository = emulator.instance.authenticator.params.credentialsRepository;
    const credentials = repository?.loadCredentials() ?? [];
    expect(credentials).toHaveLength(1);
    const credentialId = EncodeUtils.encodeBase64Url(credentials[0].publicKeyCredentialSource.id);

    const requestOptions = emulator.methods.publicKeyCredentials.parseRequestOptionsFromJSON({
      challenge: EncodeUtils.encodeBase64Url(Buffer.from("request")),
      rpId: "localhost",
      allowCredentials: [{ type: "public-key", id: credentialId }],
    });
    const parsedId = EncodeUtils.encodeBase64Url(
      new Uint8Array((requestOptions.allowCredentials?.[0].id as ArrayBuffer) ?? new ArrayBuffer(0)),
    );
    expect(parsedId).toBe(credentialId);

    try {
      await emulator.methods.credentialsContainer.get({ publicKey: requestOptions });
      throw new Error("Expected DOMException");
    } catch (error) {
      expect(error).toBeInstanceOf(DOMException);
      expect((error as DOMException).name).toBe("InvalidStateError");
    }
  });

  test("disables conditional mediation when autofill flag is false", async () => {
    const emulator = createPasskeysEmulator({ autofill: false });

    await expect(emulator.methods.publicKeyCredentials.isConditionalMediationAvailable?.()).resolves.toBe(false);
  });
});
