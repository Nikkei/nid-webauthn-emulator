import { describe, expect, test } from "@jest/globals";
import {
  type AuthenticatorCredentialManagementRequest,
  type AuthenticatorGetAssertionRequest,
  type AuthenticatorGetAssertionResponse,
  type AuthenticatorGetInfoResponse,
  type AuthenticatorMakeCredentialRequest,
  type AuthenticatorMakeCredentialResponse,
  CREDENTIAL_MANAGEMENT_SUBCOMMAND,
  CTAP_COMMAND,
  CTAP_STATUS_CODE,
  type CTAPAuthenticatorRequest,
  type CTAPAuthenticatorResponse,
  packCredentialManagementRequest,
  packCredentialManagementResponse,
  packGetAssertionRequest,
  packGetAssertionResponse,
  packGetInfoResponse,
  packMakeCredentialRequest,
  packMakeCredentialResponse,
  unpackCredentialManagementRequest,
  unpackCredentialManagementResponse,
  unpackGetAssertionResponse,
  unpackGetInfoResponse,
  unpackMakeCredentialResponse,
  unpackRequest,
} from "../../src/authenticator/ctap-model";

describe("CTAP Model Test", () => {
  test("MakeCredentialRequest CTAP Object pack and unpack", async () => {
    const testRequest: AuthenticatorMakeCredentialRequest = {
      clientDataHash: new Uint8Array([99, 104, 97, 108, 108, 101, 110, 103, 101]),
      rp: { name: "webauthn.io", id: "webauthn.io" },
      user: { id: new Uint8Array([116, 101, 115, 116, 45, 117, 115, 101, 114]), name: "user", displayName: "user" },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      excludeList: [{ id: new Uint8Array([116, 101, 115, 116, 45, 99]), type: "public-key" }],
      options: { rk: true, uv: true },
      pinAuth: new Uint8Array([112, 105, 110, 65, 117, 116, 104]),
      extensions: {},
      pinProtocol: 9,
    };

    const packed = packMakeCredentialRequest(testRequest);
    const unpacked = unpackRequest(packed);
    const rePacked = packMakeCredentialRequest(unpacked.request as AuthenticatorMakeCredentialRequest);

    expect(packed).toEqual(rePacked);
    expect(unpacked.request).toEqual(testRequest);
  });

  test("GetAssertionRequest CTAP Object pack and unpack", async () => {
    const testRequest: AuthenticatorGetAssertionRequest = {
      rpId: "webauthn.io",
      clientDataHash: new Uint8Array([99, 104, 97, 108, 108, 101, 110, 103, 101]),
      allowList: [{ id: new Uint8Array([116, 101, 115, 116, 45, 99]), type: "public-key" }],
      extensions: {},
      options: { up: true, uv: true },
      pinAuth: new Uint8Array([112, 105, 110, 65, 117, 116, 104]),
      pinProtocol: 9,
    };

    const packed = packGetAssertionRequest(testRequest);
    const unpacked = unpackRequest(packed);
    const rePacked = packGetAssertionRequest(unpacked.request as AuthenticatorGetAssertionRequest);

    expect(packed).toEqual(rePacked);
    expect(unpacked.request).toEqual(testRequest);
  });

  test("MakeCredentialResponse CTAP Object pack and unpack", async () => {
    const testResponse: AuthenticatorMakeCredentialResponse = {
      fmt: "none",
      attStmt: {},
      authData: new Uint8Array([97, 117, 116, 104, 68, 97, 116, 97]),
    };

    const packed = packMakeCredentialResponse(testResponse);
    const unpacked = unpackMakeCredentialResponse(packed);
    const rePacked = packMakeCredentialResponse(unpacked);

    expect(packed).toEqual(rePacked);
    expect(unpacked).toEqual(testResponse);
  });

  test("GetAssertionResponse CTAP Object pack and unpack", async () => {
    const testResponse: AuthenticatorGetAssertionResponse = {
      authData: new Uint8Array([97, 117, 116, 104, 68, 97, 116, 97]),
      signature: new Uint8Array([115, 105, 103]),
      user: { id: new Uint8Array([116, 101, 115, 116, 45, 117, 115, 101, 114]), name: "user", displayName: "user" },
      numberOfCredentials: 1,
    };

    const packed = packGetAssertionResponse(testResponse);
    const unpacked = unpackGetAssertionResponse(packed);
    const rePacked = packGetAssertionResponse(unpacked);

    expect(packed).toEqual(rePacked);
    expect(unpacked).toEqual(testResponse);
  });

  test("GetInfoResponse CTAP Object pack and unpack", async () => {
    const testResponse: AuthenticatorGetInfoResponse = {
      versions: ["U2F_V2"],
      extensions: ["credProtect"],
      aaguid: new Uint8Array([97, 97, 103, 117, 105, 100]),
      options: { plat: false, rk: true, clientPin: true, up: true, uv: true },
      maxMsgSize: 1200,
      pinProtocols: [1, 2, 3],
    };

    const packed = packGetInfoResponse(testResponse);
    const unpacked = unpackGetInfoResponse(packed);
    const rePacked = packGetInfoResponse(unpacked);

    expect(packed).toEqual(rePacked);
    expect(unpacked).toEqual(testResponse);
  });

  test("Illegal data parse test _ failed to unpack", async () => {
    const response = {} as unknown as CTAPAuthenticatorResponse;
    const expected = "CTAP error: CTAP2_ERR_INVALID_CBOR (18)";

    expect(() => unpackMakeCredentialResponse(response)).toThrow(expected);
    expect(() => unpackGetAssertionResponse(response)).toThrow(expected);
    expect(() => unpackGetInfoResponse(response)).toThrow(expected);
  });

  test("Illegal cbor data parse test _ failed to unpack", async () => {
    const request: CTAPAuthenticatorRequest = {
      command: CTAP_COMMAND.authenticatorMakeCredential,
      data: new Uint8Array([1, 2, 3, 4, 5]),
    };
    expect(() => unpackRequest(request)).toThrow("CTAP error: CTAP2_ERR_INVALID_CBOR (18)");
  });

  test("unpackRequest default branch returns undefined request for unhandled command", () => {
    const req = { command: CTAP_COMMAND.authenticatorClientPIN } as const; // not explicitly handled in switch
    const unpacked = unpackRequest(req);
    expect(unpacked.command).toBe(CTAP_COMMAND.authenticatorClientPIN);
    expect(unpacked.request).toBeUndefined();
  });

  test("credential management request with undefined optional params round-trips", () => {
    const packed = packCredentialManagementRequest({
      subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
      // subCommandParams and pinUvAuth* omitted intentionally
    });
    const unpacked = unpackCredentialManagementRequest(packed);
    expect(unpacked.subCommand).toBe(CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin);
    expect(unpacked.subCommandParams).toBeUndefined();
    expect(unpacked.pinUvAuthParam).toBeUndefined();
    expect(unpacked.pinUvAuthProtocol).toBeUndefined();
  });

  test("credential management response optional binary fields handled when absent/present", () => {
    // Absent case
    const packedAbsent = packCredentialManagementResponse({});
    const absent = unpackCredentialManagementResponse(packedAbsent);
    expect(absent.credentialID).toBeUndefined();
    expect(absent.publicKey).toBeUndefined();
    expect(absent.rpIDHash).toBeUndefined();
    expect(absent.largeBlobKey).toBeUndefined();

    // Present case
    const bin = new Uint8Array([1, 2, 3]);
    const packedPresent = packCredentialManagementResponse({
      credentialID: bin,
      publicKey: bin,
      rpIDHash: bin,
      largeBlobKey: bin,
    });
    const present = unpackCredentialManagementResponse(packedPresent);
    expect(present.credentialID).toBeDefined();
    expect(present.publicKey).toBeDefined();
    expect(present.rpIDHash).toBeDefined();
    expect(present.largeBlobKey).toBeDefined();
    if (present.credentialID && present.publicKey && present.rpIDHash && present.largeBlobKey) {
      expect(Array.from(present.credentialID)).toEqual([1, 2, 3]);
      expect(Array.from(present.publicKey)).toEqual([1, 2, 3]);
      expect(Array.from(present.rpIDHash)).toEqual([1, 2, 3]);
      expect(Array.from(present.largeBlobKey)).toEqual([1, 2, 3]);
    }
  });

  test("unpackCredentialManagementRequest throws on invalid CBOR", () => {
    const bad: CTAPAuthenticatorRequest = {
      command: CTAP_COMMAND.authenticatorCredentialManagement,
      data: new Uint8Array([1, 2, 3]),
    };
    expect(() => unpackCredentialManagementRequest(bad)).toThrow(/CTAP2_ERR_INVALID_CBOR/);
  });

  test("unpackCredentialManagementResponse throws on invalid CBOR", () => {
    const bad: CTAPAuthenticatorResponse = {
      status: CTAP_STATUS_CODE.CTAP2_OK,
      data: new Uint8Array([1, 2, 3]),
    };
    expect(() => unpackCredentialManagementResponse(bad)).toThrow(/CTAP2_ERR_INVALID_CBOR/);
  });

  test("unpackRequest CM includes pinUvAuthParam when present", () => {
    const pin = new Uint8Array([7, 7]);
    const packed = packCredentialManagementRequest({
      subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
      subCommandParams: { rpId: "example.com" },
      pinUvAuthParam: pin,
    });
    const unpacked = unpackRequest(packed);
    const req = unpacked.request;
    const isMgmt = (x: unknown): x is AuthenticatorCredentialManagementRequest =>
      typeof x === "object" && x !== null && "subCommand" in (x as Record<string, unknown>);
    expect(isMgmt(req)).toBe(true);
    if (isMgmt(req)) {
      expect(Array.from(req.pinUvAuthParam ?? new Uint8Array())).toEqual([7, 7]);
    }
  });

  test("unpackCredentialManagementRequest includes pinUvAuthParam when present", () => {
    const pin = new Uint8Array([9, 9]);
    const packed = packCredentialManagementRequest({
      subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
      subCommandParams: { rpId: "example.com" },
      pinUvAuthParam: pin,
    });
    const req = unpackCredentialManagementRequest(packed);
    expect(Array.from(req.pinUvAuthParam ?? new Uint8Array())).toEqual([9, 9]);
  });
});
