import { describe, test } from "@jest/globals";
import { expect } from "@jest/globals";
import {
  type AuthenticatorGetAssertionResponse,
  type AuthenticatorGetInfoResponse,
  type AuthenticatorMakeCredentialRequest,
  type AuthenticatorMakeCredentialResponse,
  packGetAssertionResponse,
  packGetInfoResponse,
  packMakeCredentialRequest,
  packMakeCredentialResponse,
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

  test("MakeCredentialResponse CTAP Object pack and unpack", async () => {
    const testResponse: AuthenticatorMakeCredentialResponse = {
      fmt: "packed",
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
});
