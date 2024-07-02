import EncodeUtils from "../libs/encode-utils";

export type AuthenticatorOptions = {
  rk: boolean;
  uv: boolean;
  up: boolean;
};

export type AuthenticatorInteractionOptions = {
  up: boolean;
  uv: boolean;
};

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialRequest {
  clientDataHash: Uint8Array;
  rp: PublicKeyCredentialRpEntity & { id: string };
  user: PublicKeyCredentialUserEntity;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  excludeList?: PublicKeyCredentialDescriptor[];
  extensions?: object;
  options?: Partial<AuthenticatorOptions>;
  pinAuth?: Uint8Array;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialResponse {
  fmt: string;
  authData: Uint8Array;
  attStmt: object;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionRequest {
  rpId: string;
  clientDataHash: Uint8Array;
  allowList?: PublicKeyCredentialDescriptor[];
  extensions?: object;
  options?: Partial<AuthenticatorOptions>;
  pinAuth?: Uint8Array;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionResponse {
  credential?: PublicKeyCredentialDescriptor;
  authData: Uint8Array;
  signature: Uint8Array;
  user?: PublicKeyCredentialUserEntity;
  numberOfCredentials: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo */
export type AuthenticatorGetInfoResponse = {
  versions: string[];
  extensions?: string[];
  aaguid: Uint8Array;
  options?: Partial<AuthenticatorOptions> & { plat?: boolean; clientPin?: boolean };
  maxMsgSize?: number;
  pinProtocols?: number[];
};

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses */
export enum CTAP_STATUS_CODE {
  CTAP2_OK = 0x00,
  CTAP1_ERR_INVALID_COMMAND = 0x01,
  CTAP1_ERR_INVALID_PARAMETER = 0x02,
  CTAP2_ERR_INVALID_CBOR = 0x12,
  CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19,
  CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26,
  CTAP2_ERR_OPERATION_DENIED = 0x27,
  CTAP2_ERR_NO_CREDENTIALS = 0x2e,
  CTAP2_ERR_NOT_ALLOWED = 0x30,
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands */
export enum CTAP_COMMAND {
  authenticatorMakeCredential = 0x01,
  authenticatorGetAssertion = 0x02,
  authenticatorGetInfo = 0x04,
  authenticatorClientPIN = 0x06,
  authenticatorReset = 0x07,
  authenticatorGetNextAssertion = 0x08,
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#responses */
export interface CTAPAuthenticatorResponse {
  status: CTAP_STATUS_CODE;
  data?: Uint8Array;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands */
export interface CTAPAuthenticatorRequest {
  command: CTAP_COMMAND;
  data?: Uint8Array;
}

// Not standard functions and interfaces

export class AuthenticationEmulatorError extends Error {
  public type = "CTAPError";
  constructor(
    public status: CTAP_STATUS_CODE,
    options?: ErrorOptions,
  ) {
    super(`CTAP error: ${CTAP_STATUS_CODE[status]} (${status})`, options);
  }
}

export function unpackRequest(request: CTAPAuthenticatorRequest): { command: CTAP_COMMAND; request: unknown } {
  let data: Record<number, unknown> = {};
  try {
    data = (request.data ? EncodeUtils.decodeCbor(request.data) : {}) as Record<number, unknown>;
  } catch (error) {
    throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }

  switch (request.command) {
    case CTAP_COMMAND.authenticatorMakeCredential:
      return {
        command: request.command,
        request: {
          clientDataHash: EncodeUtils.bufferSourceToUint8Array(data[0x01] as BufferSource),
          rp: data[0x02] as PublicKeyCredentialRpEntity,
          user: data[0x03] as PublicKeyCredentialUserEntity,
          pubKeyCredParams: data[0x04] as PublicKeyCredentialParameters[],
          excludeList: data[0x05] as PublicKeyCredentialDescriptor[] | undefined,
          extensions: data[0x06] as object | undefined,
          options: data[0x07] as { rk?: boolean; uv?: boolean } | undefined,
          pinAuth: data[0x08] ? EncodeUtils.bufferSourceToUint8Array(data[0x08] as BufferSource) : undefined,
          pinProtocol: data[0x09] as number | undefined,
        } as AuthenticatorMakeCredentialRequest,
      };

    case CTAP_COMMAND.authenticatorGetAssertion:
      return {
        command: request.command,
        request: {
          rpId: data[0x01] as string,
          clientDataHash: EncodeUtils.bufferSourceToUint8Array(data[0x02] as BufferSource),
          allowList: data[0x03] as PublicKeyCredentialDescriptor[] | undefined,
          extensions: data[0x04] as object | undefined,
          options: data[0x05] as { up?: boolean; uv?: boolean } | undefined,
          pinAuth: data[0x06] ? EncodeUtils.bufferSourceToUint8Array(data[0x06] as BufferSource) : undefined,
          pinProtocol: data[0x07] as number | undefined,
        } as AuthenticatorGetAssertionRequest,
      };
    default:
      return {
        command: request.command,
        request: undefined,
      };
  }
}

export function packMakeCredentialRequest(request: AuthenticatorMakeCredentialRequest): CTAPAuthenticatorRequest {
  return {
    command: CTAP_COMMAND.authenticatorMakeCredential,
    data: EncodeUtils.encodeCbor({
      [0x01]: request.clientDataHash,
      [0x02]: request.rp,
      [0x03]: request.user,
      [0x04]: request.pubKeyCredParams,
      [0x05]: request.excludeList,
      [0x06]: request.extensions,
      [0x07]: request.options,
      [0x08]: request.pinAuth,
      [0x09]: request.pinProtocol,
    }),
  };
}

export function packGetAssertionRequest(request: AuthenticatorGetAssertionRequest): CTAPAuthenticatorRequest {
  return {
    command: CTAP_COMMAND.authenticatorGetAssertion,
    data: EncodeUtils.encodeCbor({
      [0x01]: request.rpId,
      [0x02]: request.clientDataHash,
      [0x03]: request.allowList,
      [0x04]: request.extensions,
      [0x05]: request.options,
      [0x06]: request.pinAuth,
      [0x07]: request.pinProtocol,
    }),
  };
}

export function unpackMakeCredentialResponse(response: CTAPAuthenticatorResponse): AuthenticatorMakeCredentialResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array) as Record<number, unknown>;
    return {
      fmt: data[0x01] as string,
      authData: EncodeUtils.bufferSourceToUint8Array(data[0x02] as BufferSource),
      attStmt: data[0x03] as object,
    };
  } catch (error) {
    throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function packMakeCredentialResponse(response: AuthenticatorMakeCredentialResponse): CTAPAuthenticatorResponse {
  return {
    status: CTAP_STATUS_CODE.CTAP2_OK,
    data: EncodeUtils.encodeCbor({
      [0x01]: response.fmt,
      [0x02]: response.authData,
      [0x03]: response.attStmt,
    }),
  };
}

export function unpackGetAssertionResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetAssertionResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array) as Record<number, unknown>;
    return {
      credential: data[0x01] as PublicKeyCredentialDescriptor | undefined,
      authData: EncodeUtils.bufferSourceToUint8Array(data[0x02] as BufferSource),
      signature: EncodeUtils.bufferSourceToUint8Array(data[0x03] as BufferSource),
      user: data[0x04] as PublicKeyCredentialUserEntity,
      numberOfCredentials: data[0x05] as number,
    };
  } catch (error) {
    throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function packGetAssertionResponse(response: AuthenticatorGetAssertionResponse): CTAPAuthenticatorResponse {
  return {
    status: CTAP_STATUS_CODE.CTAP2_OK,
    data: EncodeUtils.encodeCbor({
      [0x01]: response.credential,
      [0x02]: response.authData,
      [0x03]: response.signature,
      [0x04]: response.user,
      [0x05]: response.numberOfCredentials,
    }),
  };
}

export function unpackGetInfoResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetInfoResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array) as Record<number, unknown>;
    return {
      versions: data[0x01] as string[],
      extensions: data[0x02] as string[] | undefined,
      aaguid: EncodeUtils.bufferSourceToUint8Array(data[0x03] as BufferSource),
      options: data[0x04] as AuthenticatorOptions | undefined,
      maxMsgSize: data[0x05] as number | undefined,
      pinProtocols: data[0x06] as number[] | undefined,
    };
  } catch (error) {
    throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function packGetInfoResponse(response: AuthenticatorGetInfoResponse): CTAPAuthenticatorResponse {
  return {
    status: CTAP_STATUS_CODE.CTAP2_OK,
    data: EncodeUtils.encodeCbor({
      [0x01]: response.versions,
      [0x02]: response.extensions,
      [0x03]: response.aaguid,
      [0x04]: response.options,
      [0x05]: response.maxMsgSize,
      [0x06]: response.pinProtocols,
    }),
  };
}
