import EncodeUtils from "../libs/encode-utils";

export type AuthenticatorOptions = {
  rk: boolean;
  uv: boolean;
  up: boolean;
};

/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialRequest {
  clientDataHash: Uint8Array;
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  excludeList?: PublicKeyCredentialDescriptor[];
  extensions?: object;
  options?: Partial<AuthenticatorOptions>;
  pinAuth?: Uint8Array;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialResponse {
  fmt: string;
  authData: Uint8Array;
  attStmt: object;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionRequest {
  rpId: string;
  clientDataHash: Uint8Array;
  allowList?: PublicKeyCredentialDescriptor[];
  extensions?: object;
  options?: Partial<AuthenticatorOptions>;
  pinAuth?: Uint8Array;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionResponse {
  credential?: PublicKeyCredentialDescriptor;
  authData: Uint8Array;
  signature: Uint8Array;
  user: PublicKeyCredentialUserEntity;
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
  CTAP2_ERR_NO_CREDENTIALS = 0x2d,
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

export class CTAPError extends Error {
  public type = "CTAPError";
  constructor(
    public status: CTAP_STATUS_CODE,
    options?: ErrorOptions,
  ) {
    super(`CTAP error: ${CTAP_STATUS_CODE[status]} (${status})`, options);
  }
}

export function unpackRequest(request: CTAPAuthenticatorRequest): { command: CTAP_COMMAND; request: unknown } {
  const data = request.data
    ? (EncodeUtils.decodeCbor(request.data) as Map<number, unknown>)
    : new Map<number, unknown>();
  if (request.command === CTAP_COMMAND.authenticatorMakeCredential) {
    return {
      command: request.command,
      request: {
        clientDataHash: EncodeUtils.bufferSourceToUint8Array(data.get(0x01) as BufferSource),
        rp: data.get(0x02) as PublicKeyCredentialRpEntity,
        user: data.get(0x03) as PublicKeyCredentialUserEntity,
        pubKeyCredParams: data.get(0x04) as PublicKeyCredentialParameters[],
        excludeList: data.get(0x05) as PublicKeyCredentialDescriptor[] | undefined,
        extensions: data.get(0x06) as object | undefined,
        options: data.get(0x07) as { rk?: boolean; uv?: boolean } | undefined,
        pinAuth: data.get(0x08) ? EncodeUtils.bufferSourceToUint8Array(data.get(0x08) as BufferSource) : undefined,
        pinProtocol: data.get(0x09) as number | undefined,
      } as AuthenticatorMakeCredentialRequest,
    };
  }
  if (request.command === CTAP_COMMAND.authenticatorGetAssertion) {
    return {
      command: request.command,
      request: {
        rpId: data.get(0x01) as string,
        clientDataHash: EncodeUtils.bufferSourceToUint8Array(data.get(0x02) as BufferSource),
        allowList: data.get(0x03) as PublicKeyCredentialDescriptor[] | undefined,
        extensions: data.get(0x04) as object | undefined,
        options: data.get(0x05) as { up?: boolean; uv?: boolean } | undefined,
        pinAuth: data.get(0x08) ? EncodeUtils.bufferSourceToUint8Array(data.get(0x06) as BufferSource) : undefined,
        pinProtocol: data.get(0x07) as number | undefined,
      } as AuthenticatorGetAssertionRequest,
    };
  }
  if (request.command === CTAP_COMMAND.authenticatorGetInfo) {
    return {
      command: request.command,
      request: undefined,
    };
  }
  for (const value of Object.values(CTAP_COMMAND)) {
    if (request.command === value) throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
  }
  throw new CTAPError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND);
}

export function packMakeCredentialRequest(request: AuthenticatorMakeCredentialRequest): CTAPAuthenticatorRequest {
  return {
    command: CTAP_COMMAND.authenticatorMakeCredential,
    data: EncodeUtils.encodeCbor(
      new Map<number, unknown>([
        [0x01, request.clientDataHash],
        [0x02, request.rp],
        [0x03, request.user],
        [0x04, request.pubKeyCredParams],
        [0x05, request.excludeList],
        [0x06, request.extensions],
        [0x07, request.options],
        [0x08, request.pinAuth],
        [0x09, request.pinProtocol],
      ]),
    ),
  };
}

export function packGetAssertionRequest(request: AuthenticatorGetAssertionRequest): CTAPAuthenticatorRequest {
  return {
    command: CTAP_COMMAND.authenticatorGetAssertion,
    data: EncodeUtils.encodeCbor(
      new Map<number, unknown>([
        [0x01, request.rpId],
        [0x02, request.clientDataHash],
        [0x03, request.allowList],
        [0x04, request.extensions],
        [0x05, request.options],
        [0x06, request.pinAuth],
        [0x07, request.pinProtocol],
      ]),
    ),
  };
}

export function unpackMakeCredentialResponse(response: CTAPAuthenticatorResponse): AuthenticatorMakeCredentialResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array) as Map<number, unknown>;
    return {
      fmt: data.get(0x01) as string,
      authData: EncodeUtils.bufferSourceToUint8Array(data.get(0x02) as BufferSource),
      attStmt: data.get(0x03) as object,
    };
  } catch (error) {
    throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function packMakeCredentialResponse(response: AuthenticatorMakeCredentialResponse): CTAPAuthenticatorResponse {
  return {
    status: CTAP_STATUS_CODE.CTAP2_OK,
    data: EncodeUtils.encodeCbor(
      new Map<number, unknown>([
        [0x01, response.fmt],
        [0x02, response.authData],
        [0x03, response.attStmt],
      ]),
    ),
  };
}

export function unpackGetAssertionResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetAssertionResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array) as Map<number, unknown>;
    return {
      credential: data.get(0x01) as PublicKeyCredentialDescriptor | undefined,
      authData: EncodeUtils.bufferSourceToUint8Array(data.get(0x02) as BufferSource),
      signature: EncodeUtils.bufferSourceToUint8Array(data.get(0x03) as BufferSource),
      user: data.get(0x04) as PublicKeyCredentialUserEntity,
      numberOfCredentials: data.get(0x05) as number,
    };
  } catch (error) {
    throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function packGetAssertionResponse(response: AuthenticatorGetAssertionResponse): CTAPAuthenticatorResponse {
  try {
    return {
      status: CTAP_STATUS_CODE.CTAP2_OK,
      data: EncodeUtils.encodeCbor(
        new Map<number, unknown>([
          [0x01, response.credential],
          [0x02, response.authData],
          [0x03, response.signature],
          [0x04, response.user],
          [0x05, response.numberOfCredentials],
        ]),
      ),
    };
  } catch (error) {
    throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function packGetInfoResponse(response: AuthenticatorGetInfoResponse): CTAPAuthenticatorResponse {
  try {
    return {
      status: CTAP_STATUS_CODE.CTAP2_OK,
      data: EncodeUtils.encodeCbor(
        new Map<number, unknown>([
          [0x01, response.versions],
          [0x02, response.extensions],
          [0x03, response.aaguid],
          [0x04, response.options],
          [0x05, response.maxMsgSize],
          [0x06, response.pinProtocols],
        ]),
      ),
    };
  } catch (error) {
    throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function unpackGetInfoResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetInfoResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array) as Map<number, unknown>;
    return {
      versions: data.get(0x01) as string[],
      extensions: data.get(0x02) as string[] | undefined,
      aaguid: EncodeUtils.bufferSourceToUint8Array(data.get(0x03) as BufferSource),
      options: data.get(0x04) as AuthenticatorOptions | undefined,
      maxMsgSize: data.get(0x05) as number | undefined,
      pinProtocols: data.get(0x06) as number[] | undefined,
    };
  } catch (error) {
    throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}
