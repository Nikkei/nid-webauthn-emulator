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
  clientDataHash: Uint8Array<ArrayBuffer>;
  rp: PublicKeyCredentialRpEntity & { id: string };
  user: PublicKeyCredentialUserEntity;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  excludeList?: PublicKeyCredentialDescriptor[];
  extensions?: object;
  options?: Partial<AuthenticatorOptions>;
  pinAuth?: Uint8Array<ArrayBuffer>;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential */
export interface AuthenticatorMakeCredentialResponse {
  fmt: string;
  authData: Uint8Array<ArrayBuffer>;
  attStmt: object;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionRequest {
  rpId: string;
  clientDataHash: Uint8Array<ArrayBuffer>;
  allowList?: PublicKeyCredentialDescriptor[];
  extensions?: object;
  options?: Partial<AuthenticatorOptions>;
  pinAuth?: Uint8Array<ArrayBuffer>;
  pinProtocol?: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion */
export interface AuthenticatorGetAssertionResponse {
  credential?: PublicKeyCredentialDescriptor;
  authData: Uint8Array<ArrayBuffer>;
  signature: Uint8Array<ArrayBuffer>;
  user?: PublicKeyCredentialUserEntity;
  numberOfCredentials: number;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo */
export type AuthenticatorGetInfoResponse = {
  versions: string[];
  extensions?: string[];
  aaguid: Uint8Array<ArrayBuffer>;
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
  authenticatorCredentialManagement = 0x0a,
}

export enum CREDENTIAL_MANAGEMENT_SUBCOMMAND {
  getCredsMetadata = 0x01,
  enumerateRPsBegin = 0x02,
  enumerateRPsGetNextRP = 0x03,
  enumerateCredentialsBegin = 0x04,
  enumerateCredentialsGetNextCredential = 0x05,
  deleteCredential = 0x06,
  updateUserInformation = 0x07,
}

export interface AuthenticatorCredentialManagementRequest {
  subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND;
  subCommandParams?: {
    credentialId?: Uint8Array<ArrayBuffer>;
    rpId?: string;
    user?: PublicKeyCredentialUserEntity;
  };
  pinUvAuthProtocol?: number;
  pinUvAuthParam?: Uint8Array<ArrayBuffer>;
}

export interface AuthenticatorCredentialManagementResponse {
  existingResidentCredentialsCount?: number;
  maxPossibleRemainingResidentCredentialsCount?: number;
  rp?: PublicKeyCredentialRpEntity;
  rpIDHash?: Uint8Array<ArrayBuffer>;
  totalRPs?: number;
  user?: PublicKeyCredentialUserEntity;
  credentialID?: Uint8Array<ArrayBuffer>;
  publicKey?: Uint8Array<ArrayBuffer>;
  totalCredentials?: number;
  credProtect?: number;
  largeBlobKey?: Uint8Array<ArrayBuffer>;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#responses */
export interface CTAPAuthenticatorResponse {
  status: CTAP_STATUS_CODE;
  data?: Uint8Array<ArrayBuffer>;
}

/** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#commands */
export interface CTAPAuthenticatorRequest {
  command: CTAP_COMMAND;
  data?: Uint8Array<ArrayBuffer>;
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
    case CTAP_COMMAND.authenticatorCredentialManagement:
      return {
        command: request.command,
        request: {
          subCommand: data[0x01] as CREDENTIAL_MANAGEMENT_SUBCOMMAND,
          subCommandParams: data[0x02]
            ? {
                credentialId: (data[0x02] as Record<number, unknown>)[0x01]
                  ? EncodeUtils.bufferSourceToUint8Array((data[0x02] as Record<number, unknown>)[0x01] as BufferSource)
                  : undefined,
                rpId: (data[0x02] as Record<number, unknown>)[0x02] as string | undefined,
                user: (data[0x02] as Record<number, unknown>)[0x03] as PublicKeyCredentialUserEntity | undefined,
              }
            : undefined,
          pinUvAuthProtocol: data[0x03] as number | undefined,
          pinUvAuthParam: data[0x04] ? EncodeUtils.bufferSourceToUint8Array(data[0x04] as BufferSource) : undefined,
        } as AuthenticatorCredentialManagementRequest,
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
      "1": request.clientDataHash,
      "2": request.rp,
      "3": request.user,
      "4": request.pubKeyCredParams,
      "5": request.excludeList,
      "6": request.extensions,
      "7": request.options,
      "8": request.pinAuth,
      "9": request.pinProtocol,
    }),
  };
}

export function packGetAssertionRequest(request: AuthenticatorGetAssertionRequest): CTAPAuthenticatorRequest {
  return {
    command: CTAP_COMMAND.authenticatorGetAssertion,
    data: EncodeUtils.encodeCbor({
      "1": request.rpId,
      "2": request.clientDataHash,
      "3": request.allowList,
      "4": request.extensions,
      "5": request.options,
      "6": request.pinAuth,
      "7": request.pinProtocol,
    }),
  };
}

export function packCredentialManagementRequest(
  request: AuthenticatorCredentialManagementRequest,
): CTAPAuthenticatorRequest {
  return {
    command: CTAP_COMMAND.authenticatorCredentialManagement,
    data: EncodeUtils.encodeCbor({
      "1": request.subCommand,
      "2": request.subCommandParams
        ? {
            "1": request.subCommandParams.credentialId,
            "2": request.subCommandParams.rpId,
            "3": request.subCommandParams.user,
          }
        : undefined,
      "3": request.pinUvAuthProtocol,
      "4": request.pinUvAuthParam,
    }),
  };
}

export function unpackCredentialManagementRequest(
  request: CTAPAuthenticatorRequest,
): AuthenticatorCredentialManagementRequest {
  try {
    const data = EncodeUtils.decodeCbor(request.data as Uint8Array<ArrayBuffer>) as Record<number, unknown>;
    const subCommandParams = data[0x02] as Record<number, unknown> | undefined;

    return {
      subCommand: data[0x01] as CREDENTIAL_MANAGEMENT_SUBCOMMAND,
      subCommandParams: subCommandParams
        ? {
            credentialId: subCommandParams[0x01]
              ? EncodeUtils.bufferSourceToUint8Array(subCommandParams[0x01] as BufferSource)
              : undefined,
            rpId: subCommandParams[0x02] as string | undefined,
            user: subCommandParams[0x03] as PublicKeyCredentialUserEntity | undefined,
          }
        : undefined,
      pinUvAuthProtocol: data[0x03] as number | undefined,
      pinUvAuthParam: data[0x04] ? EncodeUtils.bufferSourceToUint8Array(data[0x04] as BufferSource) : undefined,
    };
  } catch (error) {
    throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}

export function unpackMakeCredentialResponse(response: CTAPAuthenticatorResponse): AuthenticatorMakeCredentialResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array<ArrayBuffer>) as Record<number, unknown>;
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
      "1": response.fmt,
      "2": response.authData,
      "3": response.attStmt,
    }),
  };
}

export function unpackGetAssertionResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetAssertionResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array<ArrayBuffer>) as Record<number, unknown>;
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
      "1": response.credential,
      "2": response.authData,
      "3": response.signature,
      "4": response.user,
      "5": response.numberOfCredentials,
    }),
  };
}

export function unpackGetInfoResponse(response: CTAPAuthenticatorResponse): AuthenticatorGetInfoResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array<ArrayBuffer>) as Record<number, unknown>;
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
      "1": response.versions,
      "2": response.extensions,
      "3": response.aaguid,
      "4": response.options,
      "5": response.maxMsgSize,
      "6": response.pinProtocols,
    }),
  };
}

export function packCredentialManagementResponse(
  response: AuthenticatorCredentialManagementResponse,
): CTAPAuthenticatorResponse {
  return {
    status: CTAP_STATUS_CODE.CTAP2_OK,
    data: EncodeUtils.encodeCbor({
      "1": response.existingResidentCredentialsCount,
      "2": response.maxPossibleRemainingResidentCredentialsCount,
      "3": response.rp,
      "4": response.rpIDHash,
      "5": response.totalRPs,
      "6": response.user,
      "7": response.credentialID,
      "8": response.publicKey,
      "9": response.totalCredentials,
      "10": response.credProtect,
      "11": response.largeBlobKey,
    }),
  };
}

export function unpackCredentialManagementResponse(
  response: CTAPAuthenticatorResponse,
): AuthenticatorCredentialManagementResponse {
  try {
    const data = EncodeUtils.decodeCbor(response.data as Uint8Array<ArrayBuffer>) as Record<number, unknown>;

    return {
      existingResidentCredentialsCount: data[0x01] as number | undefined,
      maxPossibleRemainingResidentCredentialsCount: data[0x02] as number | undefined,
      rp: data[0x03] as PublicKeyCredentialRpEntity | undefined,
      rpIDHash: data[0x04] ? EncodeUtils.bufferSourceToUint8Array(data[0x04] as BufferSource) : undefined,
      totalRPs: data[0x05] as number | undefined,
      user: data[0x06] as PublicKeyCredentialUserEntity | undefined,
      credentialID: data[0x07] ? EncodeUtils.bufferSourceToUint8Array(data[0x07] as BufferSource) : undefined,
      publicKey: data[0x08] ? EncodeUtils.bufferSourceToUint8Array(data[0x08] as BufferSource) : undefined,
      totalCredentials: data[0x09] as number | undefined,
      credProtect: data[0x0a] as number | undefined,
      largeBlobKey: data[0x0b] ? EncodeUtils.bufferSourceToUint8Array(data[0x0b] as BufferSource) : undefined,
    };
  } catch (error) {
    throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR, { cause: error });
  }
}
