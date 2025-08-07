import { createCipheriv, createPrivateKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import EncodeUtils from "../libs/encode-utils";
import { PasskeysCredentialsMemoryRepository } from "../repository/credentials-memory-repository";
import type {
  PasskeyDiscoverableCredential,
  PasskeysCredentialsRepository,
} from "../repository/credentials-repository";
import { CoseKey } from "../webauthn/cose-key";
import {
  type AuthenticatorData,
  type PublicKeyCredentialSource,
  packAuthenticatorData,
  RpId,
} from "../webauthn/webauthn-model";
import {
  AuthenticationEmulatorError,
  type AuthenticatorCredentialManagementRequest,
  type AuthenticatorCredentialManagementResponse,
  type AuthenticatorGetAssertionRequest,
  type AuthenticatorGetAssertionResponse,
  type AuthenticatorGetInfoResponse,
  type AuthenticatorMakeCredentialRequest,
  type AuthenticatorMakeCredentialResponse,
  type AuthenticatorOptions,
  CREDENTIAL_MANAGEMENT_SUBCOMMAND,
  CTAP_COMMAND,
  CTAP_STATUS_CODE,
  type CTAPAuthenticatorRequest,
  type CTAPAuthenticatorResponse,
  packCredentialManagementResponse,
  packGetAssertionResponse,
  packGetInfoResponse,
  packMakeCredentialResponse,
  unpackCredentialManagementRequest,
  unpackRequest,
} from "./ctap-model";

type InteractionResponse = {
  options: { uv: boolean; up: boolean };
};

export const COSEAlgorithmIdentifier = {
  ES256: -7,
  RS256: -257,
  EdDSA: -8,
};

export type PasskeyCredential = {
  readonly publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor;
  readonly publicKeyCredentialSource: PublicKeyCredentialSource;
  readonly authenticatorData: AuthenticatorData;
  readonly user: PublicKeyCredentialUserEntity | undefined;
};

export type AuthenticatorParameters = {
  readonly aaguid: Uint8Array;
  readonly transports: AuthenticatorTransport[];
  readonly algorithmIdentifiers: readonly (keyof typeof COSEAlgorithmIdentifier)[];
  readonly signCounterIncrement: number;
  readonly verifications: { readonly userPresent: boolean; readonly userVerified: boolean };
  readonly userMakeCredentialInteraction: (
    user: PublicKeyCredentialUserEntity,
    options?: Partial<AuthenticatorOptions>,
  ) => InteractionResponse | undefined;
  readonly userGetAssertionInteraction: (
    user: PublicKeyCredentialUserEntity | undefined,
    options?: Partial<AuthenticatorOptions>,
  ) => InteractionResponse | undefined;
  readonly credentialsRepository: PasskeysCredentialsRepository | undefined;
  readonly stateless: boolean;
};

export type MakeCredentialInteraction = (user: PublicKeyCredentialUserEntity, uv: boolean) => boolean;

/**
 * Authenticator emulator
 */
export class AuthenticatorEmulator {
  private static readonly ENCRYPT_KEY = EncodeUtils.strToUint8Array("NID-AUTH-31415926535897932384626");

  /** Authenticator Attestation Global Unique Identifier (16byte)  */
  private static readonly DEFAULT_AAGUID = EncodeUtils.strToUint8Array("NID-AUTH-3141592");
  private static readonly DEFAULT_TRANSPORTS: AuthenticatorTransport[] = ["usb"] as const;
  private static readonly DEFAULT_ALGORITHM_IDENTIFIERS = ["ES256", "RS256", "EdDSA"] as const;
  private static readonly DEFAULT_SIGN_COUNTER_INCREMENT = 1;
  private static readonly DEFAULT_VERIFICATIONS = { userPresent: true, userVerified: true };
  private static readonly DEFAULT_MAKE_CREDENTIAL_INTERACTION = (user: PublicKeyCredentialUserEntity) => ({
    user: user,
    options: { uv: true, up: true },
  });
  private static readonly DEFAULT_GET_ASSERTION_INTERACTION = (user?: PublicKeyCredentialUserEntity) => ({
    user: user,
    options: { uv: true, up: true },
  });

  private static readonly DEFAULT_CREDENTIALS_REPOSITORY = new PasskeysCredentialsMemoryRepository();
  private static readonly DEFAULT_STATELESS = false;
  public params: AuthenticatorParameters;

  constructor(params: Partial<AuthenticatorParameters> = {}) {
    this.params = {
      aaguid: params.aaguid ?? AuthenticatorEmulator.DEFAULT_AAGUID,
      transports: params.transports ?? AuthenticatorEmulator.DEFAULT_TRANSPORTS,
      algorithmIdentifiers: params.algorithmIdentifiers ?? AuthenticatorEmulator.DEFAULT_ALGORITHM_IDENTIFIERS,
      signCounterIncrement: params.stateless
        ? 0
        : (params.signCounterIncrement ?? AuthenticatorEmulator.DEFAULT_SIGN_COUNTER_INCREMENT),
      verifications: params.verifications ?? AuthenticatorEmulator.DEFAULT_VERIFICATIONS,
      userMakeCredentialInteraction:
        params.userMakeCredentialInteraction ?? AuthenticatorEmulator.DEFAULT_MAKE_CREDENTIAL_INTERACTION,
      userGetAssertionInteraction:
        params.userGetAssertionInteraction ?? AuthenticatorEmulator.DEFAULT_GET_ASSERTION_INTERACTION,
      credentialsRepository: params.stateless
        ? undefined
        : (params.credentialsRepository ?? AuthenticatorEmulator.DEFAULT_CREDENTIALS_REPOSITORY),
      stateless: params.stateless ?? AuthenticatorEmulator.DEFAULT_STATELESS,
    };
  }

  /** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api */
  public command(request: CTAPAuthenticatorRequest): CTAPAuthenticatorResponse {
    const unpackedRequest = unpackRequest(request);
    if (unpackedRequest.command === CTAP_COMMAND.authenticatorMakeCredential) {
      const makeCredentialRequest = unpackedRequest.request as AuthenticatorMakeCredentialRequest;
      const makeCredentialResponse = this.authenticatorMakeCredential(makeCredentialRequest);
      return packMakeCredentialResponse(makeCredentialResponse);
    }

    if (unpackedRequest.command === CTAP_COMMAND.authenticatorGetAssertion) {
      const getAssertionRequest = unpackedRequest.request as AuthenticatorGetAssertionRequest;
      const getAssertionResponse = this.authenticatorGetAssertion(getAssertionRequest);
      return packGetAssertionResponse(getAssertionResponse);
    }

    if (unpackedRequest.command === CTAP_COMMAND.authenticatorGetInfo) {
      return packGetInfoResponse(this.authenticatorGetInfo());
    }

    if (unpackedRequest.command === CTAP_COMMAND.authenticatorCredentialManagement) {
      const credentialManagementRequest = unpackCredentialManagementRequest(request);
      const credentialManagementResponse = this.authenticatorCredentialManagement(credentialManagementRequest);
      return packCredentialManagementResponse(credentialManagementResponse);
    }

    throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND);
  }

  /**
   * @see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement
   */
  public authenticatorCredentialManagement(
    request: AuthenticatorCredentialManagementRequest,
  ): AuthenticatorCredentialManagementResponse {
    const repository = this.params.credentialsRepository;
    if (!repository) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
    }

    switch (request.subCommand) {
      case CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential:
        return this.authenticatorDeleteCredential(request);
      case CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin:
        return this.authenticatorEnumerateCredentialsBegin(request);
      case CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential:
        return this.authenticatorEnumerateCredentialsGetNextCredential();
      case CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation:
        return this.authenticatorUpdateUserInformation(request);
      default:
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND);
    }
  }

  // Store the current enumeration state
  private enumerationState: {
    rpId: string;
    credentials: PasskeyDiscoverableCredential[];
    currentIndex: number;
  } | null = null;

  private authenticatorEnumerateCredentialsBegin(
    request: AuthenticatorCredentialManagementRequest,
  ): AuthenticatorCredentialManagementResponse {
    const repository = this.params.credentialsRepository;
    if (!repository) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
    }

    const rpId = request.subCommandParams?.rpId;
    if (!rpId) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
    }

    // Get all credentials for the RP
    const allCredentials = repository.loadCredentials();
    const rpCredentials = allCredentials.filter((cred) => cred.publicKeyCredentialSource.rpId.value === rpId);

    // Store the enumeration state
    this.enumerationState = {
      rpId,
      credentials: rpCredentials,
      currentIndex: 0,
    };

    return {
      totalCredentials: rpCredentials.length,
    };
  }

  private authenticatorEnumerateCredentialsGetNextCredential(): AuthenticatorCredentialManagementResponse {
    if (!this.enumerationState || this.enumerationState.currentIndex >= this.enumerationState.credentials.length) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
    }

    const credential = this.enumerationState.credentials[this.enumerationState.currentIndex++];

    return {
      user: credential.user,
      credentialID: EncodeUtils.bufferSourceToUint8Array(credential.publicKeyCredentialDescriptor.id),
      publicKey: credential.authenticatorData.attestedCredentialData?.credentialPublicKey.toDer(),
    };
  }

  private authenticatorUpdateUserInformation(
    request: AuthenticatorCredentialManagementRequest,
  ): AuthenticatorCredentialManagementResponse {
    const repository = this.params.credentialsRepository;
    if (!repository) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
    }

    const rpId = request.subCommandParams?.rpId;
    const user = request.subCommandParams?.user;

    if (!rpId || !user) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
    }

    // Find all credentials for this user and RP
    const allCredentials = repository.loadCredentials();
    const userCredentials = allCredentials.filter(
      (cred) =>
        cred.publicKeyCredentialSource.rpId.value === rpId &&
        EncodeUtils.encodeBase64Url(cred.user.id) === EncodeUtils.encodeBase64Url(user.id),
    );

    if (userCredentials.length === 0) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
    }

    // Update user information for all matching credentials
    for (const credential of userCredentials) {
      const updatedCredential: PasskeyDiscoverableCredential = {
        ...credential,
        user: {
          ...user,
          id: user.id, // Keep the same ID
        },
      };

      repository.deleteCredential(credential);
      repository.saveCredential(updatedCredential);
    }

    return {};
  }

  private authenticatorDeleteCredential(
    request: AuthenticatorCredentialManagementRequest,
  ): AuthenticatorCredentialManagementResponse {
    const repository = this.params.credentialsRepository;
    if (!repository) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED);
    }

    if (!request.subCommandParams?.credentialId) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
    }

    const credentialId = request.subCommandParams.credentialId;
    const credentials = repository.loadCredentials();
    const credential = credentials.find(
      (cred) =>
        EncodeUtils.encodeBase64Url(cred.publicKeyCredentialSource.id) === EncodeUtils.encodeBase64Url(credentialId),
    );

    if (!credential) {
      throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
    }

    repository.deleteCredential(credential);

    return {
      existingResidentCredentialsCount: repository.loadCredentials().length,
    };
  }

  /** @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo */
  public authenticatorGetInfo(): AuthenticatorGetInfoResponse {
    return {
      versions: ["FIDO_2_0"],
      aaguid: this.params.aaguid,
      options: {
        rk: true,
        uv: this.params.verifications.userVerified,
        up: this.params.verifications.userPresent,
      },
    };
  }

  /**
   * @see https://www.w3.org/TR/webauthn/#sctn-op-make-cred
   * @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
   **/
  public authenticatorMakeCredential(request: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse {
    const rpId = new RpId(request.rp.id);
    const repository = this.params.credentialsRepository;

    // Exclude list
    if (request.excludeList && request.excludeList.length > 0 && repository) {
      const existingCredentials = getCredentials(rpId, request.excludeList, repository);
      if (existingCredentials.length > 0) {
        throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_CREDENTIAL_EXCLUDED);
      }
    }

    // Algorithm selection
    const allowAlgSet = new Set(request.pubKeyCredParams.map((param) => param.alg));
    const alg = this.params.algorithmIdentifiers.find((alg) => allowAlgSet.has(COSEAlgorithmIdentifier[alg]));
    if (!alg) throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_UNSUPPORTED_ALGORITHM);

    // User operation
    const interactionResponse = this.params.userMakeCredentialInteraction(request.user, request.options);
    if (!interactionResponse) throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED);

    // Create credential
    const credential = makeCredential(
      this.params.aaguid,
      rpId,
      alg,
      this.params.transports,
      interactionResponse,
      request.user,
      repository ? undefined : AuthenticatorEmulator.ENCRYPT_KEY,
    );
    if (repository) {
      const discoverableCredential: PasskeyDiscoverableCredential = {
        ...credential,
        user: request.user,
      };
      saveCredential(discoverableCredential, repository);
    }

    return {
      fmt: "none",
      authData: packAuthenticatorData(credential.authenticatorData),
      attStmt: {},
    };
  }

  /**
   * @see https://www.w3.org/TR/webauthn/#sctn-op-get-assertion
   * @see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion
   **/
  public authenticatorGetAssertion(request: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse {
    const rpId = new RpId(request.rpId);
    const repository = this.params.credentialsRepository;
    const allowList = request.allowList ?? [];

    // Allow list
    const credentials = repository
      ? getCredentials(rpId, allowList, repository)
      : getCredentialsStateless(rpId, allowList, AuthenticatorEmulator.ENCRYPT_KEY);
    if (credentials.length === 0) throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
    const credential = credentials[credentials.length - 1];

    // User operation
    const interactionResponse = this.params.userGetAssertionInteraction(credential.user, request.options);
    if (!interactionResponse) throw new AuthenticationEmulatorError(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED);

    // Get assertion
    const newSignCount = !repository ? 0 : credential.authenticatorData.signCount + this.params.signCounterIncrement;
    const { authData, signature } = getAssertion(
      rpId.hash,
      request.clientDataHash,
      newSignCount,
      credential.publicKeyCredentialSource,
      interactionResponse,
      !repository,
    );

    // Update sign count
    if (repository && credential.user) {
      const updatedCredential: PasskeyDiscoverableCredential = {
        ...credential,
        authenticatorData: {
          ...credential.authenticatorData,
          signCount: newSignCount,
        },
        user: credential.user,
      };
      saveCredential(updatedCredential, repository);
    }

    return {
      credential: request.allowList?.length === 1 ? undefined : credential.publicKeyCredentialDescriptor,
      authData,
      signature,
      user: credential.user,
      numberOfCredentials: credentials.length,
    };
  }
}

function getCredentialsStateless(
  rpId: RpId,
  allowCredentials: PublicKeyCredentialDescriptor[],
  key: Uint8Array,
): PasskeyCredential[] {
  return allowCredentials.map((descriptor) => {
    const id = EncodeUtils.bufferSourceToUint8Array(descriptor.id);
    const publicKeyCredentialSource: PublicKeyCredentialSource = {
      type: "public-key",
      id,
      privateKey: decryptBytes(key, id),
      rpId: rpId,
    };
    const authData: AuthenticatorData = {
      rpIdHash: rpId.hash,
      flags: {
        backupEligibility: false,
        backupState: false,
        userPresent: true,
        userVerified: true,
        attestedCredentialData: false,
        extensionData: false,
      },
      signCount: 0,
    };

    return {
      publicKeyCredentialDescriptor: descriptor,
      publicKeyCredentialSource,
      authenticatorData: authData,
      user: undefined,
    };
  });
}

function getCredentials(
  rpId: RpId,
  credentialsFilter: PublicKeyCredentialDescriptor[],
  repository: PasskeysCredentialsRepository,
): PasskeyDiscoverableCredential[] {
  const allowIds = new Set(credentialsFilter.map((descriptor) => EncodeUtils.encodeBase64Url(descriptor.id)));
  const credentials = repository.loadCredentials();
  return credentials.filter((credential) => {
    if (rpId.value !== credential.publicKeyCredentialSource.rpId.value) return false;
    if (credentialsFilter.length > 0) {
      const rawId = credential.publicKeyCredentialDescriptor.id;
      if (!allowIds?.has(EncodeUtils.encodeBase64Url(rawId))) return false;
    }
    return true;
  });
}

function saveCredential(credential: PasskeyDiscoverableCredential, repository: PasskeysCredentialsRepository): void {
  const credentials = repository.loadCredentials();
  const index = credentials.findIndex((c) => {
    if (c.publicKeyCredentialSource.rpId.value !== credential.publicKeyCredentialSource.rpId.value) return false;
    return EncodeUtils.encodeBase64Url(c.user.id) === EncodeUtils.encodeBase64Url(credential.user.id);
  });
  if (index >= 0) {
    repository.deleteCredential(credentials[index]);
  }
  repository.saveCredential(credential);
}

function getAssertion(
  rpIdHash: Uint8Array,
  clientDataHash: Uint8Array,
  newSignCounter: number,
  credential: PublicKeyCredentialSource,
  interactionResponse: InteractionResponse,
  stateless: boolean,
): { authData: Uint8Array; signature: Uint8Array } {
  const authenticatorData = {
    rpIdHash,
    flags: {
      userPresent: interactionResponse.options.up,
      userVerified: interactionResponse.options.uv,
      backupEligibility: !stateless,
      backupState: !stateless,
      attestedCredentialData: false,
      extensionData: false,
    },
    signCount: newSignCounter,
  };

  const payload: number[] = [];
  payload.push(...packAuthenticatorData(authenticatorData));
  payload.push(...clientDataHash);

  const privateKey = createPrivateKey({
    format: "der",
    type: "pkcs8",
    key: credential.privateKey as Buffer,
  });

  const signature = EncodeUtils.bufferSourceToUint8Array(sign(null, new Uint8Array(payload), privateKey));
  return { authData: packAuthenticatorData(authenticatorData), signature };
}

function makeCredential(
  aaguid: Uint8Array,
  rpId: RpId,
  alg: keyof typeof COSEAlgorithmIdentifier,
  transports: AuthenticatorTransport[],
  interactionResponse: InteractionResponse,
  user: PublicKeyCredentialUserEntity | undefined,
  statelessKey: Uint8Array | undefined,
): PasskeyCredential {
  const generatekeyPair = (alg: keyof typeof COSEAlgorithmIdentifier) => {
    if (alg === "RS256") return generateKeyPairSync("rsa", { modulusLength: 2048 });
    if (alg === "EdDSA") return generateKeyPairSync("ed25519");
    return generateKeyPairSync("ec", { namedCurve: "P-256" });
  };

  const keyPair = generatekeyPair(alg);
  const privateKey = new Uint8Array(keyPair.privateKey.export({ format: "der", type: "pkcs8" }));
  const credentialId = statelessKey ? encryptBytes(statelessKey, privateKey) : new Uint8Array(randomBytes(32));

  const publicKeyCredentialSource: PublicKeyCredentialSource = {
    type: "public-key",
    id: credentialId,
    privateKey: new Uint8Array(keyPair.privateKey.export({ format: "der", type: "pkcs8" })),
    rpId: rpId,
    userHandle: user && !statelessKey ? EncodeUtils.bufferSourceToUint8Array(user.id) : undefined,
  };

  const publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor = {
    type: "public-key",
    id: credentialId,
    transports,
  };

  const authenticatorData: AuthenticatorData = {
    rpIdHash: rpId.hash,
    flags: {
      backupEligibility: !statelessKey,
      backupState: !statelessKey,
      userPresent: interactionResponse.options.up,
      userVerified: interactionResponse.options.uv,
      attestedCredentialData: true,
      extensionData: false,
    },
    signCount: 0,
    attestedCredentialData: {
      aaguid,
      credentialId,
      credentialPublicKey: CoseKey.fromKeyObject(keyPair.publicKey),
    },
  };
  return {
    publicKeyCredentialDescriptor,
    publicKeyCredentialSource,
    authenticatorData,
    user,
  };
}

function encryptBytes(key: Uint8Array, data: Uint8Array): Uint8Array {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  const encrypted = cipher.update(data);
  return Buffer.concat([iv, encrypted, cipher.final()]);
}

function decryptBytes(key: Uint8Array, data: Uint8Array): Uint8Array {
  const iv = data.slice(0, 16);
  const encrypted = data.slice(16);
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([cipher.update(encrypted), cipher.final()]);
}
