import { createPrivateKey, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import type { PasskeyCredential } from "../emulators/passkeys-credential";
import { CoseKey } from "../libs/cose-key";
import EncodeUtils from "../libs/encode-utils";
import {
  type AuthenticatorData,
  type PublicKeyCredentialSource,
  RpId,
  packAuthenticatorData,
} from "../webauthn/webauthn-model";
import {
  type AuthenticatorGetAssertionRequest,
  type AuthenticatorGetAssertionResponse,
  type AuthenticatorMakeCredentialRequest,
  type AuthenticatorMakeCredentialResponse,
  type AuthenticatorOptions,
  type CTAPAuthenticatorRequest,
  type CTAPAuthenticatorResponse,
  CTAPError,
  CTAP_COMMAND,
  CTAP_STATUS_CODE,
  packGetAssertionResponse,
  packMakeCredentialResponse,
  unpackRequest,
} from "./ctap-model";

type InteractionResponse = {
  user: PublicKeyCredentialUserEntity;
  options: { uv: boolean; up: boolean };
};

type Interaction = (
  user?: PublicKeyCredentialUserEntity,
  options?: Partial<AuthenticatorOptions>,
) => InteractionResponse | undefined;

export const COSEAlgorithmIdentifier = {
  ES256: -7,
  RS256: -257,
  EdDSA: -8,
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
};

export type MakeCredentialInteraction = (user: PublicKeyCredentialUserEntity, uv: boolean) => boolean;

/**
 * Authenticator emulator
 */
export class AuthenticatorEmulator {
  private static readonly DEFAULT_USER = {
    id: new Uint8Array(16),
    name: "Anonymous NID Authenticator User",
    displayName: "Anonymous NID Authenticator User",
  };

  private static readonly DEFAULT_AAGUID = new Uint8Array([
    0x8e, 0xdf, 0xb6, 0xbb, 0x40, 0x13, 0xc4, 0xa4, 0x6c, 0x96, 0xb9, 0x63, 0x40, 0x13, 0x81, 0x3f,
  ]);
  private static readonly DEFAULT_TRANSPORTS: AuthenticatorTransport[] = ["usb"] as const;
  private static readonly DEFAULT_ALGORITHM_IDENTIFIERS = ["ES256", "RS256", "EdDSA"] as const;
  private static readonly DEFAULT_SIGN_COUNTER_INCREMENT = 1;
  private static readonly DEFAULT_VERIFICATIONS = { userPresent: true, userVerified: true };
  private static readonly DEFAULT_MAKE_CREDENTIAL_INTERACTION: Interaction = (user) => ({
    user: user ?? AuthenticatorEmulator.DEFAULT_USER,
    options: { uv: true, up: true },
  });
  private static readonly DEFAULT_GET_ASSERTION_INTERACTION: Interaction = (user) => ({
    user: user ?? AuthenticatorEmulator.DEFAULT_USER,
    options: { uv: true, up: true },
  });

  public credentials: PasskeyCredential[] = [];
  public params: AuthenticatorParameters;

  constructor(params: Partial<AuthenticatorParameters> = {}) {
    this.params = {
      aaguid: params.aaguid ?? AuthenticatorEmulator.DEFAULT_AAGUID,
      transports: params.transports ?? AuthenticatorEmulator.DEFAULT_TRANSPORTS,
      algorithmIdentifiers: params.algorithmIdentifiers ?? AuthenticatorEmulator.DEFAULT_ALGORITHM_IDENTIFIERS,
      signCounterIncrement: params.signCounterIncrement ?? AuthenticatorEmulator.DEFAULT_SIGN_COUNTER_INCREMENT,
      verifications: params.verifications ?? AuthenticatorEmulator.DEFAULT_VERIFICATIONS,
      userMakeCredentialInteraction:
        params.userMakeCredentialInteraction ?? AuthenticatorEmulator.DEFAULT_MAKE_CREDENTIAL_INTERACTION,
      userGetAssertionInteraction:
        params.userGetAssertionInteraction ?? AuthenticatorEmulator.DEFAULT_GET_ASSERTION_INTERACTION,
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
    throw new CTAPError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND);
  }

  /** @see https://www.w3.org/TR/webauthn/#sctn-op-make-cred */
  public authenticatorMakeCredential(request: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse {
    if (!request.rp.id) throw new CTAPError(CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER);
    const rpId = new RpId(request.rp.id);

    // Exclude list
    if (request.excludeList && request.excludeList.length > 0) {
      const existingCredentials = this.getCredentials(rpId, request.excludeList);
      if (existingCredentials.length > 0) throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_CREDENTIAL_EXCLUDED);
    }

    // Algorithm selection
    const allowAlgSet = new Set(request.pubKeyCredParams.map((param) => param.alg));
    const alg = this.params.algorithmIdentifiers.find((alg) => allowAlgSet.has(COSEAlgorithmIdentifier[alg]));
    if (!alg) throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_UNSUPPORTED_ALGORITHM);

    // User operation
    const interactionResponse = this.params.userMakeCredentialInteraction(request.user, request.options);
    if (!interactionResponse) throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED);

    // Create credential
    const credential = makeCredential(this.params.aaguid, rpId, alg, this.params.transports, interactionResponse);
    this.addCredential(credential, request.options?.rk ?? false);

    return {
      fmt: "packed",
      authData: packAuthenticatorData(credential.authenticatorData),
      attStmt: new Map(),
    };
  }

  /** @see https://www.w3.org/TR/webauthn/#sctn-op-get-assertion */
  public authenticatorGetAssertion(request: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse {
    const rpId = new RpId(request.rpId);

    // Allow list
    const credentials = this.getCredentials(rpId, request.allowList ?? []);
    if (credentials.length === 0) throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS);
    const credential = credentials[credentials.length - 1];

    // User operation
    const interactionResponse = this.params.userGetAssertionInteraction(credential.user, request.options);
    if (!interactionResponse) throw new CTAPError(CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED);

    // Get assertion
    const { authData, signature } = getAssertion(
      request.clientDataHash,
      this.params.signCounterIncrement,
      credential,
      interactionResponse,
    );

    return {
      credential: credential.publicKeyCredentialDescriptor,
      authData,
      signature,
      user: interactionResponse.user,
      numberOfCredentials: this.credentials.length,
    };
  }

  private getCredentials(rpId: RpId, credentialsFilter: PublicKeyCredentialDescriptor[]): PasskeyCredential[] {
    const allowIds = new Set(credentialsFilter.map((descriptor) => EncodeUtils.bufferSourceToBase64Url(descriptor.id)));
    return this.credentials.filter((credential) => {
      if (rpId.value !== credential.publicKeyCredentialSource.rpId.value) return false;
      if (credentialsFilter.length > 0) {
        const rawId = credential.publicKeyCredentialDescriptor.id;
        if (!allowIds?.has(EncodeUtils.bufferSourceToBase64Url(rawId))) return false;
      }
      return true;
    });
  }

  private addCredential(credential: PasskeyCredential, rk: boolean): void {
    if (rk) {
      const index = this.credentials.findIndex((c) => {
        if (c.publicKeyCredentialSource.rpId.value !== credential.publicKeyCredentialSource.rpId.value) return false;
        if (c.user?.id && credential.user?.id && c.user.id === credential.user.id) return true;
        return false;
      });
      if (index >= 0) {
        this.credentials[index] = credential;
        return;
      }
    }
    this.credentials.push(credential);
  }
}

function getAssertion(
  clientDataHash: Uint8Array,
  signCounterIncrement: number,
  credential: PasskeyCredential,
  interactionResponse: InteractionResponse,
): { authData: Uint8Array; signature: Uint8Array } {
  credential.authenticatorData.signCount += signCounterIncrement;
  const authenticatorData = {
    rpIdHash: credential.authenticatorData.rpIdHash,
    flags: {
      userPresent: interactionResponse.options.up,
      userVerified: interactionResponse.options.uv,
      backupEligibility: credential.authenticatorData.flags.backupEligibility,
      backupState: true,
      attestedCredentialData: false,
      extensionData: false,
    },
    signCount: credential.authenticatorData.signCount,
  };

  const payload = new Array<number>();
  payload.push(...packAuthenticatorData(authenticatorData));
  payload.push(...clientDataHash);

  const privateKey = createPrivateKey({
    format: "der",
    type: "pkcs8",
    key: credential.publicKeyCredentialSource.privateKey as Buffer,
  });

  const signature = createSign("sha256").update(new Uint8Array(payload)).sign(privateKey);
  return { authData: packAuthenticatorData(authenticatorData), signature };
}

function makeCredential(
  aaguid: Uint8Array,
  rpId: RpId,
  alg: keyof typeof COSEAlgorithmIdentifier,
  transports: AuthenticatorTransport[],
  interactionResponse: InteractionResponse,
): PasskeyCredential {
  const generatekeyPair = (alg: keyof typeof COSEAlgorithmIdentifier) => {
    if (alg === "RS256") return generateKeyPairSync("rsa", { modulusLength: 2048 });
    if (alg === "EdDSA") return generateKeyPairSync("ed25519");
    return generateKeyPairSync("ec", { namedCurve: "P-256" });
  };

  const credentialId = new Uint8Array(randomBytes(32));
  const keyPair = generatekeyPair(alg);
  const publicKeyCredentialSource: PublicKeyCredentialSource = {
    type: "public-key",
    id: credentialId,
    privateKey: new Uint8Array(keyPair.privateKey.export({ format: "der", type: "pkcs8" })),
    rpId: rpId,
    userHandle: interactionResponse.user
      ? EncodeUtils.bufferSourceToUint8Array(interactionResponse.user.id)
      : undefined,
  };

  const publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor = {
    type: "public-key",
    id: credentialId,
    transports,
  };

  const authenticatorData: AuthenticatorData = {
    rpIdHash: rpId.hash,
    flags: {
      backupEligibility: true,
      backupState: false,
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
    user: interactionResponse.user,
  };
}