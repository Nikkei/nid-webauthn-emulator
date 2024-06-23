import { createPrivateKey, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import type {
  AuthenticatorGetAssertionRequest,
  AuthenticatorGetAssertionResponse,
  AuthenticatorMakeCredentialRequest,
  AuthenticatorMakeCredentialResponse,
} from "../ctap/ctap-model";
import EncodeUtils from "../libs/encode-utils";
import { CoseKey } from "../webauthn/cose-key";
import {
  type AuthenticatorData,
  type PublicKeyCredentialSource,
  RpId,
  packAuthenticatorData,
} from "../webauthn/webauthn-model";
import type { PasskeyCredential } from "./passkeys-credential";

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
  readonly userName: string;
};

/**
 * Authenticator emulator
 */
export class AuthenticatorEmulator {
  private static readonly DEFAULT_AAGUID = new Uint8Array([
    0x8e, 0xdf, 0xb6, 0xbb, 0x40, 0x13, 0xc4, 0xa4, 0x6c, 0x96, 0xb9, 0x63, 0x40, 0x13, 0x81, 0x3f,
  ]);
  private static readonly DEFAULT_TRANSPORTS: AuthenticatorTransport[] = ["usb"] as const;
  private static readonly DEFAULT_ALGORITHM_IDENTIFIERS = ["ES256", "RS256", "EdDSA"] as const;
  private static readonly DEFAULT_SIGN_COUNTER_INCREMENT = 1;
  private static readonly DEFAULT_VERIFICATIONS = { userPresent: true, userVerified: true };
  private static readonly DEFAULT_USER_NAME = "nid-authenticator-emulator-user";

  public credentials: PasskeyCredential[] = [];
  public params: AuthenticatorParameters;

  constructor(params: Partial<AuthenticatorParameters> = {}) {
    this.params = {
      aaguid: params.aaguid ?? AuthenticatorEmulator.DEFAULT_AAGUID,
      transports: params.transports ?? AuthenticatorEmulator.DEFAULT_TRANSPORTS,
      algorithmIdentifiers: params.algorithmIdentifiers ?? AuthenticatorEmulator.DEFAULT_ALGORITHM_IDENTIFIERS,
      signCounterIncrement: params.signCounterIncrement ?? AuthenticatorEmulator.DEFAULT_SIGN_COUNTER_INCREMENT,
      verifications: params.verifications ?? AuthenticatorEmulator.DEFAULT_VERIFICATIONS,
      userName: params.userName ?? AuthenticatorEmulator.DEFAULT_USER_NAME,
    };
  }

  /** @see https://www.w3.org/TR/webauthn/#sctn-op-make-cred */
  public authenticatorMakeCredential(request: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse {
    if (!request.rp.id) throw new Error("Invalid RP ID");
    const rpId = new RpId(request.rp.id);
    const userHandle = EncodeUtils.bufferSourceToUint8Array(request.user.id);
    if (request.excludeList && request.excludeList.length > 0) {
      const existingCredentials = this.getCredentials(rpId, request.excludeList);
      if (existingCredentials.length > 0) throw new Error("Credential already exists");
    }

    const allowAlgSet = new Set(request.pubKeyCredParams.map((param) => param.alg));
    const alg = this.params.algorithmIdentifiers.find((alg) => allowAlgSet.has(COSEAlgorithmIdentifier[alg]));
    if (!alg) throw new Error("Invalid algorithm");

    const { aaguid, transports, userName } = this.params;
    const credential = generateCredential(aaguid, rpId, userHandle, userName, alg, transports);
    this.credentials.push(credential);

    return {
      fmt: "packed",
      authData: packAuthenticatorData(credential.authenticatorData),
      attStmt: new Map(),
    };
  }

  /** @see https://www.w3.org/TR/webauthn/#sctn-op-get-assertion */
  public authenticatorGetAssertion(request: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse {
    const rpId = new RpId(request.rpId);
    const credentials = this.getCredentials(rpId, request.allowList ?? []);
    if (credentials.length === 0) throw new Error("No credentials found");
    const credential = credentials[0];

    credential.authenticatorData.signCount += this.params.signCounterIncrement;
    const authenticatorData = {
      rpIdHash: credential.authenticatorData.rpIdHash,
      flags: {
        userPresent: this.params.verifications.userPresent,
        userVerified: this.params.verifications.userVerified,
        backupEligibility: credential.authenticatorData.flags.backupEligibility,
        backupState: true,
        attestedCredentialData: false,
        extensionData: false,
      },
      signCount: credential.authenticatorData.signCount,
    };

    const payload = new Array<number>();
    payload.push(...packAuthenticatorData(authenticatorData));
    payload.push(...request.clientDataHash);

    const privateKey = createPrivateKey({
      format: "der",
      type: "pkcs8",
      key: credential.publicKeyCredentialSource.privateKey as Buffer,
    });

    const signature = createSign("sha256").update(new Uint8Array(payload)).sign(privateKey);
    return {
      credential: credential.publicKeyCredentialDescriptor,
      authData: packAuthenticatorData(authenticatorData),
      signature,
      user: credential.user,
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
}

function generateCredential(
  aaguid: Uint8Array,
  rpId: RpId,
  userHandle: Uint8Array,
  userName: string,
  alg: keyof typeof COSEAlgorithmIdentifier,
  transports: AuthenticatorTransport[],
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
    userHandle,
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
      userPresent: true,
      userVerified: true,
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

  const user: PublicKeyCredentialUserEntity = {
    id: userHandle,
    name: userName,
    displayName: userName,
  };

  return {
    publicKeyCredentialDescriptor,
    publicKeyCredentialSource,
    authenticatorData,
    user,
  };
}
