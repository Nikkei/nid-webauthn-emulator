import { createHash, createPrivateKey, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import EncodeUtils from "../libs/encode-utils";
import { CoseKey } from "../webauthn/cose-key";
import {
  type AuthenticatorData,
  type CollectedClientData,
  type PublicKeyCredentialSource,
  type RpId,
  packAuthenticatorData,
} from "../webauthn/webauthn-model";
import type { PasskeyCredential } from "./passkeys-credential";

export const COSEAlgorithmIdentifier = {
  ES256: -7,
  RS256: -257,
  EdDSA: -8,
};

export type SignResponse = {
  readonly publicKeyCredentialDescriptor: PublicKeyCredentialDescriptor;
  readonly authenticatorData: AuthenticatorData;
  readonly signature: Uint8Array;
  readonly userHandle?: Uint8Array;
};

export type AuthenticatorParameters = {
  readonly aaguid: Uint8Array;
  readonly transports: AuthenticatorTransport[];
  readonly algorithmIdentifiers: readonly (keyof typeof COSEAlgorithmIdentifier)[];
  readonly signCounterIncrement: number;
  readonly verifications: { readonly userPresent: boolean; readonly userVerified: boolean };
  readonly credentialSelector: (
    rpId: RpId,
    credentialDescriptors: PublicKeyCredentialDescriptor[],
  ) => PublicKeyCredentialDescriptor | undefined;
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
  private static readonly DEFAULT_CREDENTIAL_SELECTOR = (
    _: RpId,
    credentialDescriptors: PublicKeyCredentialDescriptor[],
  ) => {
    if (credentialDescriptors.length === 0) return undefined;
    return credentialDescriptors[0];
  };

  public credentials: PasskeyCredential[] = [];
  public params: AuthenticatorParameters;

  constructor(params: Partial<AuthenticatorParameters> = {}) {
    this.params = {
      aaguid: params.aaguid ?? AuthenticatorEmulator.DEFAULT_AAGUID,
      transports: params.transports ?? AuthenticatorEmulator.DEFAULT_TRANSPORTS,
      algorithmIdentifiers: params.algorithmIdentifiers ?? AuthenticatorEmulator.DEFAULT_ALGORITHM_IDENTIFIERS,
      signCounterIncrement: params.signCounterIncrement ?? AuthenticatorEmulator.DEFAULT_SIGN_COUNTER_INCREMENT,
      verifications: params.verifications ?? AuthenticatorEmulator.DEFAULT_VERIFICATIONS,
      credentialSelector: params.credentialSelector ?? AuthenticatorEmulator.DEFAULT_CREDENTIAL_SELECTOR,
    };
  }

  /**
   * Generate a passkey's credential
   * @param rpId RP ID
   * @param keyParams Key parameters
   * @param userHandle User handle
   * @returns PasskeyCredential
   */
  public generateCredential(
    rpId: RpId,
    keyParams: PublicKeyCredentialParameters[],
    excludeCredentials: PublicKeyCredentialDescriptor[],
    userHandle: Uint8Array | undefined,
  ): PasskeyCredential {
    if (excludeCredentials.length > 0) {
      const existingCredentials = this.getCredential(rpId, excludeCredentials);
      if (existingCredentials) throw new Error("Credential already exists");
    }

    const allowAlgSet = new Set(keyParams.map((param) => param.alg));
    const alg = this.params.algorithmIdentifiers.find((alg) => allowAlgSet.has(COSEAlgorithmIdentifier[alg]));
    if (!alg) throw new Error("Invalid algorithm");
    const credential = generateCredential(this.params.aaguid, rpId, userHandle, alg, this.params.transports);
    this.credentials.push(credential);
    return credential;
  }

  /**
   * Get a passkey's credential
   * @param rpId RP ID
   * @param credentialsFilter Allow credentials
   * @returns PasskeyCredential
   */
  public getCredential(rpId: RpId, credentialsFilter: PublicKeyCredentialDescriptor[]): PasskeyCredential | undefined {
    const allowIds = new Set(credentialsFilter.map((descriptor) => EncodeUtils.bufferSourceToBase64Url(descriptor.id)));

    const credentials = this.credentials.filter((credential) => {
      if (rpId.value !== credential.publicKeyCredentialSource.rpId.value) return false;
      if (credentialsFilter.length > 0) {
        const rawId = credential.publicKeyCredentialDescriptor.id;
        if (!allowIds?.has(EncodeUtils.bufferSourceToBase64Url(rawId))) return false;
      }
      return true;
    });

    const credentialDescriptors = credentials.map((credential) => credential.publicKeyCredentialDescriptor);
    const selectedDescriptor = this.params.credentialSelector(rpId, credentialDescriptors);
    if (!selectedDescriptor) return undefined;
    const selectedCredential = credentials.find(
      (credential) =>
        EncodeUtils.bufferSourceToBase64Url(credential.publicKeyCredentialDescriptor.id) ===
        EncodeUtils.bufferSourceToBase64Url(selectedDescriptor.id),
    );
    return selectedCredential;
  }

  /**
   * Get a signature for the passkey authentication
   * @param rpId RP ID
   * @param clientData Client data
   * @param allowCredentials Allowed credentials
   * @returns Signature
   */
  public sign(
    rpId: RpId,
    clientData: CollectedClientData,
    allowCredentials: PublicKeyCredentialDescriptor[],
  ): SignResponse {
    const credential = this.getCredential(rpId, allowCredentials);
    if (!credential) throw new Error("No credentials found");

    const clientDataHash = createHash("sha256").update(JSON.stringify(clientData)).digest();
    const payload = new Array<number>();

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
      signCount: credential.authenticatorData.signCount + this.params.signCounterIncrement,
    };
    payload.push(...packAuthenticatorData(authenticatorData));
    payload.push(...clientDataHash);
    const privateKey = createPrivateKey({
      format: "der",
      type: "pkcs8",
      key: credential.publicKeyCredentialSource.privateKey as Buffer,
    });
    credential.authenticatorData.signCount++;
    const signature = createSign("sha256").update(new Uint8Array(payload)).sign(privateKey);
    return {
      publicKeyCredentialDescriptor: credential.publicKeyCredentialDescriptor,
      authenticatorData,
      signature,
      userHandle: credential.publicKeyCredentialSource.userHandle,
    };
  }
}

function generateCredential(
  aaguid: Uint8Array,
  rpId: RpId,
  userHandle: Uint8Array | undefined,
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

  return {
    publicKeyCredentialDescriptor,
    publicKeyCredentialSource,
    authenticatorData,
  };
}
