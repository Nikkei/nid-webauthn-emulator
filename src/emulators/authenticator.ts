import { createHash, createPrivateKey, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
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

/**
 * Authenticator emulator
 */
export class AuthenticatorEmulator {
  private static readonly DEFAULT_AAGUID = new Uint8Array([
    0x8e, 0xdf, 0xb6, 0xbb, 0x40, 0x13, 0xc4, 0xa4, 0x6c, 0x96, 0xb9, 0x63, 0x40, 0x13, 0x81, 0x3f,
  ]);
  private static readonly DEFAULT_TRANSPORTS: AuthenticatorTransport[] = ["usb"] as const;
  private static readonly DEFAULT_ALGORITHM_IDENTIFIERS = ["ES256", "RS256", "EdDSA"] as const;

  public credentials: PasskeyCredential[] = [];

  constructor(
    private aaguid = AuthenticatorEmulator.DEFAULT_AAGUID,
    private transports = AuthenticatorEmulator.DEFAULT_TRANSPORTS,
    private algorithmIdentifiers = AuthenticatorEmulator.DEFAULT_ALGORITHM_IDENTIFIERS,
  ) {}

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
    userHandle: Uint8Array | undefined,
  ): PasskeyCredential {
    const allowAlgSet = new Set(keyParams.map((param) => param.alg));
    const alg = this.algorithmIdentifiers.find((alg) => allowAlgSet.has(COSEAlgorithmIdentifier[alg]));
    if (!alg) throw new Error("Invalid algorithm");
    const credential = generateCredential(this.aaguid, rpId, userHandle, alg, this.transports);
    this.credentials.push(credential);
    return credential;
  }

  /**
   * Get a passkey's credential
   * @param rpId RP ID
   * @returns PasskeyCredential
   */
  public getCredential(rpId: RpId): PasskeyCredential {
    const credential = this.credentials.find((credential) => {
      if (rpId.value !== credential.publicKeyCredentialSource.rpId.value) return false;
      return true;
    });

    if (!credential) throw new Error("No credential found");
    return credential;
  }

  /**
   * Get a signature for the passkey authentication
   * @param rpId RP ID
   * @param clientData Client data
   * @returns Signature
   */
  public sign(rpId: RpId, clientData: CollectedClientData): SignResponse {
    const credential = this.getCredential(rpId);
    const clientDataHash = createHash("sha256").update(JSON.stringify(clientData)).digest();
    const payload = new Array<number>();
    const authenticatorData = {
      ...credential.authenticatorData,
      flags: {
        ...credential.authenticatorData.flags,
        attestedCredentialData: false,
      },
      attestedCredentialData: undefined,
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
