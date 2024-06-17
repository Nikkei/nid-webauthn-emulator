import { parse } from "tldts";

import crypto, { type KeyObject, type KeyPairKeyObjectResult } from "node:crypto";
import cbor from "cbor";
import EncodeUtils from "./libs/encode-utils";
import type { AuthenticationPublicKeyCredential, RegistrationPublicKeyCredential } from "./libs/json";

const FIDO2_ES256_IDENTIFIER = -7;

export const AAGUID = new Uint8Array([
  0x8e, 0xdf, 0xb6, 0xbb, 0x40, 0x13, 0xc4, 0xa4, 0x6c, 0x96, 0xb9, 0x63, 0x40, 0x13, 0x81, 0x3f,
]);

/** @see https://www.w3.org/TR/webauthn-3/#public-key-credential-source */
class PublicKeyCredentialSource {
  public type = "public-key";
  public counter = 0;

  private constructor(
    public readonly id: ArrayBuffer,
    public readonly rpId: string,
    private keyPair: KeyPairKeyObjectResult,
    public readonly userHandle?: ArrayBuffer,
  ) {}

  public static async create(rpId: string, userHandle?: ArrayBuffer): Promise<PublicKeyCredentialSource> {
    const keyPair = PublicKeyCredentialSource.generateECDSAKeyPair();
    const id = PublicKeyCredentialSource.generateSecureRandomKey();
    return new PublicKeyCredentialSource(id, rpId, keyPair, userHandle);
  }

  public get publicKey(): KeyObject {
    return this.keyPair.publicKey;
  }

  public get ___privateKey(): KeyObject {
    return this.keyPair.privateKey;
  }

  private static generateECDSAKeyPair(): KeyPairKeyObjectResult {
    return crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  }

  private static generateSecureRandomKey(size = 32): Uint8Array {
    const randomKey = new Uint8Array(size);
    crypto.getRandomValues(randomKey);
    return randomKey;
  }
}

export class PasskeysTestAuthenticator {
  private publicKeyCredentialSources: PublicKeyCredentialSource[] = [];

  constructor(private origin: string) {}

  /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
  public async get(options: CredentialRequestOptions): Promise<AuthenticationPublicKeyCredential> {
    if (!options.publicKey) {
      throw new Error("PublicKeyCredentialCreationOptions are required");
    }
    const { rpId, challenge } = options.publicKey;

    if (!rpId || !PasskeysTestAuthenticator.isValidRpId(rpId, this.origin)) {
      throw new Error("Invalid rpId");
    }

    if (this.publicKeyCredentialSources.length === 0) {
      throw new Error("No credentials available");
    }

    // allowCCredentials is not implemented
    const credential = this.publicKeyCredentialSources[0];

    const authenticatorData = await PasskeysTestAuthenticator.generateAuthData({
      rpId,
      credentialId: credential.id,
      backupEligibility: true,
      backupState: false,
      userPresence: true,
      userVerification: true,
      counter: credential.counter,
      publicKey: credential.publicKey,
    });

    const clientData = {
      type: "webauthn.get",
      challenge: EncodeUtils.encodeBase64Url(challenge as ArrayBuffer),
      origin: this.origin,
      crossOrigin: false,
    };

    const clientDataJSON = EncodeUtils.fromByteStringToArray(JSON.stringify(clientData));
    const clientDataHash = await crypto.subtle.digest({ name: "SHA-256" }, clientDataJSON);

    const signature = await PasskeysTestAuthenticator.generateSignature({
      authData: authenticatorData,
      clientDataHash: clientDataHash,
      privateKey: credential.___privateKey,
    });

    const response: AuthenticatorAssertionResponse = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle: credential.userHandle ?? null,
    };

    const publicKeyCredential: AuthenticationPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(credential.id),
      type: "public-key",
      rawId: credential.id,
      response,
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };

    return publicKeyCredential;
  }

  /** @see https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create */
  public async create(options: CredentialCreationOptions): Promise<RegistrationPublicKeyCredential> {
    if (!options.publicKey) {
      throw new Error("PublicKeyCredentialCreationOptions are required");
    }

    const { rp, challenge, pubKeyCredParams } = options.publicKey;

    if (pubKeyCredParams.every((param) => param.alg !== FIDO2_ES256_IDENTIFIER)) {
      throw new Error("Only ES256 algorithm is supported");
    }

    if (!rp.id || !PasskeysTestAuthenticator.isValidRpId(rp.id, this.origin)) {
      throw new Error("Invalid rpId");
    }

    const credential = await PublicKeyCredentialSource.create(rp.id);
    this.publicKeyCredentialSources.push(credential);

    const authData = await PasskeysTestAuthenticator.generateAuthData({
      rpId: rp.id,
      credentialId: credential.id,
      backupEligibility: true,
      backupState: false,
      userPresence: true,
      userVerification: true,
      counter: credential.counter,
      publicKey: credential.publicKey,
    });

    const attestationObject = {
      fmt: "none",
      attStmt: {},
      authData: authData,
    };

    const clientData = {
      challenge: EncodeUtils.encodeBase64Url(challenge as ArrayBuffer),
      origin: this.origin,
      type: "webauthn.create",
      crossOrigin: false,
    };

    const pubKeyDer = credential.publicKey.export({ type: "spki", format: "der" });
    const response: AuthenticatorAttestationResponse = {
      attestationObject: new Uint8Array(cbor.encode(attestationObject)).buffer,
      clientDataJSON: EncodeUtils.toArrayBuffer(JSON.stringify(clientData)),

      getAuthenticatorData: () => authData,
      getPublicKey: () => pubKeyDer,
      getPublicKeyAlgorithm: () => FIDO2_ES256_IDENTIFIER,
      getTransports: () => ["usb"],
    };

    const publicKeyCredential: RegistrationPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(credential.id),
      type: "public-key",
      rawId: credential.id,
      response,
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };

    return publicKeyCredential;
  }

  /** @see https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data */
  private static async generateAuthData(params: {
    rpId: string;
    credentialId: ArrayBuffer;
    backupEligibility: boolean;
    backupState: boolean;
    userPresence: boolean;
    userVerification: boolean;
    counter: number;
    publicKey?: KeyObject;
  }): Promise<Buffer> {
    const authData: Array<number> = [];

    const rpIdHash = new Uint8Array(
      await crypto.subtle.digest({ name: "SHA-256" }, EncodeUtils.fromByteStringToArray(params.rpId)),
    );
    authData.push(...rpIdHash);

    const flags =
      (params.userPresence ? 0b00000001 : 0) |
      (params.userVerification ? 0b00000100 : 0) |
      (params.backupEligibility ? 0b00001000 : 0) |
      (params.backupState ? 0b00010000 : 0) |
      (params.publicKey !== undefined ? 0b01000000 : 0);
    authData.push(flags);

    const counter = params.counter;
    authData.push(
      ((counter & 0xff000000) >> 24) & 0xff,
      ((counter & 0x00ff0000) >> 16) & 0xff,
      ((counter & 0x0000ff00) >> 8) & 0xff,
      counter & 0x000000ff,
    );

    if (params.publicKey) {
      const rawId = new Uint8Array(params.credentialId);
      const credentialIdLength = [(rawId.length - (rawId.length & 0xff)) / 256, rawId.length & 0xff];
      const coseBytes = await PasskeysTestAuthenticator.toCoseBytes(params.publicKey);
      authData.push(...[...AAGUID, ...credentialIdLength, ...rawId, ...coseBytes]);
    }

    return Buffer.from(authData);
  }

  /** @see https://www.w3.org/TR/webauthn-3/#sctn-validating-origin */
  private static isValidRpId(rpId: string, origin: string) {
    const parsedOrigin = parse(origin, { allowPrivateDomains: true });
    const parsedRpId = parse(rpId, { allowPrivateDomains: true });

    return (
      (parsedOrigin.domain == null &&
        parsedOrigin.hostname === parsedRpId.hostname &&
        parsedOrigin.hostname === "localhost") ||
      (parsedOrigin.domain != null &&
        parsedOrigin.subdomain !== null &&
        parsedRpId.subdomain != null &&
        parsedOrigin.domain === parsedRpId.domain &&
        parsedOrigin.subdomain.endsWith(parsedRpId.subdomain))
    );
  }

  /** @see https://github.com/bitwarden/clients/blob/main/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts */
  private static async toCoseBytes(publicKey: KeyObject): Promise<Uint8Array> {
    const publicKeyJwk = publicKey.export({ format: "jwk" });
    if (!publicKeyJwk.x || !publicKeyJwk.y) throw new Error("Public key is not ECDSA key");
    const keyX = EncodeUtils.decodeBase64Url(publicKeyJwk.x);
    const keyY = EncodeUtils.decodeBase64Url(publicKeyJwk.y);

    const coseBytes = new Uint8Array(77);
    coseBytes.set([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20], 0);
    coseBytes.set(new Uint8Array(keyX), 10);
    coseBytes.set([0x22, 0x58, 0x20], 10 + 32);
    coseBytes.set(new Uint8Array(keyY), 10 + 32 + 3);
    return coseBytes;
  }

  /** @see https://github.com/bitwarden/clients/blob/main/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts */
  private static async generateSignature(params: {
    authData: Uint8Array;
    clientDataHash: ArrayBuffer;
    privateKey: KeyObject;
  }): Promise<ArrayBuffer> {
    const payload = new Uint8Array([...params.authData, ...new Uint8Array(params.clientDataHash)]);
    const signature = crypto.createSign("sha256").update(payload).sign(params.privateKey);
    return signature;
  }
}
