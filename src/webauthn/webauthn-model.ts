import { createHash } from "node:crypto";
import { parse } from "tldts";
import EncodeUtils from "../libs/encode-utils";
import { CoseKey } from "./cose-key";

export class RpId {
  constructor(public readonly value: string) {}

  public get hash(): Uint8Array {
    return new Uint8Array(createHash("sha256").update(this.value).digest());
  }

  /** @see https://www.w3.org/TR/webauthn-3/#sctn-validating-origin */
  public validate(origin: string): boolean {
    const parsedOrigin = parse(origin);
    const parsedRpId = parse(this.value);

    return Boolean(
      parsedOrigin.domain &&
        parsedOrigin.subdomain !== null &&
        parsedRpId.subdomain !== null &&
        parsedOrigin.domain === parsedRpId.domain &&
        parsedOrigin.subdomain.endsWith(parsedRpId.subdomain),
    );
  }
}

/** @see https://www.w3.org/TR/webauthn-3/#public-key-credential-source */
export type PublicKeyCredentialSource = {
  type: "public-key";
  id: Uint8Array;
  privateKey: Uint8Array;
  rpId: RpId;
  userHandle?: Uint8Array;
};

/** @see https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data */
export type AttestedCredentialData = {
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  credentialPublicKey: CoseKey;
};

/** @see https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data */
export type AuthenticatorData = {
  rpIdHash: Uint8Array;
  flags: {
    userPresent?: boolean;
    userVerified?: boolean;
    backupEligibility?: boolean;
    backupState?: boolean;
    attestedCredentialData?: boolean;
    extensionData?: boolean;
  };
  signCount: number;
  attestedCredentialData?: AttestedCredentialData;
  extensions?: object;
};

/** @see https://www.w3.org/TR/webauthn-3/#attestation-object */
export type AttestationObject = {
  fmt: string;
  attStmt: object;
  authData: AuthenticatorData;
};

/** @see https://www.w3.org/TR/webauthn-3/#dictionary-client-data */
export type CollectedClientData = {
  type: "webauthn.get" | "webauthn.create";
  challenge: string;
  origin: string;
  crossOrigin: boolean;
};

export function packAttestationObject(attestationObject: AttestationObject): Uint8Array {
  const data = new Map<string, unknown>();
  data.set("fmt", attestationObject.fmt);
  data.set("attStmt", attestationObject.attStmt);
  data.set("authData", packAuthenticatorData(attestationObject.authData));
  return EncodeUtils.encodeCbor(data);
}

export function packAuthenticatorData(authData: AuthenticatorData): Uint8Array {
  const ret: Array<number> = [];
  const cred = authData.attestedCredentialData;
  ret.push(...authData.rpIdHash);
  ret.push(packAuthenticatorDataFlags({ ...authData.flags, attestedCredentialData: Boolean(cred) }));
  ret.push(...packSignCount(authData.signCount));
  if (cred) ret.push(...packAttestedCredentialData(cred));
  return new Uint8Array(ret);
}

function packSignCount(signCount: number): Uint8Array {
  const ret = new ArrayBuffer(4);
  const view = new DataView(ret);
  view.setUint32(0, signCount, false);
  return new Uint8Array(ret);
}

function packAttestedCredentialData(attestedCredentialData: AttestedCredentialData): Uint8Array {
  const ret: Array<number> = [];
  const rawId = attestedCredentialData.credentialId;
  const credentialIdLength = [rawId.length >> 8, rawId.length & 0xff];

  ret.push(...attestedCredentialData.aaguid);
  ret.push(...credentialIdLength);
  ret.push(...rawId);
  ret.push(...attestedCredentialData.credentialPublicKey.toBytes());
  return new Uint8Array(ret);
}

function packAuthenticatorDataFlags(flags: AuthenticatorData["flags"]): number {
  return (
    (flags.userPresent ? 1 << 0 : 0) |
    (flags.userVerified ? 1 << 2 : 0) |
    (flags.backupEligibility ? 1 << 3 : 0) |
    (flags.backupState ? 1 << 4 : 0) |
    (flags.attestedCredentialData ? 1 << 6 : 0) |
    (flags.extensionData ? 1 << 7 : 0)
  );
}

export function unpackAttestationObject(attestationObject: Uint8Array): AttestationObject {
  const { fmt, attStmt, authData } = EncodeUtils.decodeCbor<{ fmt: string; attStmt: object; authData: Uint8Array }>(
    attestationObject,
  );
  return {
    fmt,
    attStmt,
    authData: unpackAuthenticatorData(authData),
  };
}

export function unpackAuthenticatorData(authData: Uint8Array): AuthenticatorData {
  const rpIdHash = authData.slice(0, 32);
  const flags = unpackAuthenticatorDataFlags(authData[32]);
  const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];
  const attestedCredentialData = flags.attestedCredentialData
    ? unpackAttestedCredentialData(authData.slice(37))
    : undefined;
  return { rpIdHash, flags, signCount, attestedCredentialData };
}

function unpackAttestedCredentialData(data: Uint8Array): AttestedCredentialData {
  const aaguid = data.slice(0, 16);
  const credentialIdLength = (data[16] << 8) | data[17];
  const credentialId = data.slice(18, 18 + credentialIdLength);
  const publicKey = CoseKey.fromBytes(data.slice(18 + credentialIdLength));
  return { aaguid, credentialId, credentialPublicKey: publicKey };
}

function unpackAuthenticatorDataFlags(flags: number): AuthenticatorData["flags"] {
  return {
    userPresent: Boolean(flags & (1 << 0)),
    userVerified: Boolean(flags & (1 << 2)),
    backupEligibility: Boolean(flags & (1 << 3)),
    backupState: Boolean(flags & (1 << 4)),
    attestedCredentialData: Boolean(flags & (1 << 6)),
    extensionData: Boolean(flags & (1 << 7)),
  };
}

export type PublicKeyCredentialSourceJSON = {
  type: "public-key";
  id: string;
  privateKey: string;
  rpId: string;
  userHandle?: string;
};

export function toPublickeyCredentialSourceJSON(
  credentialSource: PublicKeyCredentialSource,
): PublicKeyCredentialSourceJSON {
  return {
    type: "public-key",
    id: EncodeUtils.encodeBase64Url(credentialSource.id),
    privateKey: EncodeUtils.encodeBase64Url(credentialSource.privateKey),
    rpId: credentialSource.rpId.value,
    userHandle: credentialSource.userHandle ? EncodeUtils.encodeBase64Url(credentialSource.userHandle) : undefined,
  };
}

export function parsePublicKeyCredentialSourceFromJSON(json: PublicKeyCredentialSourceJSON): PublicKeyCredentialSource {
  return {
    type: "public-key",
    id: EncodeUtils.decodeBase64Url(json.id),
    privateKey: EncodeUtils.decodeBase64Url(json.privateKey),
    rpId: new RpId(json.rpId),
    userHandle: json.userHandle ? EncodeUtils.decodeBase64Url(json.userHandle) : undefined,
  };
}
