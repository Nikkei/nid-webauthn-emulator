import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import { decodeCbor, decodeCborWithRemainder } from "../libs/cbor";

export type WebAuthnVerificationAlgorithm = -7 | -8 | -257;

export type WebAuthnVerificationErrorCode =
  | "INVALID_OPTIONS"
  | "INVALID_RESPONSE"
  | "INVALID_PUBLIC_KEY"
  | "CHALLENGE_MISMATCH"
  | "ORIGIN_MISMATCH"
  | "RP_ID_MISMATCH"
  | "CREDENTIAL_ID_MISMATCH"
  | "USER_PRESENCE_REQUIRED"
  | "USER_VERIFICATION_REQUIRED"
  | "UNSUPPORTED_CROSS_ORIGIN"
  | "UNSUPPORTED_ATTESTATION"
  | "UNSUPPORTED_ALGORITHM"
  | "ALGORITHM_NOT_ALLOWED"
  | "INVALID_BACKUP_FLAGS"
  | "BACKUP_ELIGIBILITY_MISMATCH"
  | "COUNTER_NOT_INCREASED"
  | "INVALID_SIGNATURE";

/** Stable error codes for verification failures; messages are diagnostic only. */
export class WebAuthnVerificationError extends Error {
  constructor(
    public readonly code: WebAuthnVerificationErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "WebAuthnVerificationError";
  }
}

export interface WebAuthnVerificationExpectations {
  /** The exact, unpadded Base64URL challenge issued for this ceremony. */
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID: string;
  /** Defaults to true. User presence is always required. */
  requireUserVerification?: boolean;
}

export interface VerifyRegistrationOptions extends WebAuthnVerificationExpectations {
  response: RegistrationResponseJSON;
  /** Algorithms offered in pubKeyCredParams. Defaults to ES256, Ed25519 and RS256. */
  supportedAlgorithmIDs?: readonly number[];
}

/** JSON-serializable RP credential record. Account ownership is managed by the caller. */
export interface VerifiedCredential {
  id: string;
  /** Unpadded Base64URL-encoded COSE public key, not a Node.js KeyObject. */
  publicKey: string;
  algorithm: WebAuthnVerificationAlgorithm;
  counter: number;
  backupEligible: boolean;
  backupState: boolean;
}

export interface VerifyAuthenticationOptions extends WebAuthnVerificationExpectations {
  response: AuthenticationResponseJSON;
  credential: Readonly<VerifiedCredential>;
}

export interface WebAuthnVerificationFlags {
  userPresent: boolean;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
}

export interface RegistrationVerificationResult extends WebAuthnVerificationFlags {
  credential: VerifiedCredential;
}

export interface AuthenticationVerificationResult extends WebAuthnVerificationFlags {
  newCounter: number;
}

function check(condition: unknown, code: WebAuthnVerificationErrorCode, message: string): asserts condition {
  if (!condition) throw new WebAuthnVerificationError(code, message);
}

function checked<T>(code: WebAuthnVerificationErrorCode, message: string, operation: () => T): T {
  try {
    return operation();
  } catch (cause) {
    if (cause instanceof WebAuthnVerificationError) throw cause;
    throw new WebAuthnVerificationError(code, message, { cause });
  }
}

function base64url(value: string, code: WebAuthnVerificationErrorCode = "INVALID_RESPONSE"): Buffer<ArrayBuffer> {
  check(typeof value === "string", code, "Expected base64url string");
  const bytes = Buffer.from(value, "base64url");
  check(bytes.length > 0 && bytes.toString("base64url") === value, code, "Invalid base64url");
  return bytes;
}

function record(value: unknown, code: WebAuthnVerificationErrorCode = "INVALID_RESPONSE"): Record<string, unknown> {
  check(
    value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof Uint8Array),
    code,
    "Expected a map",
  );
  return value as Record<string, unknown>;
}

function bytes(value: unknown, code: WebAuthnVerificationErrorCode = "INVALID_RESPONSE"): Buffer<ArrayBuffer> {
  check(value instanceof Uint8Array && value.length > 0, code, "Expected non-empty bytes");
  return Buffer.from(value);
}

function sha256(value: string | Uint8Array): Buffer<ArrayBuffer> {
  return createHash("sha256").update(value).digest();
}

function validateExpectations(options: WebAuthnVerificationExpectations): void {
  check(options !== null && typeof options === "object", "INVALID_OPTIONS", "Verification options are required");
  base64url(options.expectedChallenge, "INVALID_OPTIONS");
  check(
    typeof options.expectedOrigin === "string" && options.expectedOrigin.length > 0,
    "INVALID_OPTIONS",
    "Expected origin is required",
  );
  check(
    typeof options.expectedRPID === "string" && options.expectedRPID.length > 0,
    "INVALID_OPTIONS",
    "Expected RP ID is required",
  );
  check(
    options.requireUserVerification === undefined || typeof options.requireUserVerification === "boolean",
    "INVALID_OPTIONS",
    "requireUserVerification must be a boolean",
  );
}

function verifyClientData(
  response: RegistrationResponseJSON | AuthenticationResponseJSON,
  type: "webauthn.create" | "webauthn.get",
  expected: WebAuthnVerificationExpectations,
): Buffer<ArrayBuffer> {
  check(response.type === "public-key", "INVALID_RESPONSE", "Unexpected credential type");
  check(base64url(response.id).equals(base64url(response.rawId)), "CREDENTIAL_ID_MISMATCH", "Credential ID mismatch");
  const raw = base64url(response.response.clientDataJSON);
  const data = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)));
  check(data.type === type, "INVALID_RESPONSE", "Unexpected client data type");
  check(data.challenge === expected.expectedChallenge, "CHALLENGE_MISMATCH", "Unexpected challenge");
  check(data.origin === expected.expectedOrigin, "ORIGIN_MISMATCH", "Unexpected origin");
  check(
    (data.crossOrigin === undefined || data.crossOrigin === false) && !Object.hasOwn(data, "topOrigin"),
    "UNSUPPORTED_CROSS_ORIGIN",
    "Cross-origin ceremonies are unsupported",
  );
  return sha256(raw);
}

// Interpret protocol fields independently of the emulator's unpack/COSE helpers.
function readAuthenticatorData(raw: Buffer<ArrayBuffer>, expected: WebAuthnVerificationExpectations) {
  check(raw.length >= 37, "INVALID_RESPONSE", "Truncated authenticator data");
  check(raw.subarray(0, 32).equals(sha256(expected.expectedRPID)), "RP_ID_MISMATCH", "RP ID hash mismatch");
  const flags = raw[32];
  const result: WebAuthnVerificationFlags = {
    userPresent: Boolean(flags & 0x01),
    userVerified: Boolean(flags & 0x04),
    backupEligible: Boolean(flags & 0x08),
    backupState: Boolean(flags & 0x10),
  };
  check(result.userPresent, "USER_PRESENCE_REQUIRED", "User presence required");
  check(
    expected.requireUserVerification === false || result.userVerified,
    "USER_VERIFICATION_REQUIRED",
    "User verification required",
  );
  check(!result.backupState || result.backupEligible, "INVALID_BACKUP_FLAGS", "Invalid backup flags");
  return { ...result, flags, counter: raw.readUInt32BE(33) };
}

function verifyExtensions(remainder: Uint8Array<ArrayBuffer>, flags: number): void {
  if (flags & 0x80) {
    record(decodeCbor(remainder));
  } else {
    check(remainder.length === 0, "INVALID_RESPONSE", "Unexpected authenticator data suffix");
  }
}

function readPublicKey(value: unknown): { algorithm: WebAuthnVerificationAlgorithm; publicKey: KeyObject } {
  return checked("INVALID_PUBLIC_KEY", "Invalid credential public key", () => {
    const key = record(value, "INVALID_PUBLIC_KEY");
    const algorithm = key[3];
    switch (algorithm) {
      case -7: {
        check(key[1] === 2, "INVALID_PUBLIC_KEY", "ES256 requires an EC2 key");
        check(key[-1] === 1, "INVALID_PUBLIC_KEY", "ES256 requires P-256");
        const x = bytes(key[-2], "INVALID_PUBLIC_KEY");
        const y = bytes(key[-3], "INVALID_PUBLIC_KEY");
        check(x.length === 32 && y.length === 32, "INVALID_PUBLIC_KEY", "Invalid P-256 coordinate");
        return {
          algorithm,
          publicKey: createPublicKey({
            format: "jwk",
            key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") },
          }),
        };
      }
      case -8: {
        check(key[1] === 1, "INVALID_PUBLIC_KEY", "EdDSA requires an OKP key");
        check(key[-1] === 6, "INVALID_PUBLIC_KEY", "EdDSA requires Ed25519");
        const x = bytes(key[-2], "INVALID_PUBLIC_KEY");
        check(x.length === 32, "INVALID_PUBLIC_KEY", "Invalid Ed25519 key");
        return {
          algorithm,
          publicKey: createPublicKey({
            format: "jwk",
            key: { kty: "OKP", crv: "Ed25519", x: x.toString("base64url") },
          }),
        };
      }
      case -257: {
        check(key[1] === 3, "INVALID_PUBLIC_KEY", "RS256 requires an RSA key");
        const n = bytes(key[-1], "INVALID_PUBLIC_KEY");
        const e = bytes(key[-2], "INVALID_PUBLIC_KEY");
        check(
          n[0] !== 0 && e[0] !== 0,
          "INVALID_PUBLIC_KEY",
          "RSA parameters must be positive without leading zero octets",
        );
        const modulus = BigInt(`0x${n.toString("hex")}`);
        const exponent = BigInt(`0x${e.toString("hex")}`);
        // RFC 8812 requires at least 2048 bits; RFC 8017 defines the public exponent's range.
        check(
          modulus >= 1n << 2047n && modulus % 2n === 1n,
          "INVALID_PUBLIC_KEY",
          "RS256 requires an odd modulus of at least 2048 bits",
        );
        check(
          exponent >= 3n && exponent < modulus && exponent % 2n === 1n,
          "INVALID_PUBLIC_KEY",
          "Invalid RSA public exponent",
        );
        return {
          algorithm,
          publicKey: createPublicKey({
            format: "jwk",
            key: {
              kty: "RSA",
              n: n.toString("base64url"),
              e: e.toString("base64url"),
            },
          }),
        };
      }
      default:
        throw new WebAuthnVerificationError("UNSUPPORTED_ALGORITHM", "Unsupported credential algorithm");
    }
  });
}

/**
 * Verify a none-attestation registration against the expected ceremony values.
 * Returns a serializable credential and the verified authenticator flags.
 * Synchronous; throws WebAuthnVerificationError. The caller manages credential storage and challenge lifetime and consumption.
 * @see https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
 */
export function verifyRegistration(options: VerifyRegistrationOptions): RegistrationVerificationResult {
  validateExpectations(options);
  const allowedAlgorithms = options.supportedAlgorithmIDs ?? [-7, -8, -257];
  check(
    Array.isArray(allowedAlgorithms) && allowedAlgorithms.length > 0 && allowedAlgorithms.every(Number.isSafeInteger),
    "INVALID_OPTIONS",
    "supportedAlgorithmIDs must be a non-empty array of algorithm IDs",
  );
  return checked("INVALID_RESPONSE", "Malformed registration response", () => {
    const { response } = options;
    verifyClientData(response, "webauthn.create", options);
    const attestation = record(decodeCbor(base64url(response.response.attestationObject)));
    check(attestation.fmt === "none", "UNSUPPORTED_ATTESTATION", "Only none attestation is supported");
    check(
      Object.keys(record(attestation.attStmt)).length === 0,
      "INVALID_RESPONSE",
      "none attestation must have an empty statement",
    );
    const raw = bytes(attestation.authData);
    const { flags, counter, ...verificationFlags } = readAuthenticatorData(raw, options);
    check(flags & 0x40, "INVALID_RESPONSE", "Attested credential data required");
    check(raw.length >= 55, "INVALID_RESPONSE", "Truncated attested credential data");
    const idLength = raw.readUInt16BE(53);
    check(idLength <= 1023, "INVALID_RESPONSE", "Credential ID must not exceed 1023 bytes");
    check(idLength > 0 && raw.length > 55 + idLength, "INVALID_RESPONSE", "Truncated credential ID or public key");
    check(
      raw.subarray(55, 55 + idLength).equals(base64url(response.id)),
      "CREDENTIAL_ID_MISMATCH",
      "Attested credential ID mismatch",
    );
    const { value, remainder } = decodeCborWithRemainder(raw.subarray(55 + idLength));
    const { algorithm } = readPublicKey(value);
    check(allowedAlgorithms.includes(algorithm), "ALGORITHM_NOT_ALLOWED", "Credential algorithm was not offered");
    verifyExtensions(remainder, flags);
    return {
      ...verificationFlags,
      credential: {
        id: response.id,
        publicKey: raw.subarray(55 + idLength, raw.length - remainder.length).toString("base64url"),
        algorithm,
        counter,
        backupEligible: verificationFlags.backupEligible,
        backupState: verificationFlags.backupState,
      },
    };
  });
}

/**
 * Verify an authentication response's signature using the saved credential.
 * Returns the new counter and verified authenticator flags without mutating the credential.
 * Synchronous; throws WebAuthnVerificationError. The caller handles account/userHandle binding,
 * challenge lifetime and consumption, and persistence of newCounter and backupState.
 * @see https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
 */
export function verifyAuthentication(options: VerifyAuthenticationOptions): AuthenticationVerificationResult {
  validateExpectations(options);
  return checked("INVALID_RESPONSE", "Malformed authentication response", () => {
    const { response, credential } = options;
    check(credential !== null && typeof credential === "object", "INVALID_OPTIONS", "A saved credential is required");
    check(
      Number.isInteger(credential.counter) && credential.counter >= 0 && credential.counter <= 0xffffffff,
      "INVALID_OPTIONS",
      "Credential counter must be an unsigned 32-bit integer",
    );
    check(
      typeof credential.backupEligible === "boolean" &&
        typeof credential.backupState === "boolean" &&
        (!credential.backupState || credential.backupEligible),
      "INVALID_OPTIONS",
      "Invalid saved backup state",
    );
    const key = checked("INVALID_PUBLIC_KEY", "Invalid saved public key", () =>
      readPublicKey(decodeCbor(base64url(credential.publicKey, "INVALID_PUBLIC_KEY"))),
    );
    check(
      credential.algorithm === key.algorithm,
      "INVALID_PUBLIC_KEY",
      "Saved algorithm does not match the public key",
    );
    const clientDataHash = verifyClientData(response, "webauthn.get", options);
    check(response.id === credential.id, "CREDENTIAL_ID_MISMATCH", "Credential ID mismatch");
    const raw = base64url(response.response.authenticatorData);
    const { flags, counter, ...verificationFlags } = readAuthenticatorData(raw, options);
    check(!(flags & 0x40), "INVALID_RESPONSE", "Unexpected attested credential data");
    check(
      verificationFlags.backupEligible === credential.backupEligible,
      "BACKUP_ELIGIBILITY_MISMATCH",
      "Backup eligibility changed",
    );
    verifyExtensions(raw.subarray(37), flags);
    check(
      (counter === 0 && credential.counter === 0) || counter > credential.counter,
      "COUNTER_NOT_INCREASED",
      "Signature counter did not increase",
    );
    // Verify the original bytes, including extension data; ES256 signatures use DER.
    const signature = base64url(response.response.signature);
    const valid = checked("INVALID_SIGNATURE", "Invalid authentication signature", () =>
      verify(key.algorithm === -8 ? null : "sha256", Buffer.concat([raw, clientDataHash]), key.publicKey, signature),
    );
    check(valid, "INVALID_SIGNATURE", "Invalid authentication signature");
    return { newCounter: counter, ...verificationFlags };
  });
}
