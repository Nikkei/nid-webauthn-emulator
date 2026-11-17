import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, test } from "node:test";
import {
  AuthenticatorEmulator,
  type VerifiedCredential,
  verifyAuthentication,
  verifyRegistration,
  WebAuthnEmulator,
  WebAuthnVerificationError,
  type WebAuthnVerificationErrorCode,
} from "../../src";
import { decodeCbor, decodeCborWithRemainder, encodeCbor } from "../../src/libs/cbor";
import fixtures from "./verification-vectors.json";
import { WebAuthnTestServer } from "./webauthn-test-server";

type Vector = {
  name: string;
  algorithm: VerifiedCredential["algorithm"];
  registration: RegistrationResponseJSON;
  authentication: AuthenticationResponseJSON;
  zeroCounterAuthentication: AuthenticationResponseJSON;
  highCounterAuthentication: AuthenticationResponseJSON;
};

// These are fixed, independently cross-checked bytes, not emulator-generated round trips.
const vectors = fixtures.vectors as Vector[];
const expected = {
  expectedOrigin: fixtures.origin,
  expectedRPID: fixtures.rpID,
  expectedChallenge: fixtures.challenge,
};

function changeClientData(response: RegistrationResponseJSON | AuthenticationResponseJSON, fields: object): void {
  const data = JSON.parse(Buffer.from(response.response.clientDataJSON, "base64url").toString("utf8"));
  response.response.clientDataJSON = Buffer.from(JSON.stringify({ ...data, ...fields })).toString("base64url");
}

type Attestation = { fmt: string; attStmt: object; authData: Uint8Array<ArrayBuffer> };

function changeAttestation(response: RegistrationResponseJSON, change: (attestation: Attestation) => void): void {
  const attestation = decodeCbor<Attestation>(Buffer.from(response.response.attestationObject, "base64url"));
  change(attestation);
  response.response.attestationObject = Buffer.from(encodeCbor(attestation)).toString("base64url");
}

function changeKey(response: RegistrationResponseJSON, fields: Record<number, unknown>): void {
  changeAttestation(response, (attestation) => {
    const raw = Buffer.from(attestation.authData);
    const offset = 55 + raw.readUInt16BE(53);
    const { value, remainder } = decodeCborWithRemainder<Record<number, unknown>>(raw.subarray(offset));
    attestation.authData = Buffer.concat([raw.subarray(0, offset), encodeCbor({ ...value, ...fields }), remainder]);
  });
}

function changeAuthData(response: AuthenticationResponseJSON, change: (data: Buffer) => Uint8Array): void {
  response.response.authenticatorData = Buffer.from(
    change(Buffer.from(response.response.authenticatorData, "base64url")),
  ).toString("base64url");
}

type Mutation<T> = [string, (response: T) => void, WebAuthnVerificationErrorCode];

function failure(code: WebAuthnVerificationErrorCode) {
  return (error: unknown) => error instanceof WebAuthnVerificationError && error.code === code;
}

function commonMutations<T extends RegistrationResponseJSON | AuthenticationResponseJSON>(): Mutation<T>[] {
  return [
    ["challenge", (r) => changeClientData(r, { challenge: "unissued" }), "CHALLENGE_MISMATCH"],
    ["origin", (r) => changeClientData(r, { origin: "https://other.example" }), "ORIGIN_MISMATCH"],
    ["ceremony type", (r) => changeClientData(r, { type: "invalid" }), "INVALID_RESPONSE"],
    ["cross-origin", (r) => changeClientData(r, { crossOrigin: true }), "UNSUPPORTED_CROSS_ORIGIN"],
    [
      "raw ID",
      (r) => {
        r.rawId = "AA";
      },
      "CREDENTIAL_ID_MISMATCH",
    ],
    [
      "invalid base64url",
      (r) => {
        r.response.clientDataJSON += "!";
      },
      "INVALID_RESPONSE",
    ],
    [
      "invalid client JSON",
      (r) => {
        r.response.clientDataJSON = "ew";
      },
      "INVALID_RESPONSE",
    ],
  ];
}

for (const vector of vectors) {
  describe(`WebAuthn verifier independent ${vector.name} vectors`, () => {
    test("verifies registration and a signature over the original client and extension bytes", () => {
      const credential = verifyRegistration({ response: vector.registration, ...expected }).credential;
      assert.equal(credential.algorithm, vector.algorithm);
      assert.equal(credential.counter, 0);
      assert.equal(verifyAuthentication({ response: vector.authentication, credential, ...expected }).newCounter, 1);
    });

    test("accepts authenticators without counters and reads counters as unsigned 32-bit values", () => {
      const credential = verifyRegistration({ response: vector.registration, ...expected }).credential;
      assert.equal(
        verifyAuthentication({ response: vector.zeroCounterAuthentication, credential, ...expected }).newCounter,
        0,
      );
      assert.equal(
        verifyAuthentication({ response: vector.highCounterAuthentication, credential, ...expected }).newCounter,
        0x80000000,
      );
    });

    test("verifies a JSON-restored credential without mutating it", () => {
      const registration = verifyRegistration({ response: vector.registration, ...expected });
      const credential: VerifiedCredential = JSON.parse(JSON.stringify(registration.credential));
      assert.deepEqual(credential, registration.credential);
      Object.freeze(credential);
      const result = verifyAuthentication({ response: vector.authentication, credential, ...expected });
      assert.deepEqual(result, {
        newCounter: 1,
        userPresent: true,
        userVerified: true,
        backupEligible: false,
        backupState: false,
      });
      assert.equal(credential.counter, 0);
    });

    test("enforces the algorithms offered by the caller", () => {
      assert.equal(
        verifyRegistration({
          response: vector.registration,
          ...expected,
          supportedAlgorithmIDs: [vector.algorithm],
        }).credential.algorithm,
        vector.algorithm,
      );
      assert.throws(
        () =>
          verifyRegistration({
            response: vector.registration,
            ...expected,
            supportedAlgorithmIDs: [-7, -8, -257].filter((algorithm) => algorithm !== vector.algorithm),
          }),
        failure("ALGORITHM_NOT_ALLOWED"),
      );
    });

    test("rejects inconsistent or malformed saved keys", () => {
      const credential = verifyRegistration({ response: vector.registration, ...expected }).credential;
      for (const changed of [
        { ...credential, algorithm: vector.algorithm === -7 ? (-8 as const) : (-7 as const) },
        { ...credential, publicKey: "!" },
        { ...credential, publicKey: "AA" },
      ]) {
        assert.throws(
          () => verifyAuthentication({ response: vector.authentication, credential: changed, ...expected }),
          failure("INVALID_PUBLIC_KEY"),
        );
      }
    });

    const registrationMutations: Mutation<RegistrationResponseJSON>[] = [
      ...commonMutations<RegistrationResponseJSON>(),
      [
        "attestation format",
        (r) =>
          changeAttestation(r, (a) => {
            a.fmt = "packed";
          }),
        "UNSUPPORTED_ATTESTATION",
      ],
      [
        "attestation statement",
        (r) =>
          changeAttestation(r, (a) => {
            a.attStmt = { sig: "invalid" };
          }),
        "INVALID_RESPONSE",
      ],
      [
        "RP ID hash",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[0] ^= 1;
          }),
        "RP_ID_MISMATCH",
      ],
      [
        "UP flag",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[32] &= ~0x01;
          }),
        "USER_PRESENCE_REQUIRED",
      ],
      [
        "UV flag",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[32] &= ~0x04;
          }),
        "USER_VERIFICATION_REQUIRED",
      ],
      [
        "backup flags",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[32] |= 0x10;
          }),
        "INVALID_BACKUP_FLAGS",
      ],
      [
        "AT flag",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[32] &= ~0x40;
          }),
        "INVALID_RESPONSE",
      ],
      [
        "truncated header",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData = a.authData.slice(0, 36);
          }),
        "INVALID_RESPONSE",
      ],
      [
        "truncated attested data",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData = a.authData.slice(0, 54);
          }),
        "INVALID_RESPONSE",
      ],
      [
        "credential length",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[53] = 0xff;
          }),
        "INVALID_RESPONSE",
      ],
      [
        "attested ID",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[55] ^= 1;
          }),
        "CREDENTIAL_ID_MISMATCH",
      ],
      ["key type", (r) => changeKey(r, { 1: 99 }), "INVALID_PUBLIC_KEY"],
      ["algorithm", (r) => changeKey(r, { 3: -999 }), "UNSUPPORTED_ALGORITHM"],
      ["key material", (r) => changeKey(r, { [-2]: new Uint8Array() }), "INVALID_PUBLIC_KEY"],
      [
        "ED flag",
        (r) =>
          changeAttestation(r, (a) => {
            a.authData[32] &= ~0x80;
          }),
        "INVALID_RESPONSE",
      ],
    ];
    if (vector.algorithm !== -257) {
      registrationMutations.push(["curve", (r) => changeKey(r, { [-1]: 99 }), "INVALID_PUBLIC_KEY"]);
    }
    for (const [name, change, error] of registrationMutations) {
      test(`rejects registration with altered ${name}`, () => {
        const response = structuredClone(vector.registration);
        change(response);
        assert.throws(() => verifyRegistration({ response: response, ...expected }).credential, failure(error));
      });
    }

    const authenticationMutations: Mutation<AuthenticationResponseJSON>[] = [
      ...commonMutations<AuthenticationResponseJSON>(),
      [
        "RP ID hash",
        (r) =>
          changeAuthData(r, (data) => {
            data[0] ^= 1;
            return data;
          }),
        "RP_ID_MISMATCH",
      ],
      [
        "UP flag",
        (r) =>
          changeAuthData(r, (data) => {
            data[32] &= ~0x01;
            return data;
          }),
        "USER_PRESENCE_REQUIRED",
      ],
      [
        "UV flag",
        (r) =>
          changeAuthData(r, (data) => {
            data[32] &= ~0x04;
            return data;
          }),
        "USER_VERIFICATION_REQUIRED",
      ],
      [
        "backup eligibility",
        (r) =>
          changeAuthData(r, (data) => {
            data[32] |= 0x08;
            return data;
          }),
        "BACKUP_ELIGIBILITY_MISMATCH",
      ],
      [
        "AT flag",
        (r) =>
          changeAuthData(r, (data) => {
            data[32] |= 0x40;
            return data;
          }),
        "INVALID_RESPONSE",
      ],
      ["truncated header", (r) => changeAuthData(r, (data) => data.subarray(0, 36)), "INVALID_RESPONSE"],
      ["truncated extensions", (r) => changeAuthData(r, (data) => data.subarray(0, -1)), "INVALID_RESPONSE"],
      [
        "trailing data",
        (r) => changeAuthData(r, (data) => Buffer.concat([data, Buffer.from([0])])),
        "INVALID_RESPONSE",
      ],
      [
        "extension bytes",
        (r) =>
          changeAuthData(r, (data) => {
            data[data.length - 1] ^= 1;
            return data;
          }),
        "INVALID_SIGNATURE",
      ],
      [
        "client JSON whitespace",
        (r) => {
          r.response.clientDataJSON = Buffer.concat([
            Buffer.from(" "),
            Buffer.from(r.response.clientDataJSON, "base64url"),
          ]).toString("base64url");
        },
        "INVALID_SIGNATURE",
      ],
      [
        "signature",
        (r) => {
          const signature = Buffer.from(r.response.signature, "base64url");
          signature[signature.length - 1] ^= 1;
          r.response.signature = signature.toString("base64url");
        },
        "INVALID_SIGNATURE",
      ],
    ];
    for (const [name, change, error] of authenticationMutations) {
      test(`rejects authentication with altered ${name}`, () => {
        const credential = verifyRegistration({ response: vector.registration, ...expected }).credential;
        const response = structuredClone(vector.authentication);
        change(response);
        assert.throws(
          () => verifyAuthentication({ response: response, credential, ...expected }).newCounter,
          failure(error),
        );
      });
    }

    test("rejects a non-increasing counter, including a reset to zero", () => {
      const credential = {
        ...verifyRegistration({ response: vector.registration, ...expected }).credential,
        counter: 1,
      };
      assert.throws(
        () => verifyAuthentication({ response: vector.authentication, credential, ...expected }).newCounter,
        failure("COUNTER_NOT_INCREASED"),
      );
      assert.throws(
        () => verifyAuthentication({ response: vector.zeroCounterAuthentication, credential, ...expected }).newCounter,
        failure("COUNTER_NOT_INCREASED"),
      );
    });

    test("rejects a signature from another credential", () => {
      const otherVector = vectors.find((v) => v !== vector);
      assert.ok(otherVector);
      const other = verifyRegistration({ response: otherVector.registration, ...expected }).credential;
      assert.throws(() =>
        verifyAuthentication({
          response: vector.authentication,
          credential: { ...other, id: vector.authentication.id },
          ...expected,
        }),
      );
    });
  });
}

describe("CBOR verification boundaries", () => {
  // Encode keys as values to retain their CBOR types and allow deliberate duplicate keys.
  function encodeMapEntries(entries: [unknown, unknown][]): Buffer<ArrayBuffer> {
    assert.ok(entries.length < 24);
    return Buffer.concat([
      Buffer.from([0xa0 + entries.length]),
      ...entries.flatMap(([key, value]) => [encodeCbor([key]).subarray(1), encodeCbor([value]).subarray(1)]),
    ]);
  }

  test("rejects attestation fields supplied through __proto__", () => {
    const response = structuredClone(vectors[0].registration);
    const attestation = decodeCbor<Attestation>(Buffer.from(response.response.attestationObject, "base64url"));
    response.response.attestationObject = encodeMapEntries([["__proto__", attestation]]).toString("base64url");
    assert.throws(() => verifyRegistration({ response, ...expected }), failure("UNSUPPORTED_ATTESTATION"));
  });

  test("does not treat a __proto__ entry as an empty attestation statement", () => {
    const response = structuredClone(vectors[0].registration);
    changeAttestation(response, (attestation) => {
      attestation.attStmt = JSON.parse('{"__proto__":{"sig":"unexpected"}}');
    });
    assert.throws(() => verifyRegistration({ response, ...expected }), failure("INVALID_RESPONSE"));
  });

  test("rejects duplicate attestation fields", () => {
    const response = structuredClone(vectors[0].registration);
    const attestation = decodeCbor<Attestation>(Buffer.from(response.response.attestationObject, "base64url"));
    response.response.attestationObject = encodeMapEntries([
      ["fmt", "packed"],
      ...Object.entries(attestation),
    ]).toString("base64url");
    assert.throws(() => verifyRegistration({ response, ...expected }), failure("INVALID_RESPONSE"));
  });

  for (const vector of vectors) {
    const credential = verifyRegistration({ response: vector.registration, ...expected }).credential;
    const publicKey = Buffer.from(credential.publicKey, "base64url");
    const key = decodeCbor<Record<number, unknown>>(publicKey);
    const entries: [number, unknown][] = Object.entries(key).map(([label, value]) => [Number(label), value]);

    function rejectsKey(
      encoded: Buffer<ArrayBuffer>,
      registrationError: WebAuthnVerificationErrorCode,
      savedKeyError = registrationError,
    ): void {
      const response = structuredClone(vector.registration);
      changeAttestation(response, (attestation) => {
        const raw = Buffer.from(attestation.authData);
        const offset = 55 + raw.readUInt16BE(53);
        attestation.authData = Buffer.concat([
          raw.subarray(0, offset),
          encoded,
          raw.subarray(offset + publicKey.length),
        ]);
      });
      assert.throws(() => verifyRegistration({ response, ...expected }), failure(registrationError));
      assert.throws(
        () =>
          verifyAuthentication({
            response: vector.authentication,
            credential: { ...credential, publicKey: encoded.toString("base64url") },
            ...expected,
          }),
        failure(savedKeyError),
      );
    }

    test(`${vector.name}: rejects duplicate COSE labels in registration and saved keys`, () => {
      rejectsKey(encodeMapEntries([...entries, [3, vector.algorithm]]), "INVALID_RESPONSE", "INVALID_PUBLIC_KEY");
    });

    test(`${vector.name}: rejects COSE fields supplied through __proto__`, () => {
      rejectsKey(encodeMapEntries([["__proto__", key]]), "UNSUPPORTED_ALGORITHM");
    });

    for (const [label] of entries) {
      test(`${vector.name}: rejects text in place of numeric COSE label ${label}`, () => {
        rejectsKey(
          encodeMapEntries(entries.map(([k, value]) => [k === label ? String(k) : k, value])),
          label === 3 ? "UNSUPPORTED_ALGORITHM" : "INVALID_PUBLIC_KEY",
        );
      });
    }
  }

  test("rejects duplicate extension keys during registration and authentication", () => {
    const extensions = encodeMapEntries([
      ["hmac-secret", false],
      ["hmac-secret", true],
    ]);
    const response = structuredClone(vectors[0].registration);
    const credential = verifyRegistration({ response, ...expected }).credential;
    changeAttestation(response, (attestation) => {
      const raw = Buffer.from(attestation.authData);
      const offset = 55 + raw.readUInt16BE(53) + Buffer.from(credential.publicKey, "base64url").length;
      attestation.authData = Buffer.concat([raw.subarray(0, offset), extensions]);
    });
    assert.throws(() => verifyRegistration({ response, ...expected }), failure("INVALID_RESPONSE"));
    const authentication = structuredClone(vectors[0].authentication);
    changeAuthData(authentication, (raw) => Buffer.concat([raw.subarray(0, 37), extensions]));
    assert.throws(
      () => verifyAuthentication({ response: authentication, credential, ...expected }),
      failure("INVALID_RESPONSE"),
    );
  });
});

describe("WebAuthnTestServer state", () => {
  const user = { id: "user", username: "test" };

  test("tracks credentials and advances the counter only after successful verification", async () => {
    const server = new WebAuthnTestServer();
    const emulator = new WebAuthnEmulator();
    const registrationOptions = await server.getRegistrationOptions(user);
    const registration = emulator.createJSON(server.origin, registrationOptions);
    await server.getRegistrationVerification(user, registration);
    assert.deepEqual((await server.getRegistrationOptions(user)).excludeCredentials, [
      { id: registration.id, type: "public-key" },
    ]);
    const options = await server.getAuthenticationOptions();
    assert.deepEqual(options.allowCredentials, [{ id: registration.id, type: "public-key" }]);
    assert.notEqual(options.challenge, registrationOptions.challenge);
    assert.equal(Buffer.from(options.challenge, "base64url").length, 32);

    const first = emulator.getJSON(server.origin, options);
    const second = emulator.getJSON(server.origin, options);
    const bad = structuredClone(second);
    bad.response.signature = "AA";
    await assert.rejects(server.getAuthenticationVerification(bad), /Invalid authentication signature/);
    await server.getAuthenticationVerification(first);
    await server.getAuthenticationVerification(second);
    await assert.rejects(server.getAuthenticationVerification(first), /counter did not increase/);
    const unknown = { ...second, id: "AA", rawId: "AA" };
    await assert.rejects(server.getAuthenticationVerification(unknown), /Credential not found/);
  });

  test("does not accept challenges issued for a different ceremony", async () => {
    const server = new WebAuthnTestServer();
    const emulator = new WebAuthnEmulator();
    const registrationOptions = await server.getRegistrationOptions(user);
    await server.getRegistrationVerification(user, emulator.createJSON(server.origin, registrationOptions));
    const authenticationOptions = await server.getAuthenticationOptions();
    const assertion = emulator.getJSON(server.origin, {
      ...authenticationOptions,
      challenge: registrationOptions.challenge,
    });
    await assert.rejects(server.getAuthenticationVerification(assertion), /Unexpected challenge/);
    const registration = emulator.createJSON(server.origin, {
      ...registrationOptions,
      challenge: authenticationOptions.challenge,
    });
    await assert.rejects(server.getRegistrationVerification(user, registration), /Unexpected challenge/);
  });
});

describe("Public verification policy", () => {
  for (const crossOrigin of [undefined, false]) {
    test(`rejects any topOrigin when crossOrigin is ${crossOrigin === undefined ? "omitted" : "false"}`, () => {
      const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      const jwk = keys.publicKey.export({ format: "jwk" });
      assert.ok(jwk.x && jwk.y);
      const registration = structuredClone(vectors[0].registration);
      changeKey(registration, { [-2]: Buffer.from(jwk.x, "base64url"), [-3]: Buffer.from(jwk.y, "base64url") });
      const credential = verifyRegistration({ response: registration, ...expected }).credential;

      for (const topOrigin of [undefined, expected.expectedOrigin, "https://other.example", null, ""]) {
        changeClientData(registration, { crossOrigin, topOrigin });
        const authentication = structuredClone(vectors[0].authentication);
        changeClientData(authentication, { crossOrigin, topOrigin });
        const signedData = Buffer.concat([
          Buffer.from(authentication.response.authenticatorData, "base64url"),
          createHash("sha256").update(Buffer.from(authentication.response.clientDataJSON, "base64url")).digest(),
        ]);
        authentication.response.signature = sign("sha256", signedData, keys.privateKey).toString("base64url");

        if (topOrigin === undefined) {
          assert.equal(verifyRegistration({ response: registration, ...expected }).credential.id, credential.id);
          assert.equal(verifyAuthentication({ response: authentication, credential, ...expected }).newCounter, 1);
        } else {
          assert.throws(
            () => verifyRegistration({ response: registration, ...expected }),
            failure("UNSUPPORTED_CROSS_ORIGIN"),
          );
          assert.throws(
            () => verifyAuthentication({ response: authentication, credential, ...expected }),
            failure("UNSUPPORTED_CROSS_ORIGIN"),
          );
        }
      }
    });
  }

  test("UV can be optional while UP remains mandatory", async () => {
    const server = new WebAuthnTestServer();
    const options = await server.getRegistrationOptions({ id: "user", username: "test" });
    const emulator = new WebAuthnEmulator(
      new AuthenticatorEmulator({
        userMakeCredentialInteraction: (user) => ({ user, options: { up: true, uv: false } }),
        userGetAssertionInteraction: (user) => ({ user, options: { up: true, uv: false } }),
      }),
    );
    const response = emulator.createJSON(server.origin, options);
    const expectations = {
      expectedChallenge: options.challenge,
      expectedOrigin: server.origin,
      expectedRPID: server.rpID,
    };
    assert.throws(() => verifyRegistration({ response, ...expectations }), failure("USER_VERIFICATION_REQUIRED"));
    const result = verifyRegistration({ response, ...expectations, requireUserVerification: false });
    assert.equal(result.userVerified, false);
    assert.equal(result.userPresent, true);
    assert.equal(result.backupEligible, true);
    assert.equal(result.backupState, true);
    const assertion = emulator.getJSON(server.origin, {
      challenge: options.challenge,
      rpId: server.rpID,
      allowCredentials: [{ id: result.credential.id, type: "public-key" }],
    });
    assert.throws(
      () =>
        verifyAuthentication({
          response: assertion,
          credential: result.credential,
          ...expectations,
        }),
      failure("USER_VERIFICATION_REQUIRED"),
    );
    assert.deepEqual(
      verifyAuthentication({
        response: assertion,
        credential: result.credential,
        ...expectations,
        requireUserVerification: false,
      }),
      { newCounter: 1, userPresent: true, userVerified: false, backupEligible: true, backupState: true },
    );
    changeAttestation(response, (attestation) => {
      attestation.authData[32] &= ~0x01;
    });
    assert.throws(
      () => verifyRegistration({ response, ...expectations, requireUserVerification: false }),
      failure("USER_PRESENCE_REQUIRED"),
    );
    changeAuthData(assertion, (data) => {
      data[32] &= ~0x01;
      return data;
    });
    assert.throws(
      () =>
        verifyAuthentication({
          response: assertion,
          credential: result.credential,
          ...expectations,
          requireUserVerification: false,
        }),
      failure("USER_PRESENCE_REQUIRED"),
    );
  });

  test("requires explicit expectations and rejects invalid saved state", () => {
    const vector = vectors[0];
    const credential = verifyRegistration({ response: vector.registration, ...expected }).credential;
    for (const fields of [
      { expectedChallenge: "" },
      { expectedChallenge: "!" },
      { expectedChallenge: undefined },
      { expectedOrigin: "" },
      { expectedOrigin: undefined },
      { expectedRPID: "" },
      { expectedRPID: undefined },
    ]) {
      const incomplete = { ...expected, ...fields } as typeof expected;
      assert.throws(
        () => verifyRegistration({ response: vector.registration, ...incomplete }),
        failure("INVALID_OPTIONS"),
      );
      assert.throws(
        () => verifyAuthentication({ response: vector.authentication, credential, ...incomplete }),
        failure("INVALID_OPTIONS"),
      );
    }
    for (const counter of [-1, 0.5, Number.NaN, 0x100000000]) {
      assert.throws(
        () =>
          verifyAuthentication({
            response: vector.authentication,
            credential: { ...credential, counter },
            ...expected,
          }),
        failure("INVALID_OPTIONS"),
      );
    }
    assert.throws(
      () =>
        verifyRegistration({
          response: vector.registration,
          ...expected,
          supportedAlgorithmIDs: [],
        }),
      failure("INVALID_OPTIONS"),
    );
    assert.throws(
      () =>
        verifyAuthentication({
          response: vector.authentication,
          credential: { ...credential, backupState: true },
          ...expected,
        }),
      failure("INVALID_OPTIONS"),
    );
  });

  test("normalizes malformed input and preserves the parser error as its cause", () => {
    const response = structuredClone(vectors[0].registration);
    response.response.clientDataJSON = "ew";
    assert.throws(
      () => verifyRegistration({ response, ...expected }),
      (error: unknown) => {
        assert.ok(error instanceof WebAuthnVerificationError);
        assert.equal(error.name, "WebAuthnVerificationError");
        assert.equal(error.code, "INVALID_RESPONSE");
        assert.ok(error.cause instanceof SyntaxError);
        return true;
      },
    );
    assert.throws(
      () => verifyRegistration({ response: null as unknown as RegistrationResponseJSON, ...expected }),
      failure("INVALID_RESPONSE"),
    );
    const credential = verifyRegistration({ response: vectors[0].registration, ...expected }).credential;
    assert.throws(
      () =>
        verifyAuthentication({
          response: null as unknown as AuthenticationResponseJSON,
          credential,
          ...expected,
        }),
      failure("INVALID_RESPONSE"),
    );
    // Validly encoded but invalid EC points must produce the public error, not an OpenSSL error.
    const invalidKey = structuredClone(vectors[0].registration);
    changeKey(invalidKey, { [-2]: new Uint8Array(32), [-3]: new Uint8Array(32) });
    assert.throws(() => verifyRegistration({ response: invalidKey, ...expected }), failure("INVALID_PUBLIC_KEY"));
  });
});

describe("RSA public key validation", () => {
  const vector = vectors[2];
  const credential = verifyRegistration({ response: vector.registration, ...expected }).credential;
  const key = decodeCbor<Record<number, unknown>>(Buffer.from(credential.publicKey, "base64url"));
  const modulus = Buffer.from(key[-1] as Uint8Array);
  const evenModulus = Buffer.from(modulus);
  evenModulus[evenModulus.length - 1] &= ~1;
  const shortModulus = Buffer.from(modulus);
  shortModulus[0] = 0x7f; // 2047 bits
  const invalidKeys: [string, Record<number, unknown>][] = [
    ["zero modulus", { [-1]: Buffer.from([0]) }],
    ["zero exponent", { [-2]: Buffer.from([0]) }],
    ["even modulus", { [-1]: evenModulus }],
    ["modulus shorter than 2048 bits", { [-1]: shortModulus }],
    ["leading zero in modulus", { [-1]: Buffer.concat([Buffer.from([0]), modulus]) }],
    ["leading zero in exponent", { [-2]: Buffer.from([0, 1, 0, 1]) }],
    ["exponent one", { [-2]: Buffer.from([1]) }],
    ["exponent two", { [-2]: Buffer.from([2]) }],
    ["even exponent", { [-2]: Buffer.from([4]) }],
    ["exponent equal to modulus", { [-2]: modulus }],
    ["exponent greater than modulus", { [-2]: Buffer.concat([Buffer.from([1]), modulus]) }],
  ];
  for (const [name, fields] of invalidKeys) {
    test(`rejects ${name} during registration and when loading a saved credential`, () => {
      const response = structuredClone(vector.registration);
      changeKey(response, fields);
      assert.throws(() => verifyRegistration({ response, ...expected }), failure("INVALID_PUBLIC_KEY"));
      const publicKey = Buffer.from(encodeCbor({ ...key, ...fields })).toString("base64url");
      assert.throws(
        () =>
          verifyAuthentication({
            response: vector.authentication,
            credential: { ...credential, publicKey },
            ...expected,
          }),
        failure("INVALID_PUBLIC_KEY"),
      );
    });
  }

  test("accepts a 2048-bit RSA key with public exponent three", () => {
    const keys = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 3 });
    const jwk = keys.publicKey.export({ format: "jwk" });
    assert.ok(jwk.n && jwk.e);
    const response = structuredClone(vector.registration);
    changeKey(response, { [-1]: Buffer.from(jwk.n, "base64url"), [-2]: Buffer.from(jwk.e, "base64url") });
    const registered = verifyRegistration({ response, ...expected }).credential;
    const authentication = structuredClone(vector.authentication);
    // The fixture's client data and authenticator data are unchanged; sign them with the new key.
    const data = Buffer.concat([
      Buffer.from(authentication.response.authenticatorData, "base64url"),
      createHash("sha256").update(Buffer.from(authentication.response.clientDataJSON, "base64url")).digest(),
    ]);
    authentication.response.signature = sign("sha256", data, keys.privateKey).toString("base64url");
    assert.equal(verifyAuthentication({ response: authentication, credential: registered, ...expected }).newCounter, 1);
  });
});

describe("Credential ID length", () => {
  for (const length of [1, 1023, 1024]) {
    test(`${length}-byte credential ID is ${length <= 1023 ? "accepted" : "rejected"}`, () => {
      const response = structuredClone(vectors[0].registration);
      const id = Buffer.alloc(length, 7);
      changeAttestation(response, (attestation) => {
        const raw = Buffer.from(attestation.authData);
        const previousLength = raw.readUInt16BE(53);
        const header = Buffer.from(raw.subarray(0, 55));
        header.writeUInt16BE(length, 53);
        attestation.authData = Buffer.concat([header, id, raw.subarray(55 + previousLength)]);
      });
      response.id = response.rawId = id.toString("base64url");
      if (length > 1023) {
        assert.throws(() => verifyRegistration({ response, ...expected }), failure("INVALID_RESPONSE"));
      } else {
        assert.equal(verifyRegistration({ response, ...expected }).credential.id, response.id);
      }
    });
  }
});
