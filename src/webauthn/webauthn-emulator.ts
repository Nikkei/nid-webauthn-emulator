import { createHash } from "node:crypto";
import { AuthenticatorEmulator } from "../authenticator/authenticator-emulator";
import {
  AuthenticationEmulatorError,
  CREDENTIAL_MANAGEMENT_SUBCOMMAND,
  CTAP_COMMAND,
  CTAP_STATUS_CODE,
  packCredentialManagementRequest,
  packGetAssertionRequest,
  packMakeCredentialRequest,
  unpackCredentialManagementResponse,
  unpackGetAssertionResponse,
  unpackGetInfoResponse,
  unpackMakeCredentialResponse,
} from "../authenticator/ctap-model";
import EncodeUtils from "../libs/encode-utils";
import {
  type AttestationObject,
  type AttestedCredentialData,
  type CollectedClientData,
  packAttestationObject,
  packAuthenticatorData,
  RpId,
  toFido2CreateOptions,
  toFido2RequestOptions,
  unpackAuthenticatorData,
} from "./webauthn-model";
import {
  type CreatePublicKeyCredential,
  decodeBase64Url,
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
  type RequestPublicKeyCredential,
  toAuthenticationResponseJSON,
  toRegistrationResponseJSON,
} from "./webauthn-model-json";

export type AuthenticatorInfo = {
  version: string;
  aaguid: string;
  options: {
    rk?: boolean;
    uv?: boolean;
  };
};

const PRF_OUTPUT_LENGTH = 32;
const PRF_SALT_PREFIX = EncodeUtils.strToUint8Array("WebAuthn PRF");

export class WebAuthnEmulatorError extends Error {}

/**
 * WebAuthn emulator
 */
export class WebAuthnEmulator {
  constructor(public authenticator: AuthenticatorEmulator = new AuthenticatorEmulator()) {}

  private mapAuthenticatorErrorToDOMException(error: AuthenticationEmulatorError): DOMException {
    let name: string;
    switch (error.status) {
      case CTAP_STATUS_CODE.CTAP2_ERR_CREDENTIAL_EXCLUDED:
        name = "NotAllowedError";
        break;
      case CTAP_STATUS_CODE.CTAP2_ERR_UNSUPPORTED_ALGORITHM:
        name = "NotSupportedError";
        break;
      case CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED:
      case CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED:
      case CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS:
        name = "NotAllowedError";
        break;
      case CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER:
      case CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR:
        name = "DataError";
        break;
      default:
        name = "UnknownError";
        break;
    }
    return new DOMException(error.message, name);
  }

  private handleAuthenticatorCall<T>(fn: () => T): T {
    try {
      return fn();
    } catch (error) {
      if (error instanceof AuthenticationEmulatorError) {
        throw this.mapAuthenticatorErrorToDOMException(error);
      }
      throw error;
    }
  }

  public getJSON(
    origin: string,
    optionsJSON: PublicKeyCredentialRequestOptionsJSON,
    relatedOrigins: string[] = [],
  ): AuthenticationResponseJSON {
    const options = parseRequestOptionsFromJSON(optionsJSON);
    const response = this.get(origin, { publicKey: options }, relatedOrigins);
    return response.toJSON();
  }

  public createJSON(
    origin: string,
    optionsJSON: PublicKeyCredentialCreationOptionsJSON,
    relatedOrigins: string[] = [],
  ): RegistrationResponseJSON {
    const options = parseCreationOptionsFromJSON(optionsJSON);
    const response = this.create(origin, { publicKey: options }, relatedOrigins);
    return response.toJSON();
  }

  public getAuthenticatorInfo(): AuthenticatorInfo {
    const authenticatorInfo = this.handleAuthenticatorCall(() =>
      unpackGetInfoResponse(this.authenticator.command({ command: CTAP_COMMAND.authenticatorGetInfo })),
    );
    return {
      version: authenticatorInfo.versions.join(", "),
      aaguid: EncodeUtils.encodeBase64Url(authenticatorInfo.aaguid),
      options: {
        rk: authenticatorInfo.options?.rk,
        uv: authenticatorInfo.options?.uv,
      },
    };
  }

  public signalUnknownCredential(options: UnknownCredentialOptions): void {
    const credentialId = decodeBase64Url(options.credentialId);
    this.handleAuthenticatorCall(() =>
      this.authenticator.command(
        packCredentialManagementRequest({
          subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential,
          subCommandParams: {
            credentialId: EncodeUtils.bufferSourceToUint8Array(credentialId),
            rpId: options.rpId,
          },
        }),
      ),
    );
  }

  /**
   * Signal all accepted credentials for a user
   * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalAllAcceptedCredentials_static
   */
  public signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptions): void {
    // Create a set of accepted credential IDs for quick lookup
    const acceptedCredentialIds = new Set(options.allAcceptedCredentialIds);

    // Start enumerating credentials for the specified RP
    const beginResponse = this.handleAuthenticatorCall(() =>
      unpackCredentialManagementResponse(
        this.authenticator.command(
          packCredentialManagementRequest({
            subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
            subCommandParams: {
              rpId: options.rpId,
            },
          }),
        ),
      ),
    );

    // Get the total number of credentials
    const totalCredentials = beginResponse.totalCredentials ?? 0;

    // Get all credentials for the RP and delete those not in the accepted list
    this.processCredentials(options.rpId, options.userId, acceptedCredentialIds, totalCredentials);
  }

  /**
   * Process credentials for an RP and delete those not in the accepted list
   */
  private processCredentials(
    rpId: string,
    userId: string,
    acceptedCredentialIds: Set<string>,
    totalCredentials: number,
  ): void {
    // Process each credential
    for (let i = 0; i < totalCredentials; i++) {
      // Get next credential and unpack the response
      const credResponse = this.handleAuthenticatorCall(() =>
        unpackCredentialManagementResponse(
          this.authenticator.command(
            packCredentialManagementRequest({
              subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential,
            }),
          ),
        ),
      );

      // Skip if this is not for the user we're looking for
      if (credResponse.user && EncodeUtils.encodeBase64Url(credResponse.user.id) !== userId) {
        continue;
      }

      // Delete credential if it's not in the accepted list
      if (credResponse.credentialID) {
        const credentialId = EncodeUtils.encodeBase64Url(credResponse.credentialID);
        if (!acceptedCredentialIds.has(credentialId)) {
          // Delete the credential directly
          this.handleAuthenticatorCall(() =>
            this.authenticator.command(
              packCredentialManagementRequest({
                subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential,
                subCommandParams: {
                  credentialId: credResponse.credentialID,
                  rpId: rpId,
                },
              }),
            ),
          );
        }
      }
    }
  }

  /**
   * Signal current user details
   * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalCurrentUserDetails_static
   */
  public signalCurrentUserDetails(options: CurrentUserDetailsOptions): void {
    const userId = decodeBase64Url(options.userId);

    // Create user object with updated information
    const user: PublicKeyCredentialUserEntity = {
      id: userId,
      name: options.name,
      displayName: options.displayName,
    };

    // Update user information using the credential management API
    this.handleAuthenticatorCall(() =>
      this.authenticator.command(
        packCredentialManagementRequest({
          subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
          subCommandParams: {
            rpId: options.rpId,
            user: user,
          },
        }),
      ),
    );
  }

  /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
  public get(
    origin: string,
    options: CredentialRequestOptions,
    relatedOrigins: string[] = [],
  ): RequestPublicKeyCredential {
    if (!options.publicKey) throw new TypeError("PublicKeyCredentialRequestOptions are required");

    const rpId = new RpId(options.publicKey.rpId ?? new URL(origin).hostname);
    if (!rpId.validate(origin, relatedOrigins))
      throw new DOMException(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`, "SecurityError");

    const clientData: CollectedClientData = {
      type: "webauthn.get",
      challenge: EncodeUtils.encodeBase64Url(options.publicKey.challenge),
      origin,
      crossOrigin: false,
    };

    const prf = options.publicKey.extensions?.prf;
    const requestExtensions: Record<string, unknown> = {};
    if (prf) {
      const allowCredentials = options.publicKey.allowCredentials;
      const evalByCredentialKeys = prf.evalByCredential ? Object.keys(prf.evalByCredential) : [];
      if (evalByCredentialKeys.length > 0) {
        if (!allowCredentials?.length) {
          throw new DOMException("prf.evalByCredential requires allowCredentials", "NotSupportedError");
        }
        const allowedIds = new Set(allowCredentials.map((credential) => EncodeUtils.encodeBase64Url(credential.id)));
        for (const key of evalByCredentialKeys) {
          if (!allowedIds.has(key)) {
            throw new DOMException(
              "prf.evalByCredential contains a credential id not in allowCredentials",
              "SyntaxError",
            );
          }
        }
      }
      let prfValues = prf.eval;
      // In real browsers the WebAuthn layer selects the credential before building the CTAP request, which
      // resolves evalByCredential to that credential's salt. The NID emulator selects credentials in the
      // CTAP layer, so we only handle a single allowed credential to avoid polluting the CTAP layer
      if (prf.evalByCredential && allowCredentials?.length === 1) {
        const credentialId = EncodeUtils.encodeBase64Url(allowCredentials[0].id);
        prfValues = prf.evalByCredential[credentialId] ?? prfValues;
      }
      if (prfValues) {
        requestExtensions["hmac-secret"] = prfValuesToSalts(prfValues);
      }
    }

    const authenticatorRequest = packGetAssertionRequest({
      rpId: rpId.value,
      clientDataHash: EncodeUtils.bufferSourceToUint8Array(
        new Uint8Array(createHash("sha256").update(JSON.stringify(clientData)).digest()),
      ),
      allowList: options.publicKey.allowCredentials,
      extensions: requestExtensions,
      options: toFido2RequestOptions(options.publicKey.userVerification),
    });
    const authenticatorResponse = this.handleAuthenticatorCall(() =>
      unpackGetAssertionResponse(this.authenticator.command(authenticatorRequest)),
    );

    const responseId =
      authenticatorResponse.credential?.id ?? (options.publicKey.allowCredentials?.[0]?.id as BufferSource);

    const authData = unpackAuthenticatorData(authenticatorResponse.authData);
    const rawId = EncodeUtils.bufferSourceToUint8Array(responseId);

    const publicKeyCredential: RequestPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(rawId),
      type: "public-key",
      rawId: rawId.buffer,
      response: {
        clientDataJSON: EncodeUtils.strToUint8Array(JSON.stringify(clientData)).buffer,
        authenticatorData: authenticatorResponse.authData.buffer,
        signature: authenticatorResponse.signature.buffer,
        userHandle: authenticatorResponse.user
          ? EncodeUtils.bufferSourceToUint8Array(authenticatorResponse.user.id).buffer
          : null,
      },
      authenticatorAttachment: null,
      getClientExtensionResults: () => {
        const results: AuthenticationExtensionsClientOutputs = {
          credProps: { rk: authenticatorResponse.user !== undefined },
        };
        const extensions = authData.extensions as { "hmac-secret"?: Uint8Array<ArrayBuffer> | boolean } | undefined;
        const hmacOutput = extensions?.["hmac-secret"];
        if (hmacOutput instanceof Uint8Array) {
          results.prf = { results: hmacSecretToPrfResults(hmacOutput) };
        }
        return results;
      },
      toJSON: () => toAuthenticationResponseJSON(publicKeyCredential),
    };

    return publicKeyCredential;
  }

  /** @see https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create */
  public create(
    origin: string,
    options: CredentialCreationOptions,
    relatedOrigins: string[] = [],
  ): CreatePublicKeyCredential {
    if (!options.publicKey) throw new TypeError("PublicKeyCredentialCreationOptions are required");

    const rpId = new RpId(options.publicKey.rp.id ?? new URL(origin).hostname);
    if (!rpId.validate(origin, relatedOrigins))
      throw new DOMException(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`, "SecurityError");

    const clientData: CollectedClientData = {
      challenge: EncodeUtils.encodeBase64Url(options.publicKey.challenge),
      origin,
      type: "webauthn.create",
      crossOrigin: false,
    };
    const clientDataJSON = JSON.stringify(clientData);

    const prf = options.publicKey.extensions?.prf;
    if (prf?.evalByCredential !== undefined) {
      throw new DOMException("prf.evalByCredential is not supported during credential creation", "NotSupportedError");
    }
    const requestExtensions: Record<string, unknown> = {};
    if (prf) {
      requestExtensions["hmac-secret"] = true;
      if (prf.eval) {
        requestExtensions["hmac-secret-mc"] = prfValuesToSalts(prf.eval);
      }
    }

    const authenticatorRequest = packMakeCredentialRequest({
      clientDataHash: EncodeUtils.bufferSourceToUint8Array(
        new Uint8Array(createHash("sha256").update(clientDataJSON).digest()),
      ),
      rp: { name: options.publicKey.rp.name, id: rpId.value },
      user: options.publicKey.user,
      pubKeyCredParams: options.publicKey.pubKeyCredParams,
      excludeList: options.publicKey.excludeCredentials,
      extensions: requestExtensions,
      options: toFido2CreateOptions(options.publicKey.authenticatorSelection),
    });
    const authenticatorResponse = this.handleAuthenticatorCall(() =>
      unpackMakeCredentialResponse(this.authenticator.command(authenticatorRequest)),
    );

    const authData = unpackAuthenticatorData(authenticatorResponse.authData);
    const attestedCredentialData = authData.attestedCredentialData as AttestedCredentialData;

    const attestationObject: AttestationObject = {
      fmt: "none",
      attStmt: {},
      authData,
    };

    const response: AuthenticatorAttestationResponse = {
      attestationObject: packAttestationObject(attestationObject).buffer,
      clientDataJSON: EncodeUtils.strToUint8Array(clientDataJSON).buffer,

      getAuthenticatorData: () => packAuthenticatorData(authData).buffer,
      getPublicKey: () => attestedCredentialData.credentialPublicKey.toDer().buffer,
      getPublicKeyAlgorithm: () => attestedCredentialData.credentialPublicKey.alg,
      getTransports: () => this.authenticator.params.transports,
    };

    const publicKeyCredential: CreatePublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(attestedCredentialData.credentialId),
      type: "public-key",
      rawId: attestedCredentialData.credentialId.buffer,
      response,
      authenticatorAttachment: null,
      getClientExtensionResults: () => {
        const results: AuthenticationExtensionsClientOutputs = { credProps: { rk: true } };
        if (prf) {
          const extensions = authData.extensions as { "hmac-secret"?: Uint8Array<ArrayBuffer> | boolean } | undefined;
          const hmacOutput = extensions?.["hmac-secret"];
          if (hmacOutput instanceof Uint8Array) {
            results.prf = { enabled: true, results: hmacSecretToPrfResults(hmacOutput) };
          } else {
            results.prf = { enabled: hmacOutput === true };
          }
        }
        return results;
      },
      toJSON: () => toRegistrationResponseJSON(publicKeyCredential),
    };

    return publicKeyCredential;
  }
}

// A PRF input maps to a CTAP hmac-secret salt as SHA-256("WebAuthn PRF" || 0x00 || input).
function prfInputToSalt(input: BufferSource): Uint8Array<ArrayBuffer> {
  const inputBytes = EncodeUtils.bufferSourceToUint8Array(input);
  if (inputBytes.length === 0) {
    throw new TypeError("PRF eval input must not be empty");
  }
  const data = new Uint8Array(PRF_SALT_PREFIX.length + 1 + inputBytes.length);
  data.set(PRF_SALT_PREFIX, 0);
  data.set(inputBytes, PRF_SALT_PREFIX.length + 1);
  return new Uint8Array(createHash("sha256").update(data).digest());
}

function prfValuesToSalts(values: AuthenticationExtensionsPRFValues): Uint8Array<ArrayBuffer> {
  const first = prfInputToSalt(values.first);
  let salts = first;

  if (values.second) {
    const second = prfInputToSalt(values.second);
    salts = new Uint8Array(first.length + second.length);
    salts.set(first, 0);
    salts.set(second, first.length);
  }
  return salts;
}

function hmacSecretToPrfResults(output: Uint8Array<ArrayBuffer>): AuthenticationExtensionsPRFValues {
  if (output.length === PRF_OUTPUT_LENGTH) {
    return { first: output.slice(0, PRF_OUTPUT_LENGTH).buffer };
  }
  return {
    first: output.slice(0, PRF_OUTPUT_LENGTH).buffer,
    second: output.slice(PRF_OUTPUT_LENGTH, 2 * PRF_OUTPUT_LENGTH).buffer,
  };
}
