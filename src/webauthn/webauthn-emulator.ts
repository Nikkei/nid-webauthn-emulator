import { AuthenticatorEmulator } from "../authenticator/authenticator-emulator";
import EncodeUtils from "../libs/encode-utils";
import {
  type AllAcceptedCredentialsOptionsJSON,
  type AuthenticationResponseJSON,
  type CreatePublicKeyCredential,
  type CurrentUserDetailsOptionsJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  type RequestPublicKeyCredential,
  type UnknownCredentialOptionsJSON,
  decodeBase64Url,
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
  toAuthenticationResponseJSON,
  toRegistrationResponseJSON,
} from "./webauthn-model-json";

import { createHash } from "node:crypto";
import {
  CREDENTIAL_MANAGEMENT_SUBCOMMAND,
  CTAP_COMMAND,
  packCredentialManagementRequest,
  packGetAssertionRequest,
  packMakeCredentialRequest,
  unpackCredentialManagementResponse,
  unpackGetAssertionResponse,
  unpackGetInfoResponse,
  unpackMakeCredentialResponse,
} from "../authenticator/ctap-model";
import {
  type AttestationObject,
  type AttestedCredentialData,
  type CollectedClientData,
  RpId,
  packAttestationObject,
  packAuthenticatorData,
  toFido2CreateOptions,
  toFido2RequestOptions,
  unpackAuthenticatorData,
} from "./webauthn-model";

export type AuthenticatorInfo = {
  version: string;
  aaguid: string;
  options: {
    rk?: boolean;
    uv?: boolean;
  };
};

export class WebAuthnEmulatorError extends Error {}
export class NoPublicKeyError extends WebAuthnEmulatorError {}
export class InvalidRpIdError extends WebAuthnEmulatorError {}

/**
 * WebAuthn emulator
 */
export class WebAuthnEmulator {
  constructor(public authenticator: AuthenticatorEmulator = new AuthenticatorEmulator()) {}

  public getJSON(origin: string, optionsJSON: PublicKeyCredentialRequestOptionsJSON): AuthenticationResponseJSON {
    const options = parseRequestOptionsFromJSON(optionsJSON);
    const response = this.get(origin, { publicKey: options });
    return response.toJSON();
  }

  public createJSON(origin: string, optionsJSON: PublicKeyCredentialCreationOptionsJSON): RegistrationResponseJSON {
    const options = parseCreationOptionsFromJSON(optionsJSON);
    const response = this.create(origin, { publicKey: options });
    return response.toJSON();
  }

  public getAuthenticatorInfo(): AuthenticatorInfo {
    const authenticatorInfo = unpackGetInfoResponse(
      this.authenticator.command({ command: CTAP_COMMAND.authenticatorGetInfo }),
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

  public signalUnknownCredential(options: UnknownCredentialOptionsJSON): void {
    const credentialId = decodeBase64Url(options.credentialId);
    this.authenticator.command(
      packCredentialManagementRequest({
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential,
        subCommandParams: {
          credentialId: EncodeUtils.bufferSourceToUint8Array(credentialId),
          rpId: options.rpId,
        },
      }),
    );
  }

  /**
   * Signal all accepted credentials for a user
   * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalAllAcceptedCredentials_static
   */
  public signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptionsJSON): void {
    // Create a set of accepted credential IDs for quick lookup
    const acceptedCredentialIds = new Set(options.allAcceptedCredentialIds);

    // Start enumerating credentials for the specified RP
    const beginResponse = unpackCredentialManagementResponse(
      this.authenticator.command(
        packCredentialManagementRequest({
          subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsBegin,
          subCommandParams: {
            rpId: options.rpId,
          },
        }),
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
      const credResponse = unpackCredentialManagementResponse(
        this.authenticator.command(
          packCredentialManagementRequest({
            subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.enumerateCredentialsGetNextCredential,
          }),
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
          this.authenticator.command(
            packCredentialManagementRequest({
              subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.deleteCredential,
              subCommandParams: {
                credentialId: credResponse.credentialID,
                rpId: rpId,
              },
            }),
          );
        }
      }
    }
  }

  /**
   * Signal current user details
   * @see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalCurrentUserDetails_static
   */
  public signalCurrentUserDetails(options: CurrentUserDetailsOptionsJSON): void {
    const userId = decodeBase64Url(options.userId);

    // Create user object with updated information
    const user: PublicKeyCredentialUserEntity = {
      id: userId,
      name: options.name,
      displayName: options.displayName,
    };

    // Update user information using the credential management API
    this.authenticator.command(
      packCredentialManagementRequest({
        subCommand: CREDENTIAL_MANAGEMENT_SUBCOMMAND.updateUserInformation,
        subCommandParams: {
          rpId: options.rpId,
          user: user,
        },
      }),
    );
  }

  /** @see https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get */
  public get(origin: string, options: CredentialRequestOptions): RequestPublicKeyCredential {
    if (!options.publicKey) throw new NoPublicKeyError("PublicKeyCredentialCreationOptions are required");

    const rpId = new RpId(options.publicKey.rpId ?? new URL(origin).hostname);
    if (!rpId.validate(origin)) throw new InvalidRpIdError(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);

    const clientData: CollectedClientData = {
      type: "webauthn.get",
      challenge: EncodeUtils.encodeBase64Url(options.publicKey.challenge),
      origin,
      crossOrigin: false,
    };

    const authenticatorRequest = packGetAssertionRequest({
      rpId: rpId.value,
      clientDataHash: createHash("sha256").update(JSON.stringify(clientData)).digest(),
      allowList: options.publicKey.allowCredentials,
      options: toFido2RequestOptions(options.publicKey.userVerification),
    });
    const authenticatorResponse = unpackGetAssertionResponse(this.authenticator.command(authenticatorRequest));

    const responseId =
      authenticatorResponse.credential?.id ?? (options.publicKey.allowCredentials?.[0]?.id as BufferSource);

    const authData = unpackAuthenticatorData(authenticatorResponse.authData);
    const rawId = EncodeUtils.bufferSourceToUint8Array(responseId);

    const publicKeyCredential: RequestPublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(rawId),
      type: "public-key",
      rawId,
      response: {
        clientDataJSON: EncodeUtils.strToUint8Array(JSON.stringify(clientData)),
        authenticatorData: packAuthenticatorData(authData),
        signature: authenticatorResponse.signature,
        userHandle: authenticatorResponse.user
          ? EncodeUtils.bufferSourceToUint8Array(authenticatorResponse.user.id)
          : null,
      },
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: authenticatorResponse.user !== undefined } }),
      toJSON: () => toAuthenticationResponseJSON(publicKeyCredential),
    };

    return publicKeyCredential;
  }

  /** @see https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create */
  public create(origin: string, options: CredentialCreationOptions): CreatePublicKeyCredential {
    if (!options.publicKey) throw new NoPublicKeyError("PublicKeyCredentialCreationOptions are required");

    const rpId = new RpId(options.publicKey.rp.id ?? new URL(origin).hostname);
    if (!rpId.validate(origin)) throw new InvalidRpIdError(`Invalid rpId: RP_ID=${rpId.value}, ORIGIN=${origin}`);

    const clientData: CollectedClientData = {
      challenge: EncodeUtils.encodeBase64Url(options.publicKey.challenge),
      origin,
      type: "webauthn.create",
      crossOrigin: false,
    };
    const clientDataJSON = JSON.stringify(clientData);

    const authenticatorRequest = packMakeCredentialRequest({
      clientDataHash: createHash("sha256").update(clientDataJSON).digest(),
      rp: { name: options.publicKey.rp.name, id: rpId.value },
      user: options.publicKey.user,
      pubKeyCredParams: options.publicKey.pubKeyCredParams,
      excludeList: options.publicKey.excludeCredentials,
      options: toFido2CreateOptions(options.publicKey.authenticatorSelection),
    });
    const authenticatorResponse = unpackMakeCredentialResponse(this.authenticator.command(authenticatorRequest));

    const authData = unpackAuthenticatorData(authenticatorResponse.authData);
    const attestedCredentialData = authData.attestedCredentialData as AttestedCredentialData;

    const attestationObject: AttestationObject = {
      fmt: "none",
      attStmt: {},
      authData,
    };

    const response: AuthenticatorAttestationResponse = {
      attestationObject: packAttestationObject(attestationObject),
      clientDataJSON: EncodeUtils.strToUint8Array(clientDataJSON),

      getAuthenticatorData: () => packAuthenticatorData(authData),
      getPublicKey: () => attestedCredentialData.credentialPublicKey.toDer(),
      getPublicKeyAlgorithm: () => attestedCredentialData.credentialPublicKey.alg,
      getTransports: () => this.authenticator.params.transports,
    };

    const publicKeyCredential: CreatePublicKeyCredential = {
      id: EncodeUtils.encodeBase64Url(attestedCredentialData.credentialId),
      type: "public-key",
      rawId: attestedCredentialData.credentialId,
      response,
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      toJSON: () => toRegistrationResponseJSON(publicKeyCredential),
    };

    return publicKeyCredential;
  }
}
