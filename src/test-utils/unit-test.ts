import { AuthenticatorEmulator } from "../authenticator/authenticator-emulator";
import { WebAuthnEmulator } from "../webauthn/webauthn-emulator";
import {
  type AllAcceptedCredentialsOptionsJSON,
  type CurrentUserDetailsOptionsJSON,
  encodeBase64Url,
  parseCreationOptionsFromJSON,
  parseRequestOptionsFromJSON,
  type UnknownCredentialOptionsJSON,
} from "../webauthn/webauthn-model-json";

type PasskeysEmulatorParams = {
  origin?: string;
  autofill?: boolean;
  creationException?: string;
  requestException?: string;
  rpId?: string;
};

const createInteraction = (exception?: string) =>
  exception
    ? () => {
        throw new DOMException("test", exception);
      }
    : undefined;

const addTestPasskey = (emulator: WebAuthnEmulator, origin: string, userId: string, rpId = "localhost") => {
  const creationOption: PublicKeyCredentialCreationOptionsJSON = {
    challenge: "EA3d-yrkJAfNWICZ7It5ErO0XngxTe32L0t8IjEj9r8",
    rp: { name: "Test RP", id: rpId },
    user: {
      id: encodeBase64Url(Buffer.from(userId)),
      name: "test",
      displayName: "",
    },
    pubKeyCredParams: [
      { alg: -8, type: "public-key" },
      { alg: -7, type: "public-key" },
      { alg: -257, type: "public-key" },
    ],
  };
  return emulator.createJSON(origin, creationOption);
};

export const createPasskeysEmulator = (params?: PasskeysEmulatorParams) => {
  const authenticator = new AuthenticatorEmulator({
    userMakeCredentialInteraction: createInteraction(params?.creationException),
    userGetAssertionInteraction: createInteraction(params?.requestException),
  });

  const instance = new WebAuthnEmulator(authenticator);
  const origin = params?.origin ?? "http://localhost";

  const publicKeyCredentials = {
    isConditionalMediationAvailable: async () => Promise.resolve(params?.autofill ?? true),
    signalUnknownCredential: async (options: UnknownCredentialOptionsJSON) => instance.signalUnknownCredential(options),
    signalAllAcceptedCredentials: async (options: AllAcceptedCredentialsOptionsJSON) =>
      instance.signalAllAcceptedCredentials(options),
    signalCurrentUserDetails: async (options: CurrentUserDetailsOptionsJSON) =>
      instance.signalCurrentUserDetails(options),
    getClientCapabilities: async () => ({ conditionalGet: true }),
    isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
    parseCreationOptionsFromJSON: parseCreationOptionsFromJSON,
    parseRequestOptionsFromJSON: parseRequestOptionsFromJSON,
  } as unknown as typeof PublicKeyCredential & {
    signalUnknownCredential(options: UnknownCredentialOptionsJSON): Promise<void>;
    signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptionsJSON): Promise<void>;
    signalCurrentUserDetails(options: CurrentUserDetailsOptionsJSON): Promise<void>;
    isConditionalMediationAvailable?(): Promise<boolean>;
  };

  const credentialsContainer = {
    get: async (options: CredentialRequestOptions) => instance.get(origin, options ?? {}),
    create: async (options: CredentialCreationOptions) => instance.create(origin, options ?? {}),
  } as unknown as CredentialsContainer;

  const addPasskey = (userId: string) => addTestPasskey(instance, origin, userId, params?.rpId);

  return {
    instance,
    addPasskey,
    methods: {
      credentialsContainer,
      publicKeyCredentials,
    },
  };
};
