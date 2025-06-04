# NID WebAuthn Emulator

[![CI Status](https://github.com/Nikkei/nid-webauthn-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/Nikkei/nid-webauthn-emulator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Nikkei/nid-webauthn-emulator)

`NID WebAuthn Emulator` は、[FIDO2/CTAP Authenticator のエミュレータ](src/authenticator/authenticator-emulator.ts) およびそれを利用した [WebAuthn API のエミュレータ](src/webauthn/webauthn-emulator.ts) ライブラリです。それぞれ WebAuthn API および CTAP の仕様に基づいて実装されています。このモジュールは Node.js 上で動作し、ローカルでの Passkeys の統合テストを目的として設計されています。

それぞれのエミュレータの詳細な仕様は下記を参照してください。

- [FIDO2/CTAP Authenticator Emulator 開発者向け詳細仕様](docs/authenticator-emulator.md)
- [WebAuthn API Emulator 開発者向け詳細仕様](docs/webauthn-emulator.md)

## 使用方法

```bash
npm install nid-webauthn-emulator
```

基本的な使い方は `WebAuthnEmulator` クラスを作成し、`create` および `get` メソッドを利用することで、WebAuthn API における `navigator.credentials.create` および `navigator.credentials.get` をエミュレーションすることができます。

```TypeScript
import WebAuthnEmulator from "nid-webauthn-emulator";

const emulator = new WebAuthnEmulator();
const origin = "https://example.com";

emulator.create(origin, creationOptions);
emulator.get(origin, requestOptions);
```

また、`createJSON` および `getJSON` メソッドを利用することで、WebAuthn API で WebAuthn API 仕様に基づいた JSON データでのエミュレーションを行うこともできます。

```TypeScript
emulator.createJSON(origin, creationOptionsJSON);
emulator.getJSON(origin, requestOptionsJSON);
```

これらの JSON の仕様は、標準仕様の下記に定義されたデータです。

- <https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson>
- <https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson>

`WebAuthnEmulator` クラスは標準で下記の FIDO2/CTAP Authenticator をエミュレートします。

- 自動で User Verification を行います (`uv` フラグを立てます)
- ES256, RS256, EdDSA のアルゴリズムをサポートします
- USB 接続の CTAP2 デバイスをエミュレートします
- AAGUID は `NID-AUTH-3141592` です
- 認証時には Sign Counter を `1` インクリメントさせます

これらの設定は下記のように `AuthenticatorEmulator` クラスを作成し、`WebAuthnEmulator` クラスに渡すことで、Authenticator の挙動を変更することができます。

```TypeScript
import WebAuthnEmulator, { AuthenticatorEmulator } from "nid-webauthn-emulator";

const authenticator = new AuthenticatorEmulator({
  algorithmIdentifiers: ["ES256"],
  verifications: {
    userVerified: false,
    userPresent: false,
  },
  signCounterIncrement: 0,
});

const webAuthnEmulator = new WebAuthnEmulator(authenticator);
```

`AuthenticatorEmulator` は FIDO2/CTAP の仕様のうち下記のコマンドを実装しています。

- `authenticatorMakeCredential` (CTAP2) : 認証情報の作成
- `authenticatorGetAssertion` (CTAP2) : 認証情報の取得
- `authenticatorGetInfo` (CTAP2) : 認証情報の取得

これらは通常は直接利用することはありませんが、`WebAuthnEmulator` クラスの内部で CTAP のプロトコルに従って下記の通り呼び出されています。

```TypeScript
const authenticatorRequest = packMakeCredentialRequest({
  clientDataHash: createHash("sha256").update(clientDataJSON).digest(),
  rp: options.publicKey.rp,
  user: options.publicKey.user,
  pubKeyCredParams: options.publicKey.pubKeyCredParams,
  excludeList: options.publicKey.excludeCredentials,
  options: {
    rk: options.publicKey.authenticatorSelection?.requireResidentKey,
    uv: options.publicKey.authenticatorSelection?.userVerification !== "discouraged",
  },
});
const authenticatorResponse = unpackMakeCredentialResponse(this.authenticator.command(authenticatorRequest));
```

## [WebAuthn.io](https://webauthn.io/) での実行例

WebAuthn の著名なデモサイトである [webauthn.io](https://webauthn.io/) での使用例を示します。[統合テスト](spec/integration/integration.spec.ts) に実際にうごくテストコード例があります。

```TypeScript
// Origin および WebAuthn API エミュレータを初期化します
// ここでは、https://webauthn.io を Origin として利用します
const origin = "https://webauthn.io";
const emulator = new WebAuthnEmulator();
const webauthnIO = await WebAuthnIO.create();
const user = webauthnIO.getUser();

// Authenticator の情報を表示します
console.log("Authenticator Information", emulator.getAuthenticatorInfo());

// WebAuthn API Emulator により パスキーを作成します
const creationOptions = await webauthnIO.getRegistrationOptions(user);
const creationCredential = emulator.createJSON(origin, creationOptions);
await webauthnIO.getRegistrationVerification(user, creationCredential);

// 認証を webauthn.io で検証します
const requestOptions = await webauthnIO.getAuthenticationOptions();
const requestCredential = emulator.getJSON(origin, requestOptions);
await webauthnIO.getAuthenticationVerification(requestCredential);
```

## Playwright による自動テスト

このライブラリは Passkeys の E2E テストでの利用を目的としており、特に Playwright での利用を想定しています。Playwright でのテスト用にユーティリティクラス `BrowserInjection` を利用して簡単に、WebAuthn API エミュレータを利用することができます。使い方は下記の通りです。

```TypeScript
import WebAuthnEmulator, {
  BrowserInjection,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "nid-webauthn-emulator";

async function startWebAuthnEmulator(page: Page, origin: string, debug = false, relatedOrigins: string[] = []) {
  const emulator = new WebAuthnEmulator();

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorCreate,
    async (optionsJSON: PublicKeyCredentialCreationOptionsJSON) => {
      const response = emulator.createJSON(origin, optionsJSON, relatedOrigins);
      return response;
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorGet,
    async (optionsJSON: PublicKeyCredentialRequestOptionsJSON) => {
      const response = emulator.getJSON(origin, optionsJSON, relatedOrigins);
      return response;
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorSignalUnknownCredential,
    async (options: UnknownCredentialOptionsJSON) => {
      emulator.signalUnknownCredential(options);
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorSignalAllAcceptedCredentials,
    async (options: AllAcceptedCredentialsOptionsJSON) => {
      emulator.signalAllAcceptedCredentials(options);
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorSignalCurrentUserDetails,
    async (options: CurrentUserDetailsOptionsJSON) => {
      emulator.signalCurrentUserDetails(options);
    },
  );
}

test.describe("Passkeys Tests", { tag: ["@daily"] }, () => {
  test("Passkeys login test", async ({ page }) => {
    // Page内で最初に1回だけ定義する exposed functions
    // 必要に応じて関連オリジンを指定できます
    const relatedOrigins = ["https://sub.example.com", "https://alt.example.com"];
    await startWebAuthnEmulator(page, env, true, relatedOrigins);
    await page.goto("https://example.com/passkeys/login");

    // Passkeys の WebAuthn API をフック開始
    // ページ遷移後に実行する必要がある
    await page.evaluate(BrowserInjection.HookWebAuthnApis);
  });
});
```

`startWebAuthnEmulator` では Playwright の `exposeFunction` を利用して、`WebAuthnEmulator` の `createJSON` および `getJSON` メソッドをブラウザのコンテキストに注入します。これにより、Playwright でのテストコンテキストにおいて `WebAuthnEmulator` クラスの `get` および `create` の各 API がそれぞれ `window` オブジェクトの下に定義されるようになります。

- `window.webAuthnEmulatorGet`: `WebAuthnEmulator.getJSON` の Exposed Function
- `window.webAuthnEmulatorCreate`: `WebAuthnEmulator.createJSON` の Exposed Function
- `window.webAuthnEmulatorSignalUnknownCredential`: `WebAuthnEmulator.signalUnknownCredential` の Exposed Function
- `window.webAuthnEmulatorSignalAllAcceptedCredentials`: `WebAuthnEmulator.signalAllAcceptedCredentials` の Exposed Function
- `window.webAuthnEmulatorSignalCurrentUserDetails`: `WebAuthnEmulator.signalCurrentUserDetails` の Exposed Function

さらに`startWebAuthnEmulator`関数は`relatedOrigins`パラメータをサポートしています。これにより、異なるオリジンからのリクエストでも同じRP IDを使用できるようになります。例えば、マルチドメイン環境（`example.com`と`sub.example.com`など）でPasskeysを使用する場合に便利です。`relatedOrigins` の値はRP IDで指定されたドメインでホストされた `/.well-known/webauthn` の内容と同じです。

これらは Page グローバルに定義されるため、Page インスタンスにつき 1 回だけ定義する必要があります。

次に `navigator.credentials.get` 等の WebAuthn API をフックするために、`BrowserInjection.HookWebAuthnApis` をテストコンテキストにおいて評価します。

```TypeScript
await page.evaluate(BrowserInjection.HookWebAuthnApis);
```

`BrowserInjection.HookWebAuthnApis` は JavaScript 関数のシリアライズされた文字列であり、評価すると下記のような処理を行います。

- `navigator.credentials.get` の定義を上書きし、`window.webAuthnEmulatorGet` を呼び出す
- `navigator.credentials.create` の定義を上書きし、`window.webAuthnEmulatorCreate` を呼び出す
- `PublicKeyCredential.signalUnknownCredential` の定義を追加し、`window.webAuthnEmulatorSignalUnknownCredential` を呼び出す

これにより先ほどの `exposeFunction` で定義した `WebAuthnEmulator` のメソッドが、`navigator.credentials.get` および `navigator.credentials.create` 呼び出し時に実行されるようになります。これらの処理中にはテストコンテキストと Playwright のコンテキスト間の通信のためにデータのシリアライズおよびデシリアライズが行われるため、そのための処理も含まれています。

## ライセンス

MIT License

Copyright (C) 2024 Nikkei Inc.
