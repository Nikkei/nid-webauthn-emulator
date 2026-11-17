# NID WebAuthn Emulator

[![CI Status](https://github.com/Nikkei/nid-webauthn-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/Nikkei/nid-webauthn-emulator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[English](README.md) | [日本語](README.ja.md)

`NID WebAuthn Emulator` は、[FIDO2/CTAP Authenticator のエミュレータ](src/authenticator/authenticator-emulator.ts) およびそれを利用した [WebAuthn API のエミュレータ](src/webauthn/webauthn-emulator.ts) ライブラリです。それぞれ WebAuthn API および CTAP の仕様に基づいて実装されています。このモジュールは Node.js 上で動作し、ローカルでの Passkeys の統合テストを目的として設計されています。

それぞれのエミュレータの詳細な仕様は下記を参照してください。

- [FIDO2/CTAP Authenticator Emulator 開発者向け詳細仕様](docs/authenticator-emulator.ja.md)
- [WebAuthn API Emulator 開発者向け詳細仕様](docs/webauthn-emulator.ja.md)

## 使用方法

```bash
npm install nid-webauthn-emulator
```

基本的な使い方は `WebAuthnEmulator` クラスを作成し、`create` および `get` メソッドを利用することで、WebAuthn API における `navigator.credentials.create` および `navigator.credentials.get` をエミュレーションすることができます。

```TypeScript
import { WebAuthnEmulator } from "nid-webauthn-emulator";

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
import { WebAuthnEmulator, AuthenticatorEmulator } from "nid-webauthn-emulator";

const authenticator = new AuthenticatorEmulator({
  algorithmIdentifiers: ["ES256"],
  verifications: {
    userVerified: false,
    userPresent: false,
  },
  signCounterIncrement: 0,
  hmacSecret: "hmac-secret-mc",
});

const webAuthnEmulator = new WebAuthnEmulator(authenticator);
```

`hmacSecret` オプションは、WebAuthn の [PRF 拡張](https://www.w3.org/TR/webauthn-3/#prf-extension) の実装のバックエンドとなりうる CTAP2 拡張の有無を制御します。認証時にのみ評価するなら `"hmac-secret"`、登録時にも評価するなら（CTAP 2.2）`"hmac-secret-mc"`、拡張を使わないなら `"none"`（デフォルト）を指定します。

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

## 登録・認証レスポンスの検証

`verifyRegistration` と `verifyAuthentication` は、WebAuthnの登録・認証レスポンスをRP側の期待値と照合する同期APIです。登録時には検証済みのcredentialを返し、認証時には登録済み公開鍵で署名を検証して、カウンターと認証器のフラグを返します。

両関数は状態を持たず、`createJSON` / `getJSON` または `PublicKeyCredential.toJSON()` のJSONレスポンスを受け取ります。呼び出し側で保持した登録・認証処理の期待値として、`expectedChallenge`（パディングなしBase64URL）、`expectedOrigin`、`expectedRPID` を明示的に渡します。

```TypeScript
import { randomBytes } from "node:crypto";
import {
  WebAuthnEmulator,
  verifyRegistration,
  verifyAuthentication,
  type VerifiedCredential,
} from "nid-webauthn-emulator";

const emulator = new WebAuthnEmulator();
const origin = "https://example.com";
const rpId = "example.com";
const expected = { expectedOrigin: origin, expectedRPID: rpId };
const creationOptions: PublicKeyCredentialCreationOptionsJSON = {
  challenge: randomBytes(32).toString("base64url"),
  rp: { id: rpId, name: "Example" },
  user: { id: "dGVzdA", name: "test", displayName: "Test user" },
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  authenticatorSelection: { userVerification: "required" },
  attestation: "none",
};
const registration = verifyRegistration({
  response: emulator.createJSON(origin, creationOptions),
  expectedChallenge: creationOptions.challenge,
  supportedAlgorithmIDs: creationOptions.pubKeyCredParams.map(({ alg }) => alg),
  ...expected,
});
const credential: VerifiedCredential = JSON.parse(JSON.stringify(registration.credential));

const requestOptions: PublicKeyCredentialRequestOptionsJSON = {
  challenge: randomBytes(32).toString("base64url"),
  rpId,
  allowCredentials: [{ id: credential.id, type: "public-key" }],
  userVerification: "required",
};
const authentication = verifyAuthentication({
  response: emulator.getJSON(origin, requestOptions),
  credential,
  expectedChallenge: requestOptions.challenge,
  ...expected,
});
credential.counter = authentication.newCounter;
credential.backupState = authentication.backupState;
```

`VerifiedCredential` はJSONで保存・復元できます。`publicKey` はBase64URL形式のCOSE公開鍵で、ほかに `id`、`algorithm`、`counter`、`backupEligible`、`backupState` を持ちます。認証検証は渡されたcredentialを変更しません。成功後にだけ、戻り値の `newCounter` と `backupState` を保存してください。登録・認証の戻り値には、`userPresent`、`userVerified`、`backupEligible`、`backupState` も含まれます。

対応範囲と検証方針は以下のとおりです。

- 登録は `none` attestationのみ対応し、attestation statementは空を要求します。credential IDの長さは1〜1023バイトです。
- 対応鍵はES256（P-256、署名はDER形式）、EdDSA（Ed25519）、RS256（2048ビット以上のRSA鍵）です。`supportedAlgorithmIDs` には登録時の `pubKeyCredParams` で提示したアルゴリズムを渡します。省略時はこの3種類を許可します。
- UP（ユーザー操作）は常に必須です。`requireUserVerification` は両関数でデフォルト `true`、UVを任意にする場合は `false` を指定します。署名対象の変更や署名検証の省略は行いません。
- カウンターは保存値・受信値が両方0の場合を除き、増加を要求します。バックアップ可否（BE）の変化は拒否し、バックアップ状態（BS）の変化は許可します。
- 認証器の拡張データはCBORマップとして検査し、認証署名の対象に含めます。PRFの計算結果など、個々の拡張の意味は検証しません。

失敗時は `WebAuthnVerificationError` を投げます。分岐やテストのassertには `code` を使用してください。`message` は診断用で、下位のパーサー・暗号処理のエラーが `cause` に入る場合があります。

| コード                                                                              | 意味                                             |
| ----------------------------------------------------------------------------------- | ------------------------------------------------ |
| `INVALID_OPTIONS`                                                                   | 期待値・検証方針・保存状態の欠落や不正           |
| `INVALID_RESPONSE`、`INVALID_PUBLIC_KEY`                                            | レスポンスや公開鍵の形式が不正                   |
| `CHALLENGE_MISMATCH`、`ORIGIN_MISMATCH`、`RP_ID_MISMATCH`、`CREDENTIAL_ID_MISMATCH` | 期待する登録・認証処理やcredentialとの不一致     |
| `USER_PRESENCE_REQUIRED`、`USER_VERIFICATION_REQUIRED`                              | 必須フラグがない                                 |
| `UNSUPPORTED_ATTESTATION`、`UNSUPPORTED_ALGORITHM`、`UNSUPPORTED_CROSS_ORIGIN`      | 未対応の形式・機能                               |
| `ALGORITHM_NOT_ALLOWED`                                                             | `supportedAlgorithmIDs` に含まれないアルゴリズム |
| `INVALID_BACKUP_FLAGS`、`BACKUP_ELIGIBILITY_MISMATCH`                               | バックアップフラグの矛盾やBEの変化               |
| `COUNTER_NOT_INCREASED`、`INVALID_SIGNATURE`                                        | カウンター検査や署名検証の失敗                   |

challengeの生成・期限・一度限りの消費、セッションやアカウントとの紐付け、credentialの所有者と `userHandle` の確認、永続化は呼び出し側の責務です。

cross-originの処理、attestationの証明書チェーン、メタデータの信頼性評価は実装していません。プロトコルのフィールドとCOSE鍵の解釈はエミュレーターのヘルパーから分離し、共有するCBORの基本デコーダーは固定ベクトルでも検証しています。

## [WebAuthn.io](https://webauthn.io/) での実行例

WebAuthn の著名なデモサイトである [webauthn.io](https://webauthn.io/) での使用例を示します。[統合テスト](spec/integration/integration.spec.ts) に実際にうごくテストコード例があります。

webauthn.io の統合テストは外部サイトに依存するため、通常の `pnpm test` ではスキップされます。このテストだけを実行する場合は、下記のコマンドを利用してください。

```sh
pnpm test:webauthn-io
```

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
import {
  WebAuthnEmulator,
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

## ユニットテストでの WebAuthn API フック

ユニットテストで WebAuthn API を差し替えたい場合は、`src/test-utils/unit-test.ts` の `createPasskeysEmulator` を使うと `PublicKeyCredential` / `navigator.credentials` を簡単にモックできます。

```TypeScript
import { createPasskeysEmulator } from "nid-webauthn-emulator";

const { methods, addPasskey } = createPasskeysEmulator({
  origin: "http://localhost",
  rpId: "localhost",
  autofill: true, // isConditionalMediationAvailable() と conditionalGet の返り値を設定
  // creationException / requestException を指定すると DOMException が発生する挙動を注入できます
});

params?.existingPasskeys?.forEach((passkey) => {
  addPasskey(passkey); // テスト開始前に登録済みパスキーを追加
});

// 既存の実装を消し、エミュレータを差し込む
vi.stubGlobal("PublicKeyCredential", methods.publicKeyCredentials);
vi.stubGlobal("navigator", { credentials: methods.credentialsContainer });
```

## ライセンス

MIT License

Copyright (C) 2024 Nikkei Inc.
