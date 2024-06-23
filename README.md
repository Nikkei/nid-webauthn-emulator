# NID WebAuthn Emulator

## 概要

[Passkeys Authenticator のエミュレータ](src/emulators/authenticator.ts) およびそれを利用した
[WebAuthn API のエミュレータ](src/emulators/webauthn-api.ts) ライブラリです。

主にパスキーを使ったサービスの統合テストに利用します。

## 使用方法

```TypeScript
import { WebAuthnEmulator } from "./emulators/webauthn-api";

const WebAuthnEmulator = new WebAuthnEmulator();

WebAuthnEmulator.create(origin, creationOptions);
WebAuthnEmulator.get(origin, requestOptions);
```

## 実行例

[統合テスト](spec/integration/integration.spec.ts) に使用例があります。

```TypeScript
// Origin および WebAuthn API エミュレータを初期化します
// ここでは、https://webauthn.io を Origin として利用します
const origin = "https://webauthn.io";
const emulator = new WebAuthnEmulator();
const webauthnIO = await WebAuthnIO.create();

// 登録用の Options を webauthn.io から取得します
console.log("Authenticator Information", emulator.getAuthenticatorInfo());

// WebAuthn API Emulator により パスキーを作成します
const creationOptions = await webauthnIO.getRegistrationOptions();
console.log("Registration options", creationOptions);
const creationCredential = emulator.createJSON(origin, creationOptions);
console.log("Registration credential", creationCredential);
await webauthnIO.getRegistrationVerification(creationCredential);
console.log("Registration verification completed");

// 認証を webauthn.io で検証します
const requestOptions = await webauthnIO.getAuthenticationOptions();
console.log("Authentication options", requestOptions);
const requestCredential = emulator.getJSON(origin, requestOptions);
console.log("Authentication credential", requestCredential);
await webauthnIO.getAuthenticationVerification(requestCredential);
console.log("Authentication verification completed");
```

## Playwright による自動テスト

Playwright の `exposeFunction` を利用して、WebAuthn API エミュレータを利用することができます。使い方は下記の通りです。

```TypeScript
import WebAuthnEmulator, { BrowserInjection } from "@nikkei/nid-webauthn-emulator";

async function startWebAuthnEmulator(page: Page, origin: string, debug = false) {
  const emulator = new WebAuthnEmulator();

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorCreate,
    async (optionsJSON: PublicKeyCredentialCreationOptionsJSON) => {
      if (debug) console.log("WebAuthn Emulator Create: Options", optionsJSON);
      const response = emulator.createJSON(origin, optionsJSON);
      if (debug) console.log("WebAuthn Emulator Create: Response", response);
      return response;
    },
  );

  await page.exposeFunction(
    BrowserInjection.WebAuthnEmulatorGet,
    async (optionsJSON: PublicKeyCredentialRequestOptionsJSON) => {
      if (debug) console.log("WebAuthn Emulator Get: Options", optionsJSON);
      const response = emulator.getJSON(origin, optionsJSON);
      if (debug) console.log("WebAuthn Emulator Get: Response", response);
      return response;
    },
  );
}

test.describe("Passkeys Tests", { tag: ["@daily"] }, () => {
  test("Passkeys login test", async ({ page }) => {
    // Page内で最初に1回だけ定義する exposed functions
    await startWebAuthnEmulator(page, env, true);
    await page.goto("https://example.com/passkeys/login");

    // Passkeys の WebAuthn API をフック開始
    // ページ遷移後に実行する必要がある
    await page.evaluate(BrowserInjection.HookWebAuthnApis);
  });
});
```

## ライセンス

MIT
