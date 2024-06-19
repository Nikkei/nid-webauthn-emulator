# NID WebAuthn Emulator

## 概要

[Passkeys Authenticator のエミュレータ](src/emulators/authenticator.ts) およびそれを利用した
[WebAuthn API のエミュレータ](src/emulators/webauthn-api.ts) ライブラリです。

主にパスキーを使ったサービスの統合テストに利用します。

## 使用方法

```TypeScript
import { WebAuthnApiEmulator } from "./emulators/webauthn-api";

const webAuthnApiEmulator = new WebAuthnApiEmulator();

webAuthnApiEmulator.create(origin, creationOptions);
webAuthnApiEmulator.get(origin, requestOptions);
```

## 実行例

[統合テスト](spec/integration/integration.spec.ts) に使用例があります。

```TypeScript
// Origin および WebAuthn API エミュレータを初期化します
// ここでは、https://webauthn.io を Origin として利用します
const origin = "https://webauthn.io";
const webAuthnApiEmulator = new WebAuthnApiEmulator();
const webauthnIO = await WebAuthnIO.create();

// 登録用の Options を webauthn.io から取得します
const creationOptions = { publicKey: parseCreationOptionsFromJSON(await webauthnIO.getRegistrationOptions()) };
console.log("Registration options", creationOptions);

// WebAuthn API Emulator により パスキーを作成します
const creationCredential = await webAuthnApiEmulator.create(origin, creationOptions);
console.log("Registration credential", creationCredential.toJSON());

// パスキーの登録を webauthn.io に通知します
await webauthnIO.getRegistrationVerification(creationCredential.toJSON());
console.log("Registration verification completed");

// 認証用の Options を webauthn.io から取得します
const requestOptions = { publicKey: parseRequestOptionsFromJSON(await webauthnIO.getAuthenticationOptions()) };
console.log("Authentication options", requestOptions);

// WebAuthn API Emulator により 先ほど登録したパスキーで認証します
// 選択されるパスキーは、登録時に作成したパスキーと同じです
const requestCredential = await webAuthnApiEmulator.get(origin, requestOptions);
console.log("Authentication credential", requestCredential.toJSON());

// 認証を webauthn.io で検証します
await webauthnIO.getAuthenticationVerification(requestCredential.toJSON());
console.log("Authentication verification completed");
```

## ライセンス

MIT
