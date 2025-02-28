# WebAuthn API Emulator 開発者向け詳細仕様

## 概要

[WebAuthn Emulator](../src//webauthn/webauthn-emulator.ts)は、WebAuthn 仕様に基づいた認証プロセスをシミュレートするためのツールです。主にテストや開発目的で使用されることを想定しています。

## 主要クラス

### WebAuthnEmulator

WebAuthn プロトコルの主要な機能を模倣するクラスです。

#### 主要メソッド

1. `getJSON(origin: string, optionsJSON: PublicKeyCredentialRequestOptionsJSON): AuthenticationResponseJSON`

   - 認証リクエストを処理し、JSON 形式で応答を返します。

2. `createJSON(origin: string, optionsJSON: PublicKeyCredentialCreationOptionsJSON): RegistrationResponseJSON`

   - 資格情報の作成リクエストを処理し、JSON 形式で応答を返します。

3. `getAuthenticatorInfo(): AuthenticatorInfo`

   - オーセンティケータの情報を取得します。

4. `signalUnknownCredential(options: UnknownCredentialOptionsJSON): void`

   - 不明な資格情報を通知し、認証器から削除します。

5. `get(origin: string, options: CredentialRequestOptions): RequestPublicKeyCredential`

   - 認証プロセスをシミュレートします。

6. `create(origin: string, options: CredentialCreationOptions): CreatePublicKeyCredential`
   - 新しい資格情報の作成プロセスをシミュレートします。

## 主要な機能

1. **資格情報の作成**: `create`メソッドを使用して、新しい公開鍵資格情報の作成をシミュレートします。

2. **認証**: `get`メソッドを使用して、既存の資格情報を用いた認証プロセスをシミュレートします。

3. **JSON 互換性**: `getJSON`と`createJSON`メソッドにより、JSON 形式でのリクエストと応答の処理が可能です。

4. **Authenticator 情報**: `getAuthenticatorInfo`メソッドで Authenticator の詳細情報を取得できます。

## セキュリティ考慮事項

- Relying Party ID の検証: 適切な RPID の検証を行い、無効な RPID に対してはエラーを発生させます。
- チャレンジの処理: クライアントデータにチャレンジを含め、適切にハッシュ化して処理します。

## エラーハンドリング

カスタムエラークラスが定義されています：

- `WebAuthnEmulatorError`: 一般的なエミュレータエラー
- `NoPublicKeyError`: 公開鍵オプションが提供されていない場合のエラー
- `InvalidRpIdError`: 無効な Relying Party ID が検出された場合のエラー

## 注意事項

1. このエミュレータは実際の WebAuthn の完全な代替ではありません。テストと開発目的にのみ使用してください。

2. 実際の実装では、より厳密なセキュリティチェックと本番環境に適した設定が必要になる場合があります。

3. このエミュレータは、WebAuthn 仕様の基本的な機能をカバーしていますが、すべての高度な機能や拡張機能をサポートしているわけではありません。

## 使用例

```javascript
const emulator = new WebAuthnEmulator();

// 資格情報の作成
const creationOptions = {
  /* ... */
};
const credential = emulator.createJSON(origin, creationOptions);

// 認証
const requestOptions = {
  /* ... */
};
const assertion = emulator.getJSON(origin, requestOptions);
```

このドキュメントは、提供されたコードの主要な機能と使用方法の概要を説明しています。実際の実装では、より詳細な設定やエラーハンドリングが必要になる場合があります。
