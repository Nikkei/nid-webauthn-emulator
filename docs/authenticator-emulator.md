# FIDO2/CTAP Authenticator Emulator 開発者向け詳細仕様

## 概要

[Authenticator Emulator](../src/authenticator/authenticator-emulator.ts)は、FIDO2 準拠の認証器をソフトウェアでシミュレートするためのツールです。主に WebAuthn 実装のテストや開発に使用することを想定しています。

## 主要クラス

### AuthenticatorEmulator

CTAP プロトコルに基づいた認証器の主要な機能を模倣するクラスです。

#### 主要メソッド

1. `command(request: CTAPAuthenticatorRequest): CTAPAuthenticatorResponse`

   - CTAP コマンドを受け取り、適切な応答を返します。

2. `authenticatorGetInfo(): AuthenticatorGetInfoResponse`

   - 認証器の情報を返します。

3. `authenticatorMakeCredential(request: AuthenticatorMakeCredentialRequest): AuthenticatorMakeCredentialResponse`

   - 新しい資格情報を作成します。

4. `authenticatorGetAssertion(request: AuthenticatorGetAssertionRequest): AuthenticatorGetAssertionResponse`
   - 既存の資格情報を使用して認証を行います。

## 主要な機能

1. **資格情報の作成**: `authenticatorMakeCredential`メソッドを使用して、新しい公開鍵資格情報の作成をシミュレートします。

2. **認証**: `authenticatorGetAssertion`メソッドを使用して、既存の資格情報を用いた認証プロセスをシミュレートします。

3. **認証器情報の取得**: `authenticatorGetInfo`メソッドで認証器の詳細情報を取得できます。

4. **CTAP コマンドの処理**: `command`メソッドで CTAP プロトコルに基づいたコマンドを処理します。

5. **カスタマイズ可能なパラメータ**: AAGUID やサポートするアルゴリズム、ユーザー操作のシミュレーションなど、様々な認証器のパラメータをカスタマイズできます。

6. **ステートレスモード**: 認証器の状態を保持せず、各コマンドの処理を独立して行います。

## セキュリティ考慮事項

- 排他リストと許可リストの処理: 資格情報の作成時や認証時に、適切な資格情報のフィルタリングを行います。
- 署名カウンターの管理: 認証ごとに署名カウンターを増加させ、再生攻撃を防止します。

## エラーハンドリング

`AuthenticationEmulatorError`クラスを使用して、CTAP プロトコルに基づいたエラーコードを返します。

## 注意事項

1. このエミュレータは実際のハードウェア認証器の完全な代替ではありません。テストと開発目的にのみ使用してください。

2. 実際の実装では、より厳密なセキュリティチェックと本番環境に適した設定が必要になる場合があります。

3. このエミュレータは、FIDO2/WebAuthn 仕様の基本的な機能をカバーしていますが、すべての高度な機能や拡張機能をサポートしているわけではありません。

## カスタマイズ

`AuthenticatorParameters`を使用して、以下の項目をカスタマイズできます：

- AAGUID
- サポートする転送プロトコル
- サポートする暗号アルゴリズム
- 署名カウンターの増分
- ユーザー検証と存在確認のシミュレーション
- ユーザーインタラクションのシミュレーション
- 資格情報の保存方法
- ステートレスモードの有効化

## 使用例

```javascript
const emulator = new AuthenticatorEmulator({
  aaguid: new Uint8Array([
    /* カスタムAAGUID */
  ]),
  algorithmIdentifiers: ["ES256", "RS256"],
  // その他のカスタムパラメータ
});

// MakeCredentialコマンドの処理
const makeCredentialRequest = {
  /* ... */
};
const credentialResponse = emulator.command({
  command: CTAP_COMMAND.authenticatorMakeCredential,
  request: makeCredentialRequest,
});

// GetAssertionコマンドの処理
const getAssertionRequest = {
  /* ... */
};
const assertionResponse = emulator.command({
  command: CTAP_COMMAND.authenticatorGetAssertion,
  request: getAssertionRequest,
});
```

このドキュメントは、提供された CTAP ベースの Authenticator エミュレータコードの主要な機能と使用方法の概要を説明しています。実際の実装では、より詳細な設定やエラーハンドリング、セキュリティ考慮事項が必要になる場合があります。
