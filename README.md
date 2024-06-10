# テスト用 Passkeys Authenticator デモ

## 概要

Passkeys Authenticator のエミュレータおよび <https://webauthn.io/> でのデモアプリです。

## 実行方法

<https://webauthn.io/> でパスキーの登録、および登録したパスキーでのログインを行います。

```bash
git clone
cd nid-passkeys-authenticator-demo
npm install
npm test
```

[パスキーAPIインターフェース](src/test-utils/passkeys-api-client.ts) の実装を行うことで、その他のサイトのパスキーにも対応可能です。

## 参考資料

このコードは [Bitwarden](https://github.com/bitwarden/clients) (GPL 3.0) のコードを参考または一部利用しています。ライセンスに注意して利用してください。
