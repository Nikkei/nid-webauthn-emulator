# Contribution Guide

このリポジトリへのコントリビュート方法についてのガイドです。

## プロダクトの概要

このプロダクトは Node.js / TypeScript / pnpm / biome といった技術を使って開発されています。
初めての方は、[README.md](README.md) をご覧ください。

## 開発環境のセットアップ

依存関係の導入は lockfile を固定したまま行ってください。

```bash
pnpm install --frozen-lockfile
```

このリポジトリでは `pnpm-workspace.yaml` で依存関係の新規公開直後の導入を遅延させ、依存パッケージの install script を明示許可制にしています。サプライチェーン攻撃への耐性を下げるため、`--no-frozen-lockfile` や無差別な依存更新は避けてください。

## プルリクエストの作成方法

本レポジトリを Fork しローカルにて修正を行った後、本リポジトリに向けてプルリクエストを作成してください。

## Issues

次の Issue を受け付けています。

- Passkeys / WebAuthn の標準仕様に関する指摘
- 内容のエラーや問題の報告

頂いた Issue や PR は、可能な限り拝見いたしますが、全てに対応できるわけではありません。

## Pull Request

Pull Request はいつでも歓迎しています。

### 受け入れる Pull Request

次の種類の Pull Request を受け付けています。

- Passkeys / WebAuthn に関する標準仕様関連の修正
- 内容のエラーや問題の修正
