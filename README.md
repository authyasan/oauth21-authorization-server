# oauth21-server

OAuth 2.1 準拠の認可サーバー参考実装。

技術同人誌『OAuth 2.1の仕様だけではわからない設計と実装の判断を学べる本 認可サーバー編 上巻』のサンプルコードです。

## この実装について

- OAuth 2.1（draft-ietf-oauth-v2-1-16）を参照した、単一サービス構成の認可サーバー
- 認可コードグラント + PKCE、リフレッシュトークンローテーション、イントロスペクション、リボケーションに対応
- パブリッククライアント／コンフィデンシャルクライアント両対応
- 歴史的経緯や個別事情を排した「ピュアな実装」を目指しており、本物の認可サーバーを読み解くための土台となることを意図しています

**本実装は教材用です。本番環境でそのまま利用することは想定していません。**

## 書籍との対応

| 章 | 内容 |
|----|------|
| 1 | 認可サーバーの機能 |
| 2 | 全体に影響する設計判断 |
| 3 | 認可エンドポイント |
| 4 | トークンエンドポイント |

リボケーション、イントロスペクション、メタデータなど、下巻で扱う予定のコードも含みます。これらは上巻の解説範囲外で、下巻の執筆に伴って変更する可能性があります。

書籍内のサンプル実装のコード抜粋は、このリポジトリの `src/` と `scripts/` から引用されています。

## Dockerで試す

### 前提

- Docker EngineとDocker Compose v2（`run --build`と`up --wait`に対応した版）、またはそれらを利用できるDocker Desktop等
- インターネット接続（初回のイメージ・パッケージ取得用）
- ホストのTCPポート3000が空いていること

コマンドはリポジトリのルートで実行します。Node.jsとPostgreSQLはコンテナ内で動作するため、ホストへのインストールや`.env`の作成は不要です。
macOSのOrbStackで動作確認しています。WindowsではWSL2とLinuxコンテナを利用する構成を想定していますが、Windowsでの動作確認は未実施です。
WSL2では、リポジトリをLinux側のホームディレクトリ（例: `~/`）にクローンして作業してください。
PostgreSQLの使用バージョンは`compose.quickstart.yaml`、Node.jsの使用バージョンは`Dockerfile`を参照してください。

### 初回の準備

```bash
docker compose -f compose.quickstart.yaml run --rm --build setup
docker compose -f compose.quickstart.yaml up -d --build --wait app
```

`setup`は署名鍵の生成、DBスキーマの適用、テストユーザーの登録を行います。既存の鍵は上書きしません。鍵が片方しかない場合や空の場合は、鍵ファイルの確認を求めて停止します。
DBスキーマの適用は初回の空DBを対象とした手順であり、バージョン更新時のデータ移行手順ではありません。

起動後、http://localhost:3000/health にアクセスし、`{"status":"ok"}`が返ることを確認します。
メタデータは http://localhost:3000/.well-known/oauth-authorization-server で確認できます。これらは起動確認であり、トークン発行の一連の動作を確認するものではありません。

| ユーザー名 | パスワード |
|---|---|
| testuser | password123 |
| admin | admin123 |

上記は教材用の固定値です。実際のアカウント情報を投入したり、インターネットへ公開したりしないでください。クライアント設定は`src/config/clients.json`にあり、クライアントアプリやリソースサーバーはこの構成には含みません。

### 停止と再開

```bash
docker compose -f compose.quickstart.yaml down
docker compose -f compose.quickstart.yaml up -d --wait app
```

DBは`oauth21-quickstart_database`、署名鍵は`oauth21-quickstart_signing_keys`というDockerボリュームに保存します（既定のプロジェクト名を使う場合）。通常の停止・再開では保持され、初期化や鍵の再生成は行いません。`down -v`は両方を削除するため、データを残したい場合は実行しないでください。

ログの確認には次を使います。

```bash
docker compose -f compose.quickstart.yaml logs app
```

コードや設定ファイルを編集した場合は、`up -d --build --wait app`でイメージを再ビルドしてください。ホストの編集内容を自動で取り込む構成ではありません。
アプリのポートはホストの`127.0.0.1:3000`にのみ公開し、DBのポートはホストに公開しません。

## ホストのNode.jsで開発する場合

Dockerの簡易起動とは別の環境です。Node.js 26.12.1とnpm、PostgreSQL用のDockerを準備します。両方のアプリを同時に起動するとポート3000が競合するため、先に片方を停止してください。

```bash
npm ci
cp .env.example .env            # 必要に応じて値を編集
docker compose -f docker-compose.yml up -d # 開発用PostgreSQL起動
npm run db:push                 # スキーマ適用
npm run db:seed                 # テストユーザーの投入
npm run generate-keys           # 初回のみ。既存の署名鍵を上書きするので注意
npm run dev                     # 開発サーバー起動
```

## テスト

次はホストのNode.js環境で実行するコマンドです。結合テストはDBのデータを初期化します。既定では`localhost:5432/oauth21`へ接続するため、保存したいデータがあるDBでは実行しないでください。接続先は`vitest.integration.config.ts`を確認してください。

```bash
npm test                        # ユニットテスト（Vitest）
npm run test:integration        # 結合テスト
```

ブラウザを使うE2Eテストの専用DB・ブラウザの準備は、[test/e2e/README.md](test/e2e/README.md)を参照してください。

## ディレクトリ構成

```
src/
├── index.ts           # エントリーポイント
├── app.ts             # Hono アプリケーション定義
├── endpoints/         # 各エンドポイントのハンドラ
│   ├── authorize.tsx
│   ├── token.ts
│   ├── revoke.ts
│   └── introspect.ts
├── services/          # ビジネスロジック
├── repositories/      # データアクセス層
├── db/                # Drizzle スキーマ・初期データ
├── types/             # 型定義
└── utils/             # ユーティリティ
test/
├── unit/              # Vitest ユニットテスト
├── integration/       # 結合テスト
└── e2e/               # ブラウザのE2Eテスト
```

## セキュリティ対策のマーカー

本文中で解説しているセキュリティ対策の実装箇所には `[SECURITY]` プレフィックス付きのコメントを入れています。

```typescript
// [SECURITY] PKCE検証: code_verifier のハッシュが code_challenge と一致することを確認
// この検証がないと、認可コード横取り攻撃が成立する
```

書籍の続編（攻撃体験編）では、これらの対策を意図的に外した際に何が起こるかを扱う予定です。

## ライセンス

ISC

## 免責事項

本実装は学習・参考目的で提供されています。本番利用にあたっては、ご自身の責任で十分なセキュリティレビューを実施してください。
