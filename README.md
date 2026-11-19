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

### 上下巻とコード・テストの範囲

このリポジトリには、上巻の範囲に加えて、下巻で扱う予定の実装とテストも含みます。下巻部分は執筆・設計の整理が途中のもので、完成版ではありません。振る舞いや構成、テストの期待結果は、下巻の執筆に伴って変更する可能性があります。

| 範囲 | 主な処理 | 実装を読む際の入口 |
|---|---|---|
| 上巻 | 認可、ログイン・同意、トークン発行・更新 | `src/endpoints/authorize.tsx`、`login.tsx`、`token.ts` |
| 下巻予定 | リボケーション、イントロスペクション、公開鍵・メタデータの提供 | `src/endpoints/revoke.ts`、`introspect.ts`、`jwks.ts`、`metadata.ts` |
| 共通 | クライアント認証、DB操作、設定、エラー処理など | `src/services/`、`repositories/`、`db/`、`config/`、`middleware/`など |

表は解説範囲と代表的な入口の対応です。サービスやDBの処理は複数のエンドポイントで共有しており、ディレクトリ単位で上下巻に分かれているわけではありません。公開鍵の役割など、下巻予定の機能の概要を上巻で説明する場合もあります。

テストは巻別ではなく、単体・結合・E2Eに分けています。例えば`test/integration/oauth-flow.test.ts`には、認可・トークン発行とリボケーション・イントロスペクションのテストが同居しています。トークン発行のテストで、JWTの検証や無効化結果の確認のために下巻予定のエンドポイントを使う場合もあります。下巻部分にテストがあることやテストが成功することは、下巻の設計・解説が確定済みであることを意味しません。

書籍内のサンプル実装のコード抜粋は、このリポジトリの `src/` と `scripts/` から引用されています。

エンドポイントの振る舞い、保存方法、主な設計意図は[サンプル実装の機能と設計](サンプル実装の機能と設計.md)を参照してください。

## サンプルコードの取得と版の選択

Gitを用意し、次のコマンドで取得します。WindowsではWSL2のターミナルで、Linux側のホームディレクトリに配置してください。

```bash
git clone https://github.com/authyasan/oauth21-authorization-server.git
cd oauth21-authorization-server
```

現在は刊行前の準備版です。上巻対応タグ`upper-v1.0.0`は未作成です。
<!-- TODO(RELEASE): タグ作成後、対応版と実際のgit switch --detachコマンドを掲載し、未ログインで取得手順を検証する。 -->

対応版の公開後は、取得したREADMEで案内するタグを選び、`git switch --detach タグ名`で切り替えてから起動してください。`detached HEAD`は特定の版を選んだ状態であり、動作確認には問題ありません。刊行後の修正版も新しいタグで案内します。既存のタグは付け替えません。

版を切り替えると手元のREADMEもその版に戻ります。取得後の修正版の案内は、[GitHub上のリポジトリのトップページ](https://github.com/authyasan/oauth21-authorization-server)で確認してください。

## Dockerで試す

### 前提

- Docker EngineとDocker Compose v2（`run --build`と`up --wait`に対応した版）、またはそれらを利用できるDocker Desktop等
- インターネット接続（初回のイメージ・パッケージ取得用）
- ホストのTCPポート3000が空いていること

コマンドはリポジトリのルートで実行します。Node.jsとPostgreSQLはコンテナ内で動作するため、ホストへのインストールや`.env`の作成は不要です。
macOS 26.5.2上のOrbStack 2.2.5で動作確認しています。WindowsではWSL2とLinuxコンテナを利用する構成を想定していますが、Windowsでの動作確認は未実施です。
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

上記のパスワードと付属のクライアントシークレットは公開された固定値です。実際のサービスへ流用しないでください。クライアント設定は`src/config/clients.json`にあり、クライアントアプリやリソースサーバーはこの構成には含みません。

付属のDocker構成は手元での動作確認用です。クラウド上で動かす場合は、接続元を限定するなど、第三者がアクセスできない環境を用意してください。インターネットへ公開するための構成や運用上の対策は、この手順の説明範囲外です。

### 停止と再開

```bash
docker compose -f compose.quickstart.yaml down
docker compose -f compose.quickstart.yaml up -d --wait app
```

DBは`oauth21-quickstart_database`、署名鍵は`oauth21-quickstart_signing_keys`というDockerボリュームに保存します（既定のプロジェクト名を使う場合）。通常の停止・再開では保持され、初期化や鍵の再生成は行いません。メモリ上のログインセッションは停止すると失われるため、認可コードの取得を再び試す場合はログインからやり直します。

ログの確認には次を使います。

```bash
docker compose -f compose.quickstart.yaml logs app
```

リクエストを送りながらログを見る場合は、別のターミナルで次を実行します。`Ctrl+C`でログの表示を終了しても、認可サーバーは停止しません。

```bash
docker compose -f compose.quickstart.yaml logs -f app
```

コードや設定ファイルを編集した場合は、`up -d --build --wait app`でイメージを再ビルドしてください。ホストの編集内容を自動で取り込む構成ではありません。
アプリのポートはホストの`127.0.0.1:3000`にのみ公開し、DBのポートはホストに公開しません。

### 初期状態からやり直す

次の操作はDBのデータと署名鍵を削除します。ユーザー、同意記録、認可コードやトークンの記録も失われるため、残したいデータや鍵がある場合は実行しないでください。手元のソースコードと設定ファイルは残ります。

```bash
docker compose -f compose.quickstart.yaml down --volumes
docker compose -f compose.quickstart.yaml run --rm --build setup
docker compose -f compose.quickstart.yaml up -d --build --wait app
```

新しい署名鍵とDBが作成されます。動作確認は認可コードの取得からやり直してください。

## ホストのNode.jsで開発する場合

Dockerの簡易起動とは別の環境です。Node.js 26.13.1とnpm、PostgreSQL用のDockerを準備します。両方のアプリを同時に起動するとポート3000が競合するため、先に片方を停止してください。

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

次はホストのNode.js環境で実行するコマンドです。結合テストには専用DB `oauth21_integration_test`を使い、テストごとにデータを初期化します。動作確認用の`oauth21`とは分けています。付録Aの`compose.quickstart.yaml`による起動・停止手順は変更ありません。

結合テストの初回実行前に、ホスト実行用のPostgreSQLを起動し、専用DBとテーブルを作成してください。`createdb`は初回だけ実行します。

```bash
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml exec postgres createdb -U oauth21 oauth21_integration_test
DATABASE_URL=postgresql://oauth21:oauth21_dev_password@localhost:5432/oauth21_integration_test npm run db:push
```

ホスト実行用の依存パッケージと署名鍵も必要です。前節の手順で準備済みなら、再生成は不要です。ユーザーなどのデータはテスト内で作成するため、専用DBへの`db:seed`は不要です。

結合テストは通常起動用の`DATABASE_URL`を引き継ぎません。接続先のホスト・ポート・認証情報を変える場合は`INTEGRATION_DATABASE_URL`を指定してください。DB名は`oauth21_integration_test`に固定し、クエリ付きのURLは受け付けません。設定に加えて実際のDB名もテスト初期化前に確認します。

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

サンプルコードと付属の説明文書は[MITライセンス](LICENSE)で提供します。書籍本文・図版はこの許諾の対象外です。

依存する第三者OSSには、それぞれのライセンスが適用されます。[第三者OSSのライセンスについて](THIRD_PARTY_NOTICES.md)を参照してください。

## 免責事項

本実装は学習・参考目的で提供されています。本番利用にあたっては、ご自身の責任で十分なセキュリティレビューを実施してください。
