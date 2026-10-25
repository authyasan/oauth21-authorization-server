# E2Eテスト（Playwright）

## 目的

実ブラウザ（Chromium）の挙動に依存する防御と画面遷移だけを確かめる。
APIの正常系・異常系の網羅は結合テスト（`test/integration`）が担い、ここでは重複させない。

| ファイル                     | 内容                                                                                                                                                                                                   |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `authorization-flow.spec.ts` | ログイン→同意→callback→トークン交換、同意の拒否、同意の省略とscope追加時の再同意、認証失敗後の再試行、直接ログイン、複数タブ、ログイン時のCookie更新、POST後の303とGETの302                            |
| `browser-security.spec.ts`   | 別サイトからのPOST（SameSite=Lax）、同一サイト別オリジンからのPOST（CSRFトークン）、Cookie tossing（`__Host-`接頭辞）、ログイン画面とログイン済みの同意画面のiframe埋め込みの拒否、Refererによる漏えい |
| `db-guard.spec.ts`           | `/reset` の削除がE2E専用DB以外に向かないことの回帰テスト（ブラウザは使わない。削除は実行しない）                                                                                                       |

拒否を確かめるテストには、同じ手順で成功する対照を置いている。拒否が無関係なエラーで起きていないことを確かめるため。

## 継続運用

Cookie属性、リダイレクトのステータスコード、セキュリティヘッダ、ログイン・同意の画面やフォームなど、ブラウザの挙動に関わる実装を変えたときは、このE2Eを合わせて更新して実行する。

## 準備（初回のみ）

1. PostgreSQL にE2E専用のデータベース `oauth21_e2e_test` を作る。既定の接続先は `postgresql://oauth21:csrf_test_only@127.0.0.1:5493/oauth21_e2e_test`。変える場合は環境変数 `E2E_DATABASE_URL` を指定する。DB名は `oauth21_e2e_test` でなければならない（「誤接続の防止」の節）。
2. スキーマを反映する。

   ```sh
   DATABASE_URL=postgresql://oauth21:csrf_test_only@127.0.0.1:5493/oauth21_e2e_test npx drizzle-kit push --force
   ```

3. JWT署名鍵（`keys/`）を用意する（`npm run generate-keys`）。
4. Playwright の Chromium を入れる（`npx playwright install chromium`）。

## 実行

リポジトリのルートで実行する。

```sh
npm run test:e2e
# 一部だけ: npm run test:e2e -- browser-security.spec.ts
```

Playwright がE2E用サーバーを起動し、終了時に止める。各テストの前にDBとメモリ上の状態を初期化するので、繰り返し実行できる。
別のディレクトリから実行する場合も、`-c` に設定ファイルへの正しいパスを渡せば、起動されるサーバーの作業ディレクトリはリポジトリのルートに固定される（設定ファイルが自分の位置からルートを解決する）。
ポート 18443・18444 が使用中だと起動に失敗する。
失敗時のトレースは `$TMPDIR/oauth21-e2e-results/` に出る。

## 環境の組み立て

- `server.ts` が1つのHTTPSポート（18443）で、Hostヘッダによって役割を切り替える。認可サーバー本体（`as.example.test`）、テスト用クライアントのcallback（`client.example.test`）、同一サイトの別オリジン（`other.example.test`・`sub.example.test`）、別サイト（`evil.test`）。
- ホスト名は Chromium の `--host-resolver-rules` でブラウザ内だけ 127.0.0.1 に向ける。`/etc/hosts` は変更しない。
- 証明書は初回起動時に openssl で自己署名証明書を作り、`$TMPDIR/oauth21-e2e-certs/` に置く。OSの信頼ストアには登録しない。ブラウザ側は Playwright の `ignoreHTTPSErrors`（テストのcontextに限る）で検証を省略する。Cookie・SameSite・CSPなどの仕組みには手を加えない。
- サーバーは `NODE_ENV=production` で動かす（`__Host-sid`・Secure）。`ISSUER` は `https://as.example.test:18443`。
- テスト用クライアント `public-spa-client` に、非ループバックのHTTPSリダイレクトURI `https://client.example.test:18443/callback` を実行時だけ追加する。`clients.json` は変更しない。
- テストの準備は 127.0.0.1:18444（HTTP）の制御エンドポイントで行う（`POST /reset`、`GET /callbacks`）。認可サーバーのアプリにはテスト用の経路を足さない。

## 誤接続の防止

`POST /reset` は全テーブルを削除するので、E2E専用DB以外に向かないよう2段階で確かめる（`db-guard.ts`）。

1. 起動時（`env-guard.ts`。`server.ts` の最初に読み込み、DBに接続するモジュールより前に評価する）: `DATABASE_URL` をURLとして解析し、DB名が `oauth21_e2e_test` と完全一致することを確かめる。ユーザー名・パスワード・ホスト名・クエリにだけ同じ文字列がある場合や、似た名前のDBは拒否する。クエリ付きのURLも受け付けない。`NODE_ENV=production` でなければ起動しない。
2. 実際の接続先: 起動時と、`/reset` で削除する直前に、アプリの接続（`src/db/connection.ts`）と削除に使う接続（`test/integration/helpers.ts`）の両方で `current_database()` を問い合わせる。どちらかが `oauth21_e2e_test` でなければ削除へ進まない。

回帰テスト（`db-guard.spec.ts`）は、紛らわしいURLの拒否、別の実在DB（PostgreSQL標準の `postgres`。読み取りだけで変更しない）に接続したときに削除処理が呼ばれないこと、不正なURLでサーバーが接続前に起動を中止することを確かめる。削除処理は実行せず、呼ばれた回数だけを数える。

## 後片付け

- 証明書: `rm -rf "$TMPDIR/oauth21-e2e-certs"`
- データベース: `DROP DATABASE oauth21_e2e_test;`
- トレース: `rm -rf "$TMPDIR/oauth21-e2e-results"`

## 対象外

- Firefox・WebKit は実行していない。
- 実ドメインと公的な証明書での確認はしていない。
- CIには組み込んでいない。
