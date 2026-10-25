import { sql } from "drizzle-orm";
import {
	type AnyPgColumn,
	index,
	pgTable,
	text,
	timestamp,
	uniqueIndex,
	uuid,
} from "drizzle-orm/pg-core";

// ユーザーテーブル
// 簡易的なID/パスワード認証用。本格的なユーザー管理は認可サーバーのスコープ外。
export const users = pgTable("users", {
	id: uuid("id").primaryKey().defaultRandom(),
	username: text("username").notNull().unique(),
	passwordHash: text("password_hash").notNull(),
	createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
	updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// grant（認可付与）テーブル
// ユーザーがクライアントに scope を付与した認可関係そのものを表す上位概念。
// 認可コード・アクセストークン・リフレッシュトークンを束ねる grouping の起点であり、
// grant 単位のカスケード失効・認可コード再使用検知の単位として機能する。
// 認可フローが完了するたびに1行作る。
export const grants = pgTable(
	"grants",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		clientId: text("client_id").notNull(),
		userId: uuid("user_id")
			.notNull()
			.references(() => users.id),
		// スコープはスペース区切りで保存
		scope: text("scope").notNull(),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
		// [SECURITY] grant 単位の失効時刻。カスケード失効・再使用検知でセットする。
		// この grant に紐づく全トークンが失効したことを表す集約記録。
		revokedAt: timestamp("revoked_at", { withTimezone: true }),
	},
	(table) => [
		index("idx_grants_client_id").on(table.clientId),
		index("idx_grants_user_id").on(table.userId),
	],
);

// 認可コードテーブル
// [SECURITY] コードはSHA-256ハッシュで保存。DB漏洩時に認可コードが直接漏れることを防ぐ。
export const authorizationCodes = pgTable(
	"authorization_codes",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		// [SECURITY] 認可コードのSHA-256ハッシュ。平文は保存しない。
		// unique 制約が作る索引で検索するので、別の索引は作らない。
		codeHash: text("code_hash").notNull().unique(),
		// この認可コードが属する grant への参照
		grantId: uuid("grant_id")
			.notNull()
			.references(() => grants.id),
		clientId: text("client_id").notNull(),
		userId: uuid("user_id")
			.notNull()
			.references(() => users.id),
		redirectUri: text("redirect_uri").notNull(),
		scope: text("scope").notNull(),
		// [SECURITY] PKCE: code_challengeを保存し、トークン交換時にcode_verifierと照合する
		codeChallenge: text("code_challenge").notNull(),
		codeChallengeMethod: text("code_challenge_method").notNull().default("S256"),
		expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
		// 使用済みフラグ。nullでない場合は使用済み。
		usedAt: timestamp("used_at", { withTimezone: true }),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
	},
	(table) => [
		index("idx_authorization_codes_client_id").on(table.clientId),
		index("idx_authorization_codes_grant_id").on(table.grantId),
	],
);

// アクセストークンテーブル
// JWTアクセストークンのメタデータを保存。jtiで管理し、リボケーション・イントロスペクションに使用。
export const accessTokens = pgTable(
	"access_tokens",
	{
		// JWTのjtiクレームと一致する識別子
		jti: text("jti").primaryKey(),
		// [SECURITY] この AT が属する grant への参照。
		// カスケード失効・再使用検知はこの grant_id を grouping key にする。
		grantId: uuid("grant_id")
			.notNull()
			.references(() => grants.id),
		clientId: text("client_id").notNull(),
		userId: uuid("user_id")
			.notNull()
			.references(() => users.id),
		scope: text("scope").notNull(),
		// 発行時に JWT の aud へ入れたリソースサーバーIDの集合。
		// イントロスペクションは現在の scope→RS 設定から計算し直さず、この値を使う。
		// 設定を変えても、発行済みトークンの照会結果が JWT の aud と食い違わないようにするため。
		audience: text("audience").array().notNull(),
		expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
		revokedAt: timestamp("revoked_at", { withTimezone: true }),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
	},
	(table) => [
		index("idx_access_tokens_client_id").on(table.clientId),
		index("idx_access_tokens_user_id").on(table.userId),
		index("idx_access_tokens_grant_id").on(table.grantId),
	],
);

// リフレッシュトークンテーブル
// [SECURITY] トークンはSHA-256ハッシュで保存。DB漏洩時にトークンが直接漏れることを防ぐ。
export const refreshTokens = pgTable(
	"refresh_tokens",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		// [SECURITY] リフレッシュトークンのSHA-256ハッシュ。平文は保存しない。
		// unique 制約が作る索引で検索するので、別の索引は作らない。
		tokenHash: text("token_hash").notNull().unique(),
		// [SECURITY] この RT が属する grant への参照。
		// カスケード失効・再使用検知はこの grant_id を grouping key にする。
		grantId: uuid("grant_id")
			.notNull()
			.references(() => grants.id),
		clientId: text("client_id").notNull(),
		userId: uuid("user_id")
			.notNull()
			.references(() => users.id),
		// scope 列は持たない。更新の上限は grants.scope から読む。
		// ここに複写すると、後継の RT に縮小したスコープを引き継がせる余地が
		// 生まれる。列がなければその状態は作りようがない。
		expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
		// [SECURITY] ローテーションで消費された時刻。NULL なら未使用。
		// 使用済みトークンの提示は再利用の兆候であり、猶予窓を過ぎていれば
		// grant 全体の失効につながる。
		usedAt: timestamp("used_at", { withTimezone: true }),
		// この RT を消費して発行された後継 RT への前向きポインタ。
		// 監査で連鎖をたどるための記録であり、検索キーにはしない。
		replacedBy: uuid("replaced_by").references((): AnyPgColumn => refreshTokens.id),
		revokedAt: timestamp("revoked_at", { withTimezone: true }),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
	},
	(table) => [
		index("idx_refresh_tokens_client_id").on(table.clientId),
		index("idx_refresh_tokens_user_id").on(table.userId),
		index("idx_refresh_tokens_grant_id").on(table.grantId),
		// [SECURITY] 1つの grant に生きた RT は常に1本、という
		// 不変条件を DB 側でも保証する。猶予窓の処理が連鎖を分岐させると（旧 RT の直後の
		// 後継だけを失効させると）有効な RT が2本並び、どちらの枝も無効なトークンを
		// 提示しないため再利用検知が永久に発火しなくなる。
		// この索引があれば、その分岐は INSERT の失敗として表面化する。
		uniqueIndex("uq_refresh_tokens_live_per_grant")
			.on(table.grantId)
			.where(sql`used_at IS NULL AND revoked_at IS NULL`),
	],
);

// 同意テーブル
// ユーザーがクライアントに対して同意したスコープを記録する。
// ユーザーとクライアントの組につき1行。並行する承認で行が重複しないよう、DB側でも一意にする。
export const consents = pgTable(
	"consents",
	{
		id: uuid("id").primaryKey().defaultRandom(),
		userId: uuid("user_id")
			.notNull()
			.references(() => users.id),
		clientId: text("client_id").notNull(),
		scope: text("scope").notNull(),
		createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
		expiresAt: timestamp("expires_at", { withTimezone: true }),
	},
	(table) => [uniqueIndex("uq_consents_user_client").on(table.userId, table.clientId)],
);
