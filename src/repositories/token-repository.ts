import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { db, type Executor, type Transaction } from "../db/connection.js";
import { accessTokens, refreshTokens } from "../db/schema.js";

/**
 * アクセストークン・リフレッシュトークンのDB操作を提供する。
 */

/**
 * アクセストークンのメタデータをDBに保存する。
 */
export async function saveAccessToken(
	params: {
		jti: string;
		grantId: string;
		clientId: string;
		userId: string;
		scope: string;
		/** JWT の aud と同じリソースサーバーIDの集合（単一でも配列で保存する） */
		audience: string[];
		expiresAt: Date;
	},
	executor: Executor = db,
): Promise<void> {
	await executor.insert(accessTokens).values(params);
}

/**
 * リフレッシュトークンのハッシュと発行情報を保存する。
 *
 * [SECURITY] DB 漏洩時にトークンがそのまま使われないよう、呼び出し側で SHA-256 により
 * ハッシュ化した値を受け取る。更新できるスコープは紐付く grant から参照する。
 */
export async function saveRefreshToken(
	params: {
		tokenHash: string;
		grantId: string;
		clientId: string;
		userId: string;
		expiresAt: Date;
	},
	executor: Executor = db,
): Promise<void> {
	await executor.insert(refreshTokens).values(params);
}

/** リフレッシュトークンのDB行型 */
export interface RefreshTokenRecord {
	id: string;
	tokenHash: string;
	grantId: string;
	clientId: string;
	userId: string;
	expiresAt: Date;
	usedAt: Date | null;
	revokedAt: Date | null;
	createdAt: Date;
}

/**
 * リフレッシュトークンをハッシュで検索する。
 *
 * [SECURITY] 再利用を検知するため、使用済み・無効化済み・期限切れも返す。
 * 有効性は呼び出し側で判定する。リボケーションでも共用し、
 * 使用済み・無効化済みのトークンからも grant 単位の無効化を行う。
 */
export async function findRefreshTokenByHash(
	tokenHash: string,
): Promise<RefreshTokenRecord | null> {
	const result = await db
		.select()
		.from(refreshTokens)
		.where(eq(refreshTokens.tokenHash, tokenHash))
		.limit(1);

	return result[0] ?? null;
}

/**
 * 未使用・未無効化で期限内のリフレッシュトークンを使用済みにする。
 *
 * [SECURITY] 条件判定と更新を1文にまとめ、並行リクエストによる二重使用を防ぐ。
 * [SECURITY] grant のロック待ち後の時刻で判定するため、clock_timestamp() を使う。
 * 猶予期間の起点となる used_at も同じ DB の時計で記録する。
 *
 * [SECURITY] 消費と発行を同じトランザクションで行うため、Transaction を必須にする。
 * 更新できなかった場合の状態判定は classifyRefreshToken が行う。
 */
export async function consumeRefreshTokenIfFresh(
	refreshTokenId: string,
	tx: Transaction,
): Promise<boolean> {
	const result = await tx
		.update(refreshTokens)
		.set({ usedAt: sql`clock_timestamp()` })
		.where(
			and(
				eq(refreshTokens.id, refreshTokenId),
				isNull(refreshTokens.usedAt),
				isNull(refreshTokens.revokedAt),
				gt(refreshTokens.expiresAt, sql`clock_timestamp()`),
			),
		)
		.returning({ id: refreshTokens.id });

	return result.length === 1;
}

/**
 * 消費できなかったリフレッシュトークンの分類。
 * 無効化・使用の履歴を期限より先に判定する。
 * - revoked: 無効化済み。再利用として扱う
 * - used_beyond_grace: 使用済みで猶予期間外。再利用として扱う
 * - used_within_grace: 使用済みで猶予期間内。更新をやり直す
 * - expired: 未使用・未無効化のまま期限切れ。grant は無効化しない
 * - not_found: 行がない、または上記のいずれにも該当しない
 */
export type RefreshTokenState =
	| "revoked"
	| "used_beyond_grace"
	| "used_within_grace"
	| "expired"
	| "not_found";

/**
 * 消費に失敗したリフレッシュトークンの状態を判定する。
 *
 * [SECURITY] 期限切れでも再利用を見逃さないよう、無効化・使用の履歴を先に判定する。
 * 未使用・未無効化のまま期限切れになったトークンでは、grant を無効化しない。
 *
 * [SECURITY] ロック待ちで猶予期間が延びないよう、判定には clock_timestamp() を使う。
 * [SECURITY] 判定と更新のやり直しを同じ grant のロック内で行うため、Transaction を必須にする。
 */
export async function classifyRefreshToken(
	refreshTokenId: string,
	graceSeconds: number,
	tx: Transaction,
): Promise<RefreshTokenState> {
	const rows = await tx
		.select({
			used: sql<boolean>`${refreshTokens.usedAt} IS NOT NULL`,
			revoked: sql<boolean>`${refreshTokens.revokedAt} IS NOT NULL`,
			expired: sql<boolean>`${refreshTokens.expiresAt} <= clock_timestamp()`,
			inGrace: sql<boolean>`${refreshTokens.usedAt} IS NOT NULL
				AND clock_timestamp() - ${refreshTokens.usedAt} <= make_interval(secs => ${graceSeconds})`,
		})
		.from(refreshTokens)
		.where(eq(refreshTokens.id, refreshTokenId))
		.limit(1);

	const row = rows[0];
	if (!row) {
		return "not_found";
	}
	if (row.revoked) {
		return "revoked";
	}
	if (row.used) {
		return row.inGrace ? "used_within_grace" : "used_beyond_grace";
	}
	return row.expired ? "expired" : "not_found";
}

/**
 * grant 配下の未使用・未無効化のリフレッシュトークンを無効化する。
 *
 * [SECURITY] 猶予期間内に更新をやり直す際、有効なトークンが複数に分かれるのを防ぐ。
 * 提示された旧トークンの次世代だけでなく、さらに更新されたトークンも対象にする。
 * 複数が有効なままだと、正規のクライアントと攻撃者が別々に更新を続け、再利用を検知できない。
 */
export async function revokeLiveRefreshTokensOfGrant(
	grantId: string,
	tx: Transaction,
): Promise<void> {
	await tx
		.update(refreshTokens)
		.set({ revokedAt: sql`now()` })
		.where(
			and(
				eq(refreshTokens.grantId, grantId),
				isNull(refreshTokens.usedAt),
				isNull(refreshTokens.revokedAt),
			),
		);
}

/** アクセストークンのDB行型 */
export interface AccessTokenRecord {
	jti: string;
	grantId: string;
	clientId: string;
	userId: string;
	scope: string;
	/** 発行時に JWT の aud へ入れたリソースサーバーIDの集合 */
	audience: string[];
	expiresAt: Date;
	revokedAt: Date | null;
	createdAt: Date;
}

/**
 * アクセストークンをjtiで検索する。
 * リボケーション済みかどうかに関わらず返す。
 */
export async function findAccessTokenByJti(jti: string): Promise<AccessTokenRecord | null> {
	const result = await db.select().from(accessTokens).where(eq(accessTokens.jti, jti)).limit(1);

	return result[0] ?? null;
}

/**
 * アクセストークンをリボークする（jti指定）。
 */
export async function revokeAccessTokenByJti(jti: string): Promise<void> {
	await db
		.update(accessTokens)
		.set({ revokedAt: new Date() })
		.where(and(eq(accessTokens.jti, jti), isNull(accessTokens.revokedAt)));
}
