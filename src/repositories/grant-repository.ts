import { and, eq, isNull, sql } from "drizzle-orm";
import { db, type Executor, type Transaction } from "../db/connection.js";
import { accessTokens, grants, refreshTokens } from "../db/schema.js";

/**
 * 認可コードとトークンを束ねる grant（認可付与）を管理する。
 * 認可コードの再使用などに対し、同じ grant のトークンをまとめて無効化する。
 */

/**
 * 認可フローの完了ごとに grant を作成し、その ID を返す。
 *
 * @param executor 認可コードの保存と同じトランザクションを渡す（省略時は通常の DB 接続）
 */
export async function createGrant(
	params: {
		clientId: string;
		userId: string;
		scope: string;
	},
	executor: Executor = db,
): Promise<string> {
	const result = await executor.insert(grants).values(params).returning({ id: grants.id });

	return result[0].id;
}

/**
 * リフレッシュトークンの絶対上限の起点となる、grant の作成時刻を取得する。
 * トークンを更新しても起点を変えず、grant の作成時刻から上限を計算する。
 */
export async function getGrantCreatedAt(
	grantId: string,
	executor: Executor = db,
): Promise<Date | null> {
	const rows = await executor
		.select({ createdAt: grants.createdAt })
		.from(grants)
		.where(eq(grants.id, grantId))
		.limit(1);

	return rows[0]?.createdAt ?? null;
}

/**
 * 無効化されていない grant を取得し、トランザクション内で行ロックを取る。
 *
 * [SECURITY] リフレッシュによる発行と revokeGrant を同じ grant 行のロックで直列化する。
 * ロックを発行完了まで保持するため、呼び出し側は同じ tx でトークンを保存すること。
 * 通常の DB 接続を渡せないよう、Transaction を必須にしている。
 *
 * scope は更新時のスコープの上限と省略時の既定値、createdAt は絶対上限の起点に使う。
 * [SECURITY] 期限判定に使う DB 時刻を clock_timestamp() で取得する。
 *
 * @returns 無効化済み・不在なら null
 */
// #@range_begin(lock-active-grant) ※書籍掲載用の範囲マーカー
export async function lockActiveGrant(
	grantId: string,
	tx: Transaction,
): Promise<{ id: string; scope: string; createdAt: Date; now: Date } | null> {
	const rows = await tx
		.select({
			id: grants.id,
			scope: grants.scope,
			createdAt: grants.createdAt,
			now: sql<Date>`clock_timestamp()`.mapWith(grants.createdAt),
		})
		.from(grants)
		.where(and(eq(grants.id, grantId), isNull(grants.revokedAt)))
		.for("update")
		.limit(1);

	return rows[0] ?? null;
}
// #@range_end(lock-active-grant)

/**
 * grant と配下のトークンを、同じトランザクションでまとめて無効化する。
 *
 * [SECURITY] 認可コードの再使用検知やリフレッシュトークンの無効化時に、
 * 同じ grant のアクセストークンとリフレッシュトークンを残さない。
 * 無効化済みの行は更新せず、最初に記録した日時を保つ。
 * 日時はアプリの時計で記録し、ここでは期限判定に使わない。
 */
// #@range_begin(revoke-grant) ※書籍掲載用の範囲マーカー
export async function revokeGrant(grantId: string): Promise<void> {
	const now = new Date();

	await db.transaction(async (tx) => {
		// grant 行の更新で、同じ行をロックするリフレッシュ処理と直列化する。
		await tx
			.update(grants)
			.set({ revokedAt: now })
			.where(and(eq(grants.id, grantId), isNull(grants.revokedAt)));

		// [SECURITY] 配下のアクセストークンを無効化する。
		await tx
			.update(accessTokens)
			.set({ revokedAt: now })
			.where(and(eq(accessTokens.grantId, grantId), isNull(accessTokens.revokedAt)));

		// [SECURITY] 配下のリフレッシュトークンを無効化する。
		await tx
			.update(refreshTokens)
			.set({ revokedAt: now })
			.where(and(eq(refreshTokens.grantId, grantId), isNull(refreshTokens.revokedAt)));
	});
}
// #@range_end(revoke-grant)
