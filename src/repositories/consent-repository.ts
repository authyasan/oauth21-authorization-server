import { and, eq, sql } from "drizzle-orm";
import { db } from "../db/connection.js";
import { consents } from "../db/schema.js";

/**
 * ユーザーがクライアントに対して許可したスコープの記録を管理する。
 */

/**
 * ユーザーとクライアントの組み合わせで同意記録を検索する。
 *
 * @returns 同意記録（見つからない場合undefined）
 */
export async function findConsent(
	userId: string,
	clientId: string,
): Promise<{ scope: string } | undefined> {
	const result = await db
		.select({ scope: consents.scope })
		.from(consents)
		.where(and(eq(consents.userId, userId), eq(consents.clientId, clientId)))
		.limit(1);

	if (result.length === 0) {
		return undefined;
	}

	return result[0];
}

/**
 * 同意記録を保存する。
 * 既存の同意がある場合は上書きする（スコープが変わった場合に対応）。
 *
 * @param scope 同意したスコープ（スペース区切り）
 */
export async function saveConsent(userId: string, clientId: string, scope: string): Promise<void> {
	// [SECURITY] ユーザーとクライアントの一意制約を使い、並行する同意保存も1文で処理する。
	// 削除と挿入を分けず、同意記録が一時的に欠けることや挿入時の一意制約違反を避ける。
	await db
		.insert(consents)
		.values({ userId, clientId, scope })
		.onConflictDoUpdate({
			target: [consents.userId, consents.clientId],
			set: { scope, createdAt: sql`now()` },
		});
}
