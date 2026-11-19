import { and, eq, gte, isNull, sql } from "drizzle-orm";
import { db, type Executor, type Transaction } from "../db/connection.js";
import { authorizationCodes } from "../db/schema.js";

/**
 * 認可コードの保存・検索と、一度限りの使用を管理する。
 *
 * [SECURITY] 認可コードはSHA-256ハッシュで保存する。
 * DB漏洩時に認可コードが直接漏れることを防ぐ。
 */

/** 認可コードのDB行型 */
export interface AuthorizationCodeRecord {
	id: string;
	codeHash: string;
	grantId: string;
	clientId: string;
	userId: string;
	redirectUri: string;
	scope: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	expiresAt: Date;
	usedAt: Date | null;
	createdAt: Date;
}

/**
 * 認可コードをDBに保存する。
 *
 * @param codeHash 認可コードのSHA-256ハッシュ
 * @param params 認可コードに紐づくパラメータ（grantId を含む）
 * @param executor トランザクションハンドル（省略時は通常のdb接続）
 * @returns 保存されたレコードのID
 */
export async function saveAuthorizationCode(
	codeHash: string,
	params: {
		grantId: string;
		clientId: string;
		userId: string;
		redirectUri: string;
		scope: string;
		codeChallenge: string;
		codeChallengeMethod: string;
		expiresAt: Date;
	},
	executor: Executor = db,
): Promise<string> {
	const result = await executor
		.insert(authorizationCodes)
		.values({
			codeHash,
			...params,
		})
		.returning({ id: authorizationCodes.id });

	return result[0].id;
}

/**
 * 認可コードをハッシュで検索する。
 */
export async function findAuthorizationCodeByHash(
	codeHash: string,
): Promise<AuthorizationCodeRecord | null> {
	const result = await db
		.select()
		.from(authorizationCodes)
		.where(eq(authorizationCodes.codeHash, codeHash))
		.limit(1);

	return result[0] ?? null;
}

/**
 * 認可コードをIDで検索する。
 *
 * 原子的消費（consumeAuthorizationCodeIfFresh）が0行だったときに、最新の used_at を
 * 読み直して「再利用」か「期限切れ」かを再分類するために使う。
 */
export async function findAuthorizationCodeById(
	codeId: string,
): Promise<AuthorizationCodeRecord | null> {
	const result = await db
		.select()
		.from(authorizationCodes)
		.where(eq(authorizationCodes.id, codeId))
		.limit(1);

	return result[0] ?? null;
}

/**
 * 未使用で期限内の認可コードを、1文の UPDATE で使用済みにする。
 *
 * [SECURITY] 条件判定と更新を分けず、並行リクエストによる二重使用を防ぐ。
 * 使用時刻と期限の判定には DB の now() を使う。期限自体は発行時にアプリで計算するため、
 * アプリと DB の時計のずれを無視できる環境を前提とする。
 *
 * [SECURITY] トークン発行と同じトランザクションで呼ぶこと。
 * 消費だけが確定したり、再使用時の無効化より後にトークンが保存されたりするのを防ぐ。
 * 通常の DB 接続を渡せないよう、Transaction を必須にしている。
 *
 * @returns 更新できた場合は true、使用済み・期限切れ・不在の場合は false
 */
export async function consumeAuthorizationCodeIfFresh(
	codeId: string,
	tx: Transaction,
): Promise<boolean> {
	const result = await tx
		.update(authorizationCodes)
		.set({ usedAt: sql`now()` })
		.where(
			and(
				eq(authorizationCodes.id, codeId),
				isNull(authorizationCodes.usedAt),
				gte(authorizationCodes.expiresAt, sql`now()`),
			),
		)
		.returning({ id: authorizationCodes.id });

	return result.length === 1;
}
