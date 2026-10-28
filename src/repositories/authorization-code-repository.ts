import { and, eq, gte, isNull, sql } from "drizzle-orm";
import { db, type Executor, type Transaction } from "../db/connection.js";
import { authorizationCodes } from "../db/schema.js";

/**
 * 認可コードリポジトリ。
 * 認可コードのDB操作を提供する。
 *
 * [SECURITY] 認可コードはSHA-256ハッシュで保存する。
 * DB漏洩時に認可コードが直接漏れることを防ぐ。
 */

/** 認可コードのDB行型 */
export interface AuthorizationCodeRecord {
	id: string;
	codeHash: string;
	// この認可コードが属する grant のID
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
 * 認可コードを原子的に消費する（check-and-set）。
 *
 * [SECURITY] 認可コードの一回限り使用を、競合下でも保証する。
 * 「未使用（used_at IS NULL）かつ未期限切れ（expires_at >= now()）」の行だけを 1 文の
 * UPDATE で used_at に刻み、更新できた行数で消費の成否を判定する。
 *
 * PostgreSQL の行ロックにより、同一コードへの並行リクエストでは 1 本だけが 1 行更新に
 * 成功し（戻り値 true）、残りは勝者の commit 後に WHERE を再評価して 0 行になる（false）。
 *
 * - used_at / expires_at の判定と used_at の記録は DB クロック（now()）で行う。
 *   アプリ時刻と DB 時刻の混在による境界の曖昧さ（SELECT と UPDATE の時間差）を避ける。
 *   ただし expires_at の値そのものは、発行時にアプリの時計で計算して書いている
 *   （authorization-code-service）。単一ホスト構成では両者のずれは無視できるので、
 *   書き込みはアプリ、判定は DB という分担にしている。
 * - この UPDATE はトークン発行と同一トランザクション（tx）で実行すること。
 *   消費と発行の境界を揃えることで、再使用検知時の grant 単位カスケード失効が
 *   競合下でも漏れない（exchangeAuthorizationCode を参照）。
 *   [SECURITY] この安全条件を型で強制するため、引数は Transaction を必須にし、
 *   通常の db ハンドルでの呼び出し（消費と発行のトランザクション境界の分離）を禁じる。
 *
 * @param codeId 認可コードのID
 * @param tx トランザクションハンドル（必須。db.transaction のコールバック内から渡す）
 * @returns このリクエストが消費に成功したら true、先を越された／期限切れなら false
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
