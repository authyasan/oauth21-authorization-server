import { and, eq, isNull, sql } from "drizzle-orm";
import { db, type Executor, type Transaction } from "../db/connection.js";
import { accessTokens, grants, refreshTokens } from "../db/schema.js";

/**
 * grantリポジトリ。
 * grant（認可付与）のDB操作を提供する。
 *
 * grant は認可コード・アクセストークン・リフレッシュトークンを束ねる
 * 上位概念。grant 単位のカスケード失効・認可コード再使用検知の単位として機能する。
 */

/**
 * grant行を作成する。
 *
 * 認可フロー完了（同意成立）のたびに1行作成する。
 *
 * @param executor トランザクションハンドル（省略時は通常のdb接続）
 * @returns 作成されたgrantのID
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
 * grant の作成時刻を取得する。
 *
 * リフレッシュトークンの絶対上限（180日）の起点として使う。
 * 連鎖の起点となったリフレッシュトークンの created_at ではなく grant の created_at を
 * 使うのは、各 RT が持つのが後継への前向きポインタだけで、起点をたどるには再帰クエリか
 * 列の追加が要るためである。両者のずれは grant の誕生からトークン交換までの間隔、
 * すなわち最大でも認可コードの寿命ぶんであり、180日に対しては誤差といえる。
 * 加えてこの上限が果たす役割は放置された grant を掃除することなので、
 * grant の誕生を起点に測るほうが意味に合う。
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
 * 未失効の grant 行を取得し、トランザクション内で行ロック（FOR UPDATE）する。
 *
 * [SECURITY] リフレッシュと失効の競合対策:
 * リフレッシュによる AT 発行と revokeGrant を、同一 grant 行のロック上で直列化するために使う。
 * ロックはトランザクション終了まで保持されるため、必ずトランザクション内で AT 発行まで
 * 同一 tx を使い続けること。この安全条件を型で強制するため、引数は Transaction を必須にし、
 * 通常の db ハンドルでの呼び出し（ロックが文単位で終わり直列化が破れる）を禁じる（`consumeAuthorizationCodeIfFresh` と同じ規律）。
 *
 * - grant が未失効なら行を返し、その行に排他ロックを取る（revokeGrant の grants UPDATE と競合）
 * - grant が失効済み（または不在）なら null を返す
 *
 * created_at も返す。リフレッシュトークンの絶対上限は grant の誕生から数えるため、
 * ロックを取る側はこの値を使って上限に達したかを判定する。
 *
 * scope も返す。認可された範囲の権威は grant 行にあり、リフレッシュ時の
 * 上限も省略時の既定値もこの値から取る。ロックのためにどのみち読む行なので、
 * 射影に1列足すだけで済み、問い合わせは増えない。
 *
 * [SECURITY] あわせて DB の実時刻（`clock_timestamp()`）を返す。この式が評価されるのは
 * ロックを取り終えて行を返す時点なので、ロック待ちの時間を含んだ現在時刻になる。
 * 呼び出し側はこの値を基準に期限を判定し、アプリの時計を持ち込まない。
 * トランザクション開始時刻に固定される `now()` を使うと、ロック待ちのあいだに
 * 期限を越えた要求を通してしまう。
 *
 * @param tx トランザクションハンドル（必須。db.transaction のコールバック内から渡す）
 * @returns 未失効なら { id, scope, createdAt, now }、失効済み・不在なら null
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
 * grantを失効させ、配下の全トークンを連動失効させる（カスケード失効）。
 *
 * [SECURITY] grant 単位の失効。
 * リフレッシュトークンのリボークや認可コード再使用検知の起点となる。
 *
 * カスケードの方式:
 * - grants.revoked_at に「grant がいつ失効したか」を集約記録する
 * - 配下の AT / RT のうち、まだ失効していない（revoked_at IS NULL）ものに同一時刻を刻む
 * - すでに失効済みのトークンには触れない。別の理由（AT単体リボーク・ローテーション）で
 *   死んだトークンの本来の失効時刻を上書きしないため（先勝ち）
 *
 * 3つの更新は同一トランザクションで実行し、同一の失効時刻を用いる。
 * 失効時刻はアプリの時計で記録する。記録するだけで、期限の判定には使わない。
 */
// #@range_begin(revoke-grant) ※書籍掲載用の範囲マーカー
export async function revokeGrant(grantId: string): Promise<void> {
	const now = new Date();

	await db.transaction(async (tx) => {
		// grant 単位の失効記録
		await tx
			.update(grants)
			.set({ revokedAt: now })
			.where(and(eq(grants.id, grantId), isNull(grants.revokedAt)));

		// [SECURITY] 配下のアクセストークンを連動失効（未失効のもののみ）
		await tx
			.update(accessTokens)
			.set({ revokedAt: now })
			.where(and(eq(accessTokens.grantId, grantId), isNull(accessTokens.revokedAt)));

		// [SECURITY] 配下のリフレッシュトークンを連動失効（未失効のもののみ）
		await tx
			.update(refreshTokens)
			.set({ revokedAt: now })
			.where(and(eq(refreshTokens.grantId, grantId), isNull(refreshTokens.revokedAt)));
	});
}
// #@range_end(revoke-grant)
