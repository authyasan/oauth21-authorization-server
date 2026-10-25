import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { db, type Executor, type Transaction } from "../db/connection.js";
import { accessTokens, refreshTokens } from "../db/schema.js";

/**
 * トークンリポジトリ。
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
 * リフレッシュトークンをDBに保存する。
 *
 * [SECURITY] リフレッシュトークンはSHA-256ハッシュで保存する。
 * DB漏洩時にトークンが直接漏れることを防ぐ。
 *
 * スコープは受け取らない。この RT で更新できる範囲は grant_id の先にある。
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
): Promise<string> {
	const result = await executor.insert(refreshTokens).values(params).returning({
		id: refreshTokens.id,
	});

	return result[0].id;
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
	replacedBy: string | null;
	revokedAt: Date | null;
	createdAt: Date;
}

/**
 * リフレッシュトークンをハッシュで検索する。
 *
 * [SECURITY] 使用済み・失効済み・期限切れのいずれも除外しない。
 * 除外すると「消費済みのトークンが提示された」ことを検知できず、ローテーションが担う
 * 漏洩検知が成立しない。有効かどうかの判断は呼び出し側が行う。
 *
 * リボケーションエンドポイントとも共用する。使用済み・失効済みの
 * リフレッシュトークンを指定したリボークも grant のカスケード失効まで進む。
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
 * リフレッシュトークンを原子的に消費する（ローテーション）。
 *
 * [SECURITY] `consumeAuthorizationCodeIfFresh` と同じ型を用いる。
 * 「未使用（used_at IS NULL）かつ未失効（revoked_at IS NULL）かつ未期限切れ」の行だけを
 * 1文の UPDATE で used_at に刻み、更新できた行数で消費の成否を判定する。
 *
 * [SECURITY] 時刻は `clock_timestamp()` を使う。`now()` はトランザクション開始時刻に
 * 固定されるため、grant 行ロックの待ち時間が判定に反映されない。猶予窓の
 * 起点となる used_at も同じ関数で刻み、窓の判定と同じ時計にそろえる。
 *
 * 同一トークンへの並行提示では1本だけが1行更新に成功し、残りは0行になる。
 * 0行だった場合の分類は `classifyRefreshToken` が行う。
 *
 * [SECURITY] 消費と発行のトランザクション境界を揃えるため、引数は Transaction を必須にする
 * （`consumeAuthorizationCodeIfFresh` と同じ規律）。
 */
// #@range_begin(consume-refresh-token) ※書籍掲載用の範囲マーカー
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
// #@range_end(consume-refresh-token)

/**
 * 消費できなかったリフレッシュトークンの状態。
 *
 * 判定はこの順序で行う。有効期限より先にトークンの来歴を見る。
 * - revoked: 失効させられたトークンの提示。期限に関係なく再利用として扱う
 * - reused: 猶予窓を過ぎた使用済みトークンの提示。期限に関係なく再利用として扱う
 * - in_grace: 猶予窓の内側での使用済みトークンの提示。更新をやり直す
 * - expired: 一度も使われないまま有効期限に達したトークン。失効はしない
 * - not_found: 行が消えている（通常は起こらない）
 */
export type RefreshTokenState = "revoked" | "reused" | "in_grace" | "expired" | "not_found";

/**
 * 消費に失敗したリフレッシュトークンを分類する。
 *
 * [SECURITY] 有効期限より先に used_at / revoked_at を見る。
 * 期限を先に見ると、サーバー側に残っている再利用の証拠を捨てて検知を素通りさせる。
 * 期限切れとして見逃すのは、来歴を持たない（used_at も revoked_at も NULL の）
 * トークンだけに限る。これにより「期限切れのトークン1つで正規の利用者を追い出す」
 * 経路は塞いだままになる（未使用のまま期限切れになった認可コードでは grant を失効させないのと同じ線引き）。
 *
 * [SECURITY] 猶予窓の判定は `clock_timestamp()` で行う。`now()` は
 * `transaction_timestamp()` と同値でトランザクション開始時刻に固定されるため、
 * これを使うと grant 行ロックの待ち時間が判定から抜け落ちる。窓の終わり際に
 * トランザクションを始めた要求がロックを待つあいだに窓が閉じても、開始時刻で
 * 判定されて窓の内側と見なされ、猶予窓の長さが実質的に延びてしまう。
 *
 * [SECURITY] 分類から猶予窓の処理までを同じ grant 行ロックの区間に収めるため、
 * 引数は Transaction を必須にする。
 */
// #@range_begin(classify-refresh-token) ※書籍掲載用の範囲マーカー
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
		return row.inGrace ? "in_grace" : "reused";
	}
	return row.expired ? "expired" : "not_found";
}
// #@range_end(classify-refresh-token)

/**
 * grant 配下の生きたリフレッシュトークンを失効させる。
 *
 * [SECURITY] 猶予窓で更新をやり直すときに使う。失効させる相手は
 * 提示された旧トークンの直後の後継ではなく、そのとき grant に生きているトークンである。
 * 旧トークンが提示されるまでに連鎖が2世代以上進んでいる場合、直後の1世代だけを
 * 失効させるとその先のトークンが生き残り、有効なリフレッシュトークンが2本並ぶ。
 * 正規のクライアントと攻撃者がそれぞれ別の枝で並走でき、どちらも無効なトークンを
 * 提示しないため再利用検知が永久に発火しなくなる。
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

/**
 * 消費したリフレッシュトークンから後継への前向きポインタを張る。
 *
 * 監査で連鎖をたどるための記録。猶予窓で更新をやり直した場合は
 * 新しい後継に張り替える。
 */
export async function setReplacedBy(
	refreshTokenId: string,
	successorId: string,
	tx: Transaction,
): Promise<void> {
	await tx
		.update(refreshTokens)
		.set({ replacedBy: successorId })
		.where(eq(refreshTokens.id, refreshTokenId));
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
