import { serverConfig } from "../config/server.js";
import { db, type Transaction } from "../db/connection.js";
import { lockActiveGrant, revokeGrant } from "../repositories/grant-repository.js";
import {
	classifyRefreshToken,
	consumeRefreshTokenIfFresh,
	findRefreshTokenByHash,
	type RefreshTokenRecord,
	revokeLiveRefreshTokensOfGrant,
	setReplacedBy,
} from "../repositories/token-repository.js";
import type { ClientConfig } from "../types/client.js";
import { sha256 } from "../utils/crypto.js";
import { logger } from "../utils/logger.js";
import { isValidScopeSyntax } from "../utils/validation.js";
import { type IssuedToken, issueAccessToken } from "./token-service.js";

/**
 * リフレッシュトークンサービス。
 *
 * リフレッシュトークンはクライアント種別によらず発行する。
 * 更新のたびにローテーションする。
 * 応答の喪失に備え、消費から60秒の猶予窓を設ける。
 * 失効済み、または猶予期間を過ぎた使用済みリフレッシュトークンの提示を再利用として扱い、
 * grant 全体を失効させる。
 */

export interface VerifiedRefreshToken {
	tokenRecord: RefreshTokenRecord;
}

/**
 * 提示されたリフレッシュトークンの持ち主を確認する。
 *
 * [SECURITY] ここで見るのは「そのトークンがこのクライアントのものか」だけである。
 * 使用済み・失効済み・期限切れの判定はここでは行わない。除外してしまうと、
 * 消費済みのトークンが提示されたことを検知できず、ローテーションが担う漏洩検知が
 * 成立しないためである。状態の判定は `rotateRefreshToken` が grant 行ロックの内側で行う。
 *
 * @returns 見つかり、かつクライアントが一致すればトークンレコード。それ以外は null
 */
// #@range_begin(verify-refresh-token) ※書籍掲載用の範囲マーカー
export async function verifyRefreshToken(params: {
	refreshToken: string;
	clientId: string;
}): Promise<VerifiedRefreshToken | null> {
	const { refreshToken, clientId } = params;

	// [SECURITY] トークンのSHA-256ハッシュでDB検索（平文はDBに保存していない）
	const tokenHash = sha256(refreshToken);
	const tokenRecord = await findRefreshTokenByHash(tokenHash);

	if (!tokenRecord) {
		logger.warn("リフレッシュトークン検証: トークンが存在しない", { clientId });
		return null;
	}

	// [SECURITY] 他のクライアントに発行されたトークンでの更新を拒む。
	// 一致しない場合は失効させない。誤ったクライアントからの提示で正規の利用者を
	// 巻き添えにしないためである（認可コードでも、事前検証に失敗した提示では失効させないのと同じ線引き）。
	if (tokenRecord.clientId !== clientId) {
		logger.warn("リフレッシュトークン検証: client_idが一致しない", {
			expected: tokenRecord.clientId,
			actual: clientId,
		});
		return null;
	}

	return { tokenRecord };
}
// #@range_end(verify-refresh-token)

/**
 * リフレッシュトークンのローテーション結果。
 * - success: 新しいアクセストークンとリフレッシュトークンを発行した（commit 済み）
 * - invalid_grant: 更新できなかった。再利用を検知した場合は grant を失効させたうえで返す
 * - invalid_scope: 要求されたスコープが元の認可範囲を超えていた
 */
export type RefreshRotationResult =
	| { type: "success"; token: IssuedToken }
	| { type: "invalid_grant" }
	| { type: "invalid_scope" };

/** トランザクション内で決まる処理の結末 */
type RotationOutcome =
	| { kind: "rotated"; token: IssuedToken }
	| { kind: "grant_revoked" }
	| { kind: "reuse_detected" }
	| { kind: "expired" };

/**
 * スコープ超過でトランザクションを巻き戻すための内部シグナル。
 *
 * [SECURITY] スコープの検証はトークンの状態を確かめたあとに行う。
 * そのため検証に失敗する時点では、消費（used_at の記録）や猶予窓での失効が
 * すでにトランザクション内で行われている。これを投げて巻き戻すことで、
 * 不正なスコープの要求が正規のリフレッシュトークンを殺さないようにする。
 */
class ScopeExceededSignal extends Error {}

/**
 * 検証済みのリフレッシュトークンを消費し、新しいトークンを発行する。
 *
 * [SECURITY] 処理全体を grant 行のロック（FOR UPDATE）の内側で行う。ロックは2つの役割を持つ。
 *
 * 1. リフレッシュによるトークン発行と revokeGrant を直列化する。
 *    ロックがないと、grant 失効後に revoked_at=NULL のアクセストークンが生き残り、
 *    カスケード失効が競合下で破れる。
 * 2. 消費に失敗したときの分類と、猶予窓でのやり直しを同じ区間に収める。
 *    ロックを取り直す作りにすると、分類の時点で窓の内側だった要求が、
 *    ロック待ちのあいだに窓を出たまま処理されうる。
 *
 * ただしロックだけでは同一トークンの二重使用を直列化できない。ローテーションは
 * grants 行を書き換えないため、grant ロックの下でも「両方が消費できた」ことに
 * なってしまう。トークン行の原子的な消費（consumeRefreshTokenIfFresh）と両方が要る。
 *
 * grant の失効（revokeGrant）はトランザクションの外で行う。内側で呼ぶと、
 * 自分が保持している grant 行ロックを自分で待つことになる。
 *
 * @param params.tokenRecord verifyRefreshToken を通ったトークンレコード
 * @param params.requestedScope リクエストの scope パラメータ。
 *   省略時は grant のスコープとして扱う（draft-16 §4.3.1）。
 */
// #@range_begin(rotate-refresh-token) ※書籍掲載用の範囲マーカー
export async function rotateRefreshToken(params: {
	tokenRecord: RefreshTokenRecord;
	client: ClientConfig;
	requestedScope?: string;
}): Promise<RefreshRotationResult> {
	const { tokenRecord, client, requestedScope } = params;

	let outcome: RotationOutcome;
	try {
		outcome = await db.transaction<RotationOutcome>(async (tx) => {
			// grant 行のロック。並行する revoke や別のリフレッシュはここで待たされる。
			const activeGrant = await lockActiveGrant(tokenRecord.grantId, tx);
			if (!activeGrant) {
				return { kind: "grant_revoked" };
			}

			// 認可された範囲の権威は grant 行にある。scope が省略されたときの
			// 既定値も、この行から取る（draft-16 §4.3.1 "if omitted is treated as equal to
			// the scope originally granted by the resource owner"）。
			const scope = requestedScope ?? activeGrant.scope;

			// [SECURITY] トークン行の原子的な消費。1文の UPDATE で used_at を刻む。
			const consumed = await consumeRefreshTokenIfFresh(tokenRecord.id, tx);

			if (!consumed) {
				// 消費できなかった。ロックを保持したまま最新の状態を分類する。
				const state = await classifyRefreshToken(
					tokenRecord.id,
					serverConfig.rotationGraceSeconds,
					tx,
				);

				// 失効済み・猶予窓を過ぎた使用済みの提示は再利用として扱う。
				if (state === "revoked" || state === "reused") {
					return { kind: "reuse_detected" };
				}

				// 来歴を持たないまま有効期限に達したトークン。期限切れのトークン1つで正規の利用者を
				// 追い出せないよう、失効はしない。
				if (state !== "in_grace") {
					return { kind: "expired" };
				}

				// 猶予窓でのやり直しは、消費に成功する経路と違って
				// consumeRefreshTokenIfFresh の期限判定を通らない。grant の絶対上限を
				// ここで確かめないと、min(無操作期限, 絶対上限) が過去の時刻になり、
				// 受け取った瞬間に期限切れのリフレッシュトークンを 200 で返してしまう。
				if (isBeyondAbsoluteLimit(activeGrant.createdAt, activeGrant.now)) {
					return { kind: "expired" };
				}

				// 猶予窓の内側なので更新をやり直す。
				// このとき失効させるのは、提示された旧トークンの直後の後継ではなく、
				// そのとき grant に生きているトークンである（連鎖の分岐を防ぐ）。
				await revokeLiveRefreshTokensOfGrant(tokenRecord.grantId, tx);
			}

			// [SECURITY] ここから先は発行する経路である。スコープの検証を
			// この位置に置くのは、トークンの状態を確かめる前に返してしまうと、
			// 盗まれた使用済みトークンを範囲外のスコープと一緒に提示するだけで
			// 再利用検知をすり抜けられるためである。
			// 超過していた場合は例外でトランザクションごと巻き戻し、消費をなかったことにする。
			if (!isScopeWithinGrant(scope, activeGrant.scope)) {
				logger.warn("リフレッシュトークン: 要求スコープが元のスコープを超えている", {
					clientId: client.clientId,
					grantScope: activeGrant.scope,
					requestedScope: scope,
				});
				throw new ScopeExceededSignal();
			}

			const token = await issueTokens(tx, { tokenRecord, client, scope });
			return { kind: "rotated", token };
		});
	} catch (error) {
		if (error instanceof ScopeExceededSignal) {
			return { type: "invalid_scope" };
		}
		throw error;
	}

	if (outcome.kind === "rotated") {
		return { type: "success", token: outcome.token };
	}

	if (outcome.kind === "reuse_detected") {
		// [SECURITY] 再利用の検知 → grant 単位でカスケード失効。
		// トランザクションの外で呼ぶ。この時点で grant 行ロックは解放されている。
		logger.warn("リフレッシュトークン: 再利用を検知したため grant を失効させる", {
			clientId: client.clientId,
			grantId: tokenRecord.grantId,
		});
		await revokeGrant(tokenRecord.grantId);
		return { type: "invalid_grant" };
	}

	logger.warn("リフレッシュトークン: 更新できなかった", {
		clientId: client.clientId,
		grantId: tokenRecord.grantId,
		reason: outcome.kind,
	});
	return { type: "invalid_grant" };
}

/**
 * [SECURITY] 要求されたスコープが元の認可範囲に収まっているか。
 *
 * draft-16 §4.3.1: "The requested scope MUST NOT include any scope
 * not originally granted by the resource owner"。
 * 順序は問われないため、文字列の一致ではなく集合の包含で判定する。
 */
function isScopeWithinGrant(requestedScope: string, grantedScope: string): boolean {
	// 認可エンドポイントと同じ構文（draft-16 §1.4.1）で検証してから、集合の包含を見る。
	if (!isValidScopeSyntax(requestedScope)) {
		return false;
	}
	const granted = new Set(grantedScope.split(" "));
	return requestedScope.split(" ").every((s) => granted.has(s));
}

/**
 * grant が絶対上限に達しているか。
 * 起点は grant の誕生であり、リフレッシュトークンの連鎖の起点ではない。
 *
 * [SECURITY] 現在時刻は grant 行のロックと一緒に DB から受け取ったものを使う。
 * アプリの時計で判定すると、DB クロックとのずれのぶんだけ上限が前後する。
 * 猶予窓や消費の判定と同じ時計にそろえるための引数である。
 */
function isBeyondAbsoluteLimit(grantCreatedAt: Date, now: Date): boolean {
	return grantCreatedAt.getTime() + serverConfig.refreshToken.absoluteTtl * 1000 <= now.getTime();
}

/**
 * 新しいアクセストークンとリフレッシュトークンを発行し、連鎖のポインタを張る。
 *
 * アクセストークンには要求されたスコープを持たせる。後継の
 * リフレッシュトークンはスコープを持たないので、縮小はそのときのアクセストークンにだけ効き、
 * 以後の更新の上限（grant のスコープ）は動かない。draft-16 §4.3.3 の
 * "the refresh token scope MUST be identical to that of the refresh token included
 * by the client in the request" は、提示されたトークンと後継が同じ grant を指すことで満たされる。
 */
async function issueTokens(
	tx: Transaction,
	params: { tokenRecord: RefreshTokenRecord; client: ClientConfig; scope: string },
): Promise<IssuedToken> {
	const { tokenRecord, client, scope } = params;

	const token = await issueAccessToken(
		{
			client,
			userId: tokenRecord.userId,
			scope,
			grantId: tokenRecord.grantId,
		},
		tx,
	);

	// 消費したトークンから後継への前向きポインタを張る。
	// 猶予窓でやり直した場合は、新しい後継に張り替わる。
	await setReplacedBy(tokenRecord.id, token.refreshTokenId, tx);

	return token;
}
// #@range_end(rotate-refresh-token)
