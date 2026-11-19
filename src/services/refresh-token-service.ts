import { serverConfig } from "../config/server.js";
import { db } from "../db/connection.js";
import { lockActiveGrant, revokeGrant } from "../repositories/grant-repository.js";
import {
	classifyRefreshToken,
	consumeRefreshTokenIfFresh,
	findRefreshTokenByHash,
	type RefreshTokenRecord,
	revokeLiveRefreshTokensOfGrant,
} from "../repositories/token-repository.js";
import type { ClientConfig } from "../types/client.js";
import { sha256 } from "../utils/crypto.js";
import { logger } from "../utils/logger.js";
import { isValidScopeSyntax } from "../utils/validation.js";
import { type IssuedToken, issueTokens } from "./token-service.js";

/**
 * リフレッシュトークンによる更新処理。
 *
 * 提示されたRTの発行先を確認し、ローテーションで新しいAT・RTを発行する。
 * レスポンスを受け取れなかったクライアントの再送には猶予期間を設ける。
 * 再利用を検知した場合は、grantと関連するAT・RTを無効化する。
 */

export interface VerifiedRefreshToken {
	tokenRecord: RefreshTokenRecord;
}

/**
 * 提示されたRTを検索し、発行先のクライアントと一致することを確認する。
 *
 * [SECURITY] 再利用検知に必要なため、使用済み・無効化済み・期限切れのRTも取得する。
 * 状態の判定はrotateRefreshTokenで行う。
 *
 * @returns 発行先が一致すれば{ tokenRecord }、見つからない場合や不一致の場合はnull
 */
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

	// [SECURITY] 他のクライアントに発行されたRTは拒否する。
	// 誤ったクライアントからの提示で正規の利用を妨げないよう、無効化は行わない。
	if (tokenRecord.clientId !== clientId) {
		logger.warn("リフレッシュトークン検証: client_idが一致しない", {
			expected: tokenRecord.clientId,
			actual: clientId,
		});
		return null;
	}

	return { tokenRecord };
}

/**
 * リフレッシュトークンの更新結果。
 * - success: 新しいAT・RTを発行し、DBへの保存をコミットした
 * - invalid_grant: 更新を拒否した。再利用検知時はgrantと関連するAT・RTを無効化済み
 * - invalid_scope: 要求されたスコープの構文が不正、またはgrantの範囲を超えている
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
	| { kind: "expired_or_not_found" };

/**
 * スコープ検証の失敗時にトランザクションを巻き戻すための例外。
 *
 * [SECURITY] 検証前に行ったRTの使用済み記録や無効化を取り消し、
 * 誤ったスコープの要求によってRTが使えなくなることを防ぐ。
 */
class ScopeExceededSignal extends Error {}

/**
 * 発行先の確認を終えたRTについて、状態とスコープを検証し、新しいAT・RTを発行する。
 * 猶予期間内の再送は更新をやり直し、再利用を検知した場合は関連するgrantを無効化する。
 *
 * [SECURITY] 同じgrantの更新・無効化と競合しないよう、grantをロックする。
 * RTの状態確認・使用済み記録と、新しいAT・RTの保存は同じトランザクションで行う。
 *
 * @param params.tokenRecord verifyRefreshTokenで発行先を確認したレコード
 * @param params.requestedScope 要求されたスコープ。省略時はgrantのスコープを使う。
 */
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

			// RTのスコープはgrantに保存しているため、要求で省略された場合はその値を使う。
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

				// 無効化済み・猶予期間を過ぎた使用済みRTの提示は再利用として扱う。
				if (state === "revoked" || state === "used_beyond_grace") {
					return { kind: "reuse_detected" };
				}

				// 未使用・未無効化のまま期限切れになった場合や、レコードが見つからない場合は、
				// grantを無効化せずに更新を拒否する。
				if (state !== "used_within_grace") {
					return { kind: "expired_or_not_found" };
				}

				// 猶予期間内の再送でも、RTの有効期限の絶対上限は延長しない。
				// 期限切れのRTを新たに発行しないよう、ここでも上限を確認する。
				if (isBeyondAbsoluteLimit(activeGrant.createdAt, activeGrant.now)) {
					return { kind: "expired_or_not_found" };
				}

				// 更新をやり直してもRTの連鎖が分岐しないよう、
				// 同じgrantの未使用・未無効化のRTを無効化してから、新しいRTを発行する。
				await revokeLiveRefreshTokensOfGrant(tokenRecord.grantId, tx);
			}

			// [SECURITY] 範囲外のスコープを指定しても再利用検知を回避できないよう、
			// RTの状態を判定してからスコープを検証する。
			// 検証に失敗した場合は、例外でトランザクションを巻き戻す。
			if (!isScopeWithinGrant(scope, activeGrant.scope)) {
				logger.warn("リフレッシュトークン: 要求スコープが元のスコープを超えている", {
					clientId: client.clientId,
					grantScope: activeGrant.scope,
					requestedScope: scope,
				});
				throw new ScopeExceededSignal();
			}

			// 新しいRTも同じgrantに紐付け、更新できるスコープの上限を引き継ぐ。
			const token = await issueTokens(
				{
					client,
					userId: tokenRecord.userId,
					scope,
					grantId: tokenRecord.grantId,
				},
				tx,
			);
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
		// [SECURITY] 再利用を検知したため、grantと関連するAT・RTを無効化する。
		// revokeGrantは別のトランザクションで同じgrantを更新するため、
		// ここまでのトランザクションを終了してロックを解放してから呼び出す。
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
 * grantの作成時刻を起点とする、RTの有効期限の絶対上限への到達を判定する。
 * nowには、呼び出し元がDBから取得した時刻を渡す。
 */
function isBeyondAbsoluteLimit(grantCreatedAt: Date, now: Date): boolean {
	return grantCreatedAt.getTime() + serverConfig.refreshToken.absoluteTtl * 1000 <= now.getTime();
}
