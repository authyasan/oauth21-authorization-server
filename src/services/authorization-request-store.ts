import type { AuthorizationRequest } from "../types/oauth.js";
import { generateRandomString } from "../utils/crypto.js";
import { logger } from "../utils/logger.js";

/**
 * 認可リクエストのパラメーターを一時保管する。
 *
 * セッションとは別の保存先を用意し、識別子 txnId で参照する。
 * URL クエリ・hidden form field のパラメーター名も txnId とする。
 * 保存時のセッション ID を boundSid に記録し、取得時に照合する。
 */

/** 識別子 txnId のバイト長（16バイト = 128ビット） */
const TXN_ID_BYTES = 16;

/** 保存した認可リクエストの有効期間（10分） */
const REQUEST_TTL_MS = 10 * 60 * 1000;

interface StoredAuthorizationRequest {
	authorizationRequest: AuthorizationRequest;
	boundSid: string;
	expiresAt: Date;
}

/** 識別子 txnId をキーとする、メモリ上の保存先 */
const authorizationRequests = new Map<string, StoredAuthorizationRequest>();

/**
 * 検証済みの認可リクエストを保存し、識別子 txnId を返す。
 *
 * [SECURITY] txnId は CSPRNG で生成する。作成時のセッション ID も記録し、
 * 取得時に照合することで、別セッションの認可リクエストへの差し替えを拒否する。
 */
export function saveAuthorizationRequest(
	authorizationRequest: AuthorizationRequest,
	boundSid: string,
): string {
	const txnId = generateRandomString(TXN_ID_BYTES);
	const now = new Date();
	authorizationRequests.set(txnId, {
		authorizationRequest,
		boundSid,
		expiresAt: new Date(now.getTime() + REQUEST_TTL_MS),
	});
	return txnId;
}

/**
 * txnId を使って保存済みの認可リクエストを取得する（取得成功時は削除しない）。
 * 存在しない、期限切れ、boundSid 不一致の場合は null を返す。
 */
export function getAuthorizationRequest(
	txnId: string,
	currentSid: string,
): AuthorizationRequest | null {
	const stored = authorizationRequests.get(txnId);
	if (!stored) {
		return null;
	}

	// 取得時に期限切れのデータを削除する。再アクセスされないデータの定期削除は省略。
	if (new Date() > stored.expiresAt) {
		authorizationRequests.delete(txnId);
		return null;
	}

	// [SECURITY] 別セッションからの利用を拒否する。元のセッション用のデータは残す。
	if (stored.boundSid !== currentSid) {
		logger.warn("保存した認可リクエストの boundSid が現在のセッション ID と一致しません", {
			txnId,
		});
		return null;
	}

	return stored.authorizationRequest;
}

/**
 * 保存済みの認可リクエストを取得し、成功した場合だけ即座に削除する。
 * 認可コード発行に進むとき、または同意を拒否したときに使用する。
 */
export function consumeAuthorizationRequest(
	txnId: string,
	currentSid: string,
): AuthorizationRequest | null {
	const authorizationRequest = getAuthorizationRequest(txnId, currentSid);
	if (authorizationRequest) {
		authorizationRequests.delete(txnId);
	}
	return authorizationRequest;
}

/**
 * 旧セッションに紐づくすべての認可リクエストを、新しいセッションへ紐付け直す。
 *
 * [SECURITY] ログイン成功時のセッション ID 再生成に伴う更新。
 * 識別子・認可リクエストの内容・有効期限は変更しない。
 */
// #@range_begin(rebind-authorization-requests) ※書籍掲載用の範囲マーカー
export function rebindAuthorizationRequests(oldSid: string, newSid: string): void {
	for (const stored of authorizationRequests.values()) {
		if (stored.boundSid === oldSid) {
			stored.boundSid = newSid;
		}
	}
}
// #@range_end(rebind-authorization-requests)

/** テスト用: 保存した認可リクエストをすべて削除する。 */
export function clearAuthorizationRequests(): void {
	authorizationRequests.clear();
}
