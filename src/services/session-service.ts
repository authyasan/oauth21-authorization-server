import { constantTimeEqual, generateRandomString } from "../utils/crypto.js";

/**
 * セッションデータの型定義。
 *
 * セッションはユーザー識別情報とCSRFトークンを保持する。
 * 認可リクエストの一時保管は authorization-request-store で扱う。
 */
export interface SessionData {
	/** フォーム送信の検証用。セッションIDとは独立した乱数 */
	csrfToken: string;
	/** ログイン済みユーザーのID（未ログインの場合undefined） */
	userId?: string;
	/** ログイン時刻。再認証を求める条件を作り込むときのために記録する（現在は読んでいない） */
	authenticatedAt?: Date;
}

/**
 * メモリベースのセッション管理サービス。
 *
 * [SECURITY] セッションIDは128ビット（16バイト）のCSPRNG出力で生成する。
 * セッションIDが推測可能だと、セッションハイジャックが成立する。
 *
 * セッション保存先はサーバーサイド（メモリ）。
 * 単一サーバー構成の学習用プロジェクトのため、シンプルさを優先。
 * サーバー再起動で全セッションが消失するが、認可コードやトークンは
 * DBに永続化されているため影響は限定的。
 */

/** セッション有効期限（30分） */
export const SESSION_TTL_MS = 30 * 60 * 1000;

/** セッションIDのバイト長（16バイト = 128ビット） */
const SESSION_ID_BYTES = 16;

interface StoredSession {
	data: SessionData;
	createdAt: Date;
	expiresAt: Date;
}

/** メモリ上のセッションストア */
const sessions = new Map<string, StoredSession>();

/**
 * 新しいセッションを作成する。
 *
 * [SECURITY] セッションIDはCSPRNGで生成。予測可能なIDを使うと
 * セッション固定攻撃やセッションハイジャックが成立する。
 *
 * @returns セッションID
 */
export function createSession(): string {
	const sessionId = generateRandomString(SESSION_ID_BYTES);
	const now = new Date();
	sessions.set(sessionId, {
		// [SECURITY] セッションIDをフォームに露出させず、別の乱数でCSRF対策を行う。
		data: { csrfToken: generateRandomString(32) },
		createdAt: now,
		expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
	});
	return sessionId;
}

/**
 * セッションデータを取得する。
 * 有効期限切れのセッションはnullを返し、ストアから削除する。
 *
 * @param sessionId セッションID
 * @returns セッションデータ（存在しないか期限切れの場合null）
 */
export function getSession(sessionId: string): SessionData | null {
	const stored = sessions.get(sessionId);
	if (!stored) {
		return null;
	}

	// 有効期限チェック
	if (new Date() > stored.expiresAt) {
		sessions.delete(sessionId);
		return null;
	}

	return stored.data;
}

/**
 * セッションデータを更新する。
 *
 * @param sessionId セッションID
 * @param data 更新するデータ（既存データとマージ）
 * @returns 更新成功の場合true
 */
export function updateSession(
	sessionId: string,
	data: Partial<Omit<SessionData, "csrfToken">>,
): boolean {
	const stored = sessions.get(sessionId);
	if (!stored) {
		return false;
	}

	// 有効期限チェック
	if (new Date() > stored.expiresAt) {
		sessions.delete(sessionId);
		return false;
	}

	stored.data = { ...stored.data, ...data };
	return true;
}

/** セッションに保存したCSRFトークンとフォームの値を照合する。 */
// #@range_begin(validate-csrf-token) ※書籍掲載用の範囲マーカー
export function validateCsrfToken(session: SessionData | null, token: unknown): boolean {
	// [SECURITY] 欠落・重複（配列）・Fileなどの型不正を拒否する。
	// 32バイトのbase64urlに限定し、文字列比較には既存の定数時間比較を使う。
	if (!session || typeof token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
		return false;
	}
	return constantTimeEqual(session.csrfToken, token);
}
// #@range_end(validate-csrf-token)

/**
 * セッションを削除する（ログアウト）。
 *
 * @param sessionId セッションID
 */
export function deleteSession(sessionId: string): void {
	sessions.delete(sessionId);
}

/**
 * テスト用: 全セッションをクリアする。
 */
export function clearAllSessions(): void {
	sessions.clear();
}
