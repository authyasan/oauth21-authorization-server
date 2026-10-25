import crypto from "node:crypto";

/**
 * 暗号関連のユーティリティ関数。
 * 認可コード生成、PKCE検証、トークンハッシュなどで使用する。
 */

/**
 * 暗号学的に安全なランダム文字列を生成する。
 * 認可コード、トークンID (jti)、リフレッシュトークンなどに使用。
 *
 * @param byteLength バイト数（デフォルト32バイト = 256ビット）
 * @returns URL-safe Base64エンコードされた文字列
 */
export function generateRandomString(byteLength: number = 32): string {
	return crypto.randomBytes(byteLength).toString("base64url");
}

/**
 * SHA-256ハッシュを計算する。
 * 認可コードやリフレッシュトークンのDB保存時のハッシュ化に使用。
 *
 * [SECURITY] DB漏洩時にトークンが直接漏れることを防ぐため、
 * 認可コードとリフレッシュトークンはハッシュして保存する。
 *
 * @param input ハッシュ対象の文字列
 * @returns hex文字列のSHA-256ハッシュ
 */
export function sha256(input: string): string {
	return crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * SHA-256ハッシュをBase64URLエンコードで返す。
 * PKCE S256のcode_challenge計算に使用。
 *
 * [SECURITY] PKCE: code_verifierからcode_challengeを計算する際に使用。
 * code_challenge = BASE64URL(SHA256(code_verifier))
 *
 * @param input ハッシュ対象の文字列
 * @returns Base64URLエンコードされたSHA-256ハッシュ
 */
export function sha256Base64url(input: string): string {
	return crypto.createHash("sha256").update(input).digest("base64url");
}

/**
 * 定数時間での文字列比較を行う。
 *
 * [SECURITY] タイミング攻撃対策。
 * 通常の文字列比較(===)は不一致が見つかった時点で処理を終了するため、
 * 攻撃者がレスポンス時間の差から正しい文字列を推測できる。
 * この関数は入力の長さや内容に関わらず常に同じ時間で比較を行う。
 *
 * @param a 比較対象の文字列
 * @param b 比較対象の文字列
 * @returns 一致する場合true
 */
// #@range_begin(constant-time-equal) ※書籍掲載用の範囲マーカー
export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		// 長さが異なる場合もタイミングを漏らさないようにダミー比較を行う
		const dummy = Buffer.from(a);
		crypto.timingSafeEqual(dummy, dummy);
		return false;
	}

	const bufA = Buffer.from(a);
	const bufB = Buffer.from(b);
	return crypto.timingSafeEqual(bufA, bufB);
}
// #@range_end(constant-time-equal)
