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
 * DB保存用のSHA-256ハッシュをhex文字列で返す。
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
 * PKCE S256用のSHA-256ハッシュをBase64URLエンコードで返す。
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
 * ハッシュ値やCSRFトークンを比較する。
 *
 * [SECURITY] 内容の一致位置による時間差を抑えるため、timingSafeEqualを使う。
 * 文字数が同じならUTF-8のバイト数も同じになる入力を前提とする。
 * 長さの分岐やBuffer変換も含めた処理時間の一定性は保証しない。
 *
 * @param a 比較対象の文字列
 * @param b 比較対象の文字列
 * @returns 一致する場合true
 */
// #@range_begin(constant-time-equal) ※書籍掲載用の範囲マーカー
export function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		// 長さが異なる場合も比較処理を行ってから不一致を返す。
		const dummy = Buffer.from(a);
		crypto.timingSafeEqual(dummy, dummy);
		return false;
	}

	const bufA = Buffer.from(a);
	const bufB = Buffer.from(b);
	return crypto.timingSafeEqual(bufA, bufB);
}
// #@range_end(constant-time-equal)
