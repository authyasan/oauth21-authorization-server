import { sha256Base64url } from "../utils/crypto.js";

/**
 * PKCE (Proof Key for Code Exchange) 検証サービス。
 *
 * [SECURITY] PKCE検証: code_verifierのSHA-256ハッシュがcode_challengeと一致することを確認。
 * この検証がないと、認可コード横取り攻撃が成立する。
 *
 * OAuth 2.1ではPKCEが必須。
 * draft-16 §4.1.1はplainを禁止し、code_challenge_methodの指定を必須としている。
 * 本書ではS256のみを実装する。
 */

/**
 * RFC 7636 §4.1 / §4.2 の ABNF: 43〜128 文字の unreserved 文字列。
 * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
 * S256のcode_challengeは、下の専用関数でより狭い形式を検証する。
 */
const PKCE_SYNTAX = /^[A-Za-z0-9._~-]{43,128}$/;

/**
 * code_verifier が RFC 7636 §4.1 の構文（43〜128 文字・unreserved）に適合するか。
 *
 * [SECURITY] 構文（長さ・文字種）はサーバーの責務。
 * ただしエントロピー（RFC 7636 §7.1）はクライアントの生成責務であり、
 * 構文検証はそれを保証しない。
 */
export function isValidPkceCodeVerifier(codeVerifier: string): boolean {
	return PKCE_SYNTAX.test(codeVerifier);
}

/**
 * code_challenge が本書の採用するS256の形式（43文字・パディングなしBase64url）に適合するか。
 *
 * [SECURITY] 認可リクエスト時に challenge の構文を検証する。
 */
export function isValidPkceCodeChallenge(codeChallenge: string): boolean {
	return codeChallenge.length === 43 && !/[^A-Za-z0-9_-]/.test(codeChallenge);
}

/**
 * code_verifierを検証する。
 *
 * @param codeVerifier クライアントから送信されたcode_verifier
 * @param storedCodeChallenge 認可リクエスト時に保存したcode_challenge
 * @param codeChallengeMethod チャレンジメソッド（本書が受け付けるのはS256のみ）
 * @returns 検証成功ならtrue
 */
// #@range_begin(verify-code-challenge) ※書籍掲載用の範囲マーカー
export function verifyCodeChallenge(
	codeVerifier: string,
	storedCodeChallenge: string,
	codeChallengeMethod: string,
): boolean {
	// [SECURITY] 受け付ける方式はS256のみ。
	// plainはdraft-16では禁止されている。未対応の方式も受け付けない。
	if (codeChallengeMethod !== "S256") {
		return false;
	}

	// [SECURITY] code_verifier の構文検証（43〜128文字・unreserved、RFC 7636 §4.1）。
	// /tokenはこの関数の呼び出し前に構文不正をinvalid_requestで拒否する。
	// 本関数でも、構文不正な値をハッシュの一致だけで受理しない。
	if (!isValidPkceCodeVerifier(codeVerifier)) {
		return false;
	}

	// [SECURITY] code_verifier → SHA-256 → Base64URL で code_challenge を再計算
	const computedChallenge = sha256Base64url(codeVerifier);

	// code_challengeは攻撃者が推測する対象ではないため、通常の文字列比較で十分
	return computedChallenge === storedCodeChallenge;
}
// #@range_end(verify-code-challenge)
