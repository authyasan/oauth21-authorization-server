import type { Context } from "hono";
import { setCookie } from "hono/cookie";
import { SESSION_TTL_MS } from "../services/session-service.js";

/**
 * セッションCookieの名前。
 *
 * [SECURITY] 本番環境（HTTPS、Secure属性付き）では `__Host-` 接頭辞を付ける。
 * ブラウザは `__Host-` のCookieを、Secure・Path=/・Domain指定なしで設定された場合にしか受け入れない。
 * 同じサイトの別サブドメインから Domain 指定でセッションCookieを注入・上書きされる攻撃（Cookie tossing）を防ぐ。
 * ローカルのHTTPではSecure属性を付けられないため、接頭辞なしの `sid` を使う。
 * Secure属性の判定（setSessionCookie の `secure`）と条件をそろえている。
 */
export const SESSION_COOKIE_NAME = process.env.NODE_ENV === "production" ? "__Host-sid" : "sid";

/**
 * セッションの作成・再生成でCookieの属性がばらつかないよう、設定を共通化する。
 */
export function setSessionCookie(c: Context, sessionId: string): void {
	// #@range_begin(session-cookie) ※書籍掲載用の範囲マーカー
	// [SECURITY] セッションCookieの属性設定
	// HttpOnly: JavaScriptからアクセスできない（XSS対策）
	// SameSite=Lax: クロスサイトリクエストでのCookie送信を制限（CSRF対策）
	// Secure: HTTPS接続でのみ送信（本番環境）
	// Max-Age: サーバー側のセッション有効期限（秒単位）にそろえる
	setCookie(c, SESSION_COOKIE_NAME, sessionId, {
		httpOnly: true,
		sameSite: "Lax",
		secure: process.env.NODE_ENV === "production",
		path: "/",
		maxAge: SESSION_TTL_MS / 1000,
	});
	// #@range_end(session-cookie)
}
