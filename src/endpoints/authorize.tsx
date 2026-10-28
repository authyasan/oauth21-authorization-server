/** @jsxImportSource hono/jsx */
import type { Context } from "hono";
import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { serverConfig } from "../config/server.js";
import { OAuthError } from "../errors/oauth-error.js";
import { SESSION_COOKIE_NAME, setSessionCookie } from "../middleware/auth.js";
import { findClientById } from "../repositories/client-repository.js";
import { issueAuthorizationCode } from "../services/authorization-code-service.js";
import {
	consumeAuthorizationRequest,
	getAuthorizationRequest,
	saveAuthorizationRequest,
} from "../services/authorization-request-store.js";
import { validateAuthorizationRequest } from "../services/authorization-request-validator.js";
import { canSkipConsent, recordConsent } from "../services/consent-service.js";
import {
	createSession,
	getSession,
	type SessionData,
	validateCsrfToken,
} from "../services/session-service.js";
import type { ClientConfig } from "../types/client.js";
import type { AuthorizationRequest } from "../types/oauth.js";
import { logger } from "../utils/logger.js";
import { ConsentPage } from "../views/consent.js";
import { ErrorPage } from "../views/error.js";

/**
 * 認可エンドポイント。
 *
 * GET /authorize: 新規の認可リクエストを受け付け、パラメータを検証する（startAuthorization）
 *   同意省略条件を満たす → 認可コード発行 → redirect_uriにリダイレクト
 *   未ログイン → 認可リクエストを保存 → ログイン画面へリダイレクト
 *   同意省略条件を満たさない → 認可リクエストを保存 → 同意画面を表示（hidden form field に txnId）
 *
 * GET /authorize?txnId=...: ログイン後の復帰（resumeAuthorization）
 *   保存した認可リクエストを引き、同意省略の判定から続ける
 *
 * POST /authorize: 同意画面からの応答を処理し、保存した認可リクエストを消費する
 *   承認 → 同意記録保存 → 認可コード発行 → redirect_uriにリダイレクト
 *   拒否 → redirect_uriにaccess_deniedリダイレクト
 *
 * 段階的検証
 *   - client_id/redirect_uri不正 → エラー画面表示（リダイレクト不可）
 *   - その他のエラー → redirect_uriにエラーリダイレクト
 *
 * 認可リクエストはセッションと分離した専用ストアに保管し、
 *   txnId で参照する。各遷移点で boundSid を検証する。
 */
export function createAuthorizeEndpoint() {
	const app = new Hono();

	app.get("/authorize", async (c) => {
		const sessionId = getCookie(c, SESSION_COOKIE_NAME);
		const session = sessionId ? getSession(sessionId) : null;
		// ログイン後の復帰: 本サーバーが組み立てる /authorize?txnId=... だけを復帰とみなす。
		// [SECURITY] OAuth 2.1 draft-16 §3.1: 認可サーバーは認識しないパラメータを無視しなければ
		// ならない。txnId はクライアントから見て未知の名前なので、ほかのパラメータを伴う
		// リクエストは新規の認可リクエストとして扱い、txnId は無視する。
		const query = new URL(c.req.url).searchParams;
		const isResume = query.has("txnId") && [...query.keys()].every((name) => name === "txnId");
		const txnId = isResume ? query.get("txnId") : null;
		if (txnId) {
			return resumeAuthorization(c, txnId, sessionId, session);
		}
		return startAuthorization(c, sessionId, session);
	});

	// POST /authorize: 同意画面からの応答
	app.post("/authorize", async (c) => {
		const sessionId = getCookie(c, SESSION_COOKIE_NAME);
		if (!sessionId) {
			logger.warn("POST /authorize: セッションIDが存在しません");
			return c.html(<ErrorPage />, 403);
		}

		const session = getSession(sessionId);
		// #@range_begin(consent-csrf-check) ※書籍掲載用の範囲マーカー
		const body = await c.req.parseBody({ all: true });
		// [SECURITY] 承認・拒否のどちらも、保存データを消費する前にCSRFトークンを照合する。
		if (!session || !validateCsrfToken(session, body.csrfToken)) {
			return c.html(<ErrorPage />, 403);
		}
		// #@range_end(consent-csrf-check)
		if (!session?.userId) {
			logger.warn("POST /authorize: 未ログインのためエラー");
			return c.html(<ErrorPage />, 400);
		}

		const { txnId, decision } = body;

		if (typeof txnId !== "string" || !txnId || typeof decision !== "string") {
			logger.warn("POST /authorize: txnId パラメータがありません");
			return c.html(<ErrorPage />, 400);
		}

		// [SECURITY] 保存した認可リクエストを消費（boundSid 検証含む）
		const authorizationRequest = consumeAuthorizationRequest(txnId, sessionId);
		if (!authorizationRequest) {
			logger.warn("POST /authorize: txnId が見つからないか boundSid 不一致");
			return c.html(<ErrorPage />, 400);
		}

		// [SECURITY] 承認・拒否とも303でGETへ切り替え、CSRFトークンを含む同意フォームを
		// クライアントへ再送しない。
		if (decision === "deny") {
			logger.info("認可リクエスト: ユーザーが拒否", {
				clientId: authorizationRequest.clientId,
				userId: session.userId,
			});
			const error = new OAuthError(
				"access_denied",
				"The user denied access",
				400,
				authorizationRequest.state,
			);
			return redirectWithError(c, authorizationRequest.redirectUri, error, 303);
		}

		if (decision === "approve") {
			logger.info("認可リクエスト: ユーザーが承認", {
				clientId: authorizationRequest.clientId,
				userId: session.userId,
			});
			// 同意を記録（無期限）
			await recordConsent(
				session.userId,
				authorizationRequest.clientId,
				authorizationRequest.scope,
			);
			return redirectWithCode(c, authorizationRequest, session.userId, 303);
		}

		// 不正なdecision値（保存した認可リクエストは消費済み）
		logger.warn("POST /authorize: 不正なdecision値", { decision });
		return c.html(<ErrorPage />, 400);
	});

	return app;
}

/**
 * 新規の認可リクエストを受け付ける。
 */
async function startAuthorization(
	c: Context,
	sessionId: string | undefined,
	session: SessionData | null,
) {
	// #@range_begin(authorize-query-input) ※書籍掲載用の範囲マーカー
	// [SECURITY] 同名パラメータの重複を失わずに検証へ渡す。
	const params = new URL(c.req.url).searchParams;
	const result = validateAuthorizationRequest(params);
	// #@range_end(authorize-query-input)

	if (result.type === "client_error") {
		// client_id/redirect_uriが不正 → エラー画面を表示
		// [SECURITY] リダイレクトしてはならない
		logger.warn("認可リクエスト: クライアント検証エラー", {
			errorDescription: result.errorDescription,
			clientId: params.get("client_id"),
		});
		return c.html(<ErrorPage />, 400);
	}

	if (result.type === "redirect_error") {
		// redirect_uriは信頼できる → リダイレクトでエラーを返す
		logger.warn("認可リクエスト: パラメータ検証エラー", {
			errorCode: result.errorCode,
			errorDescription: result.errorDescription,
			clientId: params.get("client_id"),
		});
		const error = new OAuthError(result.errorCode, result.errorDescription, 400, result.state);
		return redirectWithError(c, result.redirectUri, error, 302);
	}

	const { client, authorizationRequest } = result;
	logger.info("認可リクエスト: バリデーション成功", {
		clientId: client.clientId,
		scope: authorizationRequest.scope,
	});

	// ログイン済みで同意画面を省略できる場合: 認可リクエストを保存せずに認可コードを発行する
	const userId = session?.userId;
	if (
		userId &&
		(await canSkipConsent(
			userId,
			client.clientId,
			authorizationRequest.scope,
			authorizationRequest.redirectUri,
		))
	) {
		logger.info("認可リクエスト: 同意済み、認可コード発行", { clientId: client.clientId, userId });
		return redirectWithCode(c, authorizationRequest, userId, 302);
	}

	// 未ログイン、未同意、または同意省略対象外: 認可リクエストを保存する
	// 必要ならセッションも作成（boundSid のため）
	const boundSid = sessionId && session ? sessionId : createSession();
	if (boundSid !== sessionId) {
		setSessionCookie(c, boundSid);
	}

	// [SECURITY] 認可リクエストの保存先に保管。boundSid で fixation を防御
	const txnId = saveAuthorizationRequest(authorizationRequest, boundSid);

	if (!userId || !session) {
		logger.info("認可リクエスト: 未ログイン、ログイン画面へリダイレクト", {
			clientId: client.clientId,
		});
		return c.redirect(`/login?txnId=${encodeURIComponent(txnId)}`, 302);
	}

	return renderConsentPage(c, client, authorizationRequest, txnId, session.csrfToken);
}

/**
 * ログイン後に、保存した認可リクエストを引いて続ける。
 */
async function resumeAuthorization(
	c: Context,
	txnId: string,
	sessionId: string | undefined,
	session: SessionData | null,
) {
	if (!sessionId) {
		logger.warn("GET /authorize: txnId 付きだがセッションがありません");
		return c.html(<ErrorPage />, 400);
	}

	// [SECURITY] boundSid の検証は getAuthorizationRequest 内で実施される
	const authorizationRequest = getAuthorizationRequest(txnId, sessionId);
	if (!authorizationRequest) {
		logger.warn("GET /authorize: txnId が見つからないか boundSid 不一致");
		return c.html(<ErrorPage />, 400);
	}

	const userId = session?.userId;
	if (!userId || !session) {
		// 未ログインのまま戻ってきた → 再度ログインへ
		logger.info("GET /authorize: txnId 付きだが未ログイン、ログイン画面へ", {
			clientId: authorizationRequest.clientId,
		});
		return c.redirect(`/login?txnId=${encodeURIComponent(txnId)}`, 302);
	}

	logger.info("認可リクエスト: 保存データから復元（ログイン後の復帰）", {
		clientId: authorizationRequest.clientId,
		userId,
	});

	if (
		await canSkipConsent(
			userId,
			authorizationRequest.clientId,
			authorizationRequest.scope,
			authorizationRequest.redirectUri,
		)
	) {
		// [SECURITY] 保存した認可リクエストの消費を認可コード発行より前に行うことで、
		// 同じ認可リクエストからの認可コード多重発行（並行リクエスト）を防ぐ
		if (!consumeAuthorizationRequest(txnId, sessionId)) {
			logger.warn("GET /authorize: 保存データの消費に失敗（並行リクエストの可能性）");
			return c.html(<ErrorPage />, 400);
		}
		logger.info("認可リクエスト: 同意済み、認可コード発行", {
			clientId: authorizationRequest.clientId,
			userId,
		});
		return redirectWithCode(c, authorizationRequest, userId, 302);
	}

	// 未同意、または省略対象外のリダイレクト先 → 同意画面を表示
	// 保存時に検証済みのクライアント。設定は起動時に固定されるので、通常は必ず見つかる。
	const client = findClientById(authorizationRequest.clientId);
	if (!client) {
		logger.error("GET /authorize: 保存した認可リクエストのクライアントが見つかりません");
		return c.html(<ErrorPage />, 400);
	}
	return renderConsentPage(c, client, authorizationRequest, txnId, session.csrfToken);
}

/**
 * 同意画面を表示する。承認・拒否は POST /authorize で受け取る。
 */
function renderConsentPage(
	c: Context,
	client: ClientConfig,
	authorizationRequest: AuthorizationRequest,
	txnId: string,
	csrfToken: string,
) {
	return c.html(
		<ConsentPage
			clientName={client.clientName}
			organizationName={client.organizationName}
			scopes={authorizationRequest.scope.split(" ")}
			txnId={txnId}
			csrfToken={csrfToken}
		/>,
	);
}

/**
 * 認可コードを発行し、redirect_uri へ返す（成功の認可レスポンス）。
 * state はリクエストにあった場合のみそのまま返す（RFC 6749 §4.1.2）。
 */
async function redirectWithCode(
	c: Context,
	authorizationRequest: AuthorizationRequest,
	userId: string,
	status: 302 | 303,
) {
	// [SECURITY] 認可コード発行（32バイトCSPRNG、SHA-256ハッシュでDB保存）
	const code = await issueAuthorizationCode({
		clientId: authorizationRequest.clientId,
		userId,
		redirectUri: authorizationRequest.redirectUri,
		scope: authorizationRequest.scope,
		codeChallenge: authorizationRequest.codeChallenge,
		codeChallengeMethod: authorizationRequest.codeChallengeMethod,
	});

	const redirectUrl = new URL(authorizationRequest.redirectUri);
	redirectUrl.searchParams.set("code", code);
	if (authorizationRequest.state) {
		redirectUrl.searchParams.set("state", authorizationRequest.state);
	}
	return redirectWithIssuer(c, redirectUrl, status);
}

/**
 * エラーを redirect_uri へ返す（エラーの認可レスポンス）。
 * error・error_description（許可文字に置換済み）・state は OAuthError が組み立てる。
 */
function redirectWithError(c: Context, redirectUri: string, error: OAuthError, status: 302 | 303) {
	return redirectWithIssuer(c, new URL(error.toRedirectUrl(redirectUri)), status);
}

/**
 * 認可レスポンスに iss を付けてリダイレクトする。
 *
 * [SECURITY] RFC 9207: ミックスアップ攻撃対策として、成功・エラーとも iss を必ず付ける（§2・§2.3）。
 * 認可レスポンスはすべてこの関数を通すので、付け忘れが起きない。
 */
function redirectWithIssuer(c: Context, redirectUrl: URL, status: 302 | 303) {
	redirectUrl.searchParams.set("iss", serverConfig.issuer);
	return c.redirect(redirectUrl.toString(), status);
}
