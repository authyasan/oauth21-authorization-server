/** @jsxImportSource hono/jsx */

import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { SESSION_COOKIE_NAME, setSessionCookie } from "../middleware/auth.js";
import { findUserByUsername } from "../repositories/user-repository.js";
import {
	getAuthorizationRequest,
	rebindAuthorizationRequests,
} from "../services/authorization-request-store.js";
import {
	createSession,
	deleteSession,
	getSession,
	updateSession,
	validateCsrfToken,
} from "../services/session-service.js";
import { logger } from "../utils/logger.js";
import { verifyDummyPassword, verifyPassword } from "../utils/password.js";
import { ErrorPage } from "../views/error.js";
import { LoginPage } from "../views/login.js";

/**
 * ログインエンドポイント。
 * GET /login: ログインフォームを表示
 * POST /login: ログイン処理を実行
 *
 * 認可フローの中では、未ログイン時に /login?txnId=... へリダイレクトされてくる。
 * txnId は hidden form field で POST /login に渡され、ログイン成功後の
 * リダイレクト先 /authorize?txnId=... に乗せて認可フローに戻る。
 *
 * 認可リクエストはセッションと分けた専用の保存先に置き、txnId で参照する。
 */
export function createLoginEndpoint() {
	const app = new Hono();

	// GET /login: ログインフォーム表示
	app.get("/login", (c) => {
		const txnId = c.req.query("txnId");

		let sessionId = getCookie(c, SESSION_COOKIE_NAME);
		let session = sessionId ? getSession(sessionId) : null;

		// [SECURITY] 認可フローの場合は、保存データの期限とセッションへの紐付けを確認する。
		if (txnId && (!sessionId || !session || !getAuthorizationRequest(txnId, sessionId))) {
			return c.html(<ErrorPage />, 400);
		}

		if (session?.userId) {
			return c.redirect(txnId ? `/authorize?txnId=${encodeURIComponent(txnId)}` : "/");
		}

		// [SECURITY] 直接ログインでも、フォーム表示時に検証用のセッションを用意する。
		if (!session) {
			sessionId = createSession();
			session = getSession(sessionId);
			setSessionCookie(c, sessionId);
		}
		// 直前に作ったセッションなので必ず存在する。型を絞るためだけの確認。
		if (!session) return c.html(<ErrorPage />, 400);

		return c.html(<LoginPage txnId={txnId} csrfToken={session.csrfToken} />);
	});

	// POST /login: ログイン処理
	app.post("/login", async (c) => {
		const sessionId = getCookie(c, SESSION_COOKIE_NAME);
		const session = sessionId ? getSession(sessionId) : null;
		const body = await c.req.parseBody({ all: true });
		// [SECURITY] 認証やセッションの更新より前に照合する。Cookieなしのログインも拒否する。
		if (!sessionId || !session || !validateCsrfToken(session, body.csrfToken)) {
			return c.html(<ErrorPage />, 403);
		}
		const { username, password, txnId } = body;
		if (
			txnId !== undefined &&
			(typeof txnId !== "string" || !getAuthorizationRequest(txnId, sessionId))
		) {
			return c.html(<ErrorPage />, 400);
		}

		// 入力バリデーション
		if (typeof username !== "string" || typeof password !== "string" || !username || !password) {
			return c.html(
				<LoginPage
					error="ユーザー名とパスワードを入力してください"
					txnId={txnId}
					csrfToken={session.csrfToken}
				/>,
				400,
			);
		}

		// ユーザー検索
		const user = await findUserByUsername(username);

		// [SECURITY] ユーザーが存在しない場合もパスワード検証を行い、
		// レスポンス時間の差からユーザーの存在を推測されにくくする。
		// 実在ユーザーと同じコストのダミーハッシュとの比較で時間を消費する。
		if (!user) {
			await verifyDummyPassword(password);
			logger.warn("ログイン失敗: ユーザーが見つからない", { username });
			return c.html(
				<LoginPage
					error="ユーザー名またはパスワードが正しくありません"
					txnId={txnId}
					csrfToken={session.csrfToken}
				/>,
				401,
			);
		}

		// パスワード検証
		const isValid = await verifyPassword(password, user.passwordHash);
		if (!isValid) {
			logger.warn("ログイン失敗: パスワード不一致", { username });
			return c.html(
				<LoginPage
					error="ユーザー名またはパスワードが正しくありません"
					txnId={txnId}
					csrfToken={session.csrfToken}
				/>,
				401,
			);
		}

		// [SECURITY] パスワード検証中に別タブがセッションを更新した場合も、旧フォームは拒否する。
		if (!validateCsrfToken(getSession(sessionId), body.csrfToken)) {
			return c.html(<ErrorPage />, 403);
		}

		// ログイン成功
		logger.info("ログイン成功", { userId: user.id, username });

		// #@range_begin(login-session-rebind) ※書籍掲載用の範囲マーカー
		// [SECURITY] セッション固定攻撃対策: ログイン成功時にセッションIDを再生成する。
		// 攻撃者が事前にセットしたセッションIDを無効化し、新しいIDに差し替える。
		const oldSessionId = sessionId;
		// CSRFトークンもcreateSessionで新しく生成する。
		const newSessionId = createSession();

		// [SECURITY] 旧 sid に紐づけて保存した認可リクエストの boundSid を、新 sid に張り替える。
		// これによりログイン後の /authorize?txnId=... で boundSid 検証を通せる。
		rebindAuthorizationRequests(oldSessionId, newSessionId);
		deleteSession(oldSessionId);
		// #@range_end(login-session-rebind)

		// 新しいセッションにユーザーIDと認証時刻を記録
		updateSession(newSessionId, {
			userId: user.id,
			authenticatedAt: new Date(),
		});

		setSessionCookie(c, newSessionId);

		// [SECURITY] 303でPOSTをGETに切り替え、資格情報を遷移先へ再送しない（OAuth 2.1 draft-16 §7.5.4）。
		// 認可フローからの遷移（txnId 付き）→ 認可エンドポイントへ戻る
		if (txnId) {
			return c.redirect(`/authorize?txnId=${encodeURIComponent(txnId)}`, 303);
		}

		// 認可フロー以外からのログインの場合
		return c.redirect("/", 303);
	});

	return app;
}
