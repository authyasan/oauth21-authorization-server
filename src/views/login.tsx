/** @jsxImportSource hono/jsx */

/**
 * ログインフォームを表示し、認可フローのtxnIdとCSRFトークンをPOSTに引き継ぐ。
 */

interface LoginPageProps {
	csrfToken: string;
	error?: string;
	/** 認可フローからの遷移時に伴う txnId（hidden form field で POST /login に渡す） */
	txnId?: string;
}

export function LoginPage({ error, txnId, csrfToken }: LoginPageProps) {
	return (
		<html lang="ja">
			<head>
				<meta charset="UTF-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1.0" />
				<title>ログイン - OAuth 2.1 認可サーバー</title>
				<style>{`
					body {
						font-family: system-ui, -apple-system, sans-serif;
						max-width: 400px;
						margin: 80px auto;
						padding: 0 20px;
						background-color: #f5f5f5;
					}
					.login-form {
						background: white;
						padding: 32px;
						border-radius: 8px;
						box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
					}
					h1 {
						text-align: center;
						color: #333;
						margin-bottom: 24px;
					}
					label {
						display: block;
						margin-bottom: 4px;
						color: #555;
						font-size: 14px;
					}
					input[type="text"],
					input[type="password"] {
						width: 100%;
						padding: 10px;
						margin-bottom: 16px;
						border: 1px solid #ddd;
						border-radius: 4px;
						font-size: 16px;
						box-sizing: border-box;
					}
					button {
						width: 100%;
						padding: 12px;
						background-color: #2563eb;
						color: white;
						border: none;
						border-radius: 4px;
						font-size: 16px;
						cursor: pointer;
					}
					button:hover {
						background-color: #1d4ed8;
					}
					.error {
						background-color: #fef2f2;
						color: #dc2626;
						padding: 12px;
						border-radius: 4px;
						margin-bottom: 16px;
						font-size: 14px;
					}
				`}</style>
			</head>
			<body>
				<div class="login-form">
					<h1>ログイン</h1>
					{error && <div class="error">{error}</div>}
					<form method="post" action="/login">
						<input type="hidden" name="csrfToken" value={csrfToken} />
						{txnId && <input type="hidden" name="txnId" value={txnId} />}
						<label for="username">ユーザー名</label>
						<input type="text" id="username" name="username" required />
						<label for="password">パスワード</label>
						<input type="password" id="password" name="password" required />
						<button type="submit">ログイン</button>
					</form>
				</div>
			</body>
		</html>
	);
}
