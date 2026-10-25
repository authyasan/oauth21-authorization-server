/** @jsxImportSource hono/jsx */

/**
 * 同意画面のビュー。
 * ユーザーにクライアントへのスコープ許可を確認する。
 */

interface ConsentPageProps {
	csrfToken: string;
	clientName: string;
	/** クライアントを登録した開発者・組織の名前（OAuth 2.1 draft-16 §7.9） */
	organizationName: string;
	scopes: string[];
	/** 認可リクエストの識別子 txnId（hidden form field で POST /authorize に渡す） */
	txnId: string;
}

export function ConsentPage({
	clientName,
	organizationName,
	scopes,
	txnId,
	csrfToken,
}: ConsentPageProps) {
	return (
		<html lang="ja">
			<head>
				<meta charset="UTF-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1.0" />
				<title>アクセス許可 - OAuth 2.1 認可サーバー</title>
				<style>{`
					body {
						font-family: system-ui, -apple-system, sans-serif;
						max-width: 480px;
						margin: 80px auto;
						padding: 0 20px;
						background-color: #f5f5f5;
					}
					.consent-form {
						background: white;
						padding: 32px;
						border-radius: 8px;
						box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
					}
					h1 {
						text-align: center;
						color: #333;
						margin-bottom: 8px;
						font-size: 20px;
					}
					.client-name {
						text-align: center;
						color: #2563eb;
						font-size: 18px;
						font-weight: bold;
						margin-bottom: 4px;
					}
					.organization-name {
						text-align: center;
						color: #555;
						font-size: 14px;
						margin-bottom: 24px;
					}
					.description {
						color: #555;
						font-size: 14px;
						margin-bottom: 16px;
					}
					.scope-list {
						list-style: none;
						padding: 0;
						margin: 0 0 24px 0;
					}
					.scope-list li {
						padding: 10px 12px;
						border: 1px solid #e5e7eb;
						border-radius: 4px;
						margin-bottom: 8px;
						font-size: 14px;
						color: #333;
					}
					.buttons {
						display: flex;
						gap: 12px;
					}
					button {
						flex: 1;
						padding: 12px;
						border: none;
						border-radius: 4px;
						font-size: 16px;
						cursor: pointer;
					}
					.approve {
						background-color: #2563eb;
						color: white;
					}
					.approve:hover {
						background-color: #1d4ed8;
					}
					.deny {
						background-color: #f3f4f6;
						color: #374151;
						border: 1px solid #d1d5db;
					}
					.deny:hover {
						background-color: #e5e7eb;
					}
				`}</style>
			</head>
			<body>
				<div class="consent-form">
					<h1>アクセス許可の確認</h1>
					<p class="client-name">{clientName}</p>
					<p class="organization-name">提供元: {organizationName}</p>
					<p class="description">このアプリケーションが以下の権限を要求しています：</p>
					<ul class="scope-list">
						{scopes.map((scope) => (
							<li>{scope}</li>
						))}
					</ul>
					<div class="buttons">
						<form method="post" action="/authorize" style="flex: 1; display: flex;">
							<input type="hidden" name="csrfToken" value={csrfToken} />
							<input type="hidden" name="decision" value="deny" />
							<input type="hidden" name="txnId" value={txnId} />
							<button type="submit" class="deny" style="flex: 1;">
								拒否
							</button>
						</form>
						<form method="post" action="/authorize" style="flex: 1; display: flex;">
							<input type="hidden" name="csrfToken" value={csrfToken} />
							<input type="hidden" name="decision" value="approve" />
							<input type="hidden" name="txnId" value={txnId} />
							<button type="submit" class="approve" style="flex: 1;">
								許可する
							</button>
						</form>
					</div>
				</div>
			</body>
		</html>
	);
}
