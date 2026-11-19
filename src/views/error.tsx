/** @jsxImportSource hono/jsx */

/**
 * リダイレクト先を確認できない場合や、ログイン・同意の検証に失敗した場合のエラー画面。
 * 内部の検証結果を推測されないよう、汎用メッセージだけを表示する。
 */
export function ErrorPage() {
	return (
		<html lang="ja">
			<head>
				<meta charset="UTF-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1.0" />
				<title>エラー - OAuth 2.1 認可サーバー</title>
				<style>{`
					body {
						font-family: system-ui, -apple-system, sans-serif;
						max-width: 500px;
						margin: 80px auto;
						padding: 0 20px;
						background-color: #f5f5f5;
					}
					.error-container {
						background: white;
						padding: 32px;
						border-radius: 8px;
						box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
					}
					h1 {
						color: #dc2626;
						margin-bottom: 16px;
					}
					.error-message {
						color: #555;
						font-size: 16px;
						line-height: 1.6;
					}
				`}</style>
			</head>
			<body>
				<div class="error-container">
					<h1>認可リクエストエラー</h1>
					<p class="error-message">不正なリクエストです。</p>
				</div>
			</body>
		</html>
	);
}
