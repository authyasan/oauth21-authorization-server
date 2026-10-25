/** E2Eテストのサーバー・ブラウザ・テストで共有する設定。 */
export const HTTPS_PORT = 18443;
export const CONTROL_PORT = 18444;

/** example.test の下は同一サイト（登録可能ドメイン example.test）、evil.test は別サイト。 */
export const HOSTS = {
	site: "example.test",
	as: "as.example.test",
	client: "client.example.test",
	other: "other.example.test",
	sub: "sub.example.test",
	evil: "evil.test",
} as const;

export const AS_ORIGIN = `https://${HOSTS.as}:${HTTPS_PORT}`;
export const CLIENT_ID = "public-spa-client";
export const REDIRECT_URI = `https://${HOSTS.client}:${HTTPS_PORT}/callback`;
export const CONTROL_ORIGIN = `http://127.0.0.1:${CONTROL_PORT}`;

export const E2E_DATABASE_URL =
	process.env.E2E_DATABASE_URL ??
	"postgresql://oauth21:csrf_test_only@127.0.0.1:5493/oauth21_e2e_test";

export const USERNAME = "testuser";
export const PASSWORD = "password123";
