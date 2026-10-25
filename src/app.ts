import { Hono } from "hono";
import { createAuthorizeEndpoint } from "./endpoints/authorize.js";
import { createIntrospectionEndpoint } from "./endpoints/introspect.js";
import { createJwksEndpoint } from "./endpoints/jwks.js";
import { createLoginEndpoint } from "./endpoints/login.js";
import { createMetadataEndpoint } from "./endpoints/metadata.js";
import { createRevocationEndpoint } from "./endpoints/revoke.js";
import { createTokenEndpoint } from "./endpoints/token.js";
import { errorHandler } from "./middleware/error-handler.js";
import { securityHeaders } from "./middleware/security-headers.js";

const app = new Hono();

// グローバルミドルウェア
app.use("*", securityHeaders);

// グローバルエラーハンドラ
app.onError(errorHandler);

// ヘルスチェックエンドポイント
app.get("/health", (c) => {
	return c.json({ status: "ok" });
});

// 各エンドポイントをマウント
app.route("/", createAuthorizeEndpoint());
app.route("/", createLoginEndpoint());
app.route("/", createTokenEndpoint());
app.route("/", createRevocationEndpoint());
app.route("/", createIntrospectionEndpoint());
app.route("/", createJwksEndpoint());
app.route("/", createMetadataEndpoint());

export default app;
