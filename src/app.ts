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

// エンドポイントを組み合わせ、共通のレスポンスヘッダーと例外処理を適用する。
// [SECURITY] 本文サイズの上限は省略しているため、第三者から受け付ける場合は解析前に制限する。
app.use("*", securityHeaders);

app.onError(errorHandler);

app.get("/health", (c) => {
	return c.json({ status: "ok" });
});

app.route("/", createAuthorizeEndpoint());
app.route("/", createLoginEndpoint());
app.route("/", createTokenEndpoint());
app.route("/", createRevocationEndpoint());
app.route("/", createIntrospectionEndpoint());
app.route("/", createJwksEndpoint());
app.route("/", createMetadataEndpoint());

export default app;
