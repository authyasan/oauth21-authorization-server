import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createAuthorizeEndpoint } from "../../src/endpoints/authorize.js";
import { createIntrospectionEndpoint } from "../../src/endpoints/introspect.js";
import { createRevocationEndpoint } from "../../src/endpoints/revoke.js";
import { createTokenEndpoint } from "../../src/endpoints/token.js";
import { errorHandler } from "../../src/middleware/error-handler.js";

const app = new Hono();
app.onError(errorHandler);
app.route("/", createAuthorizeEndpoint());
app.route("/", createTokenEndpoint());
app.route("/", createRevocationEndpoint());
app.route("/", createIntrospectionEndpoint());
const allowedDescription = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/;

describe("error_descriptionの許可文字", () => {
	it.each([
		["/token", "", "invalid_request"],
		["/token", "authorization_code", "invalid_client"],
		["/token", '日本語"\\\r\n', "unsupported_grant_type"],
		["/revoke", "", "invalid_client"],
		["/introspect", "", "invalid_client"],
	])("%sのJSON応答は復号後も許可文字だけを含む (%s)", async (endpoint, grantType, error) => {
		const response = await app.request(endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(grantType ? { grant_type: grantType } : {}),
		});
		expect(response.status).toBeGreaterThanOrEqual(400);
		const body = await response.json();
		expect(body.error).toBe(error);
		expect(body.error_description).toMatch(allowedDescription);
	});

	it.each(["", '日本語"\\\r\n'])(
		"認可エラーのクエリもURL復号後に許可文字だけを含む (%s)",
		async (responseType) => {
			const params = new URLSearchParams({
				client_id: "public-spa-client",
				response_type: responseType,
				state: "日本語-state",
			});
			const response = await app.request(`/authorize?${params}`);
			expect(response.status).toBe(302);
			const location = response.headers.get("Location");
			expect(location).not.toBeNull();
			const query = new URL(location ?? "").searchParams;
			expect(query.get("error")).toBe(
				responseType ? "unsupported_response_type" : "invalid_request",
			);
			expect(query.get("error_description")).toMatch(allowedDescription);
			expect(query.get("state")).toBe("日本語-state");
		},
	);
});
