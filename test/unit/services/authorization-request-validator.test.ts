import assert from "node:assert/strict";
import { afterEach, describe, expect, it } from "vitest";
import { getClient } from "../../../src/config/clients.js";
import { validateAuthorizationRequest } from "../../../src/services/authorization-request-validator.js";

// テスト用の有効な認可リクエストパラメータ
function validParams(overrides: Record<string, string> = {}): URLSearchParams {
	return new URLSearchParams({
		client_id: "public-spa-client",
		redirect_uri: "http://127.0.0.1:8080/callback",
		response_type: "code",
		state: "random-state-value-for-csrf-protection",
		scope: "read",
		code_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		code_challenge_method: "S256",
		...overrides,
	});
}

describe("validateAuthorizationRequest", () => {
	describe("重複と検証順序", () => {
		for (const name of ["client_id", "redirect_uri"]) {
			it.each(["same", "different", "empty"])(
				`${name}が重複している場合（%s）はclient_errorを返す`,
				(kind) => {
					const params = validParams();
					params.append(
						name,
						kind === "same" ? (params.get(name) ?? "") : kind === "empty" ? "" : "other",
					);
					expect(validateAuthorizationRequest(params).type).toBe("client_error");
				},
			);
		}
		for (const name of [
			"scope",
			"response_type",
			"code_challenge",
			"code_challenge_method",
			"state",
		]) {
			it.each(["same", "different", "empty"])(`${name}の重複（%s）はinvalid_request`, (kind) => {
				const params = validParams();
				params.append(
					name,
					kind === "same" ? (params.get(name) ?? "") : kind === "empty" ? "" : "other",
				);
				expect(validateAuthorizationRequest(params)).toMatchObject({
					type: "redirect_error",
					redirectUri: "http://127.0.0.1:8080/callback",
					errorCode: "invalid_request",
					state: name === "state" ? undefined : params.get("state"),
				});
			});
		}
		it.each<Record<string, string>>([
			{ client_id: "unknown" },
			{ redirect_uri: "https://attacker.example/callback" },
		])("scope重複と返し先の不正が共存してもリダイレクトしない: %j", (overrides) => {
			const params = validParams(overrides);
			params.append("scope", "write");
			expect(validateAuthorizationRequest(params).type).toBe("client_error");
		});
		it("未知のパラメータの重複は無視する", () => {
			const params = validParams();
			params.append("unknown", "one");
			params.append("unknown", "two");
			expect(validateAuthorizationRequest(params).type).toBe("success");
		});
		it("空値が先でも重複を見落とさない", () => {
			const params = validParams({ scope: "" });
			params.append("scope", "read");
			expect(validateAuthorizationRequest(params)).toMatchObject({
				type: "redirect_error",
				errorCode: "invalid_request",
			});
		});
	});

	describe("省略時の登録URIの採用", () => {
		const client = getClient("public-spa-client");
		assert(client);
		const originalUris = [...client.redirectUris];
		afterEach(() => {
			client.redirectUris = [...originalUris];
		});

		it("空値も省略として扱い、エラーの返し先にも登録URIを使う", () => {
			expect(
				validateAuthorizationRequest(validParams({ redirect_uri: "", scope: "unknown" })),
			).toMatchObject({
				type: "redirect_error",
				redirectUri: originalUris[0],
				errorCode: "invalid_scope",
			});
		});
		it.each([[], ["https://client.example/a", "https://client.example/b"]])(
			"登録が0件または複数件なら省略を拒否する: %j",
			(...uris) => {
				client.redirectUris = uris;
				expect(validateAuthorizationRequest(validParams({ redirect_uri: "" })).type).toBe(
					"client_error",
				);
			},
		);
		it("省略で採用したURIもスキーム検証する", () => {
			client.redirectUris = ["http://client.example/callback"];
			expect(validateAuthorizationRequest(validParams({ redirect_uri: "" })).type).toBe(
				"client_error",
			);
		});
		it("登録済みURIのクエリを保持する", () => {
			client.redirectUris = ["https://client.example/callback?action=oauth"];
			expect(validateAuthorizationRequest(validParams({ redirect_uri: "" }))).toMatchObject({
				type: "success",
				authorizationRequest: { redirectUri: client.redirectUris[0] },
			});
		});
	});

	describe("空値と構文", () => {
		it.each([
			"",
			" ",
			" read",
			"read ",
			"read  write",
			"read\twrite",
			"read\nwrite",
			"read\n",
			"read\r",
			'read"',
			"read\\",
			"読み取り",
		])("不正なscopeを正規化して受け付けない: %j", (scope) => {
			expect(validateAuthorizationRequest(validParams({ scope }))).toMatchObject({
				type: "redirect_error",
				errorCode: "invalid_scope",
			});
		});
		it.each([
			"a".repeat(42),
			"a".repeat(44),
			"a".repeat(128),
			`${"a".repeat(42)}.`,
			`${"a".repeat(42)}~`,
			`${"a".repeat(42)}=`,
			`${"a".repeat(43)}\n`,
		])("S256の出力形式ではないchallengeを拒否する: %j", (code_challenge) => {
			expect(validateAuthorizationRequest(validParams({ code_challenge }))).toMatchObject({
				type: "redirect_error",
				errorCode: "invalid_request",
			});
		});
		it.each(["response_type", "code_challenge", "code_challenge_method"])(
			"%sの空値を欠落として扱う",
			(name) => {
				expect(validateAuthorizationRequest(validParams({ [name]: "" }))).toMatchObject({
					type: "redirect_error",
					errorCode: "invalid_request",
				});
			},
		);
	});

	// === フェーズ1: client_id検証 ===
	describe("client_id検証", () => {
		it("client_idが未指定の場合、client_errorを返す", () => {
			const params = validParams();
			params.delete("client_id");
			const result = validateAuthorizationRequest(params);
			expect(result.type).toBe("client_error");
			if (result.type === "client_error") {
				expect(result.errorDescription).toContain("client_id");
			}
		});

		it("存在しないclient_idの場合、client_errorを返す", () => {
			const result = validateAuthorizationRequest(validParams({ client_id: "unknown-client" }));
			expect(result.type).toBe("client_error");
			if (result.type === "client_error") {
				expect(result.errorDescription).toContain("client_id");
			}
		});
	});

	// === フェーズ2: redirect_uri検証 ===
	describe("redirect_uri検証", () => {
		it("登録が1件ならredirect_uriを省略できる", () => {
			const params = validParams();
			params.delete("redirect_uri");
			const result = validateAuthorizationRequest(params);
			expect(result).toMatchObject({
				type: "success",
				authorizationRequest: { redirectUri: "http://127.0.0.1:8080/callback" },
			});
		});

		it("登録されていないredirect_uriの場合、client_errorを返す", () => {
			const result = validateAuthorizationRequest(
				validParams({ redirect_uri: "https://evil.com/callback" }),
			);
			expect(result.type).toBe("client_error");
		});

		it("クエリパラメータ付きredirect_uriは完全一致しないと不一致エラー", () => {
			// 登録URIにはクエリがないため、クエリを追加したURIは不一致として拒否する。
			const result = validateAuthorizationRequest(
				validParams({ redirect_uri: "http://127.0.0.1:8080/callback?extra=value" }),
			);
			expect(result.type).toBe("client_error");
			if (result.type === "client_error") {
				expect(result.errorDescription).toContain("registered URI");
			}
		});

		it("ループバックURIはポート番号が異なっても一致する", () => {
			const result = validateAuthorizationRequest(
				validParams({ redirect_uri: "http://127.0.0.1:9999/callback" }),
			);
			// clients.jsonにhttp://127.0.0.1:8080/callbackが登録されている
			// ループバックURIはポート番号を除いて比較するため、ポート9999でも一致する
			expect(result.type).toBe("success");
		});

		it("カスタムURLスキームが逆ドメイン名形式でない場合、client_errorを返す", () => {
			const result = validateAuthorizationRequest(
				validParams({ redirect_uri: "myapp://callback" }),
			);
			expect(result.type).toBe("client_error");
			if (result.type === "client_error") {
				expect(result.errorDescription).toContain("scheme");
			}
		});
	});

	// === フェーズ3: その他のパラメータ検証 ===
	describe("response_type検証", () => {
		it("response_typeが未指定の場合、redirect_errorを返す", () => {
			const params = validParams();
			params.delete("response_type");
			const result = validateAuthorizationRequest(params);
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("invalid_request");
				expect(result.errorDescription).toContain("response_type");
			}
		});

		it("response_typeがcode以外の場合、redirect_errorを返す", () => {
			const result = validateAuthorizationRequest(validParams({ response_type: "token" }));
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("unsupported_response_type");
			}
		});
	});

	describe("state検証", () => {
		it("stateが未指定でも成功する（stateは任意）", () => {
			const params = validParams();
			params.delete("state");
			const result = validateAuthorizationRequest(params);
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.authorizationRequest.state).toBeUndefined();
			}
		});

		it("stateが空文字の場合、省略されたものとして扱う（OAuth 2.1 §3.1）", () => {
			const result = validateAuthorizationRequest(validParams({ state: "" }));
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.authorizationRequest.state).toBeUndefined();
			}
		});

		it("2,000文字のstateを受け付け、値をそのまま保持する", () => {
			const longState = "a".repeat(2000);
			const result = validateAuthorizationRequest(validParams({ state: longState }));
			// エラー画面にもリダイレクトエラーにもならず、値をそのまま保持する
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.authorizationRequest.state).toBe(longState);
			}
		});
	});

	describe("scope検証", () => {
		it("scopeが未指定の場合、redirect_errorを返す", () => {
			const params = validParams();
			params.delete("scope");
			const result = validateAuthorizationRequest(params);
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("invalid_scope");
				expect(result.errorDescription).toContain("scope");
				expect(result.state).toBe(params.get("state"));
			}
		});

		it("scopeが空白文字だけの場合、invalid_scopeを返す", () => {
			const result = validateAuthorizationRequest(validParams({ scope: "   " }));
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("invalid_scope");
			}
		});

		it("未登録のscopeが含まれる場合、redirect_errorを返す（一部だけを受け付けず全体をエラーにする）", () => {
			const result = validateAuthorizationRequest(validParams({ scope: "read write delete" }));
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("invalid_scope");
				expect(result.errorDescription).toContain("delete");
			}
		});

		it("登録済みの複数scopeは正常に受け付ける", () => {
			const result = validateAuthorizationRequest(validParams({ scope: "read write" }));
			expect(result.type).toBe("success");
		});
	});

	describe("PKCE検証", () => {
		it("code_challengeが未指定の場合、redirect_errorを返す", () => {
			const params = validParams();
			params.delete("code_challenge");
			const result = validateAuthorizationRequest(params);
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("invalid_request");
				expect(result.errorDescription).toContain("code_challenge");
			}
		});

		it("code_challenge_methodが未指定の場合、redirect_errorを返す", () => {
			const params = validParams();
			params.delete("code_challenge_method");
			const result = validateAuthorizationRequest(params);
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("invalid_request");
				expect(result.errorDescription).toContain("code_challenge_method");
			}
		});

		it("code_challenge_methodがplainの場合、redirect_errorを返す", () => {
			const result = validateAuthorizationRequest(validParams({ code_challenge_method: "plain" }));
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.errorCode).toBe("invalid_request");
				expect(result.errorDescription).toContain("S256");
			}
		});
	});

	describe("未知のパラメータは無視する", () => {
		it("未知のパラメータがあっても正常に処理される", () => {
			const result = validateAuthorizationRequest(
				validParams({ unknown_param: "some_value", another_unknown: "value" }),
			);
			expect(result.type).toBe("success");
		});
	});

	describe("正常系", () => {
		it("すべてのパラメータが有効な場合、successを返す", () => {
			const result = validateAuthorizationRequest(validParams());
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.client.clientId).toBe("public-spa-client");
				expect(result.authorizationRequest.responseType).toBe("code");
				expect(result.authorizationRequest.clientId).toBe("public-spa-client");
				expect(result.authorizationRequest.redirectUri).toBe("http://127.0.0.1:8080/callback");
				expect(result.authorizationRequest.scope).toBe("read");
				expect(result.authorizationRequest.state).toBe("random-state-value-for-csrf-protection");
				expect(result.authorizationRequest.codeChallenge).toBe(
					"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				);
				expect(result.authorizationRequest.codeChallengeMethod).toBe("S256");
			}
		});

		it("コンフィデンシャルクライアントでも同一フローで処理できる", () => {
			const result = validateAuthorizationRequest(
				validParams({
					client_id: "confidential-backend-client",
					redirect_uri: "http://127.0.0.1:8081/callback",
					scope: "read write admin",
				}),
			);
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.client.clientType).toBe("confidential");
			}
		});
	});

	describe("リダイレクトエラーにはstateが含まれる", () => {
		it("stateが指定されている場合、redirect_errorにstateが含まれる", () => {
			const result = validateAuthorizationRequest(validParams({ scope: "nonexistent" }));
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.state).toBe("random-state-value-for-csrf-protection");
			}
		});

		it("stateが未指定の場合、redirect_errorのstateはundefined（stateはあった場合のみ返す）", () => {
			const params = validParams({ scope: "nonexistent" });
			params.delete("state");
			const result = validateAuthorizationRequest(params);
			expect(result.type).toBe("redirect_error");
			if (result.type === "redirect_error") {
				expect(result.state).toBeUndefined();
			}
		});
	});
});
