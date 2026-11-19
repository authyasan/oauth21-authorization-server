import { describe, expect, it } from "vitest";
import { createClientMap, getClient } from "../../../src/config/clients.js";
import type { ClientConfig } from "../../../src/types/client.js";

function clientWithUris(redirectUris: string[]): ClientConfig {
	return {
		clientId: "test-client",
		clientName: "テストクライアント",
		organizationName: "テスト開発元",
		clientType: "public",
		redirectUris,
		allowedScopes: ["read"],
	};
}

describe("クライアント設定の読み込み", () => {
	it("設定ファイルのクライアントも検証を経て取得できる", () => {
		expect(getClient("public-spa-client")?.redirectUris).toEqual([
			"http://127.0.0.1:8080/callback",
		]);
	});

	it.each([
		"https://client.example/callback",
		"https://CLIENT.example/a/../callback?b=2&a=%23",
		"http://127.0.0.1:8080/callback",
		"http://[::1]/callback",
		"com.example.app://callback",
		"com.example.app:/oauth2redirect/example-provider",
	])("許可するURIを正規化せずに登録する: %s", (uri) => {
		const clients = createClientMap([clientWithUris([uri])]);
		expect(clients.get("test-client")?.redirectUris).toEqual([uri]);
	});

	it.each(["", "/callback", "https://", "http://127.0.0.1:65536/callback"])(
		"URLとして解析できない登録値を拒否する: %s",
		(uri) => {
			expect(() => createClientMap([clientWithUris([uri])])).toThrow("URLとして解析できません");
		},
	);

	it.each([
		"https://client.example/callback#",
		"https://client.example/callback#x",
		"http://127.0.0.1:8080/callback#",
		"http://127.0.0.1:8080/callback#x",
		"com.example.app://callback#",
		"com.example.app:/callback#x",
	])("空のfragmentを含め、fragment付きの登録値を拒否する: %s", (uri) => {
		expect(() => createClientMap([clientWithUris([uri])])).toThrow("フラグメント");
	});

	it.each([
		"http://client.example/callback",
		"http://localhost/callback",
		"myapp://callback",
		"myapp:/callback",
	])("URLとして解析できても許可しないスキーム・ホストは拒否する: %s", (uri) => {
		expect(() => createClientMap([clientWithUris([uri])])).toThrow("スキームが許可されていません");
	});

	it("登録URIが複数あればすべて検証する", () => {
		expect(() =>
			createClientMap([
				clientWithUris(["https://client.example/callback", "http://127.0.0.1:8080/callback#"]),
			]),
		).toThrow("フラグメント");
	});

	it.each([
		["clientName", ""],
		["clientName", "  "],
		["organizationName", ""],
		["organizationName", undefined],
	] as const)("同意画面に表示する%sが空なら拒否する: %j", (field, value) => {
		const client = { ...clientWithUris(["https://client.example/callback"]), [field]: value };
		expect(() => createClientMap([client as ClientConfig])).toThrow(`${field}が設定されていません`);
	});

	it("どのリソースサーバーにも対応しないスコープを許可していたら拒否する", () => {
		const client = {
			...clientWithUris(["https://client.example/callback"]),
			allowedScopes: ["read", "unprotected"],
		};
		expect(() => createClientMap([client])).toThrow("どのリソースサーバーにも対応していません");
	});

	it("クライアント識別子の重複は拒否する", () => {
		const client = clientWithUris(["https://client.example/callback"]);
		expect(() => createClientMap([client, client])).toThrow("クライアントID重複");
	});
});
