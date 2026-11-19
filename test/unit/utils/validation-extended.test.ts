import { describe, expect, it } from "vitest";
import {
	getUnknownScopes,
	isAllowedRedirectUriScheme,
	isLoopbackRedirectUriMatch,
	isLoopbackUri,
	isPrivateUseScheme,
	isReverseDomainScheme,
	validateRedirectUriWithLoopback,
} from "../../../src/utils/validation.js";

describe("isLoopbackUri", () => {
	it("127.0.0.1はtrueを返す", () => {
		expect(isLoopbackUri("http://127.0.0.1:8080/callback")).toBe(true);
	});

	it("[::1]はtrueを返す", () => {
		expect(isLoopbackUri("http://[::1]:8080/callback")).toBe(true);
	});

	it("localhostはfalseを返す（IPリテラルではない）", () => {
		expect(isLoopbackUri("http://localhost:8080/callback")).toBe(false);
	});

	it("通常のホスト名はfalseを返す", () => {
		expect(isLoopbackUri("https://example.com/callback")).toBe(false);
	});
});

describe("isLoopbackRedirectUriMatch", () => {
	it.each(["HTTP", "HtTp", "HTTPS", "HtTpS"])(
		"%sでも元のスキーム表記を保持し、ポートだけを比較から除く",
		(scheme) => {
			for (const host of ["127.0.0.1", "[::1]"]) {
				const registered = `${scheme}://${host}:8080/callback?q=%2F`;
				expect(isLoopbackRedirectUriMatch(registered, registered)).toBe(true);
				expect(
					isLoopbackRedirectUriMatch(`${scheme}://${host}:54321/callback?q=%2F`, registered),
				).toBe(true);
				expect(isLoopbackRedirectUriMatch(`${scheme}://${host}/callback?q=%2F`, registered)).toBe(
					true,
				);
				expect(
					isLoopbackRedirectUriMatch(
						`${scheme.toLowerCase()}://${host}/callback?q=%2F`,
						registered,
					),
				).toBe(false);
				expect(isLoopbackRedirectUriMatch(`${scheme}://${host}/callback?q=%2f`, registered)).toBe(
					false,
				);
			}
		},
	);

	it.each([
		"http://127.0.0.1:9999/a/../callback",
		"http://127.0.0.1:9999/%2e/callback",
		"http://127.1:9999/callback",
		"http://2130706433:9999/callback",
		"http://user:pass@127.0.0.1:9999/callback",
		"HTTP://127.0.0.1:9999/callback",
		"http://127.0.0.1:9999/callback?",
	])("ポート以外の表記の違いを両方向で拒否する: %s", (uri) => {
		const registered = "http://127.0.0.1:8080/callback";
		expect(isLoopbackRedirectUriMatch(uri, registered)).toBe(false);
		expect(isLoopbackRedirectUriMatch(registered, uri)).toBe(false);
	});

	it.each([
		"http://127.0.0.1:9999/callback#",
		"http://127.0.0.1:9999/callback#x",
		"http://127.0.0.1:65536/callback",
		"http://127.0.0.1:abc/callback",
		"http://127.0.0.1.evil.example:9999/callback",
		"http://127.0.0.10:9999/callback",
		"http://127.0.0.1:9999@evil.example/callback",
	])("不正または対象外のリクエストURIを拒否する: %s", (uri) => {
		expect(isLoopbackRedirectUriMatch(uri, "http://127.0.0.1:8080/callback")).toBe(false);
	});

	it.each([
		["http://[::1]:54321/callback", "http://[::1]/callback"],
		["http://127.0.0.1:80/callback", "http://127.0.0.1/callback"],
		["http://127.0.0.1:54321/callback?q=%23", "http://127.0.0.1/callback?q=%23"],
	])("ポートの省略を許容し、元のクエリを保持する: %s", (request, registered) => {
		expect(isLoopbackRedirectUriMatch(request, registered)).toBe(true);
		expect(isLoopbackRedirectUriMatch(registered, request)).toBe(true);
	});

	it("空のパスをスラッシュに補正しない", () => {
		expect(isLoopbackRedirectUriMatch("http://127.0.0.1:9999", "http://127.0.0.1/")).toBe(false);
	});

	it("ポート番号が異なっても一致する", () => {
		expect(
			isLoopbackRedirectUriMatch(
				"http://127.0.0.1:9999/callback",
				"http://127.0.0.1:8080/callback",
			),
		).toBe(true);
	});

	it("パスが異なれば不一致", () => {
		expect(
			isLoopbackRedirectUriMatch("http://127.0.0.1:8080/callback", "http://127.0.0.1:8080/other"),
		).toBe(false);
	});

	it("プロトコルが異なれば不一致", () => {
		expect(
			isLoopbackRedirectUriMatch(
				"https://127.0.0.1:8080/callback",
				"http://127.0.0.1:8080/callback",
			),
		).toBe(false);
	});

	it("クエリ文字列が一致すれば一致（ポート以外は完全一致）", () => {
		expect(
			isLoopbackRedirectUriMatch(
				"http://127.0.0.1:9999/callback?extra=value",
				"http://127.0.0.1:8080/callback?extra=value",
			),
		).toBe(true);
	});

	it("クエリ文字列が異なれば不一致", () => {
		expect(
			isLoopbackRedirectUriMatch(
				"http://127.0.0.1:8080/callback?extra=value",
				"http://127.0.0.1:8080/callback",
			),
		).toBe(false);
	});

	// [SECURITY] redirect_uri にフラグメントを含めてはならない（RFC 6749 §3.1.2）。
	// リクエスト側のfragment禁止は照合関数で、登録側は設定読み込み時に確認する。
	it("リクエストURIにフラグメントが付いていれば不一致（RFC 6749 §3.1.2）", () => {
		expect(
			isLoopbackRedirectUriMatch(
				"http://127.0.0.1:8080/callback#evil",
				"http://127.0.0.1:8080/callback",
			),
		).toBe(false);
	});

	it("ポート違い＋フラグメント付きでも不一致（fragment除外の抜け穴を塞ぐ）", () => {
		expect(
			isLoopbackRedirectUriMatch(
				"http://127.0.0.1:9999/callback#x",
				"http://127.0.0.1:8080/callback",
			),
		).toBe(false);
	});
});

describe("isPrivateUseScheme", () => {
	it("カスタムスキームはtrueを返す", () => {
		expect(isPrivateUseScheme("com.example.app://callback")).toBe(true);
		expect(isPrivateUseScheme("myapp://callback")).toBe(true);
	});

	it("httpsはfalseを返す", () => {
		expect(isPrivateUseScheme("https://example.com/callback")).toBe(false);
	});

	it("httpはfalseを返す", () => {
		expect(isPrivateUseScheme("http://localhost/callback")).toBe(false);
	});
});

describe("isReverseDomainScheme", () => {
	it("逆ドメイン名形式（ピリオド含む）はtrueを返す", () => {
		expect(isReverseDomainScheme("com.example.app://callback")).toBe(true);
		expect(isReverseDomainScheme("jp.co.example.myapp://callback")).toBe(true);
	});

	it("ピリオドなしはfalseを返す", () => {
		expect(isReverseDomainScheme("myapp://callback")).toBe(false);
	});
});

describe("isAllowedRedirectUriScheme", () => {
	it("HTTPSは許可される", () => {
		expect(isAllowedRedirectUriScheme("https://example.com/callback")).toBe(true);
	});

	it("HTTPでループバックアドレスは許可される", () => {
		expect(isAllowedRedirectUriScheme("http://127.0.0.1:8080/callback")).toBe(true);
	});

	it("HTTPで非ループバックアドレスは拒否される", () => {
		expect(isAllowedRedirectUriScheme("http://example.com/callback")).toBe(false);
	});

	it("逆ドメイン名形式のカスタムスキームは許可される", () => {
		expect(isAllowedRedirectUriScheme("com.example.app://callback")).toBe(true);
	});

	it("逆ドメイン名形式でないカスタムスキームは拒否される", () => {
		expect(isAllowedRedirectUriScheme("myapp://callback")).toBe(false);
	});

	// draft-16 §8.4.3 / RFC 8252 §7.1の例にある、スキームの後がスラッシュ1つのURIも受け付ける。
	it("スラッシュ1つの逆ドメイン名形式は許可される（仕様の例）", () => {
		expect(isAllowedRedirectUriScheme("com.example.app:/oauth2redirect/example-provider")).toBe(
			true,
		);
	});

	it("スラッシュ1つでも逆ドメイン名形式でなければ拒否される", () => {
		expect(isAllowedRedirectUriScheme("myapp:/callback")).toBe(false);
	});

	it.each(["javascript:alert(1)", "data:text/html,x", "urn:example:callback"])(
		"ピリオドを含まないスキーム %s は拒否される",
		(uri) => {
			expect(isAllowedRedirectUriScheme(uri)).toBe(false);
		},
	);
});

describe("getUnknownScopes", () => {
	it("すべて許可されたスコープなら空配列を返す", () => {
		expect(getUnknownScopes(["read", "write"], ["read", "write", "admin"])).toEqual([]);
	});

	it("未許可のスコープを返す", () => {
		expect(getUnknownScopes(["read", "delete"], ["read", "write"])).toEqual(["delete"]);
	});

	it("複数の未許可スコープを返す", () => {
		expect(getUnknownScopes(["read", "delete", "admin"], ["read", "write"])).toEqual([
			"delete",
			"admin",
		]);
	});
});

describe("validateRedirectUriWithLoopback", () => {
	it("通常のHTTPS URIだけが登録されていればループバックURIは一致しない", () => {
		expect(
			validateRedirectUriWithLoopback("http://127.0.0.1:9999/callback", [
				"https://client.example/callback",
			]),
		).toBe(false);
	});

	it("通常のHTTPS URIとループバックURIが混在していても照合できる", () => {
		expect(
			validateRedirectUriWithLoopback("http://127.0.0.1:9999/callback", [
				"https://client.example/callback",
				"http://[::1]:8080/callback",
				"http://127.0.0.1:8080/callback",
			]),
		).toBe(true);
	});

	it("通常のURIは完全一致で検証する", () => {
		expect(
			validateRedirectUriWithLoopback("https://example.com/callback", [
				"https://example.com/callback",
			]),
		).toBe(true);
	});

	it("通常のURIはポートが異なると不一致", () => {
		expect(
			validateRedirectUriWithLoopback("https://example.com:9999/callback", [
				"https://example.com:8080/callback",
			]),
		).toBe(false);
	});

	it("ループバックURIはポート番号を除いて比較する", () => {
		expect(
			validateRedirectUriWithLoopback("http://127.0.0.1:9999/callback", [
				"http://127.0.0.1:8080/callback",
			]),
		).toBe(true);
	});
});
