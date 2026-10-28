import { describe, expect, it } from "vitest";
import {
	isExactRedirectUriMatch,
	isValidScopeSyntax,
	validateRedirectUri,
} from "../../../src/utils/validation.js";

describe("isExactRedirectUriMatch", () => {
	it("完全一致でtrue", () => {
		expect(
			isExactRedirectUriMatch("http://localhost:8080/callback", "http://localhost:8080/callback"),
		).toBe(true);
	});

	it("パスの末尾スラッシュが異なるとfalse", () => {
		expect(
			isExactRedirectUriMatch("http://localhost:8080/callback/", "http://localhost:8080/callback"),
		).toBe(false);
	});

	it("スキームが異なるとfalse", () => {
		expect(isExactRedirectUriMatch("https://example.com/cb", "http://example.com/cb")).toBe(false);
	});

	it("ポートが異なるとfalse", () => {
		expect(isExactRedirectUriMatch("http://localhost:8080/cb", "http://localhost:8081/cb")).toBe(
			false,
		);
	});

	it("クエリパラメータが異なるとfalse", () => {
		expect(
			isExactRedirectUriMatch("http://localhost:8080/cb?extra=1", "http://localhost:8080/cb"),
		).toBe(false);
	});

	it("大文字小文字が異なるとfalse（ホスト名含め厳密比較）", () => {
		expect(isExactRedirectUriMatch("http://LOCALHOST:8080/cb", "http://localhost:8080/cb")).toBe(
			false,
		);
	});
});

describe("validateRedirectUri", () => {
	const registeredUris = [
		"http://localhost:8080/callback",
		"https://app.example.com/oauth/callback",
	];

	it("登録済みURIの1つと一致すればtrue", () => {
		expect(validateRedirectUri("http://localhost:8080/callback", registeredUris)).toBe(true);
		expect(validateRedirectUri("https://app.example.com/oauth/callback", registeredUris)).toBe(
			true,
		);
	});

	it("登録されていないURIはfalse", () => {
		expect(validateRedirectUri("http://evil.com/callback", registeredUris)).toBe(false);
	});

	it("空の登録URIリストに対してはfalse", () => {
		expect(validateRedirectUri("http://localhost:8080/callback", [])).toBe(false);
	});
});

describe("isValidScopeSyntax（draft-16 §1.4.1）", () => {
	it.each(["read", "read write", "read read", "a!#[]~"])("許可する: %j", (scope) => {
		expect(isValidScopeSyntax(scope)).toBe(true);
	});

	it.each([
		"",
		" read",
		"read ",
		"read  write",
		"read\twrite",
		"read\n",
		'read"',
		"read\\",
		"読み取り",
	])("拒否する: %j", (scope) => {
		expect(isValidScopeSyntax(scope)).toBe(false);
	});
});
