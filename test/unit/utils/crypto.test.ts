import { describe, expect, it } from "vitest";
import {
	constantTimeEqual,
	generateRandomString,
	sha256,
	sha256Base64url,
} from "../../../src/utils/crypto.js";

describe("generateRandomString", () => {
	it("デフォルト32バイトのランダム文字列を生成する", () => {
		const str = generateRandomString();
		// 32バイト = Base64URLで43文字
		expect(str.length).toBe(43);
	});

	it("指定したバイト数のランダム文字列を生成する", () => {
		const str = generateRandomString(16);
		// 16バイト = Base64URLで22文字
		expect(str.length).toBe(22);
	});

	it("毎回異なる文字列を生成する", () => {
		const a = generateRandomString();
		const b = generateRandomString();
		expect(a).not.toBe(b);
	});

	it("Base64URL文字のみ含む", () => {
		const str = generateRandomString();
		// Base64URL: A-Z, a-z, 0-9, -, _
		expect(str).toMatch(/^[A-Za-z0-9_-]+$/);
	});
});

describe("sha256", () => {
	it("既知の入力に対して正しいハッシュを返す", () => {
		// echo -n "hello" | shasum -a 256
		const hash = sha256("hello");
		expect(hash).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
	});

	it("空文字列のハッシュ", () => {
		const hash = sha256("");
		expect(hash).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	});

	it("同じ入力には同じハッシュを返す", () => {
		expect(sha256("test")).toBe(sha256("test"));
	});

	it("異なる入力には異なるハッシュを返す", () => {
		expect(sha256("a")).not.toBe(sha256("b"));
	});
});

describe("sha256Base64url", () => {
	it("PKCE S256のcode_challengeを正しく計算する", () => {
		// RFC 7636 Appendix B の検証用テストベクタ
		// code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		// 期待されるcode_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		const challenge = sha256Base64url(codeVerifier);
		expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	});
});

describe("constantTimeEqual", () => {
	it("同じ文字列はtrueを返す", () => {
		expect(constantTimeEqual("hello", "hello")).toBe(true);
	});

	it("異なる文字列はfalseを返す", () => {
		expect(constantTimeEqual("hello", "world")).toBe(false);
	});

	it("長さが異なる文字列はfalseを返す", () => {
		expect(constantTimeEqual("short", "longer string")).toBe(false);
	});

	it("空文字列同士はtrueを返す", () => {
		expect(constantTimeEqual("", "")).toBe(true);
	});

	it("ハッシュ値の比較に使える", () => {
		const hash1 = sha256("test");
		const hash2 = sha256("test");
		const hash3 = sha256("different");
		expect(constantTimeEqual(hash1, hash2)).toBe(true);
		expect(constantTimeEqual(hash1, hash3)).toBe(false);
	});
});
