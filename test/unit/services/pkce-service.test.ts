import { describe, expect, it } from "vitest";
import {
	isValidPkceCodeVerifier,
	verifyCodeChallenge,
} from "../../../src/services/pkce-service.js";
import { sha256Base64url } from "../../../src/utils/crypto.js";

describe("verifyCodeChallenge", () => {
	it("正しいcode_verifierで検証が成功する", () => {
		const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		const codeChallenge = sha256Base64url(codeVerifier);

		expect(verifyCodeChallenge(codeVerifier, codeChallenge, "S256")).toBe(true);
	});

	it("ハッシュが一致しないcode_verifierで検証が失敗する", () => {
		// どちらも構文的には正当な43文字のverifier（構文検証は通過し、ハッシュ比較で落ちる）
		const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		const codeChallenge = sha256Base64url(codeVerifier);
		const wrongVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXa";

		expect(verifyCodeChallenge(wrongVerifier, codeChallenge, "S256")).toBe(false);
	});

	it("S256以外のメソッドは拒否される", () => {
		const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		const codeChallenge = sha256Base64url(codeVerifier);

		expect(verifyCodeChallenge(codeVerifier, codeChallenge, "plain")).toBe(false);
	});

	it("RFC 7636のテストベクトルで検証が成功する", () => {
		// RFC 7636 Appendix B のテストベクトル
		const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

		expect(verifyCodeChallenge(codeVerifier, expectedChallenge, "S256")).toBe(true);
	});

	// [SECURITY] code_verifier の構文検証（RFC 7636 §4.1: 43〜128文字・unreserved）
	describe("code_verifier構文検証", () => {
		it.each(["\n", "\r", "\r\n", "\t", "\u2028", "\u2029"])(
			"末尾の制御文字や改行を拒否する（%j）",
			(suffix) => {
				const verifier = `${"a".repeat(43)}${suffix}`;
				expect(isValidPkceCodeVerifier(verifier)).toBe(false);
				expect(verifyCodeChallenge(verifier, sha256Base64url(verifier), "S256")).toBe(false);
			},
		);
		it("43文字未満のcode_verifierは構文で拒否される", () => {
			// 42文字（ハッシュ計算前に構文で落ちる）
			const shortVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX";
			const codeChallenge = sha256Base64url(shortVerifier);

			expect(shortVerifier.length).toBe(42);
			expect(verifyCodeChallenge(shortVerifier, codeChallenge, "S256")).toBe(false);
		});

		it("128文字超のcode_verifierは構文で拒否される", () => {
			// 129文字
			const longVerifier = "a".repeat(129);
			const codeChallenge = sha256Base64url(longVerifier);

			expect(verifyCodeChallenge(longVerifier, codeChallenge, "S256")).toBe(false);
		});

		it("unreserved以外の文字を含むcode_verifierは構文で拒否される", () => {
			// '+' は unreserved ではない（43文字だが不正文字を含む）
			const invalidVerifier = `${"a".repeat(42)}+`;
			const codeChallenge = sha256Base64url(invalidVerifier);

			expect(invalidVerifier.length).toBe(43);
			expect(verifyCodeChallenge(invalidVerifier, codeChallenge, "S256")).toBe(false);
		});

		it("境界値: ちょうど43文字のcode_verifierは受理される", () => {
			const verifier43 = "a".repeat(43);
			const codeChallenge = sha256Base64url(verifier43);

			expect(verifyCodeChallenge(verifier43, codeChallenge, "S256")).toBe(true);
		});

		it("境界値: ちょうど128文字のcode_verifierは受理される", () => {
			const verifier128 = "a".repeat(128);
			const codeChallenge = sha256Base64url(verifier128);

			expect(verifyCodeChallenge(verifier128, codeChallenge, "S256")).toBe(true);
		});
	});
});
