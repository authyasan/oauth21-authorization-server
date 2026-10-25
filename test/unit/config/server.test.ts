import { describe, expect, it } from "vitest";
import { validateIssuer } from "../../../src/config/server.js";

describe("ISSUERの検証（RFC 8414 §2）", () => {
	it.each([
		["https://as.example", true],
		["https://as.example/tenant", true],
		["https://as.example:8443", true],
		["http://localhost:3000", false],
	])("許可する: %s（本番=%s）", (value, production) => {
		expect(validateIssuer(value, production)).toBe(value);
	});

	it.each([
		["as.example", false, "URLとして解析できません"],
		["http://localhost:3000", true, "https"],
		["ftp://as.example", false, "https"],
		["https://as.example?x=1", false, "クエリやフラグメント"],
		["https://as.example?", false, "クエリやフラグメント"],
		["https://as.example#x", false, "クエリやフラグメント"],
		["https://as.example/", false, "末尾"],
	])("拒否する: %s（本番=%s）", (value, production, message) => {
		expect(() => validateIssuer(value, production)).toThrow(message);
	});

	// URL解析は空白・タブ・改行を取り除いてから解析するので、解析の成否では検出できない
	it.each([
		"https://as.example ",
		" https://as.example",
		"https://as.example/\n",
		"https://as.example\n",
		"https://as.\texample",
		"https://as.example\r",
		"https://as.example\u0000",
		"https://as.example ",
	])("空白や制御文字を含む値は、正規化せずに拒否する: %j", (value) => {
		expect(() => validateIssuer(value, true)).toThrow("空白や制御文字");
	});
});
