import { describe, expect, it } from "vitest";
import { decodeFormComponent } from "../../../src/utils/form-encoding.js";

describe("decodeFormComponent", () => {
	it.each([
		["空白を表す「+」", "a+b", "a b"],
		["リテラルの「+」（%2B）", "a%2Bb", "a+b"],
		["「%」（%25）", "a%25b", "a%b"],
		["マルチバイト文字", "%E3%81%82", "あ"],
		["符号化のない値", "plain-value", "plain-value"],
	])("%sを戻す", (_name, input, expected) => {
		expect(decodeFormComponent(input)).toBe(expected);
	});

	it.each([
		["途中で切れたパーセントエンコード", "%E0%A4%A"],
		["「%」の単独", "%"],
		["16進数でない", "%zz"],
		["UTF-8として不正なバイト列", "%FF"],
	])("%sは例外を投げずnullを返す", (_name, input) => {
		expect(decodeFormComponent(input)).toBeNull();
	});
});
