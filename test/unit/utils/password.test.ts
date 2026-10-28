import bcrypt from "bcryptjs";
import { describe, expect, it } from "vitest";
import {
	DUMMY_PASSWORD_HASH,
	hashPassword,
	verifyDummyPassword,
	verifyPassword,
} from "../../../src/utils/password.js";

describe("パスワードハッシュ", () => {
	it("パスワードをハッシュ化できる", async () => {
		const hash = await hashPassword("test-password");
		expect(hash).toBeDefined();
		// bcryptハッシュは$2a$または$2b$で始まる
		expect(hash).toMatch(/^\$2[ab]\$/);
	});

	it("同じパスワードでも毎回異なるハッシュが生成される（ソルトが異なる）", async () => {
		const hash1 = await hashPassword("same-password");
		const hash2 = await hashPassword("same-password");
		expect(hash1).not.toBe(hash2);
	});

	it("正しいパスワードで検証が成功する", async () => {
		const hash = await hashPassword("correct-password");
		const result = await verifyPassword("correct-password", hash);
		expect(result).toBe(true);
	});

	it("間違ったパスワードで検証が失敗する", async () => {
		const hash = await hashPassword("correct-password");
		const result = await verifyPassword("wrong-password", hash);
		expect(result).toBe(false);
	});
});

describe("存在しないユーザー用のダミーハッシュ", () => {
	// 形式を満たさない値では bcrypt.compare が計算に進まず、時間差が残る。
	// 時間そのものは環境で揺れるので、形式とコストが実在ユーザーと同じことを確かめる。
	it("bcryptの形式（60文字）を満たす", () => {
		expect(DUMMY_PASSWORD_HASH).toHaveLength(60);
		expect(DUMMY_PASSWORD_HASH).toMatch(/^\$2[ab]\$\d{2}\$[./A-Za-z0-9]{53}$/);
	});

	it("実在ユーザーのハッシュと同じコストを使う", async () => {
		const userHash = await hashPassword("password123");
		expect(bcrypt.getRounds(DUMMY_PASSWORD_HASH)).toBe(bcrypt.getRounds(userHash));
	});

	it("比較を最後まで行い、例外を投げない", async () => {
		await expect(verifyDummyPassword("password123")).resolves.toBeUndefined();
	});
});
