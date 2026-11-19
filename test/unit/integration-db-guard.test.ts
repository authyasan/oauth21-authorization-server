import { describe, expect, it } from "vitest";
import {
	assertIntegrationDatabaseConnections,
	assertIntegrationDatabaseUrl,
	assertTestCleanupDatabaseName,
	DEFAULT_INTEGRATION_DATABASE_URL,
	INTEGRATION_DATABASE_NAME,
} from "../integration/db-guard.js";

describe("結合テストのDB接続先確認", () => {
	it("既定の接続先は専用DBである", () => {
		expect(() => assertIntegrationDatabaseUrl(DEFAULT_INTEGRATION_DATABASE_URL)).not.toThrow();
	});
	it.each([
		"postgresql://localhost/oauth21",
		"postgresql://localhost/oauth21_e2e_test",
		"postgresql://oauth21_integration_test:password@localhost/oauth21",
		"postgresql://localhost/oauth21_integration_test_copy",
		"postgresql://localhost/oauth21_integration_test?dbname=oauth21",
		"postgresql://localhost/oauth21_integration_test#fragment",
		"https://localhost/oauth21_integration_test",
		"postgresql://localhost/%ZZ",
		"not-a-url",
	])("専用DB以外や紛らわしい接続設定を拒否する: %s", (url) => {
		expect(() => assertIntegrationDatabaseUrl(url)).toThrow();
	});
	it.each([0, 1])("接続%dの実際のDB名が異なれば拒否する", async (index) => {
		const databases = [INTEGRATION_DATABASE_NAME, INTEGRATION_DATABASE_NAME];
		databases[index] = "oauth21";
		await expect(
			assertIntegrationDatabaseConnections(databases.map((name) => async () => name)),
		).rejects.toThrow("専用DB");
	});
	it("アプリ用・テスト用の両接続が専用DBなら受け付ける", async () => {
		await expect(
			assertIntegrationDatabaseConnections([
				async () => INTEGRATION_DATABASE_NAME,
				async () => INTEGRATION_DATABASE_NAME,
			]),
		).resolves.toBeUndefined();
	});
});

describe("テスト用共有ヘルパーの削除先確認", () => {
	it.each(["oauth21_integration_test", "oauth21_e2e_test"])(
		"専用DB %s での削除は許可する",
		(name) => {
			expect(() => assertTestCleanupDatabaseName(name)).not.toThrow();
		},
	);
	it.each(["oauth21", "postgres", "", "oauth21_integration_test_copy"])(
		"専用DB以外では削除を拒否する: %s",
		(name) => {
			expect(() => assertTestCleanupDatabaseName(name)).toThrow();
		},
	);
});
