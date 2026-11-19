/** 結合テストが動作確認用DBのデータを変更しないための接続先確認。 */
export const INTEGRATION_DATABASE_NAME = "oauth21_integration_test";
export const DEFAULT_INTEGRATION_DATABASE_URL =
	"postgresql://oauth21:oauth21_dev_password@localhost:5432/oauth21_integration_test";

/** 接続前にDB名を確認する。クエリによる接続先の上書きは受け付けない。 */
export function assertIntegrationDatabaseUrl(value: string): void {
	const url = new URL(value);
	if (
		(url.protocol !== "postgres:" && url.protocol !== "postgresql:") ||
		url.search ||
		url.hash ||
		decodeURIComponent(url.pathname.slice(1)) !== INTEGRATION_DATABASE_NAME
	) {
		throw new Error(`結合テストには専用DB ${INTEGRATION_DATABASE_NAME} を指定してください`);
	}
}

/** 設定だけでなく、アプリ用・テスト用の接続先が専用DBであることを確認する。 */
export async function assertIntegrationDatabaseConnections(
	currentDatabases: Array<() => Promise<string>>,
): Promise<void> {
	for (const currentDatabase of currentDatabases) {
		if ((await currentDatabase()) !== INTEGRATION_DATABASE_NAME) {
			throw new Error("接続先が結合テスト専用DBではないため、テストを中止します");
		}
	}
}

/** 共有ヘルパーによる削除は、結合テスト用またはE2E用のDBだけで許可する。 */
export function assertTestCleanupDatabaseName(name: string): void {
	if (name !== INTEGRATION_DATABASE_NAME && name !== "oauth21_e2e_test") {
		throw new Error("専用のテストDBではないため、データを削除しません");
	}
}
