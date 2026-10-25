/**
 * E2Eの /reset は全テーブルを削除する。誤って通常のDBへ接続したまま削除しないための確認。
 *
 * 1. 起動時: DATABASE_URL を URL として解析し、DB名が E2E 専用の名前と完全に一致することを確かめる。
 *    ユーザー名・パスワード・ホスト・クエリなど、DB名以外の部分に同じ文字列があっても通さない。
 * 2. 削除の直前: 実際の接続先で current_database() を問い合わせ、E2E 専用DBであることを確かめる。
 *    接続文字列の解釈の違い（環境変数やクエリによる上書きなど）があっても、実際の接続先で止める。
 */

export const E2E_DATABASE_NAME = "oauth21_e2e_test";

/** DATABASE_URL のDB名が E2E 専用DBと完全一致しなければ例外を投げる。 */
export function assertE2eDatabaseUrl(url: string | undefined): void {
	if (!url) throw new Error("DATABASE_URL が設定されていません");
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error("DATABASE_URL をURLとして解析できません");
	}
	if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
		throw new Error(`DATABASE_URL のスキームが postgres ではありません: ${parsed.protocol}`);
	}
	// クエリで接続先のDB名などを上書きできる形式は受け付けない。
	if (parsed.search) throw new Error("DATABASE_URL にクエリを含めないでください");
	const name = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
	if (name !== E2E_DATABASE_NAME) {
		throw new Error(
			`E2E専用DB（${E2E_DATABASE_NAME}）以外には接続しません: ${name || "(DB名なし)"}`,
		);
	}
}

/** 実際の接続先がE2E専用DBであることを確かめてから、削除処理を実行する。 */
export async function resetIfE2eDatabase(options: {
	/** 削除に使う接続ごとの current_database() */
	currentDatabases: Array<() => Promise<string>>;
	/** 確認に通った後にだけ実行する削除処理 */
	reset: () => Promise<void>;
}): Promise<void> {
	for (const currentDatabase of options.currentDatabases) {
		const name = await currentDatabase();
		if (name !== E2E_DATABASE_NAME) {
			throw new Error(`接続先がE2E専用DBではないので削除しません: ${name}`);
		}
	}
	await options.reset();
}
