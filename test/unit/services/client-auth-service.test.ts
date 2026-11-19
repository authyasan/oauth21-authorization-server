import { describe, expect, it } from "vitest";
import { authenticateClient } from "../../../src/services/client-auth-service.js";

// テスト用のclient_secret: "test-client-secret"
// SHA-256ハッシュ: 8ac950188678f9bb3524b275130332b511bf5092394da6975b5fb9e84302f026

describe("authenticateClient", () => {
	describe("client_secret_post", () => {
		it("正しいclient_idとclient_secretで認証が成功する", () => {
			const result = authenticateClient(
				undefined,
				"confidential-backend-client",
				"test-client-secret",
			);
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.client.clientId).toBe("confidential-backend-client");
				expect(result.authMethod).toBe("client_secret_post");
			}
		});

		it("不正なclient_secretで認証が失敗する（invalid_client）", () => {
			const result = authenticateClient(undefined, "confidential-backend-client", "wrong-secret");
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_client");
			}
		});

		it("存在しないclient_idで認証が失敗する（invalid_client）", () => {
			const result = authenticateClient(undefined, "unknown-client", "test-client-secret");
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_client");
			}
		});
	});

	describe("client_secret_basic", () => {
		it.each(
			["Basic", "bAsIc", "basic", "BASIC"].flatMap((scheme) =>
				[1, 2, 5].map((spaces) => ({ scheme, spaces })),
			),
		)("$scheme・$spaces SPで認証が成功する", ({ scheme, spaces }) => {
			// Basic base64("confidential-backend-client:test-client-secret")
			const credentials = Buffer.from("confidential-backend-client:test-client-secret").toString(
				"base64",
			);
			const result = authenticateClient(
				`${scheme}${" ".repeat(spaces)}${credentials}`,
				undefined,
				undefined,
			);
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.client.clientId).toBe("confidential-backend-client");
				expect(result.authMethod).toBe("client_secret_basic");
			}
		});

		it.each([
			"CONFIDENTIAL-BACKEND-CLIENT:test-client-secret",
			"confidential-backend-client:TEST-CLIENT-SECRET",
		])("認証情報の大小を区別する: %s", (value) => {
			const credentials = Buffer.from(value).toString("base64");
			expect(authenticateClient(`basic   ${credentials}`, undefined, undefined)).toMatchObject({
				type: "failure",
				errorCode: "invalid_client",
			});
		});

		it.each(["空のBasic", "SPのみ", "タブ区切り", "SPとタブ", "内部SP", "内部タブ"])(
			"不正なBasic認証（%s）を無視せず拒否する",
			(kind) => {
				const credentials = Buffer.from("confidential-backend-client:test-client-secret").toString(
					"base64",
				);
				const headers: Record<string, string> = {
					空のBasic: "basic",
					SPのみ: "basic   ",
					タブ区切り: `basic\t${credentials}`,
					SPとタブ: `basic \t${credentials}`,
					内部SP: `basic   ${credentials.slice(0, 8)} ${credentials.slice(8)}`,
					内部タブ: `basic   ${credentials.slice(0, 8)}\t${credentials.slice(8)}`,
				};
				expect(authenticateClient(headers[kind], "public-spa-client", undefined)).toMatchObject({
					type: "failure",
					errorCode: "invalid_client",
				});
			},
		);

		it("登録済みの認証情報から構築したBasic認証を受け付ける", () => {
			// 登録済みの認証情報をエンコードしてBasic認証ヘッダーを作る。
			// この値はエンコードしても変わらないため、特殊文字のデコードは確認していない。
			const encoded = `${encodeURIComponent("confidential-backend-client")}:${encodeURIComponent("test-client-secret")}`;
			const credentials = Buffer.from(encoded).toString("base64");
			const result = authenticateClient(`Basic ${credentials}`, undefined, undefined);
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.authMethod).toBe("client_secret_basic");
			}
		});

		it("不正なBase64で認証が失敗する（invalid_client）", () => {
			const result = authenticateClient("Basic !!!invalid!!!", undefined, undefined);
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_client");
			}
		});

		describe("標準Base64（RFC 4648 §4）以外の認証情報", () => {
			// 正しい認証情報。46バイトなので末尾に「==」が付く
			const valid = Buffer.from("confidential-backend-client:test-client-secret").toString(
				"base64",
			);

			it.each([
				// 4文字単位を保ったまま、デコーダが読み飛ばす文字を差し込む
				["「.」の挿入", `${valid.slice(0, 8)}....${valid.slice(8)}`],
				["「~」の挿入", `${valid.slice(0, 8)}~~~~${valid.slice(8)}`],
				["パディングの欠落", valid.slice(0, -2)],
				["パディングの過剰", `${valid}=`],
				["パディングの後の文字", `${valid}AAAA`],
				["末尾の改行", `${valid}\n`],
			])("%sは、正しい認証情報を含んでいても拒否する", (_name, credentials) => {
				expect(authenticateClient(`Basic ${credentials}`, undefined, undefined)).toMatchObject({
					type: "failure",
					errorCode: "invalid_client",
				});
			});

			it("不正なBase64でも、方式の同時送信は先にinvalid_requestにする", () => {
				expect(
					authenticateClient(
						`Basic ${valid.slice(0, 8)}....${valid.slice(8)}`,
						"confidential-backend-client",
						"test-client-secret",
					),
				).toMatchObject({ type: "failure", errorCode: "invalid_request" });
			});
		});

		it.each([
			["クライアントID側", "confidential-backend-client%E0%A4%A:test-client-secret"],
			["シークレット側", "confidential-backend-client:%E0%A4%A"],
			["「%」の単独", "%:x"],
			["UTF-8として不正なバイト列", "confidential-backend-client:%FF"],
		])("%sの不正なパーセントエンコードは例外にせず認証失敗にする", (_name, value) => {
			const credentials = Buffer.from(value).toString("base64");
			// ボディにパブリッククライアントのclient_idがあっても、不正なBasic認証を無視しない。
			expect(
				authenticateClient(`Basic ${credentials}`, "public-spa-client", undefined),
			).toMatchObject({ type: "failure", errorCode: "invalid_client" });
		});

		it("不正なパーセントエンコードでも、方式の同時送信は先にinvalid_requestにする", () => {
			const credentials = Buffer.from("confidential-backend-client:%E0%A4%A").toString("base64");
			expect(
				authenticateClient(
					`Basic ${credentials}`,
					"confidential-backend-client",
					"test-client-secret",
				),
			).toMatchObject({ type: "failure", errorCode: "invalid_request" });
		});

		it("コロンがない形式で認証が失敗する（invalid_client）", () => {
			const credentials = Buffer.from("no-colon-here").toString("base64");
			const result = authenticateClient(`Basic ${credentials}`, undefined, undefined);
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_client");
			}
		});
	});

	describe("複数認証方式の同時送信", () => {
		it.each(["Basic", "bAsIc", "basic", "BASIC"])(
			"%sスキームのBasic認証とclient_secret_postを同時に指定するとinvalid_requestを返す",
			(scheme) => {
				const credentials = Buffer.from("confidential-backend-client:test-client-secret").toString(
					"base64",
				);
				const result = authenticateClient(
					`${scheme} ${credentials}`,
					"confidential-backend-client",
					"test-client-secret",
				);
				expect(result.type).toBe("failure");
				if (result.type === "failure") {
					expect(result.errorCode).toBe("invalid_request");
				}
			},
		);
	});

	describe("パブリッククライアント", () => {
		it("client_idのみでパブリッククライアントを識別し、authMethod=noneを返す", () => {
			const result = authenticateClient(undefined, "public-spa-client", undefined);
			expect(result.type).toBe("success");
			if (result.type === "success") {
				expect(result.client.clientId).toBe("public-spa-client");
				expect(result.authMethod).toBe("none");
			}
		});

		it("パブリッククライアントがclient_secretを送信するとinvalid_request", () => {
			const result = authenticateClient(undefined, "public-spa-client", "some-secret");
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_request");
			}
		});

		it("パブリッククライアントがBasic認証を送信するとinvalid_request", () => {
			const credentials = Buffer.from("public-spa-client:some-secret").toString("base64");
			const result = authenticateClient(`Basic ${credentials}`, undefined, undefined);
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_request");
			}
		});

		it("client_idが指定されないとエラー（invalid_client）", () => {
			const result = authenticateClient(undefined, undefined, undefined);
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_client");
			}
		});
	});

	describe("コンフィデンシャルクライアントの認証情報なし", () => {
		it("コンフィデンシャルクライアントが認証情報なしでリクエストするとエラー（invalid_client）", () => {
			const result = authenticateClient(undefined, "confidential-backend-client", undefined);
			expect(result.type).toBe("failure");
			if (result.type === "failure") {
				expect(result.errorCode).toBe("invalid_client");
			}
		});
	});
});
