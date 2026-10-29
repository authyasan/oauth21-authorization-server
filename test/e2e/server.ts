/**
 * E2Eテスト専用のHTTPSサーバー。
 *
 * 1つのHTTPSポートで、Hostヘッダによって次の役割を切り替える。
 * ブラウザ側では Chromium の --host-resolver-rules でこれらの名前を 127.0.0.1 に向ける（hostsは変更しない）。
 *
 * - as.example.test     認可サーバー本体（src/app.ts をそのまま使う）
 * - client.example.test テスト用クライアントのリダイレクト先。受け取ったクエリとRefererを記録する
 * - other.example.test  同一サイトの別オリジン（攻撃者のページを置く想定）
 * - sub.example.test    同一サイトのサブドメイン（Cookie tossingを試みる）
 * - evil.test           別サイト（攻撃者のページ）
 *
 * テストの準備用に、別ポートのHTTP（127.0.0.1のみ）で制御エンドポイントを出す。
 * 認可サーバーのアプリにはテスト用の経路を足さない。
 */
// 最初に読み込む: DB名の確認は、DBに接続するモジュールを読み込むより前に行う。
import "./env-guard.js";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import { sql } from "drizzle-orm";
import { Hono } from "hono";
import app from "../../src/app.js";
import { getClient } from "../../src/config/clients.js";
import { client as appDbClient } from "../../src/db/connection.js";
import { clearAuthorizationRequests } from "../../src/services/authorization-request-store.js";
import { clearAllSessions } from "../../src/services/session-service.js";
import { cleanupDatabase, createTestUser, testDb } from "../integration/helpers.js";
import { CLIENT_ID, CONTROL_PORT, HOSTS, HTTPS_PORT, REDIRECT_URI } from "./config.js";
import { resetIfE2eDatabase } from "./db-guard.js";

// テスト専用の自己署名証明書。OSの信頼ストアには登録せず、ブラウザ側はテストのcontextでだけ検証を省略する。
function ensureCertificate(): { key: Buffer; cert: Buffer } {
	const dir = join(tmpdir(), "oauth21-e2e-certs");
	const keyPath = join(dir, "key.pem");
	const certPath = join(dir, "cert.pem");
	if (!existsSync(keyPath) || !existsSync(certPath)) {
		mkdirSync(dir, { recursive: true });
		const san = Object.values(HOSTS)
			.map((h) => `DNS:${h}`)
			.join(",");
		execFileSync("openssl", [
			"req",
			"-x509",
			"-newkey",
			"rsa:2048",
			"-nodes",
			"-days",
			"30",
			"-subj",
			"/CN=oauth21-e2e",
			"-addext",
			`subjectAltName=${san}`,
			"-keyout",
			keyPath,
			"-out",
			certPath,
		]);
	}
	return { key: readFileSync(keyPath), cert: readFileSync(certPath) };
}

// テスト用クライアントに、非ループバックのHTTPSリダイレクトURIを追加する（consent-skip.test.ts と同じ方法）。
// clients.json は変更しない。
const client = getClient(CLIENT_ID);
if (!client) throw new Error(`${CLIENT_ID} が見つかりません`);
if (!client.redirectUris.includes(REDIRECT_URI)) client.redirectUris.push(REDIRECT_URI);

type CallbackRecord = { query: Record<string, string>; referer: string | null };
const callbacks: CallbackRecord[] = [];

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
const page = (title: string, body: string) =>
	`<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body>${body}</body></html>`;

/** 攻撃者側・対照用のページ（other.example.test / evil.test で共通）。 */
function attackerPages(): Hono {
	const pages = new Hono();
	// 指定のフィールドを持つフォーム。テストがボタンを押して送信する。
	pages.get("/form", (c) => {
		const action = c.req.query("action") ?? "";
		const fields = new URLSearchParams(c.req.query("fields") ?? "");
		const inputs = [...fields]
			.map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
			.join("");
		return c.html(
			page(
				"form",
				`<form method="post" action="${escapeHtml(action)}">${inputs}<button>送信</button></form>`,
			),
		);
	});
	pages.get("/frame", (c) => {
		const src = c.req.query("src") ?? "";
		return c.html(
			page(
				"frame",
				`<iframe id="target" src="${escapeHtml(src)}" width="600" height="400"></iframe>`,
			),
		);
	});
	// 埋め込みを禁止しないページ（iframeの対照）。
	pages.get("/embeddable", (c) => c.html(page("embeddable", `<p id="embeddable">embeddable</p>`)));
	// 既定のReferrer-Policyのページからのリンク（Refererの対照）。
	pages.get("/link", (c) => {
		const to = c.req.query("to") ?? "";
		return c.html(page("link", `<a id="go" href="${escapeHtml(to)}">go</a>`));
	});
	return pages;
}

const clientApp = new Hono();
clientApp.get("/callback", (c) => {
	callbacks.push({ query: c.req.query(), referer: c.req.header("Referer") ?? null });
	return c.html(page("callback", `<p id="callback">callback</p>`));
});

// 同一サイトのサブドメインから、親ドメイン宛てのCookieを設定しようとする（Cookie tossing）。
// Honoのcookieヘルパーは __Host- とDomainの組み合わせを拒否するので、ヘッダを直接書く。
const subApp = new Hono();
subApp.get("/toss", (c) => {
	const domain = HOSTS.site;
	c.header(
		"Set-Cookie",
		`__Host-sid=tossed; Domain=${domain}; Path=/; Secure; HttpOnly; SameSite=Lax`,
		{
			append: true,
		},
	);
	// 対照: 同じ応答の、接頭辞なしのDomain Cookieは受け入れられる。
	c.header("Set-Cookie", `toss-control=1; Domain=${domain}; Path=/; Secure; SameSite=Lax`, {
		append: true,
	});
	const sid = c.req.query("sid");
	if (sid) {
		c.header("Set-Cookie", `sid=${sid}; Domain=${domain}; Path=/; Secure; HttpOnly; SameSite=Lax`, {
			append: true,
		});
	}
	return c.html(page("toss", `<p id="tossed">tossed</p>`));
});

const byHost: Record<string, Hono> = {
	[HOSTS.as]: app,
	[HOSTS.client]: clientApp,
	[HOSTS.sub]: subApp,
	[HOSTS.other]: attackerPages(),
	[HOSTS.evil]: attackerPages(),
	// トークン交換はNode側（Playwrightのrequest）から行う。名前解決をブラウザに頼れないので、IPでも本体に届ける。
	"127.0.0.1": app,
};

// アプリの接続（src/db/connection.ts）と削除に使う接続（test/integration/helpers.ts）の両方を確かめる。
const currentDatabases = [
	async () => (await appDbClient`select current_database() as name`)[0].name as string,
	async () => {
		const rows = await testDb.execute<{ name: string }>(sql`select current_database() as name`);
		return rows[0].name;
	},
];

// 起動時にも実際の接続先を確かめ、違えばサーバーを立てずに終了する。
await resetIfE2eDatabase({ currentDatabases, reset: async () => {} });

const { key, cert } = ensureCertificate();
serve({
	fetch: (req) => {
		const host = new URL(req.url).hostname;
		const target = byHost[host];
		return target ? target.fetch(req) : new Response("unknown host", { status: 421 });
	},
	port: HTTPS_PORT,
	hostname: "127.0.0.1",
	createServer,
	serverOptions: { key, cert },
});

const control = new Hono();
control.get("/health", (c) => c.text("ok"));
control.post("/reset", async (c) => {
	await resetIfE2eDatabase({
		currentDatabases,
		reset: async () => {
			await cleanupDatabase();
			await createTestUser();
			await createTestUser({ username: "other-user" });
		},
	});
	clearAllSessions();
	clearAuthorizationRequests();
	callbacks.length = 0;
	return c.json({ ok: true });
});
control.get("/callbacks", (c) => c.json(callbacks));
serve({ fetch: control.fetch, port: CONTROL_PORT, hostname: "127.0.0.1" });

console.log(
	`E2E server: https://${HOSTS.as}:${HTTPS_PORT} / control http://127.0.0.1:${CONTROL_PORT}`,
);
