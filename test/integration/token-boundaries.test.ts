import assert from "node:assert/strict";
import { eq, sql } from "drizzle-orm";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import app from "../../src/app.js";
import { accessTokens, authorizationCodes, grants, refreshTokens } from "../../src/db/schema.js";
import { issueAuthorizationCode } from "../../src/services/authorization-code-service.js";
import { sha256 } from "../../src/utils/crypto.js";
import {
	basicAuthHeader,
	cleanupDatabase,
	closeDatabase,
	createTestUser,
	generatePkce,
	TEST_CONFIDENTIAL_CLIENT,
	TEST_PUBLIC_CLIENT,
	testDb,
} from "./helpers.js";

type TestClient = typeof TEST_PUBLIC_CLIENT | typeof TEST_CONFIDENTIAL_CLIENT;
const clients = [TEST_PUBLIC_CLIENT, TEST_CONFIDENTIAL_CLIENT];
const { codeVerifier, codeChallenge } = generatePkce();

async function post(path: string, client: TestClient, params: Record<string, string>) {
	const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
	if ("clientSecret" in client) {
		headers.Authorization = basicAuthHeader(client.clientId, client.clientSecret);
	} else {
		params = { ...params, client_id: client.clientId };
	}
	return app.request(path, { method: "POST", headers, body: new URLSearchParams(params) });
}

function exchange(code: string, client: TestClient) {
	return post("/token", client, {
		grant_type: "authorization_code",
		code,
		code_verifier: codeVerifier,
	});
}

function refresh(token: string, client: TestClient) {
	return post("/token", client, { grant_type: "refresh_token", refresh_token: token });
}

async function issued(
	response: Response,
): Promise<{ access_token: string; refresh_token: string }> {
	expect(response.status).toBe(200);
	const body = await response.json();
	expect(body.access_token).toEqual(expect.any(String));
	expect(body.refresh_token).toEqual(expect.any(String));
	return body;
}

async function invalidGrant(response: Response) {
	expect(response.status).toBe(400);
	expect((await response.json()).error).toBe("invalid_grant");
}

async function snapshot() {
	return {
		codes: await testDb.select().from(authorizationCodes).orderBy(authorizationCodes.id),
		grants: await testDb.select().from(grants).orderBy(grants.id),
		at: await testDb.select().from(accessTokens).orderBy(accessTokens.jti),
		rt: await testDb.select().from(refreshTokens).orderBy(refreshTokens.id),
	};
}

function stateOf(state: Awaited<ReturnType<typeof snapshot>>, grantId: string) {
	return {
		codes: state.codes.filter((row) => row.grantId === grantId),
		grants: state.grants.filter((row) => row.id === grantId),
		at: state.at.filter((row) => row.grantId === grantId),
		rt: state.rt.filter((row) => row.grantId === grantId),
	};
}

function expectRevoked(state: ReturnType<typeof stateOf>) {
	expect(state.grants).toHaveLength(1);
	expect(state.at.length).toBeGreaterThan(0);
	expect(state.rt.length).toBeGreaterThan(0);
	for (const row of [...state.grants, ...state.at, ...state.rt]) {
		expect(row.revokedAt).toBeInstanceOf(Date);
	}
}

// 実DBでロック待ちに入ったことを確認する。一定時間sleepするだけでは競合の再現にならない。
// SQLの照合は、Drizzleがテーブル名を二重引用符で囲む表記に依存する。
async function waitForBlocked(table: "authorization_codes" | "grants", count: number) {
	await expect
		.poll(
			async () => {
				const [row] = await testDb.execute(sql`
			SELECT count(*)::int AS count FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid()
			  AND wait_event_type = 'Lock' AND cardinality(pg_blocking_pids(pid)) > 0
			  AND query LIKE ${`%"${table}"%`}
		`);
				return Number(row.count);
			},
			{ timeout: 5000, interval: 10 },
		)
		.toBe(count);
}

async function withRowLock(
	table: "authorization_codes" | "grants",
	id: string,
	run: (release: () => void, pending: Promise<Response>[]) => Promise<void>,
) {
	let release = () => {};
	const held = new Promise<void>((resolve) => {
		release = resolve;
	});
	let ready = () => {};
	let failed: (error: unknown) => void = () => {};
	const acquired = new Promise<void>((resolve, reject) => {
		ready = resolve;
		failed = reject;
	});
	const holding = testDb.transaction(async (tx) => {
		const rows = await tx.execute(
			sql`SELECT id FROM ${sql.identifier(table)} WHERE id = ${id} FOR UPDATE`,
		);
		expect(rows).toHaveLength(1);
		ready();
		await held;
	});
	void holding.catch(failed);
	const pending: Promise<Response>[] = [];
	try {
		await acquired;
		await run(release, pending);
	} finally {
		release();
		await holding;
		await Promise.allSettled(pending);
	}
}

describe("不正なトークン交換の拒否・無効化の範囲・並行処理", () => {
	let userId: string;
	beforeEach(async () => {
		await cleanupDatabase();
		userId = (await createTestUser()).id;
	});
	afterAll(async () => {
		await cleanupDatabase();
		await closeDatabase();
	});

	async function authorization(client: TestClient = TEST_CONFIDENTIAL_CLIENT) {
		const code = await issueAuthorizationCode({
			clientId: client.clientId,
			userId,
			redirectUri: client.redirectUri,
			scope: "read write",
			codeChallenge,
			codeChallengeMethod: "S256",
		});
		const [row] = await testDb
			.select()
			.from(authorizationCodes)
			.where(eq(authorizationCodes.codeHash, sha256(code)));
		assert(row);
		return { code, row };
	}

	describe.each(clients)("発行先: $clientId", (owner) => {
		const other = clients.find((candidate) => candidate.clientId !== owner.clientId);
		assert(other);

		it.each([false, true])(
			"別クライアントの認可コードを拒否し、状態を変えない（使用済み=%s）",
			async (used) => {
				const { code } = await authorization(owner);
				if (used) await issued(await exchange(code, owner));
				const before = await snapshot();
				// PKCEは正しい値を指定し、クライアントの不一致だけで拒否されることを確かめる。
				await invalidGrant(await exchange(code, other));
				expect(await snapshot()).toEqual(before);
				if (!used) await issued(await exchange(code, owner));
			},
		);

		it.each(["fresh", "used_within_grace", "used_beyond_grace", "revoked"])(
			"別クライアントのRTを拒否し、状態を変えない（%s）",
			async (state) => {
				const { code } = await authorization(owner);
				const tokens = await issued(await exchange(code, owner));
				if (state === "used_within_grace" || state === "used_beyond_grace") {
					await issued(await refresh(tokens.refresh_token, owner));
				}
				if (state === "used_beyond_grace") {
					await testDb
						.update(refreshTokens)
						.set({ usedAt: sql`clock_timestamp() - interval '120 seconds'` })
						.where(eq(refreshTokens.tokenHash, sha256(tokens.refresh_token)));
				}
				if (state === "revoked") {
					await testDb
						.update(refreshTokens)
						.set({ revokedAt: new Date() })
						.where(eq(refreshTokens.tokenHash, sha256(tokens.refresh_token)));
				}
				const before = await snapshot();
				await invalidGrant(await refresh(tokens.refresh_token, other));
				expect(await snapshot()).toEqual(before);
				if (state === "fresh") await issued(await refresh(tokens.refresh_token, owner));
			},
		);
	});

	it.each([false, true])(
		"期限切れ認可コードでも使用済みなら関連するgrantとAT・RTを無効化し、別のgrantには影響しない（使用済み=%s）",
		async (used) => {
			const target = await authorization();
			if (used) await issued(await exchange(target.code, TEST_CONFIDENTIAL_CLIENT));
			const unrelated = await authorization();
			await issued(await exchange(unrelated.code, TEST_CONFIDENTIAL_CLIENT));
			await testDb
				.update(authorizationCodes)
				.set({ expiresAt: sql`now() - interval '1 minute'` })
				.where(eq(authorizationCodes.id, target.row.id));
			const before = await snapshot();
			await invalidGrant(await exchange(target.code, TEST_CONFIDENTIAL_CLIENT));
			const after = await snapshot();
			expect(stateOf(after, unrelated.row.grantId)).toEqual(stateOf(before, unrelated.row.grantId));
			if (used) {
				expectRevoked(stateOf(after, target.row.grantId));
				expect(after.codes).toEqual(before.codes);
				expect(after.at).toHaveLength(before.at.length);
				expect(after.rt).toHaveLength(before.rt.length);
			} else {
				expect(after).toEqual(before);
			}
		},
	);

	it.each(["used_beyond_grace", "revoked"])(
		"RTの再利用検知は対象grantのAT・RTだけを無効化する（%s）",
		async (state) => {
			const target = await authorization();
			const tokens = await issued(await exchange(target.code, TEST_CONFIDENTIAL_CLIENT));
			const next = await issued(await refresh(tokens.refresh_token, TEST_CONFIDENTIAL_CLIENT));
			let presented = tokens.refresh_token;
			if (state === "used_beyond_grace") {
				await testDb
					.update(refreshTokens)
					.set({ usedAt: sql`clock_timestamp() - interval '120 seconds'` })
					.where(eq(refreshTokens.tokenHash, sha256(presented)));
			} else {
				// 猶予期間内の再送で直前の後継を無効化し、実際に起こり得る失効済みRTを用意する。
				await issued(await refresh(tokens.refresh_token, TEST_CONFIDENTIAL_CLIENT));
				presented = next.refresh_token;
			}
			const unrelated = await authorization();
			await issued(await exchange(unrelated.code, TEST_CONFIDENTIAL_CLIENT));
			const before = await snapshot();
			await invalidGrant(await refresh(presented, TEST_CONFIDENTIAL_CLIENT));
			const after = await snapshot();
			expectRevoked(stateOf(after, target.row.grantId));
			expect(stateOf(after, unrelated.row.grantId)).toEqual(stateOf(before, unrelated.row.grantId));
			expect(after.codes).toEqual(before.codes);
			expect(after.at).toHaveLength(before.at.length);
			expect(after.rt).toHaveLength(before.rt.length);
			for (const row of before.rt.filter((row) => row.revokedAt !== null)) {
				expect(after.rt.find((candidate) => candidate.id === row.id)?.revokedAt).toEqual(
					row.revokedAt,
				);
			}
		},
	);

	it("同じ認可コードの交換2件をロック待ちにすると、AT・RTは1組だけ発行され、再利用検知で無効化される", async () => {
		const { code, row } = await authorization();
		await withRowLock("authorization_codes", row.id, async (release, pending) => {
			pending.push(
				exchange(code, TEST_CONFIDENTIAL_CLIENT),
				exchange(code, TEST_CONFIDENTIAL_CLIENT),
			);
			await waitForBlocked("authorization_codes", 2);
			release();
			const responses = await Promise.all(pending);
			expect(responses.map((response) => response.status).sort()).toEqual([200, 400]);
			const rejected = responses.find((response) => response.status === 400);
			assert(rejected);
			await invalidGrant(rejected);
		});
		const state = stateOf(await snapshot(), row.grantId);
		expect(state.at).toHaveLength(1);
		expect(state.rt).toHaveLength(1);
		expect(state.codes[0].usedAt).toBeInstanceOf(Date);
		expectRevoked(state);
	});

	it.each(["revoke-first", "refresh-first"])(
		"RTによる更新と無効化のどちらを先に処理しても、関連するAT・RTをすべて無効化する（%s）",
		async (order) => {
			const { code, row } = await authorization();
			const tokens = await issued(await exchange(code, TEST_CONFIDENTIAL_CLIENT));
			const revoke = () =>
				post("/revoke", TEST_CONFIDENTIAL_CLIENT, {
					token: tokens.refresh_token,
					token_type_hint: "refresh_token",
				});
			await withRowLock("grants", row.grantId, async (release, pending) => {
				const updating = () => refresh(tokens.refresh_token, TEST_CONFIDENTIAL_CLIENT);
				// この競合では、PostgreSQLが先に待機した要求へ先に行ロックを渡すことを前提にする。
				pending.push(order === "revoke-first" ? revoke() : updating());
				await waitForBlocked("grants", 1);
				pending.push(order === "revoke-first" ? updating() : revoke());
				await waitForBlocked("grants", 2);
				release();
				const responses = await Promise.all(pending);
				const revocation = responses[order === "revoke-first" ? 0 : 1];
				const rotation = responses[order === "revoke-first" ? 1 : 0];
				expect(revocation.status).toBe(200);
				if (order === "revoke-first") await invalidGrant(rotation);
				else await issued(rotation);
			});
			const state = stateOf(await snapshot(), row.grantId);
			expect(state.at).toHaveLength(order === "revoke-first" ? 1 : 2);
			expect(state.rt).toHaveLength(order === "revoke-first" ? 1 : 2);
			expectRevoked(state);
		},
	);
});
