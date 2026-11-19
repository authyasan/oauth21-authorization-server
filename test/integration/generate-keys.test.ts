import { execFile } from "node:child_process";
import {
	chmod,
	copyFile,
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { importJWK, importPKCS8, jwtVerify, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(import.meta.dirname, "../..");

// POSIXのファイル権限を実ファイルで確認する。DBや作業場のkeys/には触れない。
describe.runIf(process.platform !== "win32")("署名鍵生成時の保存権限", () => {
	let directory = "";

	beforeEach(async () => {
		directory = await mkdtemp(join(tmpdir(), "oauth21-generate-keys-"));
		await mkdir(join(directory, "scripts"));
		await copyFile(
			join(projectRoot, "scripts/generate-keys.ts"),
			join(directory, "scripts/generate-keys.ts"),
		);
		await copyFile(join(projectRoot, "package.json"), join(directory, "package.json"));
		await symlink(join(projectRoot, "node_modules"), join(directory, "node_modules"));
	});

	afterEach(async () => {
		if (directory) await rm(directory, { recursive: true, force: true });
		directory = "";
	});

	async function generateAndVerify() {
		// ホストで直接実行した場合を再現し、テストプロセス自体のumaskは変更しない。
		await execFileAsync(
			process.execPath,
			[
				"--import",
				"tsx",
				"--input-type=module",
				"-e",
				"process.umask(0o022); await import('./scripts/generate-keys.ts');",
			],
			{ cwd: directory, timeout: 15000 },
		);

		const privatePath = join(directory, "keys/private.pem");
		expect((await stat(privatePath)).mode & 0o777).toBe(0o600);
		const privateKey = await importPKCS8(await readFile(privatePath, "utf8"), "RS256");
		const jwks = JSON.parse(await readFile(join(directory, "keys/jwks.json"), "utf8"));
		expect(jwks.keys).toHaveLength(1);
		expect(jwks.keys[0].d).toBeUndefined();
		const publicKey = await importJWK(jwks.keys[0], "RS256");
		const jwt = await new SignJWT({ sub: "permission-test" })
			.setProtectedHeader({ alg: "RS256", kid: jwks.keys[0].kid })
			.sign(privateKey);
		const { payload } = await jwtVerify(jwt, publicKey, { algorithms: ["RS256"] });
		expect(payload.sub).toBe("permission-test");
	}

	it("umaskが022でも新しい秘密鍵を0600で保存する", async () => {
		await generateAndVerify();
	});

	it("既存ファイルが0644でも上書き後の秘密鍵を0600にする", async () => {
		await mkdir(join(directory, "keys"));
		const privatePath = join(directory, "keys/private.pem");
		await writeFile(privatePath, "テスト用の置き換え対象");
		await chmod(privatePath, 0o644);
		await generateAndVerify();
	});
});
