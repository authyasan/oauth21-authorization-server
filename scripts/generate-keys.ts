/**
 * RS256 JWT署名鍵の生成スクリプト。
 *
 * RS256 (RSASSA-PKCS1-v1_5 + SHA-256) を採用。
 * - RFC 9068 §2.1が、準拠するAS/RSのサポートすべき署名アルゴリズムにRS256を含めることをMUSTとしている
 * - リソースサーバー側の検証ライブラリが事実上すべて対応している
 *
 * 使い方: npm run generate-keys
 * 出力先: keys/ ディレクトリ（.gitignore対象）
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { exportJWK, exportPKCS8, generateKeyPair } from "jose";

const KEYS_DIR = join(import.meta.dirname, "..", "keys");

async function main() {
	// keys/ ディレクトリを作成
	await mkdir(KEYS_DIR, { recursive: true });

	// #@range_begin(generate-keys) ※書籍掲載用の範囲マーカー
	// RSA 2048ビット鍵ペアを生成
	const { publicKey, privateKey } = await generateKeyPair("RS256", {
		modulusLength: 2048,
		extractable: true,
	});

	// 秘密鍵はPEM形式で書き出す
	const privatePem = await exportPKCS8(privateKey);
	await writeFile(join(KEYS_DIR, "private.pem"), privatePem);

	// 公開鍵はJWK形式だけで書き出す（JWKSエンドポイントと自前の検証の両方で使う）
	const publicJwk = await exportJWK(publicKey);
	publicJwk.kid = `oauth21-${Date.now()}`;
	publicJwk.use = "sig";
	publicJwk.alg = "RS256";

	const jwks = { keys: [publicJwk] };
	await writeFile(join(KEYS_DIR, "jwks.json"), JSON.stringify(jwks, null, 2));
	// #@range_end(generate-keys)

	console.log("鍵ファイルを生成しました:");
	console.log(`  秘密鍵: ${join(KEYS_DIR, "private.pem")}`);
	console.log(`  JWKS:   ${join(KEYS_DIR, "jwks.json")}`);
	console.log(`  kid:    ${publicJwk.kid}`);
}

main().catch((err) => {
	console.error("鍵生成に失敗しました:", err);
	process.exit(1);
});
