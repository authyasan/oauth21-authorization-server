import { readFileSync } from "node:fs";
import { join } from "node:path";
import { importJWK, importPKCS8, type JWK } from "jose";

const KEYS_DIR = join(import.meta.dirname, "..", "..", "keys");

let cachedPrivateKey: CryptoKey | null = null;
let cachedPublicKey: CryptoKey | null = null;
let cachedJwks: { keys: Record<string, unknown>[] } | null = null;

/**
 * JWT署名用の秘密鍵は初回に読み込み、以降は同じ鍵を使う。
 */
export async function getPrivateKey(): Promise<CryptoKey> {
	if (cachedPrivateKey) return cachedPrivateKey;

	const pem = readFileSync(join(KEYS_DIR, "private.pem"), "utf-8");
	cachedPrivateKey = await importPKCS8(pem, "RS256");
	return cachedPrivateKey;
}

/**
 * JWT検証用の公開鍵を取得する。
 *
 * リソースサーバーに公開する jwks.json の鍵（署名に使う kid と同じ先頭の鍵）から作る。
 * 自前の検証（リボケーション・イントロスペクション）とリソースサーバーの検証で
 * 公開鍵の出どころを1つにし、両者が食い違わないようにする。
 */
export async function getPublicKey(): Promise<CryptoKey> {
	if (cachedPublicKey) return cachedPublicKey;

	const jwk = getJwks().keys[0] as JWK;
	cachedPublicKey = (await importJWK(jwk, "RS256")) as CryptoKey;
	return cachedPublicKey;
}

/**
 * JWKSエンドポイント用のJWKSオブジェクトを取得する。
 * 初回読み込み時に jwks.json の妥当性を検証し、不正な場合は例外を投げる。
 */
// #@range_begin(load-keys) ※書籍掲載用の範囲マーカー
export function getJwks(): { keys: Record<string, unknown>[] } {
	if (cachedJwks) return cachedJwks;

	const json = readFileSync(join(KEYS_DIR, "jwks.json"), "utf-8");
	const parsed: unknown = JSON.parse(json);

	// [SECURITY] jwks.json の構造検証。keys が空または kid がない場合は失敗させる
	if (
		typeof parsed !== "object" ||
		parsed === null ||
		!Array.isArray((parsed as Record<string, unknown>).keys) ||
		(parsed as { keys: unknown[] }).keys.length === 0 ||
		typeof (parsed as { keys: Record<string, unknown>[] }).keys[0].kid !== "string"
	) {
		throw new Error("jwks.json が不正です: keys が空か kid がありません");
	}

	cachedJwks = parsed as { keys: Record<string, unknown>[] };
	return cachedJwks;
}
// #@range_end(load-keys)

/**
 * 署名に使う先頭の鍵のkidを返す。型はgetJwks()で検証済み。
 */
// #@range_begin(get-kid) ※書籍掲載用の範囲マーカー
export function getKid(): string {
	const jwks = getJwks();
	return jwks.keys[0].kid as string;
}
// #@range_end(get-kid)
