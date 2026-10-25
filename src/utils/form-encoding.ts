/**
 * application/x-www-form-urlencoded で符号化された1つの値を戻す。
 *
 * RFC 6749 §2.3.1: Basic認証のクライアントIDとシークレットは、付録Bの
 * フォーム符号化で符号化される。付録Bの符号化では空白が「+」になるので、
 * パーセントエンコードを戻す前に「+」を空白に戻す（リテラルの「+」は「%2B」で届く）。
 *
 * [SECURITY] 不正なパーセントエンコード（UTF-8として不正なバイト列を含む）は
 * 例外を投げずに null を返す。呼び出し側はこれを認証失敗として扱う。
 *
 * @param value 符号化された値
 * @returns 戻した値。不正な符号化の場合は null
 */
export function decodeFormComponent(value: string): string | null {
	try {
		return decodeURIComponent(value.replaceAll("+", " "));
	} catch {
		return null;
	}
}
