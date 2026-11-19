/**
 * OAuthリクエストのバリデーションユーティリティ。
 */

/**
 * redirect_uriの完全一致検証。
 *
 * [SECURITY] 登録先に似せた別のURIへ認可コードを送らないよう、文字列全体を比較する。
 *
 * @param requestUri リクエストに含まれるredirect_uri
 * @param registeredUri クライアントに登録されたredirect_uri
 * @returns 完全一致する場合true
 */
export function isExactRedirectUriMatch(requestUri: string, registeredUri: string): boolean {
	return requestUri === registeredUri;
}

/**
 * redirect_uriがクライアントに登録されたいずれかのURIと一致するか検証する。
 *
 * @param requestUri リクエストに含まれるredirect_uri
 * @param registeredUris クライアントに登録された全redirect_uri
 * @returns 一致するURIがある場合true
 */
export function validateRedirectUri(requestUri: string, registeredUris: string[]): boolean {
	return registeredUris.some((uri) => isExactRedirectUriMatch(requestUri, uri));
}

/**
 * scopeパラメータが構文に従うか検証する。
 * OAuth 2.1 draft-16 §1.4.1: scope = scope-token *( SP scope-token )
 *   scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
 *
 * [SECURITY] 空白を補正（trimや任意の空白での分割）せずに検証し、
 * 不正な入力を受け入れない。通過した値は半角スペース1つで区切られている。
 * (?![\s\S]) は入力末尾。末尾改行の前にも一致する $ は使わない。
 */
export function isValidScopeSyntax(scope: string): boolean {
	return /^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*(?![\s\S])/.test(scope);
}

/**
 * リクエストされたスコープのうち、許可されていないものを返す。
 *
 * @param requestedScopes リクエストされたスコープの配列
 * @param allowedScopes 許可されたスコープの配列
 * @returns 許可されていないスコープの配列
 */
export function getUnknownScopes(requestedScopes: string[], allowedScopes: string[]): string[] {
	const allowedSet = new Set(allowedScopes);
	return requestedScopes.filter((scope) => !allowedSet.has(scope));
}

/**
 * ループバックアドレスかどうかを判定する。
 * OAuth 2.1 Section 8.4.2: 127.0.0.1 または [::1] を使用する。
 *
 * redirect_uri の照合でポートを除外してよいかの判定に使うので、仕様が示す2つの表記だけを
 * 対象にする（127.0.0.2 や IPv4-mapped は対象外で、通常の完全一致になる）。
 * 同意画面を省略してよいかの判定（consent-service の allowsConsentReuse）は、これより広く
 * 127.0.0.0/8 と IPv4-mapped まで含めてループバックとみなす。目的が違うため基準が異なる。
 *
 * @param uri 検証対象のURI
 * @returns ループバックアドレスの場合true
 */
export function isLoopbackUri(uri: string): boolean {
	try {
		const parsed = new URL(uri);
		return parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
	} catch {
		return false;
	}
}

/**
 * ループバックURIの一致検証。ポート番号を除いて比較する。
 * OAuth 2.1 Section 8.4.2: ネイティブアプリが動的にポートを割り当てるため、
 * ポート番号は完全一致の対象外とする。
 *
 * クエリ文字列は完全一致の対象に含める
 *   （ポートだけが例外で、それ以外は simple string comparison）。
 *
 * [SECURITY] ループバックURIのポート番号を除外して比較する。
 * ポート番号を含めると、ネイティブアプリが動的ポートを使えなくなる。
 *
 * @param requestUri リクエストに含まれるredirect_uri
 * @param registeredUri クライアントに登録されたredirect_uri
 * @returns ポート番号を除いて一致する場合true
 */
export function isLoopbackRedirectUriMatch(requestUri: string, registeredUri: string): boolean {
	// registeredUriは設定読み込み時にURL解析・スキーム・fragment禁止を確認済み。
	// [SECURITY] 空のfragmentも拒否する。URL.hashでは末尾の「#」を検出できない。
	if (requestUri.includes("#")) {
		return false;
	}
	try {
		// URLは構文・ポート範囲の確認だけに使い、正規化後の値は比較しない。
		new URL(requestUri);
	} catch {
		return false;
	}
	const requestWithoutPort = removeLoopbackPort(requestUri);
	const registeredWithoutPort = removeLoopbackPort(registeredUri);
	return requestWithoutPort !== undefined && requestWithoutPort === registeredWithoutPort;
}

/** ポートを除いた元の文字列を返す。対象のループバック表記でなければundefined。 */
function removeLoopbackPort(uri: string): string | undefined {
	// [SECURITY] スキームの大小文字は受付時だけ区別せず、比較には元の表記を残す。
	const prefix = uri.match(/^https?:\/\/(?:127\.0\.0\.1|\[::1\])/i)?.[0];
	if (prefix === undefined) {
		return undefined;
	}

	const remainder = uri.slice(prefix.length);
	// [SECURITY] IPリテラルの直後にある「:数字」だけを削り、パス・クエリを補正しない。
	const pathAndQuery = remainder.replace(/^:[0-9]+/, "");
	// IPの後ろに別の文字が続くもの（127.0.0.1.evil.exampleなど）は対象外。
	if (pathAndQuery !== "" && !pathAndQuery.startsWith("/") && !pathAndQuery.startsWith("?")) {
		return undefined;
	}
	return prefix + pathAndQuery;
}

/**
 * URIのスキーム部（RFC 3986 §3.1）を取り出す。
 * private-use URI schemeは「スキーム:/パス」のようにスラッシュ1つで書かれることが多い
 * （OAuth 2.1 draft-16 §8.4.3の例 com.example.app:/oauth2redirect/example-provider）ので、
 * 「//」の有無は問わない。
 */
function getScheme(uri: string): string | undefined {
	return uri.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/)?.[1];
}

/**
 * カスタムURLスキーム（private-use URI scheme）かどうかを判定する。
 *
 * @param uri 検証対象のURI
 * @returns httpsでもhttpでもないスキームの場合true
 */
export function isPrivateUseScheme(uri: string): boolean {
	const scheme = getScheme(uri)?.toLowerCase();
	return scheme !== undefined && scheme !== "https" && scheme !== "http";
}

/**
 * カスタムURLスキームが逆ドメイン名形式かを検証する。
 * OAuth 2.1 draft-16 §8.4.3: アプリは逆ドメイン名形式のスキームを使わなければならない（MUST）。
 * 同 §2.3.1: 認可サーバーはそれを強制すべきで、少なくともピリオドを含まないスキームは
 * 拒否すべき（SHOULD）。本書の認可サーバーはピリオドを含まないスキームを拒否する。
 *
 * [SECURITY] 逆ドメイン名形式を強制することで、スキームの衝突リスクを軽減する。
 * 例: com.example.app:/callback は許可、myapp:/callback は拒否。
 *
 * @param uri 検証対象のURI
 * @returns 逆ドメイン名形式（ピリオドを含む）の場合true
 */
export function isReverseDomainScheme(uri: string): boolean {
	return getScheme(uri)?.includes(".") ?? false;
}

/**
 * redirect_uriのスキームが許可されたものかを検証する。
 * - HTTPS: 常に許可
 * - HTTP: ループバックアドレスの場合のみ許可
 * - カスタムスキーム: 逆ドメイン名形式のみ許可
 *
 * @param uri 検証対象のURI
 * @returns 許可されたスキームの場合true
 */
export function isAllowedRedirectUriScheme(uri: string): boolean {
	if (isPrivateUseScheme(uri)) {
		return isReverseDomainScheme(uri);
	}

	try {
		const parsed = new URL(uri);

		if (parsed.protocol === "https:") {
			return true;
		}

		if (parsed.protocol === "http:") {
			return isLoopbackUri(uri);
		}

		return false;
	} catch {
		return false;
	}
}

/**
 * redirect_uriの総合的な検証（登録済みURIとの一致検証）。
 * ループバックURIの場合はポート番号を除いて比較する。
 *
 * @param requestUri リクエストに含まれるredirect_uri
 * @param registeredUris クライアントに登録された全redirect_uri
 * @returns 一致するURIがある場合true
 */
export function validateRedirectUriWithLoopback(
	requestUri: string,
	registeredUris: string[],
): boolean {
	if (isLoopbackUri(requestUri)) {
		return registeredUris.some((uri) => isLoopbackRedirectUriMatch(requestUri, uri));
	}
	return validateRedirectUri(requestUri, registeredUris);
}
