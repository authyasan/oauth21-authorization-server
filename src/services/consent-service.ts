import { BlockList, isIP } from "node:net";
import { findConsent, saveConsent } from "../repositories/consent-repository.js";

/**
 * 同意サービス。
 * ユーザーの同意状態の確認と記録を行う。
 *
 * 非ループバックHTTPSへの応答で、要求スコープが同意済みならスキップ
 * 同意保存期間は無期限
 */

const loopbackAddresses = new BlockList();
loopbackAddresses.addSubnet("127.0.0.0", 8, "ipv4");
loopbackAddresses.addAddress("::1", "ipv6");

/**
 * 登録値との照合を通過したリダイレクトURIについて、同意の再利用を許可するか。
 * HTTPSの受信先を正規クライアントが管理することは、設定登録時に管理者が確認する。
 *
 * ループバックの判定は、redirect_uri の照合（utils/validation.ts の isLoopbackUri）より広い。
 * 端末上の別アプリが受け取れる宛先を取りこぼさないよう、127.0.0.0/8 と IPv4-mapped も含める。
 */
function allowsConsentReuse(redirectUri: string): boolean {
	const url = new URL(redirectUri);
	if (url.protocol !== "https:") return false;

	const host = url.hostname.startsWith("[")
		? url.hostname.slice(1, -1)
		: url.hostname.replace(/\.$/, "");
	if (host === "localhost" || host.endsWith(".localhost")) return false;

	// IPv4-mapped IPv6を含むループバック判定は標準ライブラリに任せる。
	const version = isIP(host);
	return version === 0 || !loopbackAddresses.check(host, version === 4 ? "ipv4" : "ipv6");
}

/**
 * 今回のリダイレクト先と保存済みのスコープから、同意画面を省略できるか確認する。
 *
 * @param userId ユーザーID
 * @param clientId クライアントID
 * @param requestedScope リクエストされたスコープ（スペース区切り）
 * @param redirectUri 検証済みの、今回使用するリダイレクトURI
 * @returns 同意画面を省略できる場合true
 */
export async function canSkipConsent(
	userId: string,
	clientId: string,
	requestedScope: string,
	redirectUri: string,
): Promise<boolean> {
	// [SECURITY] 同意済みでも、別アプリがコードを受け取れるURIでは毎回確認する。
	// クライアント種別には依存せず、ログイン前後の両経路でこの条件を適用する。
	if (!allowsConsentReuse(redirectUri)) return false;

	const existing = await findConsent(userId, clientId);
	if (!existing) {
		return false;
	}

	// リクエストされたスコープがすべて過去の同意に含まれているか
	const requestedScopes = requestedScope.split(" ");
	const consentedScopes = new Set(existing.scope.split(" "));

	return requestedScopes.every((scope) => consentedScopes.has(scope));
}

/**
 * 同意を記録する。
 *
 * @param userId ユーザーID
 * @param clientId クライアントID
 * @param scope 同意したスコープ（スペース区切り）
 */
export async function recordConsent(
	userId: string,
	clientId: string,
	scope: string,
): Promise<void> {
	await saveConsent(userId, clientId, scope);
}
