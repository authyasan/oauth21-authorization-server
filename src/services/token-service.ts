import { SignJWT } from "jose";
import { getKid, getPrivateKey } from "../config/keys.js";
import { getAudienceForScopes } from "../config/resource-server.js";
import { serverConfig } from "../config/server.js";
import { db, type Executor } from "../db/connection.js";
import {
	type AuthorizationCodeRecord,
	consumeAuthorizationCodeIfFresh,
	findAuthorizationCodeById,
} from "../repositories/authorization-code-repository.js";
import { getGrantCreatedAt, revokeGrant } from "../repositories/grant-repository.js";
import { saveAccessToken, saveRefreshToken } from "../repositories/token-repository.js";
import type { ClientConfig } from "../types/client.js";
import { generateRandomString, sha256 } from "../utils/crypto.js";

/**
 * アクセストークンとリフレッシュトークンの発行を行う。
 *
 * 認可コードとの交換処理も担当し、認可コードの使用済み記録と
 * トークン発行を同一トランザクションで行う。
 * 使用済み認可コードの再利用を検知した場合は、grantと関連するトークンを無効化する。
 */

/** jtiのバイト長（16バイト = 128ビット） */
const JTI_BYTES = 16;

/** リフレッシュトークンのバイト長（32バイト = 256ビット） */
const REFRESH_TOKEN_BYTES = 32;

export interface IssuedToken {
	accessToken: string;
	expiresIn: number;
	scope: string;
	refreshToken: string;
}

/**
 * JWTアクセストークンとリフレッシュトークンを発行する。
 *
 * @param params.client クライアント設定
 * @param params.userId ユーザー識別子
 * @param params.scope アクセストークンに付与するスコープ
 * @param params.grantId 発行するAT・RTが属するgrantの識別子
 * @param executor DB操作に使う接続またはトランザクション（省略時はdb）。
 *   認可コードやRTの使用済み記録とトークン保存をまとめて確定するため、
 *   呼び出し元のトランザクションを渡す。
 * @returns 発行されたアクセストークン・リフレッシュトークンとメタデータ
 */
export async function issueTokens(
	params: {
		client: ClientConfig;
		userId: string;
		scope: string;
		grantId: string;
	},
	executor: Executor = db,
): Promise<IssuedToken> {
	const { client, userId, scope, grantId } = params;

	// アクセストークンを識別するjtiは、衝突を避けるため128ビットの乱数から生成する。
	const jti = generateRandomString(JTI_BYTES);

	// クライアント種別・スコープによらず、同じ有効期間を使う。
	const expiresIn = serverConfig.accessToken.ttl;

	const now = Math.floor(Date.now() / 1000);
	const expiresAt = new Date((now + expiresIn) * 1000);

	const privateKey = await getPrivateKey();
	const kid = getKid();

	// #@range_begin(sign-jwt) ※書籍掲載用の範囲マーカー
	// 本サンプルでは、スコープに対応するリソースサーバーの識別子をaudに設定する。
	// 対象が1つなら文字列、複数なら配列にする。
	const scopes = scope.split(" ");
	const audiences = getAudienceForScopes(scopes);
	const aud = audiences.length === 1 ? audiences[0] : audiences;

	// RFC 9068 §2.2で必須のクレームにscopeを加える。
	// 署名にはRS256を使う。
	const accessToken = await new SignJWT({
		scope,
		client_id: client.clientId,
	})
		.setProtectedHeader({ alg: "RS256", kid, typ: "at+jwt" })
		.setJti(jti)
		.setIssuer(serverConfig.issuer)
		.setSubject(userId)
		.setAudience(aud)
		.setIssuedAt(now)
		.setExpirationTime(now + expiresIn)
		.sign(privateKey);
	// #@range_end(sign-jwt)

	// アクセストークンの無効化とイントロスペクションに使う情報をDBに保存する。
	// audは設定変更後もJWTと食い違わないよう、発行時の値を保存する。
	// #@range_begin(save-access-token)
	await saveAccessToken(
		{
			jti,
			grantId,
			clientId: client.clientId,
			userId,
			scope,
			audience: audiences,
			expiresAt,
		},
		executor,
	);
	// #@range_end(save-access-token)

	// リフレッシュトークンはクライアント種別によらず発行する。
	// リフレッシュトークンのスコープは、紐付くgrantから参照する。
	// アクセストークンのスコープを狭めても、grantのスコープは変更しない。
	const refreshToken = await issueRefreshToken(
		{
			grantId,
			clientId: client.clientId,
			userId,
		},
		executor,
	);

	return {
		accessToken,
		expiresIn,
		scope,
		refreshToken,
	};
}

/**
 * リフレッシュトークンを生成し、ハッシュ値と関連情報をDBに保存する。
 *
 * 有効期限は、発行時点からの無操作期限と、grant作成時点からの
 * 絶対期限のうち、早い方とする。RTを更新しても絶対期限は延長しない。
 *
 * [SECURITY] 平文のトークンはDBに保存せず、呼び出し元に返す。
 *
 * @returns 平文のリフレッシュトークン
 */
async function issueRefreshToken(
	params: {
		grantId: string;
		clientId: string;
		userId: string;
	},
	executor: Executor = db,
): Promise<string> {
	// [SECURITY] リフレッシュトークンの推測を困難にするため、32バイトの暗号論的乱数から生成する。
	const token = generateRandomString(REFRESH_TOKEN_BYTES);

	// [SECURITY] DB漏洩時にリフレッシュトークンがそのまま使われないよう、ハッシュ値を保存する。
	const tokenHash = sha256(token);

	const grantCreatedAt = await getGrantCreatedAt(params.grantId, executor);
	if (!grantCreatedAt) {
		throw new Error(`grant が見つかりません: ${params.grantId}`);
	}
	const idleExpiry = Date.now() + serverConfig.refreshToken.idleTtl * 1000;
	const absoluteExpiry = grantCreatedAt.getTime() + serverConfig.refreshToken.absoluteTtl * 1000;
	const expiresAt = new Date(Math.min(idleExpiry, absoluteExpiry));

	await saveRefreshToken(
		{
			tokenHash,
			...params,
			expiresAt,
		},
		executor,
	);

	return token;
}

/**
 * 認可コード交換の結果。
 * - success: 認可コードの使用済み記録とトークン保存をDBにコミット済み
 * - invalid_grant: 認可コードが無効（使用済み・期限切れ・レコード不在）
 */
export type AuthorizationCodeExchangeResult =
	| { type: "success"; token: IssuedToken }
	| { type: "invalid_grant" };

/**
 * 認可コードと引き換えにアクセストークンとリフレッシュトークンを発行する。
 * 使用済み認可コードの再利用を検知した場合は、grantと関連するAT・RTを無効化する。
 *
 * 呼び出し前の条件:
 * クライアントの識別・種別に応じた認証、および認可コードの存在、
 * クライアント識別子、指定されたredirect_uri、PKCEの検証を済ませておく。
 * [SECURITY] 認可コードだけを入手した攻撃者による、
 * 関連トークンの巻き添え無効化を防ぐため、これらの検証は無効化より先に行う。
 *
 * [SECURITY] 認可コードの使用済み記録とトークン保存は、
 * 同一トランザクションで確定し、途中で失敗した場合は両方を巻き戻す。
 *
 * 再利用時の拒否と発行済みAT・RTの無効化については、
 * OAuth 2.1 draft-16 §4.1.3・§7.5.3を参照。
 *
 * [SECURITY] 将来、管理機能などから認可コードの初回交換前にgrantを
 * 無効化できるようにする場合は、交換時にgrantの有効性も確認すること。
 *
 * @param params.codeRecord 事前検証済みの認可コードレコード
 * @param params.client クライアント設定
 * @returns DBへの保存確定後の発行トークン、
 * または認可コードが使用済み・期限切れ・レコード不在の場合はinvalid_grant
 * @throws DB操作やトークン生成などの例外は呼び出し元へ伝播する
 */
export async function exchangeAuthorizationCode(params: {
	codeRecord: AuthorizationCodeRecord;
	client: ClientConfig;
}): Promise<AuthorizationCodeExchangeResult> {
	const { codeRecord, client } = params;

	// [SECURITY] 未使用かつ期限内の認可コードだけを使用済みに更新する。
	// 同じ認可コードへの更新は行ロックで待機するため、並行して二重発行しない。
	// ロックはトークン保存のコミットまで保持し、再利用時の無効化が保存より先になるのを防ぐ。
	const token = await db.transaction(async (tx) => {
		const consumed = await consumeAuthorizationCodeIfFresh(codeRecord.id, tx);
		if (!consumed) {
			return null;
		}
		return await issueTokens(
			{
				client,
				userId: codeRecord.userId,
				scope: codeRecord.scope,
				grantId: codeRecord.grantId,
			},
			tx,
		);
	});

	// DBへのコミットが成功してから発行結果を返す。
	// コミットに失敗した場合は例外となり、保存できなかったトークンを返さない。
	if (token) {
		return { type: "success", token };
	}

	// [SECURITY] 認可コードを使用済みにできなかった場合は、DBから読み直して再利用を判定する。
	// 別の処理が同じ認可コードを更新中なら、前段のUPDATEは行ロックにより、そのトランザクションの終了を待つ。
	// その処理がコミットした場合、発行したAT・RTも保存済みなので、再利用の検知時に無効化できる。
	const latest = await findAuthorizationCodeById(codeRecord.id);
	if (latest?.usedAt) {
		// 事前検証を通過したリクエストによる再利用なので、grantと関連トークンを無効化する。
		await revokeGrant(codeRecord.grantId);
	}

	return { type: "invalid_grant" };
}
