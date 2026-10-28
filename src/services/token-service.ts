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
 * トークンサービス。
 * JWTアクセストークンの生成を行う。
 *
 * jtiは16バイト（128ビット）。衝突回避が目的で推測攻撃の対象にならない。
 * RS256 (RSASSA-PKCS1-v1_5 + SHA-256) で署名する。RFC 9068 §2.1 が、準拠する認可サーバーと
 * リソースサーバーに RS256 のサポートを求めているため採用する（RFC 7518 §3.1 での区分は Recommended）。
 * RFC 9068準拠の最小クレーム + scope。
 *
 * JWTペイロード:
 * {
 *   jti: トークン識別子（イントロスペクション・リボケーション用）
 *   iss: 認可サーバーのURL
 *   sub: ユーザー識別子
 *   aud: リソースサーバーID（発行時にスコープから逆引きし、DBにも保存。複数の場合は配列）
 *   client_id: クライアント識別子
 *   scope: 許可されたスコープ
 *   iat: 発行時刻
 *   exp: 有効期限
 * }
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
	/** 発行したリフレッシュトークンの行ID。ローテーションで replaced_by を張るために使う */
	refreshTokenId: string;
}

/**
 * JWTアクセストークンを発行する。
 *
 * @param params.client クライアント設定
 * @param params.userId ユーザーID
 * @param params.scope 許可されたスコープ
 * @param params.grantId この AT が属する grant のID（カスケード失効用の grouping key）
 * @param executor トランザクションハンドル（省略時は通常のdb接続）。
 *   認可コードグラントでは消費 UPDATE と同一トランザクションを渡す。
 * @returns 発行されたアクセストークンとメタデータ
 */
export async function issueAccessToken(
	params: {
		client: ClientConfig;
		userId: string;
		scope: string;
		grantId: string;
	},
	executor: Executor = db,
): Promise<IssuedToken> {
	const { client, userId, scope, grantId } = params;

	// 16バイトのjtiを生成
	const jti = generateRandomString(JTI_BYTES);

	// クライアント種別・スコープによらず一律30分
	const expiresIn = serverConfig.accessToken.ttl;

	const now = Math.floor(Date.now() / 1000);
	const expiresAt = new Date((now + expiresIn) * 1000);

	// JWT署名鍵を取得
	const privateKey = await getPrivateKey();
	const kid = getKid();

	// #@range_begin(sign-jwt) ※書籍掲載用の範囲マーカー
	// RFC 9068準拠の最小クレーム + scope
	// audはスコープに対応するリソースサーバーIDから決定する。
	// 複数リソースサーバーが該当する場合は配列で設定される。
	const scopes = scope.split(" ");
	const audiences = getAudienceForScopes(scopes);
	const aud = audiences.length === 1 ? audiences[0] : audiences;

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

	// アクセストークンのメタデータをDBに保存（リボケーション・イントロスペクション用）
	// JWT の aud に入れたものと同じ集合を保存する。
	// イントロスペクションは設定から計算し直さず、この値で照会元RSを判定し、応答の aud にも使う。
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
	// リフレッシュトークンにスコープは持たせない。更新できる範囲は
	// grant 行にあり、アクセストークンのスコープを縮めてもそこは動かない。
	// draft-16 §4.3.3 の「後継のスコープは提示されたリフレッシュトークンと同一」という MUST は、
	// 両者が同じ grant を指すことで自動的に満たされる。
	const refresh = await issueRefreshToken(
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
		refreshToken: refresh.token,
		refreshTokenId: refresh.id,
	};
}

/**
 * リフレッシュトークンを生成し、DBに保存する。
 *
 * 有効期限は「無操作30日」と「grant 誕生から絶対上限180日」の小さいほう。
 * 無操作期限は更新のたびに引き直されるので、使われ続けている限りトークンは生き続ける。
 * 絶対上限は放置された grant を掃除するためのもので、更新では延びない。
 * 再利用検知は正規の利用者と攻撃者の両方が使ったときにしか発火しないため、
 * 利用者が使わなくなった grant を無期限に延ばさない仕組みが要る。
 *
 * 更新のたびにローテーションする。
 *
 * [SECURITY] リフレッシュトークンの生成フロー:
 * 1. 32バイトのランダム文字列を生成（平文トークン）
 * 2. SHA-256ハッシュを計算してDBに保存
 * 3. 平文トークンをクライアントに返す
 * 4. リフレッシュ時に受け取った平文トークンをハッシュしてDB照合
 *
 * @returns 平文のリフレッシュトークンと、その行ID
 */
async function issueRefreshToken(
	params: {
		grantId: string;
		clientId: string;
		userId: string;
	},
	executor: Executor = db,
): Promise<{ token: string; id: string }> {
	// [SECURITY] 32バイトの暗号論的乱数でリフレッシュトークンを生成
	const token = generateRandomString(REFRESH_TOKEN_BYTES);

	// [SECURITY] SHA-256ハッシュをDBに保存（平文は保存しない）
	const tokenHash = sha256(token);

	// min(now + 無操作30日, grant.created_at + 絶対上限180日)
	// 期限はアプリの時計で計算して書く。期限の判定は消費時に DB の時計で行う
	// （consumeRefreshTokenIfFresh）。単一ホスト構成では両者のずれは無視できる。
	const grantCreatedAt = await getGrantCreatedAt(params.grantId, executor);
	if (!grantCreatedAt) {
		throw new Error(`grant が見つかりません: ${params.grantId}`);
	}
	const idleExpiry = Date.now() + serverConfig.refreshToken.idleTtl * 1000;
	const absoluteExpiry = grantCreatedAt.getTime() + serverConfig.refreshToken.absoluteTtl * 1000;
	const expiresAt = new Date(Math.min(idleExpiry, absoluteExpiry));

	const id = await saveRefreshToken(
		{
			tokenHash,
			...params,
			expiresAt,
		},
		executor,
	);

	return { token, id };
}

/**
 * 認可コード交換の結果。
 * - success: トークン発行に成功（commit 済み）
 * - invalid_grant: コードが無効（再利用・期限切れ・並行交換で先を越された等）
 */
export type AuthorizationCodeExchangeResult =
	| { type: "success"; token: IssuedToken }
	| { type: "invalid_grant" };

/**
 * 事前検証済みの認可コードをトークンに交換する（原子的 consume ＋ 発行）。
 *
 * [SECURITY] 消費と発行の原子性:
 * 認可コードの消費（used_at 刻み）とアクセストークン／リフレッシュトークンの保存を
 * 同一トランザクションで行う。これにより、同一コードの並行交換において
 * 「敗者が grant を失効させた後に、勝者が失効対象外の新トークンを挿入して生き残る」
 * 順序を排除する。勝者は authorization_codes 行ロックを保持したままトークンを INSERT して
 * commit するため、敗者の consume は 0 行になり、その後の再利用検知（revokeGrant）は
 * commit 済みの勝者トークンを確実に巻き込んで失効できる。
 *
 * 0 行（消費できなかった）場合は最新の used_at を読み直して分類する:
 * - used_at が刻まれている → 正規パラメータでの再利用 → grant 単位で失効（OAuth 2.1 §7.5.2 SHOULD）
 * - used_at が NULL（＝期限切れ／存在しない） → 失効はしない（不正なリクエストによる巻き添え失効を防ぐ DoS 対策）
 *
 * このコードに到達する時点で client_id / 指定時の redirect_uri / PKCE は検証済みであること。
 * それが「valid な再使用リクエスト」の前提であり、不正パラメータでの巻き添え
 * 失効を防ぐ。
 *
 * [SECURITY] 現行のHTTP経路では、認可コードの初回交換前にgrantを無効化できない。
 * その経路を追加する場合は、消費・発行と同じトランザクション内でgrantをロックして
 * 有効性を確認し、無効化済みなら発行を拒否すること。
 *
 * @param params.codeRecord 事前検証済みの認可コードレコード
 * @param params.client クライアント設定
 * @returns 成功時は発行トークン、失敗時は invalid_grant
 */
export async function exchangeAuthorizationCode(params: {
	codeRecord: AuthorizationCodeRecord;
	client: ClientConfig;
}): Promise<AuthorizationCodeExchangeResult> {
	const { codeRecord, client } = params;

	// [SECURITY] 原子的 consume ＋ トークン発行を同一トランザクションで実行する。
	// consume が成功した場合のみトークンを発行し、両者を同時に commit する。
	const token = await db.transaction(async (tx) => {
		const consumed = await consumeAuthorizationCodeIfFresh(codeRecord.id, tx);
		if (!consumed) {
			return null;
		}
		return await issueAccessToken(
			{
				client,
				userId: codeRecord.userId,
				scope: codeRecord.scope,
				grantId: codeRecord.grantId,
			},
			tx,
		);
	});

	// commit 成功後にのみ成功とみなす。
	// （トランザクション内でレスポンスを組み立てないことで、commit 失敗時に
	//  DB 上存在しない「幽霊トークン」をクライアントへ返す事故を防ぐ）
	if (token) {
		return { type: "success", token };
	}

	// [SECURITY] 消費できなかった（0 行）→ 再利用か期限切れかを最新状態で再分類する。
	// この時点で勝者は commit 済みなので、再利用なら revokeGrant が勝者トークンを巻き込める。
	const latest = await findAuthorizationCodeById(codeRecord.id);
	if (latest?.usedAt) {
		// 正規パラメータによる使用済みコードの再利用 → grant 単位で失効
		await revokeGrant(codeRecord.grantId);
	}

	return { type: "invalid_grant" };
}
