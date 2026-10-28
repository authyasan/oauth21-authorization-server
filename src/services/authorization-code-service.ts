import { db } from "../db/connection.js";
import { saveAuthorizationCode } from "../repositories/authorization-code-repository.js";
import { createGrant } from "../repositories/grant-repository.js";
import { generateRandomString, sha256 } from "../utils/crypto.js";

/**
 * 認可コードサービス。
 * 認可コードの生成とDB保存を行う。
 *
 * 認可コードは32バイト（256ビット）のCSPRNG出力。
 * 有効期限は5分。
 *
 * [SECURITY] 認可コードの生成フロー:
 * 1. 32バイトのランダム文字列を生成（平文コード）
 * 2. SHA-256ハッシュを計算してDBに保存
 * 3. 平文コードをクライアントにリダイレクトで返す
 * 4. トークンエンドポイントで受け取った平文コードをハッシュしてDB照合
 *
 * 平文コードはDBに保存しない。これにより、DB漏洩時に認可コードが
 * 直接漏れることを防ぐ。
 */

/** 認可コードの有効期限（5分） */
const AUTHORIZATION_CODE_LIFETIME_MS = 5 * 60 * 1000;

/** 認可コードのバイト長（32バイト = 256ビット） */
const AUTHORIZATION_CODE_BYTES = 32;

/**
 * 認可コードを生成し、DBに保存する。
 *
 * 認可フロー完了（同意成立）時に grant 行を作成し、
 * 認可コードをその grant に紐づける。grant 作成と認可コード保存は
 * 同一トランザクションで実行し、片方だけが残る中途半端な状態を防ぐ。
 *
 * @param params 認可コードに紐づくパラメータ
 * @returns 平文の認可コード（クライアントに返す値）
 */
export async function issueAuthorizationCode(params: {
	clientId: string;
	userId: string;
	redirectUri: string;
	scope: string;
	codeChallenge: string;
	codeChallengeMethod: string;
}): Promise<string> {
	// [SECURITY] 32バイトのCSPRNG出力で認可コードを生成
	const code = generateRandomString(AUTHORIZATION_CODE_BYTES);

	// [SECURITY] SHA-256ハッシュをDBに保存（平文は保存しない）
	const codeHash = sha256(code);

	// 有効期限はアプリの時計で計算して書く。期限の判定は消費時に DB の時計で行う
	// （consumeAuthorizationCodeIfFresh）。単一ホスト構成では両者のずれは無視できる。
	const expiresAt = new Date(Date.now() + AUTHORIZATION_CODE_LIFETIME_MS);

	// grant 作成 → 認可コード保存を1トランザクションで行う
	await db.transaction(async (tx) => {
		const grantId = await createGrant(
			{
				clientId: params.clientId,
				userId: params.userId,
				scope: params.scope,
			},
			tx,
		);

		await saveAuthorizationCode(
			codeHash,
			{
				grantId,
				...params,
				expiresAt,
			},
			tx,
		);
	});

	// 平文コードをクライアントに返す
	return code;
}
