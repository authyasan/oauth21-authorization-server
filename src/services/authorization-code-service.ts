import { db } from "../db/connection.js";
import { saveAuthorizationCode } from "../repositories/authorization-code-repository.js";
import { createGrant } from "../repositories/grant-repository.js";
import { generateRandomString, sha256 } from "../utils/crypto.js";

/**
 * 認可コードを生成し、grantとともにDBへ保存する。
 *
 * [SECURITY] DB漏洩時に認可コードが直接漏れないよう、ハッシュだけを保存する。
 * 平文コードはクライアントへのレスポンス用に呼び出し元へ返す。
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
	// [SECURITY] 認可コードを推測されないよう、CSPRNGで生成する。
	const code = generateRandomString(AUTHORIZATION_CODE_BYTES);

	// [SECURITY] SHA-256ハッシュをDBに保存（平文は保存しない）
	const codeHash = sha256(code);

	// 有効期限はアプリの時計で計算して書く。期限の判定は消費時に DB の時計で行う
	// （consumeAuthorizationCodeIfFresh）。単一ホスト構成では両者のずれは無視できる。
	const expiresAt = new Date(Date.now() + AUTHORIZATION_CODE_LIFETIME_MS);

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

	return code;
}
