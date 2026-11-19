/**
 * 発行者識別子（issuer）の設定値を確かめる。
 *
 * [SECURITY] RFC 8414 §2: issuer は https スキームで、クエリもフラグメントも持たないURL。
 * この値はJWTの iss、認可レスポンスの iss（RFC 9207）、メタデータのURLの組み立てに使うので、
 * 誤った値は起動時に拒否する。末尾の「/」も拒否する（メタデータが //authorize になるため）。
 * ローカルのHTTP開発環境だけは http を許可し、本番（NODE_ENV=production）では https を要求する。
 *
 * @param value 設定された issuer
 * @param production 本番環境かどうか
 * @returns 検証済みの issuer（入力をそのまま返す）
 */
export function validateIssuer(value: string, production: boolean): string {
	// [SECURITY] URL解析は前後の空白や途中のタブ・改行を取り除いてから解析するので、
	// 解析の成否だけでは元の文字列に残る空白・制御文字を検出できない。
	// issuer は元の文字列のまま使うため、黙って正規化せず、解析の前に拒否する。
	const hasSpaceOrControl = [...value].some((ch) => {
		const code = ch.charCodeAt(0);
		return /\s/.test(ch) || code < 0x20 || code === 0x7f;
	});
	if (hasSpaceOrControl) {
		throw new Error(`ISSUERに空白や制御文字を含めることはできません: ${JSON.stringify(value)}`);
	}
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		throw new Error(`ISSUERをURLとして解析できません: ${value}`);
	}
	if (url.protocol !== "https:" && (production || url.protocol !== "http:")) {
		throw new Error(`ISSUERはhttpsでなければなりません: ${value}`);
	}
	if (value.includes("?") || value.includes("#")) {
		throw new Error(`ISSUERにクエリやフラグメントを含めることはできません: ${value}`);
	}
	if (value.endsWith("/")) {
		throw new Error(`ISSUERの末尾に「/」を付けることはできません: ${value}`);
	}
	return value;
}

export const serverConfig = {
	// 認可サーバーのissuer URL (JWTのissクレーム)
	issuer: validateIssuer(
		process.env.ISSUER || "http://localhost:3000",
		process.env.NODE_ENV === "production",
	),

	port: Number(process.env.PORT) || 3000,
	host: process.env.HOST || "localhost",

	// アクセストークン有効期限（秒）
	// クライアント種別・スコープによらず一律30分。
	// JWTだけで検証するアクセスでは、無効化後も最大30分残ることを許容する選択。
	accessToken: {
		ttl: 30 * 60, // 30分
	},

	// リフレッシュトークン有効期限（秒）
	// 無操作30日＋絶対上限180日の2パラメータ。
	// 無操作期限は更新のたびに引き直され、絶対上限は grant の誕生から数える。
	refreshToken: {
		idleTtl: 30 * 24 * 60 * 60, // 30日
		absoluteTtl: 180 * 24 * 60 * 60, // 180日
	},

	// ローテーションの猶予窓（秒）。
	// 塞ぐのは並行リクエストではなく応答の喪失。HTTP クライアントのタイムアウト
	// 1回分と再送を収める必要があるため、数秒では足りない。
	rotationGraceSeconds: 60,
} as const;
