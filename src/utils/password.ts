import bcrypt from "bcryptjs";
import { generateRandomString } from "./crypto.js";

/**
 * [SECURITY] 人が決めるパスワードへの総当たりを遅くするため、bcryptを使う。
 */

/**
 * パスワード保存とダミーハッシュで同じ計算コストを使う。
 */
const COST_FACTOR = 10;

/**
 * パスワードをbcryptでハッシュ化する。
 * ソルト（ランダムな値）は自動的に生成され、ハッシュに含まれる。
 *
 * @param password 平文パスワード
 * @returns bcryptハッシュ文字列（ソルト込み）
 */
export async function hashPassword(password: string): Promise<string> {
	return bcrypt.hash(password, COST_FACTOR);
}

/**
 * 平文パスワードとbcryptハッシュを比較する。
 *
 * [SECURITY] 保存済みハッシュとの照合はbcrypt.compareに委ねる。
 *
 * @param password 検証する平文パスワード
 * @param hash 保存されたbcryptハッシュ
 * @returns 一致する場合true
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
	return bcrypt.compare(password, hash);
}

/**
 * ユーザーが存在しないときに比較する、ダミーのbcryptハッシュ。
 *
 * [SECURITY] 実在ユーザーのハッシュと同じ形式・同じコストでなければならない。
 * 形式（60文字）を満たさない値をbcrypt.compareに渡すと、ハッシュ計算に進まずに
 * すぐfalseが返り、ユーザーの有無による時間差が残る。
 * 起動時に1度だけ、推測できない乱数から作る。
 */
export const DUMMY_PASSWORD_HASH = bcrypt.hashSync(generateRandomString(), COST_FACTOR);

/**
 * 存在しないユーザーのために、ダミーハッシュとの比較で時間を消費する。
 * 比較結果は使わない。
 *
 * @param password 送信された平文パスワード
 */
export async function verifyDummyPassword(password: string): Promise<void> {
	await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
}
