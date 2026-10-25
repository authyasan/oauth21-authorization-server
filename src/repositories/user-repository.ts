import { eq } from "drizzle-orm";
import { db } from "../db/connection.js";
import { users } from "../db/schema.js";

/**
 * ユーザーの型定義。
 */
export interface User {
	id: string;
	username: string;
	passwordHash: string;
	createdAt: Date;
	updatedAt: Date;
}

/**
 * ユーザーリポジトリ。
 * usersテーブルへのデータアクセスを提供する。
 */

/**
 * ユーザー名でユーザーを検索する。
 *
 * @param username 検索するユーザー名
 * @returns ユーザー情報（見つからない場合undefined）
 */
export async function findUserByUsername(username: string): Promise<User | undefined> {
	const result = await db.select().from(users).where(eq(users.username, username)).limit(1);

	if (result.length === 0) {
		return undefined;
	}

	return result[0] as User;
}

/**
 * ユーザーIDでユーザーを検索する。
 *
 * @param id ユーザーID（UUID）
 * @returns ユーザー情報（見つからない場合undefined）
 */
export async function findUserById(id: string): Promise<User | undefined> {
	const result = await db.select().from(users).where(eq(users.id, id)).limit(1);

	if (result.length === 0) {
		return undefined;
	}

	return result[0] as User;
}
