import { eq } from "drizzle-orm";
import { db } from "../db/connection.js";
import { users } from "../db/schema.js";

export interface User {
	id: string;
	username: string;
	passwordHash: string;
	createdAt: Date;
	updatedAt: Date;
}

/**
 * ログイン時のユーザー名検索と、ログイン後の ID によるユーザー取得を提供する。
 */

/**
 * ユーザー名でユーザーを検索する。
 *
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
 * @returns ユーザー情報（見つからない場合undefined）
 */
export async function findUserById(id: string): Promise<User | undefined> {
	const result = await db.select().from(users).where(eq(users.id, id)).limit(1);

	if (result.length === 0) {
		return undefined;
	}

	return result[0] as User;
}
