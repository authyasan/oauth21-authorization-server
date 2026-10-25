import { exportJWK, jwtVerify, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { getJwks, getKid, getPrivateKey, getPublicKey } from "../../../src/config/keys.js";

describe("鍵の読み込み", () => {
	it("検証用の公開鍵は、リソースサーバーに公開するJWKSの先頭の鍵と同じ", async () => {
		const published = getJwks().keys[0];
		const used = await exportJWK(await getPublicKey());
		expect({ n: used.n, e: used.e }).toEqual({ n: published.n, e: published.e });
	});

	it("秘密鍵で署名したJWTを、JWKSから作った公開鍵で検証できる", async () => {
		const token = await new SignJWT({})
			.setProtectedHeader({ alg: "RS256", kid: getKid(), typ: "at+jwt" })
			.sign(await getPrivateKey());
		await expect(jwtVerify(token, await getPublicKey())).resolves.toBeDefined();
	});
});
