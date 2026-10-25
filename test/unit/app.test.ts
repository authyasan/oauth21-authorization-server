import { describe, expect, it } from "vitest";
import app from "../../src/app.js";

describe("GET /health", () => {
	it("200とstatus: okを返す", async () => {
		const res = await app.request("/health");
		expect(res.status).toBe(200);

		const body = await res.json();
		expect(body).toEqual({ status: "ok" });
	});
});
