import { beforeEach, describe, expect, it, vi } from "vitest";
import { findConsent } from "../../../src/repositories/consent-repository.js";
import { canSkipConsent } from "../../../src/services/consent-service.js";

vi.mock("../../../src/repositories/consent-repository.js", () => ({
	findConsent: vi.fn(),
	saveConsent: vi.fn(),
}));

beforeEach(() => {
	vi.resetAllMocks();
	vi.mocked(findConsent).mockResolvedValue({ scope: "read write" });
});

describe("canSkipConsent", () => {
	it.each([
		"http://127.0.0.1:54321/callback",
		"http://[::1]:54321/callback",
		"com.example.app:/callback",
		"com.example.app://callback",
		"http://client.example/callback",
		"https://127.0.0.1:54321/callback",
		"https://127.0.0.2/callback",
		"https://127.1/callback",
		"https://2130706433/callback",
		"https://[::1]/callback",
		"https://[::ffff:127.0.0.1]/callback",
		"https://localhost/callback",
		"https://LOCALHOST./callback",
		"https://app.localhost/callback",
	])("同意済みでも省略対象外: %s", async (uri) => {
		expect(await canSkipConsent("user", "client", "read", uri)).toBe(false);
		expect(findConsent).not.toHaveBeenCalled();
	});

	it.each([
		"https://client.example/callback",
		"https://client.example:8443/callback?service=one",
		"https://192.0.2.1/callback",
		"https://[2001:db8::1]/callback",
	])("非ループバックHTTPSで同意済みなら省略: %s", async (uri) => {
		expect(await canSkipConsent("user", "client", "read", uri)).toBe(true);
		expect(findConsent).toHaveBeenCalledWith("user", "client");
	});

	it.each([
		["read write", true],
		["write read", true],
		["read", true],
		["read profile", false],
	])("HTTPSでもスコープの包含関係を確認する: %s", async (scope, expected) => {
		expect(await canSkipConsent("user", "client", scope, "https://client.example/callback")).toBe(
			expected,
		);
	});

	it("HTTPSでも同意の記録がなければ表示する", async () => {
		vi.mocked(findConsent).mockResolvedValue(undefined);
		expect(await canSkipConsent("user", "client", "read", "https://client.example/callback")).toBe(
			false,
		);
	});
});
