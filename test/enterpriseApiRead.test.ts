import { describe, expect, it, vi } from "vitest";
import {
  CookieSsoAuthProvider,
  EnterpriseApiReadService,
  KeychainBearerAuthProvider,
  buildRequestUrl,
  extractTokenFromKeychainSecret,
  normalizeBaseUrl,
  parseResponseBody
} from "../src/enterprise-api-read.mjs";

describe("enterprise-api-read", () => {
  it("normalizes base URLs", () => {
    expect(normalizeBaseUrl("https://jira.example.com///")).toBe("https://jira.example.com");
    expect(normalizeBaseUrl("not-a-url")).toBe("");
  });

  it("builds request URLs with query params", () => {
    const url = buildRequestUrl("https://jira.example.com", "/rest/api/2/search", {
      jql: "project = ABC",
      maxResults: 1
    });
    expect(url.pathname).toBe("/rest/api/2/search");
    expect(url.searchParams.get("jql")).toBe("project = ABC");
    expect(url.searchParams.get("maxResults")).toBe("1");
  });

  it("extracts tokens from keychain secrets", () => {
    expect(extractTokenFromKeychainSecret('{"token":"abc"}')).toBe("abc");
    expect(extractTokenFromKeychainSecret("plain-token")).toBe("plain-token");
  });

  it("parses JSON or falls back to text", () => {
    expect(parseResponseBody('{"a":1}')).toEqual({ a: 1 });
    expect(parseResponseBody("plain")).toBe("plain");
  });

  it("performs keychain-backed GET reads", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ issues: [] })
    }));
    const execFileImpl = vi.fn(async () => ({ stdout: "token-123" }));

    const service = new EnterpriseApiReadService({
      serviceName: "Jira",
      defaultBaseUrl: "https://jira.example.com",
      defaultUserAgent: "test-agent",
      keychainService: "jira",
      keychainAccount: "user",
      normalizePath: (path) => path,
      fetchImpl,
      execFileImpl
    });

    const output = JSON.parse(await service.invoke({ restPath: "/rest/api/2/myself" }));
    expect(output.status).toBe(200);
    expect(output.data).toEqual({ issues: [] });
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("performs cookie-sso GET reads via CookieSsoAuthProvider", async () => {
    const fetchImpl = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true })
    }));

    const service = new EnterpriseApiReadService({
      serviceName: "Jira",
      defaultBaseUrl: "https://jira.example.com",
      defaultUserAgent: "test-agent",
      normalizePath: (path) => path,
      fetchImpl,
      authProvider: new CookieSsoAuthProvider({
        resolveCookieHeader: async () => "session=abc"
      })
    });

    const output = JSON.parse(await service.invoke({ restPath: "/rest/api/2/myself" }));
    expect(output.status).toBe(200);
    const [, requestInit] = fetchImpl.mock.calls[0];
    expect(requestInit.headers.cookie).toBe("session=abc");
    expect(requestInit.headers.authorization).toBeUndefined();
  });
});
