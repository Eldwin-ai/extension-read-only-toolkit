import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { assertNonHtmlApiResponse } from "./devops-diagnostics.mjs";

const execFileAsync = promisify(execFile);

export function normalizeBaseUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const url = new URL(raw);
    url.pathname = url.pathname.replace(/\/+$/, "");
    url.search = "";
    url.hash = "";
    return url.toString().replace(/\/+$/, "");
  } catch {
    return "";
  }
}

export function appendQueryValue(searchParams, key, value) {
  if (Array.isArray(value)) {
    for (const item of value) appendQueryValue(searchParams, key, item);
    return;
  }
  if (value === undefined || value === null) return;
  searchParams.append(key, String(value));
}

export function buildRequestUrl(baseUrl, requestPath, query) {
  const url = new URL(`${baseUrl}${requestPath}`);
  for (const [key, value] of Object.entries(query || {})) {
    if (key) appendQueryValue(url.searchParams, key, value);
  }
  return url;
}

export function extractTokenFromKeychainSecret(rawSecret = "") {
  const text = typeof rawSecret === "string" ? rawSecret.trim() : "";
  if (!text) return "";
  try {
    const parsed = JSON.parse(text);
    return typeof parsed?.token === "string" ? parsed.token.trim() : "";
  } catch {
    return text;
  }
}

export async function readTokenFromKeychain({ execFileImpl = execFileAsync, keychainService, keychainAccount }) {
  try {
    const result = await execFileImpl("/usr/bin/security", [
      "find-generic-password",
      "-s",
      keychainService,
      "-a",
      keychainAccount,
      "-w"
    ], { maxBuffer: 1024 * 1024 });
    return extractTokenFromKeychainSecret(String(result?.stdout || ""));
  } catch {
    return "";
  }
}

export function parseResponseBody(text) {
  try {
    return JSON.parse(text);
  } catch {
    return String(text || "");
  }
}

export class KeychainBearerAuthProvider {
  constructor(options = {}) {
    this.mode = "keychain";
    this.execFileImpl = options.execFileImpl || execFileAsync;
    this.keychainService = options.keychainService;
    this.keychainAccount = options.keychainAccount;
    this.authorizationHeader = options.authorizationHeader || ((token) => `Bearer ${token}`);
  }

  async buildHeaders() {
    const token = await readTokenFromKeychain({
      execFileImpl: this.execFileImpl,
      keychainService: this.keychainService,
      keychainAccount: this.keychainAccount
    });
    if (!token) {
      throw new Error(
        `Keychain token missing for ${this.keychainService}/${this.keychainAccount}. Save the personal access token in Keychain.`
      );
    }
    return { authorization: this.authorizationHeader(token) };
  }
}

/** Cookie SSO auth — inject `resolveCookieHeader(input)` from @eldwin-ai/extension-browser-sso. */
export class CookieSsoAuthProvider {
  constructor(options = {}) {
    this.mode = "cookie-sso";
    this.resolveCookieHeader = options.resolveCookieHeader;
    if (typeof this.resolveCookieHeader !== "function") {
      throw new Error("CookieSsoAuthProvider requires resolveCookieHeader(input) async function.");
    }
  }

  async buildHeaders(input = {}) {
    const cookie = await this.resolveCookieHeader(input);
    if (!cookie) {
      throw new Error("Browser SSO cookie header is missing. Open the service in Chrome via Okta and retry.");
    }
    return { cookie };
  }
}

export class EnterpriseApiReadService {
  constructor(options = {}) {
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    this.execFileImpl = options.execFileImpl || execFileAsync;
    this.serviceName = options.serviceName;
    this.defaultBaseUrl = options.defaultBaseUrl;
    this.defaultUserAgent = options.defaultUserAgent;
    this.keychainService = options.keychainService;
    this.keychainAccount = options.keychainAccount;
    this.normalizePath = options.normalizePath;
    this.accept = options.accept || "application/json";
    this.extraHeaders = options.extraHeaders || {};
    this.authorizationHeader = options.authorizationHeader || ((token) => `Bearer ${token}`);
    this.formatErrorPayload = options.formatErrorPayload;
    this.includeMethodInPayload = options.includeMethodInPayload === true;
    this.transformPayload = options.transformPayload || ((payload) => payload);
    this.authProvider =
      options.authProvider ??
      new KeychainBearerAuthProvider({
        execFileImpl: this.execFileImpl,
        keychainService: this.keychainService,
        keychainAccount: this.keychainAccount,
        authorizationHeader: this.authorizationHeader
      });
  }

  async invoke(input = {}) {
    if (typeof this.fetchImpl !== "function") {
      throw new Error(`Fetch API is unavailable for ${this.serviceName} requests.`);
    }
    const baseUrl = normalizeBaseUrl(input.baseUrl || this.defaultBaseUrl);
    if (!baseUrl) {
      throw new Error(`${this.serviceName} base URL is missing or invalid. Expected something like ${this.defaultBaseUrl}.`);
    }
    const requestPath = this.normalizePath(input.restPath || input.path);
    const url = buildRequestUrl(baseUrl, requestPath, input.query);
    const authHeaders = await this.authProvider.buildHeaders(input);
    const response = await this.fetchImpl(url, {
      method: "GET",
      headers: {
        accept: this.accept,
        "user-agent": this.defaultUserAgent,
        ...this.extraHeaders,
        ...authHeaders,
        ...(input.headers ?? {})
      }
    });
    const text = await response.text();
    assertNonHtmlApiResponse(this.serviceName, text);
    const payload = parseResponseBody(text);
    if (!response.ok) {
      throw new Error(`${this.serviceName} request failed with status ${response.status}: ${this.formatErrorPayload(payload)}.`);
    }
    const output = {
      baseUrl,
      restPath: requestPath,
      path: requestPath,
      url: url.toString(),
      status: response.status,
      data: this.transformPayload(payload)
    };
    if (this.includeMethodInPayload) output.method = "GET";
    return JSON.stringify(output, null, 2);
  }
}
