/**
 * `POST /mcp/tools` (issue #145) — native MCP JSON-RPC endpoint.
 *
 * 既存の `mcp-relay-bridge.ts` (mcp.ippoan.org/mcp) は WS-attached binary
 * (`github-mcp-server-rs`) に JSON-RPC を転送する設計だが、issue #145 は
 * **auth-worker 自身が GitHub API proxy を tool として公開** することで
 * binary 不要・ローカル CLI 不要 の MCP server を実現する。
 *
 * Auth: `Authorization: Bearer <MCP_JWT>` (mode 1 introspect と同じ verify)。
 *   - `aud=github-mcp-server-rs` (device/pair flow JWT) も
 *   - `aud=<mcp relay origin>` (Authorization Code + Resource Indicator) も accept
 *
 * Supported JSON-RPC methods (subset of MCP spec 2025-06-18):
 *   - `initialize`     → server capabilities
 *   - `tools/list`     → list of supported GitHub proxy tools
 *   - `tools/call`     → execute tool (proxy to api.github.com)
 *   - `ping`           → no-op (keepalive)
 *
 * Errors follow JSON-RPC 2.0 §5.1:
 *   - parse error  → -32700
 *   - invalid req  → -32600
 *   - method NF    → -32601
 *   - invalid prm  → -32602
 *   - internal err → -32603
 *   - tool 固有: -32000..-32099 (server-defined)
 *
 * Scope minimisation (issue #145 task #9):
 *   - `mcp.read`  → `github_get_*`, `github_list_*` のみ
 *   - `mcp.write` → 加えて `github_create_*` も
 */

import type { Env } from "../index";
import { issueDevLoginCode, mintDevToken } from "../lib/dev-login";
import { decryptWithKey } from "../lib/mcp-crypto";
import { resolveMcpJwtSecret, verifyMcpJwt, type McpJwtPayload } from "../lib/mcp-jwt";
import {
  MCP_GOOGLE_SURFACE_PATH,
  mcpRelayOrigin,
  wwwAuthenticateValue,
} from "../lib/mcp-origins";
import { resolveSecret } from "../lib/secret";
import {
  isAllowedVerifyTarget,
  runVerifyEval,
  runVerifyShots,
  VERIFY_EVAL_EXPR_MAX,
  VERIFY_SHOT_MAX_URLS,
  VerifyShotError,
  type VerifyEngine,
} from "../lib/verify-shot";

const MCP_AUD_LEGACY = "github-mcp-server-rs";
const MCP_PROTOCOL_VERSION = "2025-06-18";
const MCP_SERVER_NAME = "auth-worker-github-bridge";
const GITHUB_API = "https://api.github.com";
const GITHUB_UA = "auth-worker-mcp-tools";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: unknown;
}

interface JsonRpcSuccess {
  jsonrpc: "2.0";
  id: string | number | null;
  result: unknown;
}

interface JsonRpcError {
  jsonrpc: "2.0";
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
}

type JsonRpcResponse = JsonRpcSuccess | JsonRpcError;

/** `tool.call` に渡す実行 context。 */
interface ToolCallCtx {
  env: Env;
  payload: McpJwtPayload;
  /** `requiresGithubToken: true` のツールにのみ意味を持つ値 (解決済み)。
   *  `false` のツールでは空文字 (未使用)。 */
  ghToken: string;
}

interface ToolDef {
  name: string;
  description: string;
  /** JSON Schema for `inputSchema` (MCP spec §tools). */
  inputSchema: Record<string, unknown>;
  /** Minimum MCP scope required to call this tool. */
  requiredScope: "mcp.read" | "mcp.write";
  /** true なら呼び出し前に github_token (KV `github_token:<sub>`) の解決を必須にする
   *  (無ければ JSON-RPC error)。dev-login 系ツールは GitHub token を使わないので false。 */
  requiresGithubToken: boolean;
  /** Implementation. `args` is the validated `params.arguments` blob. */
  call: (args: Record<string, unknown>, ctx: ToolCallCtx) => Promise<unknown>;
}

/** dev-login tool (`issue_dev_token` / `issue_dev_login_url`) 用のエラー。
 *  GhError と同様、`dispatchToolsCall` の catch で `isError:true` content に変換する。 */
class DevLoginError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "DevLoginError";
  }
}

function rpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcError {
  const err: JsonRpcError = {
    jsonrpc: "2.0",
    id,
    error: { code, message },
  };
  if (data !== undefined) err.error.data = data;
  return err;
}

function rpcOk(id: string | number | null, result: unknown): JsonRpcSuccess {
  return { jsonrpc: "2.0", id, result };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function unauthorized(
  env: Env,
  body: unknown,
  surface: "default" | "google" = "default",
): Response {
  return new Response(JSON.stringify(body), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": wwwAuthenticateValue(env, surface),
      "Cache-Control": "no-store",
    },
  });
}

/** Strict typing for `tools/call.params`. */
interface ToolCallParams {
  name?: unknown;
  arguments?: unknown;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v ? v : null;
}

function scopeIncludes(scope: string, required: "mcp.read" | "mcp.write"): boolean {
  const tokens = scope.split(/\s+/).filter(Boolean);
  if (required === "mcp.read") return tokens.includes("mcp.read") || tokens.includes("mcp.write");
  return tokens.includes("mcp.write");
}

/**
 * Proxy a JSON-returning GET to api.github.com. The caller passes the
 * already-validated path (`/repos/<owner>/<repo>` etc.) and decrypted
 * `ghToken`. Returns the parsed JSON or throws an Error with a message
 * suitable for JSON-RPC `error.message`.
 */
async function ghGet(path: string, ghToken: string): Promise<unknown> {
  const resp = await fetch(`${GITHUB_API}${path}`, {
    headers: {
      Authorization: `Bearer ${ghToken}`,
      "User-Agent": GITHUB_UA,
      Accept: "application/vnd.github+json",
    },
  });
  return await readGhJson(resp);
}

async function ghPost(
  path: string,
  body: unknown,
  ghToken: string,
): Promise<unknown> {
  const resp = await fetch(`${GITHUB_API}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${ghToken}`,
      "User-Agent": GITHUB_UA,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return await readGhJson(resp);
}

async function readGhJson(resp: Response): Promise<unknown> {
  const text = await resp.text();
  let parsed: unknown = null;
  if (text) {
    try { parsed = JSON.parse(text); } catch { parsed = text; }
  }
  if (!resp.ok) {
    const msg = isObject(parsed) && typeof parsed["message"] === "string"
      ? parsed["message"]
      : `GitHub API ${resp.status}`;
    throw new GhError(resp.status, msg);
  }
  return parsed;
}

class GhError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "GhError";
  }
}

const TOOLS: ToolDef[] = [
  {
    name: "github_get_authenticated_user",
    description: "Get the GitHub profile of the authenticated user (login, name, email-if-public). Useful as a smoke test.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    requiredScope: "mcp.read",
    requiresGithubToken: true,
    call: async (_args, ctx) => ghGet("/user", ctx.ghToken),
  },
  {
    name: "github_get_repo",
    description: "Get metadata for a single repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Repository owner (user or org)" },
        repo: { type: "string", description: "Repository name" },
      },
      required: ["owner", "repo"],
      additionalProperties: false,
    },
    requiredScope: "mcp.read",
    requiresGithubToken: true,
    call: async (args, ctx) => {
      const owner = asString(args["owner"]);
      const repo = asString(args["repo"]);
      if (!owner || !repo) throw new GhError(400, "owner and repo are required");
      return ghGet(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, ctx.ghToken);
    },
  },
  {
    name: "github_list_issues",
    description: "List issues in a repository (open by default).",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        state: { type: "string", enum: ["open", "closed", "all"], default: "open" },
        per_page: { type: "integer", minimum: 1, maximum: 100, default: 30 },
      },
      required: ["owner", "repo"],
      additionalProperties: false,
    },
    requiredScope: "mcp.read",
    requiresGithubToken: true,
    call: async (args, ctx) => {
      const owner = asString(args["owner"]);
      const repo = asString(args["repo"]);
      if (!owner || !repo) throw new GhError(400, "owner and repo are required");
      const state = asString(args["state"]) ?? "open";
      const perPageRaw = args["per_page"];
      const perPage = typeof perPageRaw === "number" && Number.isInteger(perPageRaw)
        ? Math.min(100, Math.max(1, perPageRaw))
        : 30;
      const qs = `?state=${encodeURIComponent(state)}&per_page=${perPage}`;
      return ghGet(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues${qs}`, ctx.ghToken);
    },
  },
  {
    name: "github_list_pull_requests",
    description: "List pull requests in a repository.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        state: { type: "string", enum: ["open", "closed", "all"], default: "open" },
        per_page: { type: "integer", minimum: 1, maximum: 100, default: 30 },
      },
      required: ["owner", "repo"],
      additionalProperties: false,
    },
    requiredScope: "mcp.read",
    requiresGithubToken: true,
    call: async (args, ctx) => {
      const owner = asString(args["owner"]);
      const repo = asString(args["repo"]);
      if (!owner || !repo) throw new GhError(400, "owner and repo are required");
      const state = asString(args["state"]) ?? "open";
      const perPageRaw = args["per_page"];
      const perPage = typeof perPageRaw === "number" && Number.isInteger(perPageRaw)
        ? Math.min(100, Math.max(1, perPageRaw))
        : 30;
      const qs = `?state=${encodeURIComponent(state)}&per_page=${perPage}`;
      return ghGet(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls${qs}`, ctx.ghToken);
    },
  },
  {
    name: "github_create_issue",
    description: "Create an issue in a repository. Requires mcp.write scope.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string" },
        repo: { type: "string" },
        title: { type: "string" },
        body: { type: "string" },
      },
      required: ["owner", "repo", "title"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: true,
    call: async (args, ctx) => {
      const owner = asString(args["owner"]);
      const repo = asString(args["repo"]);
      const title = asString(args["title"]);
      if (!owner || !repo || !title) {
        throw new GhError(400, "owner, repo, and title are required");
      }
      const body = typeof args["body"] === "string" ? args["body"] : undefined;
      return ghPost(
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`,
        body !== undefined ? { title, body } : { title },
        ctx.ghToken,
      );
    },
  },
  {
    name: "issue_dev_token",
    description:
      "Issue a short-lived (30 min, no refresh) dev session JWT for localhost " +
      "browser/curl verification (issue #423/#424). Only works for pre-approved " +
      "subjects (DEV_LOGIN_ALLOWED_SUBJECTS).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (_args, ctx) => {
      const result = await mintDevToken(ctx.env, ctx.payload);
      if (result.kind === "error") throw new DevLoginError(result.status, result.error);
      return {
        access_token: result.token,
        token_type: "Bearer",
        expires_in: result.expires_in,
      };
    },
  },
  {
    name: "issue_dev_login_url",
    description:
      "Issue a one-time http://localhost:<port>/__dev/callback?code=... URL " +
      "(60s TTL, single use) for browser-based dev-login verification (issue #423/#424).",
    inputSchema: {
      type: "object",
      properties: {
        port: { type: "integer", minimum: 1024, maximum: 65535 },
      },
      required: ["port"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const portRaw = args["port"];
      if (
        typeof portRaw !== "number" ||
        !Number.isInteger(portRaw) ||
        portRaw < 1024 ||
        portRaw > 65535
      ) {
        throw new DevLoginError(400, "port must be an integer in [1024, 65535]");
      }
      const result = await mintDevToken(ctx.env, ctx.payload);
      if (result.kind === "error") throw new DevLoginError(result.status, result.error);
      const code = await issueDevLoginCode(ctx.env, result.token);
      return { url: `http://localhost:${portRaw}/__dev/callback?code=${code}` };
    },
  },
  {
    name: "verify_screenshot",
    description:
      "Screenshot up to 5 https://*.ippoan.org pages as a logged-in dev session " +
      "(mints a dev JWT internally and injects the logi_auth_token cookie; CF " +
      "Access passes silently via the auth-worker OIDC IdP). Returns short-lived " +
      "(5 min) PNG URLs — fetch with `curl -o shot.png <shot_url>`. Intended for " +
      "post-merge production verification. Same allowlist gate as issue_dev_token.",
    inputSchema: {
      type: "object",
      properties: {
        urls: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: VERIFY_SHOT_MAX_URLS,
          description: "https://*.ippoan.org page URLs to screenshot (in order)",
        },
        engine: {
          type: "string",
          enum: ["chromium", "kitesurf"],
          description:
            "Browser Run engine. Default chromium (full browser). kitesurf is " +
            "Cloudflare's lighter agent browser (beta).",
        },
      },
      required: ["urls"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const rawUrls = args["urls"];
      if (
        !Array.isArray(rawUrls) ||
        rawUrls.length === 0 ||
        rawUrls.length > VERIFY_SHOT_MAX_URLS ||
        !rawUrls.every((u): u is string => typeof u === "string")
      ) {
        throw new VerifyShotError(
          400,
          `urls must be a string array (1..${VERIFY_SHOT_MAX_URLS})`,
        );
      }
      const bad = rawUrls.find((u) => !isAllowedVerifyTarget(u));
      if (bad !== undefined) {
        throw new VerifyShotError(400, `url not allowed (https://*.ippoan.org only): ${bad}`);
      }
      const engineRaw = args["engine"];
      if (engineRaw !== undefined && engineRaw !== "chromium" && engineRaw !== "kitesurf") {
        throw new VerifyShotError(400, "engine must be 'chromium' or 'kitesurf'");
      }
      const engine: VerifyEngine = engineRaw === "kitesurf" ? "kitesurf" : "chromium";
      // ブラウザ未 bind は dev JWT を mint する前に落とす (無駄な upsert を避ける)。
      if (!ctx.env.BROWSER) {
        throw new VerifyShotError(503, "browser_binding_not_configured");
      }
      const minted = await mintDevToken(ctx.env, ctx.payload);
      if (minted.kind === "error") throw new DevLoginError(minted.status, minted.error);
      return await runVerifyShots(ctx.env, {
        urls: rawUrls,
        engine,
        cookieValue: minted.token,
      });
    },
  },
  {
    name: "verify_eval",
    description:
      "Open one https://*.ippoan.org page as a logged-in dev session (same auth " +
      "path as verify_screenshot) and evaluate a JavaScript expression in the " +
      "page, returning its JSON-serialized value (e.g. document.body.innerText, " +
      "a querySelector probe, or an in-page fetch). Stateless: each call opens a " +
      "fresh browser — 'navigate' is the url argument. Set screenshot:true to " +
      "also get a short-lived PNG of the page AFTER evaluation (captures click " +
      "side-effects). Same allowlist gate as issue_dev_token.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "https://*.ippoan.org page URL to open" },
        expression: {
          type: "string",
          maxLength: VERIFY_EVAL_EXPR_MAX,
          description:
            "JavaScript expression evaluated in the page (async supported via " +
            "IIFE; the resolved value is returned)",
        },
        engine: { type: "string", enum: ["chromium", "kitesurf"] },
        screenshot: {
          type: "boolean",
          description: "also return shot_url of the post-evaluation viewport",
        },
      },
      required: ["url", "expression"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const url = asString(args["url"]);
      if (!url || !isAllowedVerifyTarget(url)) {
        throw new VerifyShotError(400, `url not allowed (https://*.ippoan.org only): ${url ?? ""}`);
      }
      const expression = asString(args["expression"]);
      if (!expression || expression.length > VERIFY_EVAL_EXPR_MAX) {
        throw new VerifyShotError(
          400,
          `expression must be a non-empty string (max ${VERIFY_EVAL_EXPR_MAX} chars)`,
        );
      }
      const engineRaw = args["engine"];
      if (engineRaw !== undefined && engineRaw !== "chromium" && engineRaw !== "kitesurf") {
        throw new VerifyShotError(400, "engine must be 'chromium' or 'kitesurf'");
      }
      const screenshotRaw = args["screenshot"];
      if (screenshotRaw !== undefined && typeof screenshotRaw !== "boolean") {
        throw new VerifyShotError(400, "screenshot must be a boolean");
      }
      if (!ctx.env.BROWSER) {
        throw new VerifyShotError(503, "browser_binding_not_configured");
      }
      const minted = await mintDevToken(ctx.env, ctx.payload);
      if (minted.kind === "error") throw new DevLoginError(minted.status, minted.error);
      return await runVerifyEval(ctx.env, {
        url,
        expression,
        engine: engineRaw === "kitesurf" ? "kitesurf" : "chromium",
        cookieValue: minted.token,
        screenshot: screenshotRaw === true,
      });
    },
  },
];

const TOOL_BY_NAME: Record<string, ToolDef> = Object.fromEntries(
  TOOLS.map((t) => [t.name, t]),
);

/**
 * Authenticate the request: verify Bearer JWT only.
 * Returns `{kind:"ok"}` with the payload, or `{kind:"error"}` carrying an
 * HTTP `Response` to return immediately.
 *
 * github_token 解決 (dev-login 系ツールには不要) は `resolveGithubToken` に
 * 分離し、`dispatchToolsCall` が `tool.requiresGithubToken` の時だけ呼ぶ。
 */
type AuthGate =
  | { kind: "ok"; payload: McpJwtPayload }
  | { kind: "error"; response: Response };

async function authenticate(request: Request, env: Env): Promise<AuthGate> {
  // issue #438: Google IdP surface (`POST /mcp/google`) 経由の 401 は surface 専用
  // PRM に誘導する (discovery chain が Google 既定の authorize に繋がる)。
  const surface: "default" | "google" =
    new URL(request.url).pathname === MCP_GOOGLE_SURFACE_PATH ? "google" : "default";
  const jwtSecret = await resolveMcpJwtSecret(env.MCP_JWT_SECRET);
  if (!env.MCP_OAUTH_KV || !jwtSecret) {
    return {
      kind: "error",
      response: jsonResponse(
        { error: "server_error", error_description: "MCP OAuth Provider not configured" },
        503,
      ),
    };
  }
  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return {
      kind: "error",
      response: unauthorized(env, { error: "unauthorized", error_description: "Bearer token required" }, surface),
    };
  }
  const relayOrigin = mcpRelayOrigin(env);
  // issue #438: Google IdP surface の PRM は resource `<auth origin>/mcp/google` を
  // advertise するため、client がそれを RFC 8707 で echo すると aud は auth origin
  // 配下の URL で焼かれる。relay origin と並んで auth origin も受理する
  // (native tools は auth-worker 自身 = 同一 RS なので audience 逸脱ではない)。
  const authOrigin = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const payload = await verifyMcpJwt(m[1], jwtSecret, (aud) => {
    if (aud === MCP_AUD_LEGACY) return true;
    try {
      const origin = new URL(aud).origin;
      return origin === relayOrigin || origin === authOrigin;
    } catch { return false; }
  });
  if (!payload) {
    return {
      kind: "error",
      response: unauthorized(env, { error: "invalid_token", error_description: "JWT verification failed" }, surface),
    };
  }
  return { kind: "ok", payload };
}

type GithubTokenResolution =
  | { kind: "ok"; token: string }
  | { kind: "error"; code: number; message: string };

/**
 * `requiresGithubToken: true` なツール呼び出し専用の github_token 解決。
 * 旧 `authenticate()` が全メソッドに強制していたものを tool-call 単位に局所化
 * したもの (dev-login 系ツールは github_token を持たない Google IdP セッション
 * からも呼べる必要があるため)。
 */
async function resolveGithubToken(env: Env, sub: string): Promise<GithubTokenResolution> {
  const ssoKey = await resolveSecret(env.SSO_ENCRYPTION_KEY);
  if (!ssoKey) {
    return { kind: "error", code: -32603, message: "SSO_ENCRYPTION_KEY not configured" };
  }
  const encrypted = await env.MCP_OAUTH_KV!.get(`github_token:${sub}`);
  if (!encrypted) {
    return {
      kind: "error",
      code: -32001,
      message: "no_github_token: re-authorize via the MCP OAuth flow to refresh the GitHub token",
    };
  }
  try {
    const token = await decryptWithKey(encrypted, ssoKey);
    return { kind: "ok", token };
  } catch {
    return { kind: "error", code: -32603, message: "failed to decrypt stored GitHub token" };
  }
}

function dispatchInitialize(id: string | number | null): JsonRpcResponse {
  return rpcOk(id, {
    protocolVersion: MCP_PROTOCOL_VERSION,
    serverInfo: { name: MCP_SERVER_NAME, version: "1.0.0" },
    capabilities: {
      // issue #155: advertise tools/list_changed support so clients re-fetch
      // tools/list when the DO broadcasts notifications/tools/list_changed
      // (binary attach/detach, elevate completion, pair-claim 等)。
      tools: { listChanged: true },
    },
  });
}

function dispatchToolsList(id: string | number | null, payload: McpJwtPayload): JsonRpcResponse {
  // `requiresGithubToken` なツールは github_token (KV `github_token:<sub>`、
  // GitHub flow の callback でのみ保存される) が無いと呼んでも
  // `no_github_token` で必ず失敗する。Google flow セッション (`github_login` 無し
  // — 不変条件は McpJwtPayload 参照) には最初から出さない (Refs #438、Google IdP
  // surface `/mcp/google` 接続時に「一覧にあるのに呼べない」体験を防ぐ)。
  const hasGithubIdentity = typeof payload.github_login === "string";
  const visible = TOOLS.filter(
    (t) => scopeIncludes(payload.scope, t.requiredScope) && (hasGithubIdentity || !t.requiresGithubToken),
  );
  return rpcOk(id, {
    tools: visible.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  });
}

async function dispatchToolsCall(
  id: string | number | null,
  params: unknown,
  env: Env,
  payload: McpJwtPayload,
): Promise<JsonRpcResponse> {
  if (!isObject(params)) {
    return rpcError(id, -32602, "params must be an object with `name` and `arguments`");
  }
  const tp = params as ToolCallParams;
  const name = asString(tp.name);
  if (!name) return rpcError(id, -32602, "tool name is required");
  const tool = TOOL_BY_NAME[name];
  if (!tool) return rpcError(id, -32601, `unknown tool: ${name}`);
  if (!scopeIncludes(payload.scope, tool.requiredScope)) {
    return rpcError(id, -32000, `insufficient scope: ${tool.requiredScope} required`);
  }
  let ghToken = "";
  if (tool.requiresGithubToken) {
    const resolved = await resolveGithubToken(env, payload.sub);
    if (resolved.kind === "error") return rpcError(id, resolved.code, resolved.message);
    ghToken = resolved.token;
  }
  const args = isObject(tp.arguments) ? tp.arguments : {};
  try {
    const result = await tool.call(args, { env, payload, ghToken });
    // MCP spec: `tools/call.result.content` is an array of content items.
    // For structured data we wrap as a single `text` content with stringified JSON.
    return rpcOk(id, {
      content: [
        { type: "text", text: JSON.stringify(result, null, 2) },
      ],
      isError: false,
    });
  } catch (e) {
    if (e instanceof GhError) {
      return rpcOk(id, {
        content: [{ type: "text", text: `GitHub error ${e.status}: ${e.message}` }],
        isError: true,
      });
    }
    if (e instanceof DevLoginError) {
      return rpcOk(id, {
        content: [{ type: "text", text: `dev-login error ${e.status}: ${e.message}` }],
        isError: true,
      });
    }
    if (e instanceof VerifyShotError) {
      return rpcOk(id, {
        content: [{ type: "text", text: `verify-shot error ${e.status}: ${e.message}` }],
        isError: true,
      });
    }
    return rpcError(id, -32603, e instanceof Error ? e.message : "internal error");
  }
}

async function dispatch(
  req: JsonRpcRequest,
  env: Env,
  payload: McpJwtPayload,
): Promise<JsonRpcResponse> {
  const id = req.id ?? null;
  switch (req.method) {
    case "initialize":
      return dispatchInitialize(id);
    case "ping":
      return rpcOk(id, {});
    case "tools/list":
      return dispatchToolsList(id, payload);
    case "tools/call":
      return await dispatchToolsCall(id, req.params, env, payload);
    default:
      return rpcError(id, -32601, `method not found: ${req.method}`);
  }
}

export async function handleMcpTools(request: Request, env: Env): Promise<Response> {
  const gate = await authenticate(request, env);
  if (gate.kind === "error") return gate.response;

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return jsonResponse(rpcError(null, -32700, "parse error"));
  }
  // MCP spec allows JSON-RPC batches (array). Handle both.
  if (Array.isArray(raw)) {
    const responses: JsonRpcResponse[] = [];
    for (const item of raw) {
      const r = validateRpc(item);
      if (r.kind === "error") {
        responses.push(rpcError(null, -32600, r.message));
      } else {
        responses.push(await dispatch(r.request, env, gate.payload));
      }
    }
    return jsonResponse(responses);
  }
  const v = validateRpc(raw);
  if (v.kind === "error") {
    return jsonResponse(rpcError(null, -32600, v.message));
  }
  const resp = await dispatch(v.request, env, gate.payload);
  return jsonResponse(resp);
}

function validateRpc(
  v: unknown,
): { kind: "ok"; request: JsonRpcRequest } | { kind: "error"; message: string } {
  if (!isObject(v)) return { kind: "error", message: "request must be an object" };
  if (v["jsonrpc"] !== "2.0") return { kind: "error", message: 'jsonrpc must be "2.0"' };
  const method = asString(v["method"]);
  if (!method) return { kind: "error", message: "method is required" };
  const idRaw = v["id"];
  const id = typeof idRaw === "string" || typeof idRaw === "number" || idRaw === null
    ? idRaw
    : undefined;
  const req: JsonRpcRequest = { jsonrpc: "2.0", method };
  if (id !== undefined) req.id = id;
  if (v["params"] !== undefined) req.params = v["params"];
  return { kind: "ok", request: req };
}

/** Test-only export: surface the tool list for snapshot tests. */
export const __TEST__ = { TOOLS };
