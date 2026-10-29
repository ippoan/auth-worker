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
 *   - `ota_device` (登録済みデバイスへ公式 firmware の OTA、issue #535) も `mcp.write`
 *   - `lineworks_get` (LINE WORKS API への read-only GET、掲示板/ユーザー配下のみ。
 *     #540 の掲示板既読の調査用) も `mcp.write` + dev-login allowlist
 *   - `run_cam_clips_auto` (拠点カメラ 1 台の自動切り出しを今すぐ回す。dev token は画面用の proxy で
 *     書き込みを止められるので、試験記録の切り出しを確かめる口として MCP に置く) も `mcp.write` + dev-login allowlist
 *   - `dtako_restore` (R2 に退避した車両の現在地のログの 1 日ぶんを DB に書き戻す。rust-alc-api の archive Job の
 *     `dtako-restore` を移した、W9 / Refs ippoan/rust-alc-api#680) も `mcp.write` + dev-login allowlist
 */

import type { Env } from "../index";
import { buildVerifyRlsResult, fetchRlsCheck, fetchVeinDbRole } from "../lib/alc-internal";
import {
  checkDevLoginAllowlist,
  issueDevLoginCode,
  mintDevToken,
  resolveTenantId,
} from "../lib/dev-login";
import { worksApiGet } from "../lib/lineworks-bot-api";
import { getBotAccess, pickLineworksBotConfigId } from "../lib/lineworks-bot-creds";
import { LINEWORKS_GET_BODY_MAX, resolveLineworksGetTarget } from "../lib/lineworks-get-path";
import { getCommandResult, managedDeviceKind, sendDeviceCommand } from "./device-setup";
import { DEVICE_ROLE_HUB, DEVICE_ROLE_PRINT, DEVICE_ROLE_TIMECARD } from "../lib/device";
import { forwardAlcTenantRequest } from "../lib/alc-tenant-forward";
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

/** `get_device_log` — 端末が返せるログ本文の上限 (firmware 側 ippoan/alc-app-s3#195 に合わせる)。 */
const GET_LOG_MAX_BYTES_LIMIT = 3800;
/** `get_device_log` の `max_bytes` 省略時の値。 */
const GET_LOG_MAX_BYTES_DEFAULT = 3000;
/** `command_result` のポーリング間隔と全体の待ち時間 (端末は WS 越しに数百 ms で返す)。 */
const GET_LOG_POLL_INTERVAL_MS = 500;
const GET_LOG_TIMEOUT_MS = 8000;
/** `ota_device` の進捗ポーリング間隔と全体の待ち時間 (書き込みは数十秒かかる)。 */
const OTA_POLL_INTERVAL_MS = 2000;
const OTA_TIMEOUT_MS = 90_000;
/** `create_test_record` — 記録の行が backend に入るのを待つ間隔と全体の待ち時間 (機体は次の周回で送る)。 */
const TEST_RECORD_POLL_INTERVAL_MS = 1500;
const TEST_RECORD_TIMEOUT_MS = 15_000;
/** `run_cam_clips_auto` — カメラの ID (ingest の cameras.id) の形。 */
const CAMERA_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** `dtako_restore` の日付 (`YYYY-MM-DD`。暦の検査は alc-dtako-worker が 400 で返す)。 */
const ARCHIVE_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
/** alc-dtako-worker の書き戻しの内部口。振り分けの表には載せない (画面・内部用の proxy からは届かない)。 */
const DTAKO_RESTORE_URL = "https://alc-dtako/internal/archive/restore";
/** `create_test_record` が読み返す件数 (試験記録だけの一覧の新しい順。command_id で 1 件を選ぶ)。 */
const TEST_RECORD_LIST_LIMIT = 20;

/** `ota_device` が焼ける機種の role。p4-gw (GitHub Releases 配布) は進捗 phase の形が
 *  未確認なので入れない — `managedDeviceKind` は p4-gw でも kind を返すため別に絞る。 */
const OTA_DEVICE_ROLES: ReadonlySet<string> = new Set([
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_PRINT,
  DEVICE_ROLE_TIMECARD,
]);

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

/** `verify_eval` / `verify_screenshot` の `dev_axis` (開発の軸 = dev端末の行を見る。Refs ippoan/rust-alc-api#680) */
const DEV_AXIS_SCHEMA = {
  type: "boolean",
  description:
    "read the development axis (rows written by dev-marked devices, X-Device-Dev) instead of " +
    "production rows. Default false. Writes stay forbidden as for any dev session.",
} as const;

/**
 * `dev_axis` を読む (省略は false)。boolean のほか、文字列の `"true"` / `"false"` も受ける —
 * ツールの一覧を古いまま持つ MCP クライアントは、知らない引数を文字列で送るため。それ以外は 400
 */
function devAxisArg(args: Record<string, unknown>): boolean {
  const v = args["dev_axis"];
  if (v === undefined || v === false || v === "false") return false;
  if (v === true || v === "true") return true;
  throw new VerifyShotError(400, "dev_axis must be a boolean");
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
        dev_axis: DEV_AXIS_SCHEMA,
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
      const devAxis = devAxisArg(args);
      // ブラウザ未 bind は dev JWT を mint する前に落とす (無駄な upsert を避ける)。
      if (!ctx.env.BROWSER) {
        throw new VerifyShotError(503, "browser_binding_not_configured");
      }
      const minted = await mintDevToken(ctx.env, ctx.payload, { devAxis });
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
        dev_axis: DEV_AXIS_SCHEMA,
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
      const devAxis = devAxisArg(args);
      if (!ctx.env.BROWSER) {
        throw new VerifyShotError(503, "browser_binding_not_configured");
      }
      const minted = await mintDevToken(ctx.env, ctx.payload, { devAxis });
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
  {
    name: "lineworks_get",
    description:
      "Read-only GET against the LINE WORKS API (https://www.worksapis.com) using the " +
      "caller tenant's LINE WORKS Bot service account — for debugging the LINE WORKS " +
      "integration (e.g. board read status). Only paths under /v1.0/boards (token scope " +
      "board.read) and /v1.0/users (scope directory.read) are allowed; pass query " +
      "parameters via `query` with string values (e.g. {\"count\":\"40\",\"cursor\":\"...\"}). " +
      "Returns the upstream HTTP status and body as the raw upstream text (not parsed, so " +
      "64-bit IDs such as boardId/postId stay exact; truncated to 64KB). Same allowlist " +
      "gate as issue_dev_token; the caller must be an admin " +
      "of their tenant.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description:
            "API path, e.g. /v1.0/boards or /v1.0/boards/{boardId}/posts/{postId}/readers",
        },
        query: {
          type: "object",
          additionalProperties: { type: "string" },
          description: "query parameters (string values)",
        },
      },
      required: ["path"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const target = resolveLineworksGetTarget(args["path"], args["query"]);
      if (!target.ok) throw new Error(target.error);
      const minted = await mintDevToken(ctx.env, ctx.payload);
      if (minted.kind === "error") throw new DevLoginError(minted.status, minted.error);
      const botConfigId = await pickLineworksBotConfigId(ctx.env, minted.token);
      if (!botConfigId) throw new Error("no enabled LINE WORKS bot config for this tenant");
      // access token (alc-lineworks が出す) は worksApiGet に渡すだけ。応答にもログにも出さない。
      const bot = await getBotAccess(ctx.env, minted.token, botConfigId, target.scope);
      const res = await worksApiGet(bot.accessToken, target.url);
      const text = await res.text();
      if (text.length > LINEWORKS_GET_BODY_MAX) {
        return {
          status: res.status,
          scope: target.scope,
          body: text.slice(0, LINEWORKS_GET_BODY_MAX),
          body_truncated: true,
        };
      }
      // body は parse せず上流の生テキストのまま返す。デバッグ用の素通し口なので parse →
      // 再直列化の往復は要らず、往復すると 64bit の boardId/postId が float64 に丸まる
      // (2026-09-11 実測: 丸めた ID で /posts を叩くと 403)。
      return { status: res.status, scope: target.scope, body: text };
    },
  },
  {
    name: "get_device_log",
    description:
      "Fetch the recent serial log of one managed hub device (CoreS3 / VoiceS3R) " +
      "by sending it a `get_log` command over the recorder WebSocket and waiting " +
      "up to 8s for the device to answer. Returns `{text, bytes, total_bytes, " +
      "truncated, uptime_ms, device_id}` plus, from newer firmware, `offset` " +
      "(bytes skipped from the end of the ring — `text` is the window that ends " +
      "there, snapped to line boundaries; to read older lines call again with " +
      "`offset + bytes` while that is below `total_bytes`; firmware without it " +
      "ignores the `offset` argument and returns the tail), `boot_history` " +
      "(up to 8 `{reset_reason, reset_code}`, newest first — the first entry is the " +
      "current boot; absent on models without a history), `pwa_log` (diagnostic log " +
      "relayed from the kiosk PWA, or null) and `pwa_log_error` (why pwa_log is " +
      "null, e.g. `no_host`). Errors are returned as `{error}`: " +
      "`device_not_found` (not a device of your tenant, or revoked), " +
      "`device_not_connected` (device is offline), `timeout` (no answer in time), " +
      "`unsupported_firmware` (device firmware predates the get_log command). " +
      "Same allowlist gate as issue_dev_token; only devices of the caller's own " +
      "tenant are reachable.",
    inputSchema: {
      type: "object",
      properties: {
        device_id: {
          type: "string",
          description: "Device ID as shown in the device management page",
        },
        max_bytes: {
          type: "integer",
          minimum: 1,
          maximum: GET_LOG_MAX_BYTES_LIMIT,
          default: GET_LOG_MAX_BYTES_DEFAULT,
          description:
            "Max bytes of log text to return (the window ending `offset` bytes before " +
            "the end of the ring buffer — the tail by default)",
        },
        offset: {
          type: "integer",
          minimum: 0,
          default: 0,
          description:
            "Bytes to skip from the end of the ring buffer before taking the window " +
            "(0 = newest). Use the previous answer's `offset + bytes` to page back",
        },
      },
      required: ["device_id"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const deviceId = asString(args["device_id"]);
      if (!deviceId) throw new DevLoginError(400, "device_id is required");
      const maxBytesRaw = args["max_bytes"];
      if (
        maxBytesRaw !== undefined &&
        (typeof maxBytesRaw !== "number" ||
          !Number.isInteger(maxBytesRaw) ||
          maxBytesRaw < 1 ||
          maxBytesRaw > GET_LOG_MAX_BYTES_LIMIT)
      ) {
        throw new DevLoginError(
          400,
          `max_bytes must be an integer in [1, ${GET_LOG_MAX_BYTES_LIMIT}]`,
        );
      }
      const maxBytes = maxBytesRaw === undefined ? GET_LOG_MAX_BYTES_DEFAULT : maxBytesRaw;
      // 末尾から遡るバイト数 (ippoan/alc-app-s3#217)。省略時は command に載せない
      // (旧 firmware は未知のキーを無視して末尾を返す)。
      const offset = args["offset"];
      if (
        offset !== undefined &&
        (typeof offset !== "number" || !Number.isInteger(offset) || offset < 0)
      ) {
        throw new DevLoginError(400, "offset must be a non-negative integer");
      }

      // MCP JWT には tenant が無いので dev-login と同じ経路で解決する
      // (allowlist gate 込み — 拒否は issue_dev_token と同じエラー型)。
      const resolved = await resolveTenantId(ctx.env, ctx.payload);
      if (resolved.kind === "error") throw new DevLoginError(resolved.status, resolved.error);
      const tenantId = resolved.user.tenant_id;

      const sent = await sendDeviceCommand(ctx.env, tenantId, deviceId, {
        action: "get_log",
        max_bytes: maxBytes,
        ...(offset === undefined ? {} : { offset }),
      });
      if ("error" in sent) {
        return sent.error === "recorder_error"
          ? { device_id: deviceId, error: sent.error, status: sent.status }
          : { device_id: deviceId, error: sent.error };
      }

      const attempts = Math.floor(GET_LOG_TIMEOUT_MS / GET_LOG_POLL_INTERVAL_MS);
      for (let i = 0; i < attempts; i++) {
        await new Promise((resolve) => setTimeout(resolve, GET_LOG_POLL_INTERVAL_MS));
        const result = await getCommandResult(ctx.env, tenantId, sent.id);
        if (result.kind === "error") {
          return result.error === "recorder_error"
            ? { device_id: deviceId, error: result.error, status: result.status }
            : { device_id: deviceId, error: result.error };
        }
        if (result.kind === "pending") continue;
        const payload = result.payload;
        // 旧 firmware は未知の action を `{}` で ack するだけ (text が無い)。
        if (!isObject(payload) || typeof payload["text"] !== "string") {
          return { device_id: deviceId, error: "unsupported_firmware" };
        }
        // device_id は最後に置く (端末が返した値で上書きさせない)。
        return { ...payload, device_id: deviceId };
      }
      return { device_id: deviceId, error: "timeout" };
    },
  },
  {
    name: "ota_device",
    description:
      "Re-flash one managed device of your tenant with its official firmware over " +
      "the air (the same OTA as the update button of /device/setup) and wait up to " +
      "90s for the result. There is no URL input: the firmware URL is picked " +
      "server-side from the device's kind (the official distribution URL of hub / " +
      "print / timecard devices), so only official images can be flashed. " +
      "`channel`: `prod` (default, the release build) or `dev` (the dev build with " +
      "the memory HUD — only kinds that have one). The device reboots about 1.5s " +
      "after reporting `ok`. CAUTION: the firmware does NOT refuse a second OTA or " +
      "an OTA during an alcohol check — make sure the device is not in use before " +
      "calling. Returns `{device_id, command_id, channel, url, phase, last, " +
      "timed_out}`: `phase` is `ok` / `error` (or the last progress phase seen, " +
      "`pending` if none), `last` is the last progress payload the device sent. If " +
      "the OTA does not finish in 90s, `timed_out` is true and the device may still " +
      "be flashing — check with get_device_log: `boot_history[0].reset_reason` is " +
      "`sw` once the device rebooted into the new firmware. Errors are returned as " +
      "`{error}`: " +
      "`device_not_found` (not a device of your tenant, or revoked), " +
      "`unsupported_device_kind` (not a hub / print / timecard device), " +
      "`dev_build_not_available` (channel dev on a kind without a dev build), " +
      "`device_not_connected` (device is offline). Same allowlist gate as " +
      "issue_dev_token; only devices of the caller's own tenant are reachable.",
    inputSchema: {
      type: "object",
      properties: {
        device_id: {
          type: "string",
          description: "Device ID as shown in the device management page",
        },
        channel: {
          type: "string",
          enum: ["prod", "dev"],
          default: "prod",
          description: "Which official build to flash",
        },
      },
      required: ["device_id"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const deviceId = asString(args["device_id"]);
      if (!deviceId) throw new DevLoginError(400, "device_id is required");
      const channelRaw = args["channel"];
      if (channelRaw !== undefined && channelRaw !== "prod" && channelRaw !== "dev") {
        throw new DevLoginError(400, "channel must be 'prod' or 'dev'");
      }
      const channel = channelRaw === "dev" ? "dev" : "prod";

      const resolved = await resolveTenantId(ctx.env, ctx.payload);
      if (resolved.kind === "error") throw new DevLoginError(resolved.status, resolved.error);
      const tenantId = resolved.user.tenant_id;

      // 他テナント・revoked・未登録は null (fail-closed)。
      const kind = await managedDeviceKind(ctx.env, tenantId, deviceId);
      if (!kind) return { device_id: deviceId, error: "device_not_found" };
      // pairRole を持たない機種 (血圧測定台・警告デバイス等) は managedDeviceKind
      // (= kindNameForRole 経由) からは返らないはずだが、型上は string | undefined
      // なので fail-closed に倒す。
      if (!kind.pairRole || !OTA_DEVICE_ROLES.has(kind.pairRole)) {
        return { device_id: deviceId, error: "unsupported_device_kind" };
      }
      // URL は入力から受け取らず、機種の公式配信先 (DEVICE_KINDS の定数) に固定する。
      const url = channel === "dev" ? kind.devAppUrl : kind.appUrl;
      if (!url) return { device_id: deviceId, channel, error: "dev_build_not_available" };

      const sent = await sendDeviceCommand(ctx.env, tenantId, deviceId, { action: "ota", url });
      if ("error" in sent) {
        return sent.error === "recorder_error"
          ? { device_id: deviceId, error: sent.error, status: sent.status }
          : { device_id: deviceId, error: sent.error };
      }

      // 端末は進捗 (`{phase, received, total}`) を同じ command_result に上書きしていく。
      let last: unknown = null;
      let phase = "pending";
      const attempts = Math.floor(OTA_TIMEOUT_MS / OTA_POLL_INTERVAL_MS);
      for (let i = 0; i < attempts && phase !== "ok" && phase !== "error"; i++) {
        await new Promise((resolve) => setTimeout(resolve, OTA_POLL_INTERVAL_MS));
        const result = await getCommandResult(ctx.env, tenantId, sent.id);
        if (result.kind === "error") {
          // command_id を返し、途中で切れても get_device_log で追えるようにする。
          const base = { device_id: deviceId, command_id: sent.id, channel, url };
          return result.error === "recorder_error"
            ? { ...base, error: result.error, status: result.status }
            : { ...base, error: result.error };
        }
        if (result.kind === "pending") continue;
        last = result.payload;
        if (isObject(last) && typeof last["phase"] === "string") phase = last["phase"];
      }
      return {
        device_id: deviceId,
        command_id: sent.id,
        channel,
        url,
        phase,
        last,
        timed_out: phase !== "ok" && phase !== "error",
      };
    },
  },
  {
    name: "create_test_record",
    description:
      "Make one managed hub device (CoreS3) of your tenant create a development test record " +
      "(hub_measurements kind `test`) through its normal measurement queue and uplink, then read " +
      "the stored row back. Use after an OTA to check the record path without waiting for a real " +
      "measurement. The row ALWAYS goes to the development axis (is_dev = true) even on a " +
      "production device, so it never shows in the production record book, tenko, timecard or CSV. " +
      "Sends a `test_record` command over the recorder WebSocket, waits up to 8s for `{ok, seq}`, " +
      "then up to 15s for the row. Returns `{device_id, command_id, seq, record, pending}`: " +
      "`record` is `{id, device_id, via_device_id, machine_id, kind, seq, payload, recorded_at, " +
      "created_at, is_dev}` (`device_id` is the record ID — `alarm:<fp>` when the device proved its " +
      "machine key — and `via_device_id` the hub ID it connected with), or null with `pending: true` " +
      "if the row has not arrived yet — call again with the same `command_id` to only read it back " +
      "(no new record). Errors are returned as `{error}`: `device_not_found`, " +
      "`unsupported_device_kind` (not a hub device), `device_not_connected`, `busy` (OTA or tenko " +
      "in progress), `timeout`, `unsupported_firmware` (firmware predates `test_record`), " +
      "`backend_error`. Same allowlist gate as issue_dev_token; only devices of the caller's own " +
      "tenant are reachable.",
    inputSchema: {
      type: "object",
      properties: {
        device_id: {
          type: "string",
          description: "Device ID as shown in the device management page (the hub ID)",
        },
        command_id: {
          type: "string",
          description:
            "command_id of a previous call: only read that record back, do not create a new one",
        },
      },
      required: ["device_id"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const deviceId = asString(args["device_id"]);
      if (!deviceId) throw new DevLoginError(400, "device_id is required");
      const givenCommandId = args["command_id"];
      if (givenCommandId !== undefined && (typeof givenCommandId !== "string" || !givenCommandId)) {
        throw new DevLoginError(400, "command_id must be a non-empty string");
      }

      const resolved = await resolveTenantId(ctx.env, ctx.payload);
      if (resolved.kind === "error") throw new DevLoginError(resolved.status, resolved.error);
      const tenantId = resolved.user.tenant_id;

      // 他テナント・revoked・未登録は null (fail-closed)。試験記録は hub の測定の経路なので hub だけ
      const kind = await managedDeviceKind(ctx.env, tenantId, deviceId);
      if (!kind) return { device_id: deviceId, error: "device_not_found" };
      if (kind.pairRole !== DEVICE_ROLE_HUB) {
        return { device_id: deviceId, error: "unsupported_device_kind" };
      }

      let commandId: string;
      let seq: number | null = null;
      if (typeof givenCommandId === "string") {
        commandId = givenCommandId;
      } else {
        const sent = await sendDeviceCommand(ctx.env, tenantId, deviceId, { action: "test_record" });
        if ("error" in sent) {
          return sent.error === "recorder_error"
            ? { device_id: deviceId, error: sent.error, status: sent.status }
            : { device_id: deviceId, error: sent.error };
        }
        commandId = sent.id;
        const answer = await waitTestRecordAnswer(ctx.env, tenantId, commandId);
        if ("error" in answer) return { device_id: deviceId, command_id: commandId, ...answer };
        seq = answer.seq;
      }

      // 機体は積んだ記録を次の周回で送る。開発の軸の試験記録から command_id で 1 件を選ぶ
      const attempts = Math.floor(TEST_RECORD_TIMEOUT_MS / TEST_RECORD_POLL_INTERVAL_MS);
      for (let i = 0; i < attempts; i++) {
        const found = await findTestRecord(ctx.env, tenantId, commandId);
        if (found === "backend_error") {
          return { device_id: deviceId, command_id: commandId, seq, error: "backend_error" };
        }
        if (found) {
          return { device_id: deviceId, command_id: commandId, seq: found.seq, record: found, pending: false };
        }
        await new Promise((resolve) => setTimeout(resolve, TEST_RECORD_POLL_INTERVAL_MS));
      }
      return { device_id: deviceId, command_id: commandId, seq, record: null, pending: true };
    },
  },
  {
    name: "run_cam_clips_auto",
    description:
      "Run the automatic clipping of one site camera of your tenant now (the same job as the hourly " +
      "cron of alc-cam-sd-ingest and the 今すぐ切り出す button of the recording tab): every event of " +
      "the devices tied to the camera that has no clip yet gets its ±10s clip cut from the camera's " +
      "SD recording. Use after create_test_record to check the clip path without waiting for the " +
      "next cron. Waits for the ingest answer (it pulls from the SD, so it can take up to ~2 minutes). " +
      "Returns `{camera_id, status, result}`: `result` is the ingest answer as is (`cameras[0]` " +
      "carries the counts). Errors are returned as `{camera_id, error}`: `not_configured` (no " +
      "ALC_CAM_CLIPS binding — staging), `forbidden` (your user is not a tenant admin), " +
      "`backend_error` (with `status` and `body`). Same allowlist gate as issue_dev_token; only " +
      "cameras of the caller's own tenant are reachable (ingest scopes by X-Tenant-ID).",
    inputSchema: {
      type: "object",
      properties: {
        camera_id: {
          type: "string",
          description: "Camera ID (UUID) as shown in the recording tab (/api/cam-clips/cameras)",
        },
      },
      required: ["camera_id"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const cameraId = asString(args["camera_id"]);
      if (!cameraId || !CAMERA_ID_RE.test(cameraId)) {
        throw new DevLoginError(400, "camera_id must be a UUID");
      }
      const fetcher = ctx.env.ALC_CAM_CLIPS;
      if (!fetcher) return { camera_id: cameraId, error: "not_configured" };

      const resolved = await resolveTenantId(ctx.env, ctx.payload);
      if (resolved.kind === "error") throw new DevLoginError(resolved.status, resolved.error);
      // ingest は X-User-Role: admin だけを管理者として受ける。画面用の proxy と同じく、本人が admin のときだけ名乗る
      if (resolved.user.role !== "admin") return { camera_id: cameraId, error: "forbidden" };

      const res = await fetcher.fetch("https://alc-cam-sd-ingest/api/cam-clips/auto-run", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Tenant-ID": resolved.user.tenant_id,
          "X-User-Role": "admin",
        },
        body: JSON.stringify({ camera_id: cameraId }),
      });
      const text = await res.text();
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
      if (!res.ok || body === null) {
        return { camera_id: cameraId, error: "backend_error", status: res.status, body: text.slice(0, 500) };
      }
      return { camera_id: cameraId, status: res.status, result: body };
    },
  },
  {
    name: "dtako_restore",
    description:
      "Restore one day of archived vehicle location logs (dtakologs) of a tenant from R2 back into the DB " +
      "(the `dtako-restore` of the old rust-alc-api archive Job; the daily cron of alc-dtako-worker moves " +
      "rows older than 7 days to R2 and deletes them). Rows are upserted, so running it twice is harmless. " +
      "Only rows whose tenant_id is the given tenant are written (the whole day is refused otherwise). " +
      "Returns `{tenant_id, date, restored}` (the number of rows). Errors are returned as " +
      "`{tenant_id, date, error}`: `not_configured` (no ALC_DTAKO binding), `backend_error` (with `status` " +
      "and `body`; 404 = no archive for that day, 422 = the archive is unreadable or holds another tenant's rows). " +
      "Same allowlist gate as issue_dev_token.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: { type: "string", description: "Tenant ID (UUID) whose archive to restore" },
        date: { type: "string", description: "Day to restore (YYYY-MM-DD, UTC date of data_date_time)" },
      },
      required: ["tenant_id", "date"],
      additionalProperties: false,
    },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (args, ctx) => {
      const tenantId = asString(args["tenant_id"]);
      if (!tenantId || !CAMERA_ID_RE.test(tenantId)) {
        throw new DevLoginError(400, "tenant_id must be a UUID");
      }
      const date = asString(args["date"]);
      if (!date || !ARCHIVE_DATE_RE.test(date)) throw new DevLoginError(400, "date must be YYYY-MM-DD");
      // 会社をまたぐ書き戻し (rust の CLI と同じく、会社は引数)。許可リストの判定だけを通す
      const allowed = await checkDevLoginAllowlist(ctx.env, ctx.payload);
      if (allowed.kind === "error") throw new DevLoginError(allowed.status, allowed.error);
      const fetcher = ctx.env.ALC_DTAKO;
      if (!fetcher) return { tenant_id: tenantId, date, error: "not_configured" };

      const res = await fetcher.fetch(DTAKO_RESTORE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Tenant-ID": tenantId },
        body: JSON.stringify({ date }),
      });
      const text = await res.text();
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
      const restored = (body as { restored?: unknown } | null)?.restored;
      if (!res.ok || typeof restored !== "number") {
        return { tenant_id: tenantId, date, error: "backend_error", status: res.status, body: text.slice(0, 500) };
      }
      return { tenant_id: tenantId, date, restored };
    },
  },
  {
    name: "verify_rls",
    description:
      "本番 DB で、テナントごとの行の出し分け (RLS) の不変条件・backend の実行用ロールの属性・" +
      "いま繋いでいるロール・migration の適用履歴・履歴との食い違いを、backend に固定された検査で" +
      "確かめ、分割 worker (vein) の DB 接続のロールと合わせて返す。" +
      "読み取りだけ・引数なし (SQL も表名も受け取らない)。行のデータは返さない。" +
      "返す値: `{ok, verdicts: {invariants, runtime_role, migrations, drift, vein}, drift, " +
      "workers: {vein: {bound, current_user, is_runtime_role}}, migrations: {applied, max_version, " +
      "binary_count, binary_max_version, matches_binary}, runtime_role: {current_user, " +
      "is_runtime_role, rolsuper, rolbypassrls, rolinherit, member_of_table_owner}, " +
      "connections: [{usename, count}], owner_role_connected, invariants: {violation_count, " +
      "checks: [{check_no, title, violations}], violations: [{check_no, object, detail}]}, state}`。" +
      "`ok` は `verdicts` の全部が合格のときだけ true。" +
      "`ok` が false のときは `verdicts` でどれが原因かを読む: " +
      "`invariants` = 不変条件の違反が 0 件、`runtime_role` = backend が実行用ロールで繋いでいる、" +
      "`migrations` = 適用履歴が backend の想定と一致 (`matches_binary`)、" +
      "`drift` = 本番の実物が migration の履歴どおり、`vein` = vein が実行用ロールで繋いでいる。" +
      "`verdicts` の値が null の項目は、その backend・その環境では判定していない " +
      "(内訳を返さない古い backend・vein が bind されていない環境) — null は `ok` を false にしない " +
      "(古い backend では backend 自身の合否を使う)。" +
      "`drift` は食い違った表・関数・view を期待 (履歴を 0 から当てた状態) と実物で並べたもの。" +
      "null なら比べられなかった (古い backend、または状態を取れなかった)。" +
      "`workers.vein` は vein の DB 接続: `bound` は vein がこの環境に bind されているか、" +
      "`current_user` は繋いでいるロール名、`is_runtime_role` は実行用ロールか。" +
      "`bound: true` なのに 2 つが null なら vein に聞けなかった (`verdicts.vein` は false)。" +
      "vein は backend と別の接続を持ち、所有者ロールで繋いでいると RLS が掛からない。" +
      "`invariants.checks` は検査ごとの題と違反の件数で、違反が無くても毎回返る (何を確かめたかの一覧)。" +
      "`state` は観測したカタログの値 (表の組・policy の式・view・SECURITY DEFINER の関数・sequence)。" +
      "表は状態が同じものを組にまとめてあり、式が違う表・FORCE だけ違う表は別の組に出る。" +
      "`state` が null なら状態を取れなかった。" +
      "`owner_role_connected` は注意の表示で `ok` には入らない (migration の job の実行中は " +
      "true になりうる)。migration の直後は、新しい backend への切り替えが終わるまで " +
      "`matches_binary: false` (= `ok: false`) になる — `binary_max_version` が古ければ切り替え前。" +
      "staging の backend は実行用ロールで繋いでいないので、staging では `ok: false` が正しい結果。" +
      "backend から結果を取れないときは `rls_check_unavailable` (vein に聞けないだけなら結果は返る)。" +
      "issue_dev_token と同じ許可リストで絞る。",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    requiredScope: "mcp.write",
    requiresGithubToken: false,
    call: async (_args, ctx) => {
      // テナントをまたぐ値を返すので、許可リストの判定だけを通す。
      // resolveTenantId (利用者登録の POST を伴う) は通さない。
      const allowed = await checkDevLoginAllowlist(ctx.env, ctx.payload);
      if (allowed.kind === "error") throw new DevLoginError(allowed.status, allowed.error);
      const result = await fetchRlsCheck(ctx.env);
      if (!result) throw new DevLoginError(502, "rls_check_unavailable");
      // backend の結果が無ければ返すものが無いので、vein は backend の後にだけ聞く。
      // vein に聞けなくても backend の結果は返す (verdicts.vein が false になるだけ)。
      return buildVerifyRlsResult(result, await fetchVeinDbRole(ctx.env));
    },
  },
];

/**
 * `create_test_record` — 機体の `command_result` を待つ。`{ok:true, seq}` なら seq、
 * `{ok:false, error}` は機体の断り (`busy` 等)、`ok` の無い応答は旧ファーム (未知の action を `{}` で ack する)。
 */
async function waitTestRecordAnswer(
  env: Env,
  tenantId: string,
  commandId: string,
): Promise<{ seq: number } | { error: string; status?: number }> {
  const attempts = Math.floor(GET_LOG_TIMEOUT_MS / GET_LOG_POLL_INTERVAL_MS);
  for (let i = 0; i < attempts; i++) {
    await new Promise((resolve) => setTimeout(resolve, GET_LOG_POLL_INTERVAL_MS));
    const result = await getCommandResult(env, tenantId, commandId);
    if (result.kind === "error") {
      return result.error === "recorder_error"
        ? { error: result.error, status: result.status }
        : { error: result.error };
    }
    if (result.kind === "pending") continue;
    const payload = result.payload;
    if (!isObject(payload) || typeof payload["ok"] !== "boolean") {
      return { error: "unsupported_firmware" };
    }
    if (payload["ok"] !== true) {
      return { error: asString(payload["error"]) ?? "device_error" };
    }
    if (typeof payload["seq"] !== "number") return { error: "unsupported_firmware" };
    return { seq: payload["seq"] };
  }
  return { error: "timeout" };
}

/**
 * `create_test_record` — 開発の軸 (`X-Device-Dev: 1`) の試験記録 (kind `test`) から、payload の
 * `command_id` が一致する行を探す。本番の軸は読まない。無ければ null、backend が答えなければ `backend_error`。
 */
async function findTestRecord(
  env: Env,
  tenantId: string,
  commandId: string,
): Promise<Record<string, unknown> | null | "backend_error"> {
  const res = await forwardAlcTenantRequest(env, {
    tenantId,
    path: "/api/hub/measurements",
    method: "GET",
    search: `?kind=test&limit=${TEST_RECORD_LIST_LIMIT}`,
    deviceDev: true,
  });
  if (res.status !== 200) return "backend_error";
  let body: unknown;
  try {
    body = JSON.parse(res.body);
  } catch {
    return "backend_error";
  }
  const items = isObject(body) && Array.isArray(body["items"]) ? body["items"] : [];
  const row = items.find(
    (r): r is Record<string, unknown> =>
      isObject(r) && isObject(r["payload"]) && r["payload"]["command_id"] === commandId,
  );
  // この口が読むのは開発の軸だけ (is_dev は backend の応答に無いので、読み方から付ける)
  return row ? { ...row, is_dev: true } : null;
}

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
