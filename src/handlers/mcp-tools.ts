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
import { decryptWithKey } from "../lib/mcp-crypto";
import { verifyMcpJwt, type McpJwtPayload } from "../lib/mcp-jwt";
import { mcpRelayOrigin, wwwAuthenticateValue } from "../lib/mcp-origins";

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

interface ToolDef {
  name: string;
  description: string;
  /** JSON Schema for `inputSchema` (MCP spec §tools). */
  inputSchema: Record<string, unknown>;
  /** Minimum MCP scope required to call this tool. */
  requiredScope: "mcp.read" | "mcp.write";
  /** Implementation. `args` is the validated `params.arguments` blob;
   *  `ghToken` is the user's GitHub API token (already decrypted). */
  call: (args: Record<string, unknown>, ghToken: string) => Promise<unknown>;
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

function unauthorized(env: Env, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": wwwAuthenticateValue(env),
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
    call: async (_args, ghToken) => ghGet("/user", ghToken),
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
    call: async (args, ghToken) => {
      const owner = asString(args["owner"]);
      const repo = asString(args["repo"]);
      if (!owner || !repo) throw new GhError(400, "owner and repo are required");
      return ghGet(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, ghToken);
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
    call: async (args, ghToken) => {
      const owner = asString(args["owner"]);
      const repo = asString(args["repo"]);
      if (!owner || !repo) throw new GhError(400, "owner and repo are required");
      const state = asString(args["state"]) ?? "open";
      const perPageRaw = args["per_page"];
      const perPage = typeof perPageRaw === "number" && Number.isInteger(perPageRaw)
        ? Math.min(100, Math.max(1, perPageRaw))
        : 30;
      const qs = `?state=${encodeURIComponent(state)}&per_page=${perPage}`;
      return ghGet(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues${qs}`, ghToken);
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
    call: async (args, ghToken) => {
      const owner = asString(args["owner"]);
      const repo = asString(args["repo"]);
      if (!owner || !repo) throw new GhError(400, "owner and repo are required");
      const state = asString(args["state"]) ?? "open";
      const perPageRaw = args["per_page"];
      const perPage = typeof perPageRaw === "number" && Number.isInteger(perPageRaw)
        ? Math.min(100, Math.max(1, perPageRaw))
        : 30;
      const qs = `?state=${encodeURIComponent(state)}&per_page=${perPage}`;
      return ghGet(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls${qs}`, ghToken);
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
    call: async (args, ghToken) => {
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
        ghToken,
      );
    },
  },
];

const TOOL_BY_NAME: Record<string, ToolDef> = Object.fromEntries(
  TOOLS.map((t) => [t.name, t]),
);

/**
 * Authenticate the request: verify Bearer JWT + look up github_token.
 * Returns `{kind:"ok"}` with the payload + decrypted github_token, or
 * `{kind:"error"}` carrying an HTTP `Response` to return immediately.
 */
type AuthGate =
  | { kind: "ok"; payload: McpJwtPayload; ghToken: string }
  | { kind: "error"; response: Response };

async function authenticate(request: Request, env: Env): Promise<AuthGate> {
  if (
    !env.MCP_OAUTH_KV ||
    !env.MCP_JWT_SECRET ||
    !env.SSO_ENCRYPTION_KEY
  ) {
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
      response: unauthorized(env, { error: "unauthorized", error_description: "Bearer token required" }),
    };
  }
  const relayOrigin = mcpRelayOrigin(env);
  const payload = await verifyMcpJwt(m[1], env.MCP_JWT_SECRET, (aud) => {
    if (aud === MCP_AUD_LEGACY) return true;
    try { return new URL(aud).origin === relayOrigin; } catch { return false; }
  });
  if (!payload) {
    return {
      kind: "error",
      response: unauthorized(env, { error: "invalid_token", error_description: "JWT verification failed" }),
    };
  }
  const encrypted = await env.MCP_OAUTH_KV.get(`github_token:${payload.sub}`);
  if (!encrypted) {
    return {
      kind: "error",
      response: jsonResponse(
        { error: "no_github_token", error_description: "Re-authorize via the MCP OAuth flow to refresh the GitHub token." },
        403,
      ),
    };
  }
  let ghToken: string;
  try {
    ghToken = await decryptWithKey(encrypted, env.SSO_ENCRYPTION_KEY);
  } catch {
    return {
      kind: "error",
      response: jsonResponse(
        { error: "server_error", error_description: "Failed to decrypt stored GitHub token" },
        500,
      ),
    };
  }
  return { kind: "ok", payload, ghToken };
}

function dispatchInitialize(id: string | number | null): JsonRpcResponse {
  return rpcOk(id, {
    protocolVersion: MCP_PROTOCOL_VERSION,
    serverInfo: { name: MCP_SERVER_NAME, version: "1.0.0" },
    capabilities: {
      tools: { listChanged: false },
    },
  });
}

function dispatchToolsList(id: string | number | null, scope: string): JsonRpcResponse {
  const visible = TOOLS.filter((t) => scopeIncludes(scope, t.requiredScope));
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
  payload: McpJwtPayload,
  ghToken: string,
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
  const args = isObject(tp.arguments) ? tp.arguments : {};
  try {
    const result = await tool.call(args, ghToken);
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
    return rpcError(id, -32603, e instanceof Error ? e.message : "internal error");
  }
}

async function dispatch(
  req: JsonRpcRequest,
  payload: McpJwtPayload,
  ghToken: string,
): Promise<JsonRpcResponse> {
  const id = req.id ?? null;
  switch (req.method) {
    case "initialize":
      return dispatchInitialize(id);
    case "ping":
      return rpcOk(id, {});
    case "tools/list":
      return dispatchToolsList(id, payload.scope);
    case "tools/call":
      return await dispatchToolsCall(id, req.params, payload, ghToken);
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
        responses.push(await dispatch(r.request, gate.payload, gate.ghToken));
      }
    }
    return jsonResponse(responses);
  }
  const v = validateRpc(raw);
  if (v.kind === "error") {
    return jsonResponse(rpcError(null, -32600, v.message));
  }
  const resp = await dispatch(v.request, gate.payload, gate.ghToken);
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
