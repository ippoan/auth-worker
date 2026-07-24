/**
 * `handleMcpPairRegisterViaGithubComment` —
 * `POST /mcp/pair/register-via-github-comment` テスト
 * (issues ippoan/auth-worker#174, #176)。
 *
 * - env / KV guard (503)
 * - MCP_HEADLESS_GRANT_ENABLED kill switch (503、issue #432 regression test)
 * - rate limit per IP (429)
 * - Content-Type check (400)
 * - invalid JSON body (400)
 * - comment_url validation: missing / wrong host / wrong path (400)
 * - oat_hash format validation (400)
 * - nonce format validation (400)
 * - GitHub comment fetch: 404 / 401 / 403 / 5xx / network
 * - comment shape: missing user.login / body
 * - binding line missing (400 binding_mismatch)
 * - GITHUB_MCP_USER_ALLOWLIST ACL (403 access_denied、2026-07-24 修正の regression test)
 * - 正常系: KV に binding を書き込み、TTL 30d、github_login echo
 * - #176 Bearer OAT path: dual binding write (oat_hash + org_uuid)
 * - #176 oat_hash mismatch with Bearer (400)
 * - #176 Bearer OAT invalid (Anthropic 401 reject)
 * - #176 Bearer present but org_uuid header missing → only oat_hash binding
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { handleMcpPairRegisterViaGithubComment } from "../../src/handlers/mcp-pair-register-via-github-comment";
import {
  OAT_BINDING_TTL_SEC,
  getOatBinding,
  getOrgBinding,
  hashOat,
} from "../../src/lib/mcp-oat-binding";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth-staging.test.example";
const OAT_HASH =
  "a".repeat(64); // 64-char hex
const NONCE = "nonce-1234abcd";
const COMMENT_URL =
  "https://api.github.com/repos/ippoan/auth-worker/issues/comments/12345";

// #176 — real-ish OAT used to derive a real sha256 for Bearer-attached tests.
const REAL_OAT = "sk-ant-oat01-real-test-token-zzzzzzzzzzzzzzzzzz";
const ORG_UUID = "bbe9480d-6a09-4689-92d2-7197609417fe";

function envWith(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    // 2026-07-24: ACL 修正後は allowlist が無いと全て 403 になるため、既存
    // happy-path テスト (login=yhonda-ohishi / alice) が通るよう default で
    // 両方を含める。ACL 自体のテストは明示的に上書きする (下の describe 参照)。
    GITHUB_MCP_USER_ALLOWLIST: '["yhonda-ohishi","alice"]',
    // issue #432: kill switch 未設定だと全て 503 になるため、既存テストが
    // 通るよう default で有効化する。kill switch 自体のテストは明示的に
    // 上書きする (下の describe ブロック参照)。
    MCP_HEADLESS_GRANT_ENABLED: "1",
    ...overrides,
  });
  return { env, kv };
}

function buildReq(opts: {
  body?: string | object;
  contentType?: string;
  ip?: string;
  auth?: string;
} = {}): Request {
  const headers: Record<string, string> = {
    "Content-Type": opts.contentType ?? "application/json",
  };
  if (opts.ip) headers["CF-Connecting-IP"] = opts.ip;
  if (opts.auth) headers.Authorization = opts.auth;
  const bodyStr =
    typeof opts.body === "string"
      ? opts.body
      : opts.body
        ? JSON.stringify(opts.body)
        : undefined;
  return new Request(`${ISSUER}/mcp/pair/register-via-github-comment`, {
    method: "POST",
    headers,
    body: bodyStr,
  });
}

interface CommentMock {
  status?: number;
  body?: { user?: { login?: string }; body?: string };
  raw?: string;
}

function mockGithubComment(opts: CommentMock = {}): void {
  const status = opts.status ?? 200;
  const body =
    opts.raw ??
    JSON.stringify(
      opts.body ?? {
        user: { login: "yhonda-ohishi" },
        body: `oat-binding: ${OAT_HASH} ${NONCE}`,
      },
    );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url === COMMENT_URL) {
        return new Response(body, {
          status,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }),
  );
}

function mockGithubThrow(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("network down");
    }),
  );
}

/**
 * Mock both GitHub comment fetch AND Anthropic `/v1/models`. Used by #176
 * Bearer-attached register tests.
 */
function mockGithubAndAnthropic(opts: {
  comment?: CommentMock;
  anthropicStatus?: number;
  orgUuid?: string | null;
  throwOnAnthropic?: boolean;
} = {}): void {
  const status = opts.comment?.status ?? 200;
  const commentBody =
    opts.comment?.raw ??
    JSON.stringify(
      opts.comment?.body ?? {
        user: { login: "yhonda-ohishi" },
        body: `oat-binding: ${OAT_HASH} ${NONCE}`,
      },
    );
  const anthropicStatus = opts.anthropicStatus ?? 200;
  const orgUuid = opts.orgUuid === undefined ? ORG_UUID : opts.orgUuid;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url === COMMENT_URL) {
        return new Response(commentBody, {
          status,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "https://api.anthropic.com/v1/models") {
        if (opts.throwOnAnthropic) throw new Error("anthropic network down");
        const headers: Record<string, string> = {
          "content-type": "application/json",
        };
        if (orgUuid !== null) headers["anthropic-organization-id"] = orgUuid;
        if (anthropicStatus >= 200 && anthropicStatus < 300) {
          return new Response(JSON.stringify({ data: [] }), {
            status: anthropicStatus,
            headers,
          });
        }
        return new Response(JSON.stringify({ error: { message: "fail" } }), {
          status: anthropicStatus,
          headers,
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }),
  );
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("handleMcpPairRegisterViaGithubComment — env guards", () => {
  it("503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({
      AUTH_WORKER_ORIGIN: ISSUER,
      MCP_HEADLESS_GRANT_ENABLED: "1",
    });
    delete (env as { MCP_OAUTH_KV?: unknown }).MCP_OAUTH_KV;
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(503);
  });
});

describe("handleMcpPairRegisterViaGithubComment — MCP_HEADLESS_GRANT_ENABLED kill switch (issue #432)", () => {
  it("503 when unset (fail-closed)", async () => {
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: undefined });
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("503 when set to a truthy-looking but non-'1' value (fail-closed)", async () => {
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: "true" } as Partial<Env>);
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("does not call api.github.com when kill switch is off (fails closed before upstream)", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: undefined });
    await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("200 when explicitly set to '1'", async () => {
    mockGithubComment();
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: "1" });
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairRegisterViaGithubComment — rate limit", () => {
  it("429 after 10 requests from same IP", async () => {
    mockGithubComment();
    const { env } = envWith();
    for (let i = 0; i < 10; i += 1) {
      const res = await handleMcpPairRegisterViaGithubComment(
        buildReq({
          body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
          ip: "1.2.3.4",
        }),
        env,
      );
      expect(res.status).toBe(200);
    }
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
        ip: "1.2.3.4",
      }),
      env,
    );
    expect(res.status).toBe(429);
  });
});

describe("handleMcpPairRegisterViaGithubComment — request validation", () => {
  it("400 when Content-Type is not application/json", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({ contentType: "text/plain", body: "anything" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/Content-Type/);
  });

  it("400 when Content-Type header is missing entirely", async () => {
    const { env } = envWith();
    const req = new Request(`${ISSUER}/mcp/pair/register-via-github-comment`, {
      method: "POST",
      body: JSON.stringify({
        comment_url: COMMENT_URL,
        oat_hash: OAT_HASH,
        nonce: NONCE,
      }),
    });
    // Force-remove Content-Type that fetch auto-sets when body is a string.
    req.headers.delete("Content-Type");
    const res = await handleMcpPairRegisterViaGithubComment(req, env);
    expect(res.status).toBe(400);
  });

  it("400 when body is invalid JSON", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({ body: "not-json" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when comment_url is missing", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({ body: { oat_hash: OAT_HASH, nonce: NONCE } }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/comment_url/);
  });

  it("400 when oat_hash is non-string (number)", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: 12345, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/oat_hash/);
  });

  it("400 when nonce is non-string (null)", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: null },
      }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/nonce/);
  });

  it("400 when comment_url host is not api.github.com", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: {
          comment_url:
            "https://evil.example.com/repos/x/y/issues/comments/1",
          oat_hash: OAT_HASH,
          nonce: NONCE,
        },
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when comment_url path shape is wrong", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: {
          comment_url: "https://api.github.com/users/foo",
          oat_hash: OAT_HASH,
          nonce: NONCE,
        },
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when oat_hash is not 64-char hex", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: "tooshort", nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/oat_hash/);
  });

  it("400 when nonce contains invalid chars", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: {
          comment_url: COMMENT_URL,
          oat_hash: OAT_HASH,
          nonce: "has spaces!",
        },
      }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/nonce/);
  });

  it("400 when nonce is too short", async () => {
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: "abc" },
      }),
      env,
    );
    expect(res.status).toBe(400);
  });
});

describe("handleMcpPairRegisterViaGithubComment — GitHub fetch errors", () => {
  it("404 comment_not_found when GitHub returns 404", async () => {
    mockGithubComment({ status: 404 });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("comment_not_found");
  });

  it("403 comment_forbidden when GitHub returns 401", async () => {
    mockGithubComment({ status: 401 });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("comment_forbidden");
  });

  it("403 comment_forbidden when GitHub returns 403", async () => {
    mockGithubComment({ status: 403 });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("502 upstream_error when GitHub returns 5xx", async () => {
    mockGithubComment({ status: 503 });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(502);
  });

  it("502 upstream_error when network fetch throws", async () => {
    mockGithubThrow();
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(502);
  });
});

describe("handleMcpPairRegisterViaGithubComment — comment shape errors", () => {
  it("502 when comment.user.login missing", async () => {
    mockGithubComment({
      body: {
        user: {},
        body: `oat-binding: ${OAT_HASH} ${NONCE}`,
      },
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/login/);
  });

  it("502 when comment.body missing", async () => {
    mockGithubComment({
      body: { user: { login: "alice" } },
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/body/);
  });

  it("400 binding_mismatch when comment body lacks expected line", async () => {
    mockGithubComment({
      body: {
        user: { login: "alice" },
        body: "different comment body",
      },
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("binding_mismatch");
  });

  it("400 binding_mismatch when hash matches but nonce differs", async () => {
    mockGithubComment({
      body: {
        user: { login: "alice" },
        body: `oat-binding: ${OAT_HASH} wrong-nonce-1234`,
      },
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(400);
  });
});

describe("handleMcpPairRegisterViaGithubComment — GITHUB_MCP_USER_ALLOWLIST ACL (2026-07-24 修正)", () => {
  it("403 access_denied + no KV write when comment.user.login is not in allowlist", async () => {
    mockGithubComment({
      body: { user: { login: "mallory" }, body: `oat-binding: ${OAT_HASH} ${NONCE}` },
    });
    const { env, kv } = envWith({ GITHUB_MCP_USER_ALLOWLIST: '["yhonda-ohishi"]' } as Partial<Env>);
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("access_denied");
    expect(kv._data[`oat_hash:${OAT_HASH}`]).toBeUndefined();
  });

  it("403 access_denied when allowlist is unset (fail-closed)", async () => {
    mockGithubComment();
    const { env } = envWith({ GITHUB_MCP_USER_ALLOWLIST: undefined });
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("200 when comment.user.login is in allowlist", async () => {
    mockGithubComment(); // login: yhonda-ohishi (default)
    const { env } = envWith({ GITHUB_MCP_USER_ALLOWLIST: '["yhonda-ohishi"]' } as Partial<Env>);
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairRegisterViaGithubComment — happy path", () => {
  it("writes KV binding and returns github_login", async () => {
    mockGithubComment();
    const { env, kv } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { github_login: string; bound: boolean };
    expect(body.github_login).toBe("yhonda-ohishi");
    expect(body.bound).toBe(true);

    // KV state: ~30d TTL (±2s for clock drift between now() calls), JSON stored under oat_hash:<hash>
    const ttl = kv._ttls[`oat_hash:${OAT_HASH}`] as number;
    expect(ttl).toBeGreaterThanOrEqual(OAT_BINDING_TTL_SEC - 2);
    expect(ttl).toBeLessThanOrEqual(OAT_BINDING_TTL_SEC);
    const stored = await getOatBinding(env, OAT_HASH);
    expect(stored).not.toBeNull();
    expect(stored!.github_login).toBe("yhonda-ohishi");
  });

  it("accepts mixed-case oat_hash by normalizing to lowercase", async () => {
    mockGithubComment({
      body: {
        user: { login: "alice" },
        body: `oat-binding: ${OAT_HASH} ${NONCE}`,
      },
    });
    const { env } = envWith();
    const upper = OAT_HASH.toUpperCase();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: upper, nonce: NONCE },
      }),
      env,
    );
    // strict 64-char hex lowercase regex なので upper-case 入力は弾く想定だが、
    // handler 内で toLowerCase() 後に validate しているため通る。
    expect(res.status).toBe(200);
  });

  it("accepts comment body containing the expected line as substring", async () => {
    mockGithubComment({
      body: {
        user: { login: "alice" },
        body: `# Header\n\nlots of text\n\noat-binding: ${OAT_HASH} ${NONCE}\n\nmore stuff`,
      },
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { github_login: string };
    expect(body.github_login).toBe("alice");
  });

  it("defaults source IP to 'unknown' when CF-Connecting-IP missing", async () => {
    mockGithubComment();
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("legacy (no Bearer) flow: org_uuid_bound=false in response", async () => {
    mockGithubComment();
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      org_uuid_bound: boolean;
      bound: boolean;
    };
    expect(body.bound).toBe(true);
    expect(body.org_uuid_bound).toBe(false);
  });
});

// ── #176 Bearer OAT path: dual binding (oat_hash + org_uuid) ─────────────

describe("handleMcpPairRegisterViaGithubComment — #176 Bearer OAT path", () => {
  it("writes both oat_hash and org_uuid bindings when Bearer attached", async () => {
    // body.oat_hash must match sha256(REAL_OAT) for the Bearer path to succeed.
    const realHash = await hashOat(REAL_OAT);
    mockGithubAndAnthropic({
      comment: {
        body: {
          user: { login: "yhonda-ohishi" },
          body: `oat-binding: ${realHash} ${NONCE}`,
        },
      },
    });
    const { env, kv } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: realHash, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      github_login: string;
      bound: boolean;
      org_uuid_bound: boolean;
    };
    expect(body.github_login).toBe("yhonda-ohishi");
    expect(body.bound).toBe(true);
    expect(body.org_uuid_bound).toBe(true);
    // both KV keys populated
    expect(kv._data[`oat_hash:${realHash}`]).toBeDefined();
    expect(kv._data[`org_uuid:${ORG_UUID}`]).toBeDefined();
    const oatRec = await getOatBinding(env, realHash);
    const orgRec = await getOrgBinding(env, ORG_UUID);
    expect(oatRec?.github_login).toBe("yhonda-ohishi");
    expect(orgRec?.github_login).toBe("yhonda-ohishi");
  });

  it("400 oat_hash_mismatch when sha256(Bearer) != body.oat_hash", async () => {
    mockGithubAndAnthropic();
    const { env, kv } = envWith();
    // body.oat_hash uses the canned OAT_HASH (= "a".repeat(64)), but Bearer OAT
    // hashes to a totally different value → 400 reject, no KV writes.
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: OAT_HASH, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("oat_hash_mismatch");
    // confirm: no KV entries written
    expect(kv._data[`oat_hash:${OAT_HASH}`]).toBeUndefined();
    expect(kv._data[`org_uuid:${ORG_UUID}`]).toBeUndefined();
  });

  it("401 invalid_token when Anthropic rejects Bearer OAT", async () => {
    const realHash = await hashOat(REAL_OAT);
    mockGithubAndAnthropic({
      comment: {
        body: {
          user: { login: "yhonda-ohishi" },
          body: `oat-binding: ${realHash} ${NONCE}`,
        },
      },
      anthropicStatus: 401,
    });
    const { env, kv } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: realHash, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_token");
    // no KV writes (= attacker who submits a revoked OAT cannot bind even
    // their own legitimate comment to a binding entry).
    expect(kv._data[`oat_hash:${realHash}`]).toBeUndefined();
  });

  it("401 invalid_token when Anthropic returns 403 for Bearer OAT", async () => {
    const realHash = await hashOat(REAL_OAT);
    mockGithubAndAnthropic({
      comment: {
        body: {
          user: { login: "yhonda-ohishi" },
          body: `oat-binding: ${realHash} ${NONCE}`,
        },
      },
      anthropicStatus: 403,
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: realHash, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("502 upstream_error when Anthropic returns 5xx", async () => {
    const realHash = await hashOat(REAL_OAT);
    mockGithubAndAnthropic({
      comment: {
        body: {
          user: { login: "yhonda-ohishi" },
          body: `oat-binding: ${realHash} ${NONCE}`,
        },
      },
      anthropicStatus: 503,
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: realHash, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(502);
  });

  it("502 upstream_error when Anthropic fetch throws", async () => {
    const realHash = await hashOat(REAL_OAT);
    mockGithubAndAnthropic({
      comment: {
        body: {
          user: { login: "yhonda-ohishi" },
          body: `oat-binding: ${realHash} ${NONCE}`,
        },
      },
      throwOnAnthropic: true,
    });
    const { env } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: realHash, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(502);
  });

  it("Bearer present but org_uuid header missing → only oat_hash binding, org_uuid_bound=false", async () => {
    const realHash = await hashOat(REAL_OAT);
    mockGithubAndAnthropic({
      comment: {
        body: {
          user: { login: "yhonda-ohishi" },
          body: `oat-binding: ${realHash} ${NONCE}`,
        },
      },
      orgUuid: null,
    });
    const { env, kv } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: realHash, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { org_uuid_bound: boolean };
    expect(body.org_uuid_bound).toBe(false);
    expect(kv._data[`oat_hash:${realHash}`]).toBeDefined();
    expect(kv._data[`org_uuid:${ORG_UUID}`]).toBeUndefined();
  });

  it("Bearer present but org_uuid header malformed → graceful skip", async () => {
    const realHash = await hashOat(REAL_OAT);
    mockGithubAndAnthropic({
      comment: {
        body: {
          user: { login: "yhonda-ohishi" },
          body: `oat-binding: ${realHash} ${NONCE}`,
        },
      },
      orgUuid: "garbage-not-a-uuid",
    });
    const { env, kv } = envWith();
    const res = await handleMcpPairRegisterViaGithubComment(
      buildReq({
        body: { comment_url: COMMENT_URL, oat_hash: realHash, nonce: NONCE },
        auth: `Bearer ${REAL_OAT}`,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { org_uuid_bound: boolean };
    expect(body.org_uuid_bound).toBe(false);
    expect(kv._data[`oat_hash:${realHash}`]).toBeDefined();
  });
});
