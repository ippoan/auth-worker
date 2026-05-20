/**
 * `handleMcpPairRegisterViaGithubComment` —
 * `POST /mcp/pair/register-via-github-comment` テスト
 * (issue ippoan/auth-worker#174)。
 *
 * - env / KV guard (503)
 * - rate limit per IP (429)
 * - Content-Type check (400)
 * - invalid JSON body (400)
 * - comment_url validation: missing / wrong host / wrong path (400)
 * - oat_hash format validation (400)
 * - nonce format validation (400)
 * - GitHub comment fetch: 404 / 401 / 403 / 5xx / network
 * - comment shape: missing user.login / body
 * - binding line missing (400 binding_mismatch)
 * - 正常系: KV に binding を書き込み、TTL 30d、github_login echo
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { handleMcpPairRegisterViaGithubComment } from "../../src/handlers/mcp-pair-register-via-github-comment";
import {
  OAT_BINDING_TTL_SEC,
  getOatBinding,
} from "../../src/lib/mcp-oat-binding";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth-staging.test.example";
const OAT_HASH =
  "a".repeat(64); // 64-char hex
const NONCE = "nonce-1234abcd";
const COMMENT_URL =
  "https://api.github.com/repos/ippoan/auth-worker/issues/comments/12345";

function envWith(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    ...overrides,
  });
  return { env, kv };
}

function buildReq(opts: {
  body?: string | object;
  contentType?: string;
  ip?: string;
} = {}): Request {
  const headers: Record<string, string> = {
    "Content-Type": opts.contentType ?? "application/json",
  };
  if (opts.ip) headers["CF-Connecting-IP"] = opts.ip;
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

beforeEach(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("handleMcpPairRegisterViaGithubComment — env guards", () => {
  it("503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: ISSUER });
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
});
