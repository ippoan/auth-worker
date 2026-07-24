/**
 * `mcp-github-grant.ts` — GitHub login → MCP binding_jwt 発行の共通入口。
 * 2026-07-24: `mcp-pair-grant-via-github.ts` の ACL 欠落修正 (issue 参照は
 * PR description) に伴い新設。この関数を経由する限り
 * `GITHUB_MCP_USER_ALLOWLIST` の fail-closed チェックを省略できないことを
 * 確認する regression test。
 */
import { describe, it, expect } from "vitest";
import {
  grantMcpBindingJwtForGithubLogin,
  isGithubLoginAllowed,
  parseGithubMcpAllowlist,
} from "../../src/lib/mcp-github-grant";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import { createMockEnv } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!!!!!";

function envWith(allowlist: string | undefined): Env {
  return createMockEnv({
    GITHUB_MCP_USER_ALLOWLIST: allowlist,
  } as Partial<Env>);
}

describe("parseGithubMcpAllowlist", () => {
  it("valid JSON string array をそのまま返す", () => {
    expect(parseGithubMcpAllowlist('["alice","bob"]')).toEqual(["alice", "bob"]);
  });

  it("undefined/空文字は空配列 (deny all)", () => {
    expect(parseGithubMcpAllowlist(undefined)).toEqual([]);
    expect(parseGithubMcpAllowlist("")).toEqual([]);
  });

  it("不正 JSON は空配列 (fail-closed)", () => {
    expect(parseGithubMcpAllowlist("not-json")).toEqual([]);
  });

  it("非 array JSON は空配列 (fail-closed)", () => {
    expect(parseGithubMcpAllowlist('{"login":"alice"}')).toEqual([]);
  });

  it("文字列以外を含む array は空配列 (fail-closed)", () => {
    expect(parseGithubMcpAllowlist('["alice", 123]')).toEqual([]);
  });
});

describe("isGithubLoginAllowed", () => {
  it("allowlist に含まれる login は true", async () => {
    const env = envWith('["alice","bob"]');
    expect(await isGithubLoginAllowed(env, "alice")).toBe(true);
  });

  it("allowlist に無い login は false", async () => {
    const env = envWith('["alice"]');
    expect(await isGithubLoginAllowed(env, "mallory")).toBe(false);
  });

  it("allowlist 未設定は false (fail-closed、権限昇格を防ぐ)", async () => {
    const env = envWith(undefined);
    expect(await isGithubLoginAllowed(env, "alice")).toBe(false);
  });
});

describe("grantMcpBindingJwtForGithubLogin", () => {
  it("allowlist 内の login には binding_jwt を mint する", async () => {
    const env = envWith('["alice"]');
    const result = await grantMcpBindingJwtForGithubLogin(env, MCP_JWT_SECRET, {
      login: "alice",
      scope: "mcp.read mcp.write",
      aud: "github-mcp-server-rs",
      ttlSec: 3600,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    const claims = await verifyMcpJwt(result.jwt, MCP_JWT_SECRET, "github-mcp-server-rs");
    expect(claims).not.toBeNull();
    expect(claims!.sub).toBe("github:alice");
    expect(claims!.github_login).toBe("alice");
    expect(claims!.scope).toBe("mcp.read mcp.write");
  });

  it("allowlist 外の login は mint せず not_allowed を返す", async () => {
    const env = envWith('["alice"]');
    const result = await grantMcpBindingJwtForGithubLogin(env, MCP_JWT_SECRET, {
      login: "mallory",
      scope: "mcp.read mcp.write",
      aud: "github-mcp-server-rs",
      ttlSec: 3600,
    });
    expect(result).toEqual({ ok: false, reason: "not_allowed" });
  });

  it("allowlist 未設定 (fail-closed) では誰も mint できない", async () => {
    const env = envWith(undefined);
    const result = await grantMcpBindingJwtForGithubLogin(env, MCP_JWT_SECRET, {
      login: "alice",
      scope: "mcp.read mcp.write",
      aud: "github-mcp-server-rs",
      ttlSec: 3600,
    });
    expect(result).toEqual({ ok: false, reason: "not_allowed" });
  });
});
