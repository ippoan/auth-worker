/**
 * Tests for handleHealthOAuth (issue #209 PR1 — Google probe + JWT guard).
 *
 * 外部 provider (Google) を実際に叩かないよう、fetch を vi.stubGlobal で差し替える。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import { handleHealthOAuth } from "../../src/handlers/health-oauth";

async function authedRequest(): Promise<Request> {
  const token = await signTestJwt({ sub: "ci" }, TEST_JWT_SECRET);
  return new Request("https://auth.test.example/health/oauth", {
    headers: { Authorization: `Bearer ${token}` },
  });
}

interface OAuthBody {
  checked_at: string;
  overall: "ok" | "degraded" | "unknown";
  providers: {
    google:
      | { configured: false }
      | { configured: true; ok: boolean; status: number; hint?: string }
      | { configured: true; unknown: true; hint: string };
  };
}

describe("handleHealthOAuth", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 503 when JWT_SECRET is empty (fail-closed)", async () => {
    const env = createMockEnv({ JWT_SECRET: "" });
    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe("server not configured");
  });

  it("returns 401 when Authorization header is missing", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/health/oauth");
    const res = await handleHealthOAuth(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 401 when Bearer token signature is invalid", async () => {
    const env = createMockEnv();
    const badToken = await signTestJwt({ sub: "ci" }, "wrong-secret");
    const req = new Request("https://auth.test.example/health/oauth", {
      headers: { Authorization: `Bearer ${badToken}` },
    });
    const res = await handleHealthOAuth(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 401 when header has Bearer but no token", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/health/oauth", {
      headers: { Authorization: "Basic xxx" },
    });
    const res = await handleHealthOAuth(req, env);
    expect(res.status).toBe(401);
  });

  it("reports configured:false for Google when GOOGLE_CLIENT_ID is empty", async () => {
    const env = createMockEnv({ GOOGLE_CLIENT_ID: "" });
    // fetch must NOT be called for skipped providers.
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("ok");
    expect(body.providers.google).toEqual({ configured: false });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("reports ok when Google returns 302 to /v3/signin/identifier (real happy-path)", async () => {
    // 実応答観測: 正常時の Location は /v3/signin/identifier (path に
    // /signin/oauth/error を含まず、authError も無い)
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: {
          Location:
            "https://accounts.google.com/v3/signin/identifier?opparams=%253F&access_type=online&client_id=valid.apps.googleusercontent.com",
        },
      }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("ok");
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(true);
    expect(g.status).toBe(302);
    expect(typeof body.checked_at).toBe("string");
  });

  it("reports degraded (503) when Google 302s to /signin/oauth/error with authError= (real invalid_client)", async () => {
    // 実応答観測: 不正 client_id で Google は 302 + Location
    // /signin/oauth/error?authError=Cg5pbnZhbGlkX2NsaWVudBI... (base64 で
    // "invalid_client / The OAuth client was not found.")
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: {
          Location:
            "https://accounts.google.com/signin/oauth/error?authError=Cg5pbnZhbGlkX2NsaWVudBIfVGhlIE9BdXRoIGNsaWVudCB3YXMgbm90IGZvdW5kLiCRAw&flowName=GeneralOAuthFlow",
        },
      }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("degraded");
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
    expect(g.hint).toMatch(/client_id/);
  });

  it("reports degraded (503) when Location has plain 'error=' query (defensive)", async () => {
    // 観測では出ないが、Google 仕様変更で `error=` クエリで返されたケースの保険。
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { Location: "https://accounts.google.com/o/oauth2/v2/auth?error=invalid_client" },
      }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
  });

  it("reports unknown when 30x redirects to an unexpected host", async () => {
    // Google が別 host (CDN, etc.) に飛ばすことは観測されなかったが、防御的に
    // host mismatch は ok とも fail とも言えない → unknown。
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { Location: "https://example.com/somewhere" },
      }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/example\.com/);
  });

  it("reports unknown when 30x Location is a malformed URL", async () => {
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { Location: "not a url" },
      }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/malformed Location/);
  });

  it("reports degraded (503) when Google returns 400 with 'OAuth client was not found'", async () => {
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(
        "<html>Error 401 — The OAuth client was not found.</html>",
        { status: 400 },
      ),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
    expect(g.status).toBe(400);
    expect(g.hint).toMatch(/client_id/);
  });

  it("reports degraded when Google returns 200 with invalid_client error body", async () => {
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response("error=invalid_client", { status: 200 }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
    expect(g.status).toBe(200);
  });

  it("reports unknown when Google returns unexpected non-redirect 2xx", async () => {
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response("totally fine", { status: 200 }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    // unknown → 200 (CI should NOT fail on unknown, only on degraded)
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.unknown).toBe(true);
    expect(g.hint).toMatch(/unexpected status 200/);
  });

  it("reports unknown when fetch itself throws (network/timeout)", async () => {
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce(new Error("timeout")));

    const res = await handleHealthOAuth(await authedRequest(), env);
    expect(res.status).toBe(200);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toMatch(/timeout/);
  });

  it("handles fetch throwing a non-Error value", async () => {
    const env = createMockEnv();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce("network down"));

    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("unknown" in g)) throw new Error("expected unknown variant");
    expect(g.hint).toContain("network down");
  });

  it("treats redirect without Location header as unknown status", async () => {
    const env = createMockEnv();
    // 302 but no Location header → falls through to body-sniff path.
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response("", { status: 302 }),
    ));

    const res = await handleHealthOAuth(await authedRequest(), env);
    const body = await res.json() as OAuthBody;
    expect(body.overall).toBe("unknown");
  });

  it("tolerates body.text() throwing when sniffing error body", async () => {
    const env = createMockEnv();
    const broken = new Response("placeholder", { status: 400 });
    // Replace text() with a thrower.
    (broken as unknown as { text: () => Promise<string> }).text = () => {
      throw new Error("body read failed");
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(broken));

    const res = await handleHealthOAuth(await authedRequest(), env);
    // status >= 400 → invalid regardless of body
    expect(res.status).toBe(503);
    const body = await res.json() as OAuthBody;
    const g = body.providers.google;
    if (!("ok" in g)) throw new Error("expected ok variant");
    expect(g.ok).toBe(false);
  });
});
