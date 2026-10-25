/**
 * 参加ページ `GET /join/:slug` — 会社は alc-auth-worker の `GET /internal/tenant-by-slug/{slug}` で引く
 * (Refs ippoan/rust-alc-api#680)。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { createFakeAlcAuth, FAKE_ALC_AUTH_SECRET, type FakeAlcAuth } from "../helpers/fake-alc-auth";
import type { Env } from "../../src/index";

vi.mock("../../src/lib/join-html", () => ({
  renderJoinPage: vi.fn(() => "<html>mock join page</html>"),
  renderJoinNotFoundPage: vi.fn(() => "<html>mock not found</html>"),
}));

import { handleJoinPage } from "../../src/handlers/join-page";
import { renderJoinPage, renderJoinNotFoundPage } from "../../src/lib/join-html";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function withAlcAuth(respond: (req: Request) => Response, extra: Partial<Env> = {}): { env: Env; alcAuth: FakeAlcAuth } {
  const alcAuth = createFakeAlcAuth({ override: respond });
  return {
    alcAuth,
    env: createMockEnv({ ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET, ...extra }),
  };
}

const page = new Request("https://auth.test.example/join/acme");

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", vi.fn(async () => new Response("cloud run should not be called", { status: 599 })));
});

describe("handleJoinPage", () => {
  it("会社が在れば名前と slug でページを出す (Google が設定されていればボタンも)", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, { found: true, id: "t", name: "Acme", slug: "acme" }));
    const res = await handleJoinPage(page, env, "acme");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock join page</html>");
    expect(renderJoinPage).toHaveBeenCalledWith({
      orgName: "Acme",
      orgSlug: "acme",
      googleEnabled: true,
      authWorkerOrigin: "https://auth.test.example",
    });
    expect(new URL(alcAuth.calls[0]!.url).pathname).toBe("/internal/tenant-by-slug/acme");
  });

  it("slug は URL エンコードして引く。Google が無ければボタンを出さない", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, { found: true, id: "t", name: "A", slug: "a b" }), {
      GOOGLE_CLIENT_ID: undefined as never,
    });
    await handleJoinPage(page, env, "a b");
    expect(new URL(alcAuth.calls[0]!.url).pathname).toBe("/internal/tenant-by-slug/a%20b");
    expect(renderJoinPage).toHaveBeenCalledWith(expect.objectContaining({ googleEnabled: false }));
  });

  it("会社が無ければ 404 のページ", async () => {
    const { env } = withAlcAuth(() => json(404, { error: "tenant_not_found" }));
    const res = await handleJoinPage(page, env, "nope");
    expect(res.status).toBe(404);
    expect(await res.text()).toBe("<html>mock not found</html>");
    expect(renderJoinNotFoundPage).toHaveBeenCalled();
  });

  it("alc-auth-worker の失敗・binding 無しは 500", async () => {
    for (const env of [
      withAlcAuth(() => json(500, { error: "internal_error" })).env,
      createMockEnv({ ALC_AUTH: undefined }),
    ]) {
      const res = await handleJoinPage(page, env, "acme");
      expect(res.status).toBe(500);
      expect(await res.text()).toBe("Internal Server Error");
    }
  });
});
