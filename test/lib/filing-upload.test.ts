import { describe, it, expect } from "vitest";
import { handleFilingUpload, issueFilingUpload, FILING_UPLOAD_KV_PREFIX } from "../../src/lib/filing-upload";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ID = "b".repeat(64);
const UPLOAD = { tenant_id: "tenant-uuid-1", user_id: "user-uuid-1", email: "dev@example.com", arrive_id: "20991231235959001e", name: "控え.zip" };
const ZIP = new Uint8Array([0x50, 0x4b, 3, 4, 1, 2]);

/** ALC_TENKO を模した Fetcher。受けた要求を記録する */
function tenkoEnv(answer: () => Response, kv = createMockKV() as MockKV) {
  const calls: Array<{ url: string; method: string; headers: Headers; body: Uint8Array }> = [];
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    ALC_TENKO: {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({ url: req.url, method: req.method, headers: req.headers, body: new Uint8Array(await req.arrayBuffer()) });
        return answer();
      },
    } as unknown as Env["ALC_TENKO"],
  });
  return { env, kv, calls };
}

const put = (body: BodyInit = ZIP, method = "PUT") => new Request(`https://auth.test.example/mcp/filing-upload/${ID}`, { method, body: method === "GET" ? undefined : body });

describe("filing-upload", () => {
  it("発行は KV に TTL つきで置き、AUTH_WORKER_ORIGIN の URL を返す (無ければ auth.ippoan.org)", async () => {
    const { env, kv } = tenkoEnv(() => new Response("{}"));
    const url = await issueFilingUpload(env, UPLOAD);
    const id = url.split("/mcp/filing-upload/")[1]!;
    expect(url.startsWith("https://auth.ippoan.org/mcp/filing-upload/") || url.startsWith(`${env.AUTH_WORKER_ORIGIN}/mcp/filing-upload/`)).toBe(true);
    expect(JSON.parse(kv._data[`${FILING_UPLOAD_KV_PREFIX}${id}`]!)).toEqual(UPLOAD);
    const withOrigin = createMockEnv({ MCP_OAUTH_KV: createMockKV(), AUTH_WORKER_ORIGIN: "https://auth.test.example" });
    expect(await issueFilingUpload(withOrigin, UPLOAD)).toMatch(/^https:\/\/auth\.test\.example\/mcp\/filing-upload\/[0-9a-f]{64}$/);
    const noOrigin = createMockEnv({ MCP_OAUTH_KV: createMockKV(), AUTH_WORKER_ORIGIN: undefined });
    expect(await issueFilingUpload(noOrigin, UPLOAD)).toMatch(/^https:\/\/auth\.ippoan\.org\/mcp\/filing-upload\//);
  });

  it("★ PUT は 1 回きりで、発行した人のテナントと admin の名乗りで控えの口へ本文を転送し、応答をそのまま返す", async () => {
    const answer = { id: UPLOAD.arrive_id, name: UPLOAD.name, size: 6 };
    const { env, kv, calls } = tenkoEnv(() => new Response(JSON.stringify(answer), { status: 200, headers: { "Content-Type": "application/json" } }));
    kv._data[`${FILING_UPLOAD_KV_PREFIX}${ID}`] = JSON.stringify(UPLOAD);
    const res = await handleFilingUpload(put(), env, ID);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(answer);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(calls).toHaveLength(1);
    const u = new URL(calls[0]!.url);
    expect([u.pathname, u.searchParams.get("name"), u.searchParams.get("meta"), calls[0]!.method]).toEqual([
      "/api/tenko/filing-archives/20991231235959001e", "控え.zip", '{"via":"mcp"}', "PUT",
    ]);
    const h = calls[0]!.headers;
    expect([h.get("X-Tenant-ID"), h.get("X-User-ID"), h.get("X-User-Email"), h.get("X-User-Role"), h.get("Content-Type")]).toEqual([
      "tenant-uuid-1", "user-uuid-1", "dev@example.com", "admin", "application/zip",
    ]);
    expect(calls[0]!.body).toEqual(ZIP);
    // 2 回目は消えていて 404
    expect((await handleFilingUpload(put(), env, ID)).status).toBe(404);
  });

  it("控えの口の失敗はそのまま返す (Content-Type が無ければ JSON とみなす)", async () => {
    const { env, kv } = tenkoEnv(() => new Response("bad", { status: 400 }));
    kv._data[`${FILING_UPLOAD_KV_PREFIX}${ID}`] = JSON.stringify(UPLOAD);
    const res = await handleFilingUpload(put(), env, ID);
    expect([res.status, await res.text()]).toEqual([400, "bad"]);
  });

  it("PUT 以外は 405、KV が無ければ 503、id の形でない・無い id は 404、binding が無ければ 503", async () => {
    const { env, kv } = tenkoEnv(() => new Response("{}"));
    expect((await handleFilingUpload(put(ZIP, "GET"), env, ID)).status).toBe(405);
    expect((await handleFilingUpload(put(), createMockEnv({ MCP_OAUTH_KV: undefined }), ID)).status).toBe(503);
    for (const bad of ["short", "B".repeat(64), `${"b".repeat(64)}x`]) {
      expect((await handleFilingUpload(put(), env, bad)).status).toBe(404);
    }
    expect((await handleFilingUpload(put(), env, ID)).status).toBe(404);
    const noBinding = createMockEnv({ MCP_OAUTH_KV: kv, ALC_TENKO: undefined });
    kv._data[`${FILING_UPLOAD_KV_PREFIX}${ID}`] = JSON.stringify(UPLOAD);
    const res = await handleFilingUpload(put(), noBinding, ID);
    expect([res.status, await res.json()]).toEqual([503, { error: "not_configured" }]);
  });
});
