import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { getOrRegisterDcrClient } from "../src/dcr";
import { makeKv } from "./_helpers";

const REDIRECT_URI = "https://ci-dashboard.ippoan.org/oauth/callback";
const AUTH_WORKER_ORIGIN = "https://auth.ippoan.org";
const DCR_KEY = "auth-client-worker:dcr-client";

describe("getOrRegisterDcrClient", () => {
  let kv: KVNamespace;
  beforeEach(() => { kv = makeKv(); });
  afterEach(() => { vi.restoreAllMocks(); });

  it("registers on first call and caches the result in KV", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        client_id: "dcr-uuid-123",
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: [REDIRECT_URI],
      }),
    );

    const client = await getOrRegisterDcrClient({
      authWorkerOrigin: AUTH_WORKER_ORIGIN,
      redirectUri: REDIRECT_URI,
      kv,
      scope: "mcp.write mcp.workflow mcp.project",
      clientName: "ci-dashboard",
    });
    expect(client.client_id).toBe("dcr-uuid-123");
    expect(spy).toHaveBeenCalledTimes(1);

    const call = spy.mock.calls[0]!;
    expect(call[0]).toBe("https://auth.ippoan.org/mcp/register");
    const body = JSON.parse(call[1]!.body as string);
    expect(body.redirect_uris).toEqual([REDIRECT_URI]);
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.grant_types).toEqual(["authorization_code", "refresh_token"]);
    expect(body.response_types).toEqual(["code"]);
    expect(body.scope).toBe("mcp.write mcp.workflow mcp.project");
    expect(body.client_name).toBe("ci-dashboard");

    const cached = await kv.get(DCR_KEY, "json") as { client_id: string };
    expect(cached.client_id).toBe("dcr-uuid-123");
  });

  it("returns the cached client when within TTL and redirect_uri matches", async () => {
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-cached",
      redirect_uri: REDIRECT_URI,
      issued_at_ms: Date.now() - 60_000,
    }));
    const spy = vi.spyOn(globalThis, "fetch");

    const client = await getOrRegisterDcrClient({
      authWorkerOrigin: AUTH_WORKER_ORIGIN,
      redirectUri: REDIRECT_URI,
      kv,
    });
    expect(client.client_id).toBe("dcr-cached");
    expect(spy).not.toHaveBeenCalled();
  });

  it("re-registers when within 10d of the upstream 90d TTL", async () => {
    const eightyOneDaysAgo = Date.now() - 81 * 24 * 60 * 60 * 1000;
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-stale",
      redirect_uri: REDIRECT_URI,
      issued_at_ms: eightyOneDaysAgo,
    }));
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ client_id: "dcr-fresh" }),
    );

    const client = await getOrRegisterDcrClient({
      authWorkerOrigin: AUTH_WORKER_ORIGIN,
      redirectUri: REDIRECT_URI,
      kv,
    });
    expect(client.client_id).toBe("dcr-fresh");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("re-registers when the cached redirect_uri drifted from config", async () => {
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-old-uri",
      redirect_uri: "https://old.example.com/oauth/callback",
      issued_at_ms: Date.now() - 60_000,
    }));
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ client_id: "dcr-new" }),
    );

    const client = await getOrRegisterDcrClient({
      authWorkerOrigin: AUTH_WORKER_ORIGIN,
      redirectUri: REDIRECT_URI,
      kv,
    });
    expect(client.client_id).toBe("dcr-new");
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("throws verbosely when /mcp/register returns an error", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("invalid_client_metadata", { status: 400 }),
    );
    await expect(getOrRegisterDcrClient({
      authWorkerOrigin: AUTH_WORKER_ORIGIN,
      redirectUri: REDIRECT_URI,
      kv,
    })).rejects.toThrow(/\/mcp\/register failed \(400\).*invalid_client_metadata/);
  });
});
