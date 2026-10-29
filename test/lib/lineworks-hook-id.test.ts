import { describe, expect, it } from "vitest";

import {
  decodeHookId,
  encodeHookId,
  handleWebhookUrlPath,
  WEBHOOK_URL_PATH,
} from "../../src/lib/lineworks-hook-id";

const KEY = "test-sso-key";
const T = "11111111-2222-4333-8444-555555555555";

describe("encodeHookId / decodeHookId", () => {
  it("round-trips and is deterministic per (tenant, bot)", async () => {
    const a = await encodeHookId({ tenantId: T, botId: "13333925" }, KEY);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a).not.toContain(T);
    expect(await encodeHookId({ tenantId: T.toUpperCase(), botId: "13333925" }, KEY)).toBe(a);
    expect(await decodeHookId(a, KEY)).toEqual({ tenantId: T, botId: "13333925" });

    const b = await encodeHookId({ tenantId: T, botId: "8977068" }, KEY);
    expect(b).not.toBe(a);
    // IV (先頭 12 バイト) も平文ごとに違う
    expect(b.slice(0, 16)).not.toBe(a.slice(0, 16));
  });

  it("rejects ids made with another key, tampered, or malformed", async () => {
    const id = await encodeHookId({ tenantId: T, botId: "b1" }, KEY);
    expect(await decodeHookId(id, "other-key")).toBeNull();

    const last = id.at(-1) === "A" ? "B" : "A";
    expect(await decodeHookId(id.slice(0, -1) + last, KEY)).toBeNull();
    expect(await decodeHookId("not+base64", KEY)).toBeNull();
    expect(await decodeHookId("A", KEY)).toBeNull();
    expect(await decodeHookId("AAAA", KEY)).toBeNull();
  });

  it("rejects a validly sealed id whose IV is not the synthetic one", async () => {
    // 同じ派生の鍵で、IV だけ乱数にして封じる (encodeHookId 以外の作り方)。GCM は通るが IV の検査で落ちる
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey("raw", enc.encode(KEY), "HKDF", false, ["deriveKey"]);
    const aes = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("lineworks-webhook-hook-id/v1/enc") },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, enc.encode(`${T}\nb1`)),
    );
    const raw = new Uint8Array([...iv, ...sealed]);
    const id = btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await decodeHookId(id, KEY)).toBeNull();
  });

  it("refuses to encode a non-uuid tenant or an empty / multi-line bot_id", async () => {
    await expect(encodeHookId({ tenantId: "t1", botId: "b" }, KEY)).rejects.toThrow("uuid");
    await expect(encodeHookId({ tenantId: T, botId: "" }, KEY)).rejects.toThrow("bot_id");
    await expect(encodeHookId({ tenantId: T, botId: "a\nb" }, KEY)).rejects.toThrow("bot_id");
  });
});

describe("handleWebhookUrlPath", () => {
  const admin = { tenantId: T, role: "admin" };
  const call = (over: Partial<{ key: string | null; path: string; method: string; search: string; role: string }> = {}) =>
    handleWebhookUrlPath(
      "key" in over ? over.key : KEY,
      over.path ?? WEBHOOK_URL_PATH,
      over.method ?? "GET",
      over.search ?? "?bot_id=13333925",
      { ...admin, role: over.role ?? "admin" },
    );

  it("returns the hook path for the caller's tenant", async () => {
    const res = (await call())!;
    expect(res.status).toBe(200);
    const body = (await res.json()) as { path: string };
    expect(body.path).toMatch(/^\/lineworks\/hook\/[A-Za-z0-9_-]+$/);
    const id = body.path.slice("/lineworks/hook/".length);
    expect(await decodeHookId(id, KEY)).toEqual({ tenantId: T, botId: "13333925" });
  });

  it("passes other paths through and rejects bad requests", async () => {
    expect(await call({ path: "/api/leave/settings" })).toBeNull();
    expect((await call({ method: "POST" }))!.status).toBe(405);
    expect((await call({ role: "member" }))!.status).toBe(403);
    expect((await call({ search: "" }))!.status).toBe(400);
    expect((await call({ search: "?bot_id=a%0Ab" }))!.status).toBe(400);
    expect((await call({ key: null }))!.status).toBe(503);
    const bad = await handleWebhookUrlPath(KEY, WEBHOOK_URL_PATH, "GET", "?bot_id=b", {
      tenantId: "not-a-uuid",
      role: "admin",
    });
    expect(bad!.status).toBe(400);
    expect(await bad!.json()).toEqual({ error: "invalid_tenant" });
  });
});
