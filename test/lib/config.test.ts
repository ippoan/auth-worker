import { describe, expect, it, beforeEach } from "vitest";
import { getAllowedOrigins, _clearAllowedOriginsCache } from "../../src/lib/config";
import { createMockEnv, createMockKV } from "../helpers/mock-env";

describe("getAllowedOrigins", () => {
  beforeEach(() => {
    _clearAllowedOriginsCache();
  });

  it("unions origins:<WORKER_ENV>, origins:dev and origins:wt", async () => {
    const env = createMockEnv({
      WORKER_ENV: "prod",
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://a.example,https://b.example",
        "origins:dev": "https://x-dev.example",
        "origins:wt": "https://fluffy-frog.trycloudflare.com",
        "origins:staging": "https://should-not-appear.example",
      }),
    });

    const result = await getAllowedOrigins(env);
    expect(result).toBe(
      "https://a.example,https://b.example,https://x-dev.example,https://fluffy-frog.trycloudflare.com",
    );
  });

  it("reads origins:staging when WORKER_ENV=staging", async () => {
    const env = createMockEnv({
      WORKER_ENV: "staging",
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://prod-only.example",
        "origins:staging": "https://staging.example",
        "origins:dev": "https://dev.example",
        "origins:wt": "https://wt.trycloudflare.com",
      }),
    });

    const result = await getAllowedOrigins(env);
    expect(result).toBe(
      "https://staging.example,https://dev.example,https://wt.trycloudflare.com",
    );
  });

  it("returns empty string when KV is empty", async () => {
    const env = createMockEnv({
      WORKER_ENV: "prod",
      AUTH_CONFIG: createMockKV(),
    });

    const result = await getAllowedOrigins(env);
    expect(result).toBe("");
  });

  it("returns empty string when KV throws", async () => {
    const env = createMockEnv({
      WORKER_ENV: "prod",
      AUTH_CONFIG: {
        get: async () => {
          throw new Error("kv down");
        },
      } as unknown as KVNamespace,
    });

    const result = await getAllowedOrigins(env);
    expect(result).toBe("");
  });

  it("caches origins:<WORKER_ENV> and origins:dev but re-reads origins:wt each call", async () => {
    const calls: Record<string, number> = {};
    const env = createMockEnv({
      WORKER_ENV: "prod",
      AUTH_CONFIG: {
        get: async (key: string) => {
          calls[key] = (calls[key] ?? 0) + 1;
          if (key === "origins:prod") return "https://cached.example";
          if (key === "origins:wt") return "https://ephemeral.example";
          return null;
        },
      } as unknown as KVNamespace,
    });

    await getAllowedOrigins(env);
    await getAllowedOrigins(env);
    await getAllowedOrigins(env);

    expect(calls["origins:prod"]).toBe(1); // cached
    expect(calls["origins:dev"]).toBe(1); // cached
    expect(calls["origins:wt"]).toBe(3); // NOT cached — fresh read every call
  });

  it("defaults WORKER_ENV to 'prod' when unset", async () => {
    const env = createMockEnv({
      WORKER_ENV: "",
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://default-prod.example",
      }),
    });

    const result = await getAllowedOrigins(env);
    expect(result).toBe("https://default-prod.example");
  });

  it("includes origins:wt when other keys are missing", async () => {
    const env = createMockEnv({
      WORKER_ENV: "prod",
      AUTH_CONFIG: createMockKV({
        "origins:wt": "https://only-wt.trycloudflare.com",
      }),
    });

    const result = await getAllowedOrigins(env);
    expect(result).toBe("https://only-wt.trycloudflare.com");
  });

  it("reflects origins:wt updates immediately (no in-memory cache)", async () => {
    let wtValue = "https://first.trycloudflare.com";
    const env = createMockEnv({
      WORKER_ENV: "prod",
      AUTH_CONFIG: {
        get: async (key: string) => {
          if (key === "origins:wt") return wtValue;
          return null;
        },
      } as unknown as KVNamespace,
    });

    const r1 = await getAllowedOrigins(env);
    expect(r1).toBe("https://first.trycloudflare.com");

    // simulate `wrangler kv key put origins:wt <new>` returning a new value
    wtValue = "https://second.trycloudflare.com";

    const r2 = await getAllowedOrigins(env);
    expect(r2).toBe("https://second.trycloudflare.com");
  });
});
