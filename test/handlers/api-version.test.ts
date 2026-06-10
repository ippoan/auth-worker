import { describe, it, expect } from "vitest";
import { createMockEnv, createMockKV } from "../helpers/mock-env";
import {
  handleVersion,
  DEV_PLANS_SNAPSHOT_KEY,
} from "../../src/handlers/version";
import type { ActivePlan } from "../../src/handlers/version";

interface VersionBody {
  auth_worker_version: string;
  active_plans: ActivePlan[];
}

function envWithSnapshot(raw?: string) {
  const initial: Record<string, string> = {};
  if (raw !== undefined) initial[DEV_PLANS_SNAPSHOT_KEY] = raw;
  return createMockEnv({ AUTH_CONFIG: createMockKV(initial) });
}

describe("handleVersion", () => {
  it("returns version and empty plans when snapshot key is absent", async () => {
    const res = await handleVersion(envWithSnapshot());

    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = await res.json() as VersionBody;
    expect(body.auth_worker_version).toBe("test");
    expect(body.active_plans).toEqual([]);
  });

  it("falls back to 'dev' when VERSION is empty", async () => {
    const env = envWithSnapshot();
    env.VERSION = "";
    const res = await handleVersion(env);

    const body = await res.json() as VersionBody;
    expect(body.auth_worker_version).toBe("dev");
  });

  it("returns plans from a bare-array snapshot", async () => {
    const snapshot: ActivePlan[] = [
      { id: "20260420_002_csv_parser_skeleton", stage: "ga" },
      { id: "20260502_001_new_csv_parser", stage: "early", scope: "ohishi-exp" },
    ];
    const res = await handleVersion(envWithSnapshot(JSON.stringify(snapshot)));

    const body = await res.json() as VersionBody;
    expect(body.active_plans).toEqual(snapshot);
  });

  it("returns plans from an object snapshot with active_plans key", async () => {
    const snapshot = {
      active_plans: [{ id: "20260510_001_tenko_v2_endpoint", stage: "applied" }],
    };
    const res = await handleVersion(envWithSnapshot(JSON.stringify(snapshot)));

    const body = await res.json() as VersionBody;
    expect(body.active_plans).toEqual(snapshot.active_plans);
  });

  it("filters malformed entries and drops empty scope", async () => {
    const snapshot = [
      { id: "valid_plan", stage: "ga", scope: "" },
      { id: "missing_stage" },
      { stage: "ga" },
      "not-an-object",
      null,
      { id: 123, stage: "ga" },
    ];
    const res = await handleVersion(envWithSnapshot(JSON.stringify(snapshot)));

    const body = await res.json() as VersionBody;
    expect(body.active_plans).toEqual([{ id: "valid_plan", stage: "ga" }]);
  });

  it("returns empty plans for malformed JSON snapshot", async () => {
    const res = await handleVersion(envWithSnapshot("{not json"));

    const body = await res.json() as VersionBody;
    expect(body.active_plans).toEqual([]);
  });

  it("returns empty plans when snapshot is JSON but not array/object shape", async () => {
    const res = await handleVersion(envWithSnapshot(JSON.stringify({ foo: 1 })));

    const body = await res.json() as VersionBody;
    expect(body.active_plans).toEqual([]);
  });

  it("fails open (empty plans) when KV read throws", async () => {
    const env = createMockEnv();
    env.AUTH_CONFIG = {
      get: async () => {
        throw new Error("kv down");
      },
    } as unknown as KVNamespace;

    const res = await handleVersion(env);

    expect(res.status).toBe(200);
    const body = await res.json() as VersionBody;
    expect(body.auth_worker_version).toBe("test");
    expect(body.active_plans).toEqual([]);
  });
});
