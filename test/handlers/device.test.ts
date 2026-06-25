import { describe, it, expect } from "vitest";
import {
  handleDevicePair,
  handleDeviceToken,
  handleDeviceRevoke,
} from "../../src/handlers/device";
import { createDeviceCredential } from "../../src/lib/device";
import { verifyJwt } from "../../src/lib/jwt";
import { createMockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "device-test-secret";
const ENV = "staging";

function makeEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_CONFIG: createMockKV(),
    JWT_SECRET: SECRET,
    WORKER_ENV: ENV,
    ...overrides,
  } as unknown as Env;
}

function post(path: string, body?: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://auth.ippoan.org${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/** operator session JWT (tenant_id claim, env match). */
async function opToken(claims: Record<string, unknown> = {}): Promise<string> {
  return signTestJwt({ tenant_id: "tenant-1", email: "op@example.com", env: ENV, ...claims }, SECRET);
}

describe("handleDevicePair", () => {
  it("401 without a session", async () => {
    const res = await handleDevicePair(post("/device/pair", {}), makeEnv());
    expect(res.status).toBe(401);
  });

  it("401 for an invalid bearer token", async () => {
    const res = await handleDevicePair(post("/device/pair", {}, bearer("garbage")), makeEnv());
    expect(res.status).toBe(401);
  });

  it("401 when JWT_SECRET is unset", async () => {
    const t = await opToken();
    const res = await handleDevicePair(post("/device/pair", {}, bearer(t)), makeEnv({ JWT_SECRET: undefined }));
    expect(res.status).toBe(401);
  });

  it("401 when the session has no tenant", async () => {
    const t = await signTestJwt({ email: "x@y", env: ENV }, SECRET); // no tenant_id/org
    const res = await handleDevicePair(post("/device/pair", {}, bearer(t)), makeEnv());
    expect(res.status).toBe(401);
  });

  it("issues a credential bound to the operator tenant (201)", async () => {
    const env = makeEnv();
    const res = await handleDevicePair(post("/device/pair", { label: "ohishi-data" }, bearer(await opToken())), env);
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, string>;
    expect(body.device_id).toBeTruthy();
    expect(body.device_secret).toBeTruthy();
    expect(body.tenant_id).toBe("tenant-1");
    expect(body.label).toBe("ohishi-data");
  });

  it("defaults the label and accepts the org claim as tenant", async () => {
    const env = makeEnv();
    const t = await signTestJwt({ org: "org-9", env: ENV }, SECRET); // org fallback, no label
    const res = await handleDevicePair(post("/device/pair", {}, bearer(t)), env);
    const body = (await res.json()) as Record<string, string>;
    expect(body.tenant_id).toBe("org-9");
    expect(body.label).toBe("device");
  });
});

describe("handleDeviceToken", () => {
  it("400 when fields are missing (empty object)", async () => {
    const res = await handleDeviceToken(post("/device/token", {}), makeEnv());
    expect(res.status).toBe(400);
  });

  it("400 on malformed JSON body", async () => {
    const res = await handleDeviceToken(post("/device/token", "{bad"), makeEnv());
    expect(res.status).toBe(400);
  });

  it("400 on a non-object JSON body (number)", async () => {
    const res = await handleDeviceToken(post("/device/token", "5"), makeEnv());
    expect(res.status).toBe(400);
  });

  it("400 on a null JSON body", async () => {
    const res = await handleDeviceToken(post("/device/token", "null"), makeEnv());
    expect(res.status).toBe(400);
  });

  it("401 for an invalid credential", async () => {
    const res = await handleDeviceToken(
      post("/device/token", { device_id: "nope", device_secret: "x" }),
      makeEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("mints a verifiable device JWT for a valid credential", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "tenant-7", "l", 1700);
    const res = await handleDeviceToken(
      post("/device/token", { device_id: cred.device_id, device_secret: cred.device_secret }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.token_type).toBe("Bearer");
    expect(body.tenant_id).toBe("tenant-7");
    expect(typeof body.expires_in).toBe("number");
    const payload = await verifyJwt(body.access_token as string, SECRET, ENV);
    expect(payload?.tenant_id).toBe("tenant-7");
  });

  it("503 when JWT_SECRET is unset (mint fails)", async () => {
    const kv = createMockKV();
    const seedEnv = { AUTH_CONFIG: kv, JWT_SECRET: SECRET, WORKER_ENV: ENV } as unknown as Env;
    const cred = await createDeviceCredential(seedEnv, "t", "l", 1700);
    const noSecretEnv = { AUTH_CONFIG: kv, JWT_SECRET: undefined, WORKER_ENV: ENV } as unknown as Env;
    const res = await handleDeviceToken(
      post("/device/token", { device_id: cred.device_id, device_secret: cred.device_secret }),
      noSecretEnv,
    );
    expect(res.status).toBe(503);
  });
});

describe("handleDeviceRevoke", () => {
  it("401 without a session", async () => {
    const res = await handleDeviceRevoke(post("/device/revoke", { device_id: "x" }), makeEnv());
    expect(res.status).toBe(401);
  });

  it("400 when device_id is missing", async () => {
    const res = await handleDeviceRevoke(post("/device/revoke", {}, bearer(await opToken())), makeEnv());
    expect(res.status).toBe(400);
  });

  it("404 for an unknown device", async () => {
    const res = await handleDeviceRevoke(
      post("/device/revoke", { device_id: "missing" }, bearer(await opToken())),
      makeEnv(),
    );
    expect(res.status).toBe(404);
  });

  it("403 when the device belongs to another tenant", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "other-tenant", "l", 1700);
    const res = await handleDeviceRevoke(
      post("/device/revoke", { device_id: cred.device_id }, bearer(await opToken())),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("revokes a device owned by the operator tenant", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "tenant-1", "l", 1700);
    const res = await handleDeviceRevoke(
      post("/device/revoke", { device_id: cred.device_id }, bearer(await opToken())),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.revoked).toBe(true);
  });
});
