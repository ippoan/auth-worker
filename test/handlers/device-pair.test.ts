import { describe, it, expect } from "vitest";
import {
  handleDevicePairStart,
  handleDevicePairApprovePage,
  handleDevicePairApprove,
  handleDevicePairToken,
} from "../../src/handlers/device-pair";
import {
  startPairing,
  approvePairing,
  getPairingByUserCode,
} from "../../src/lib/device-pair";
import { createMockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "device-pair-test-secret";
const ENV = "staging";
const ISSUER = "https://auth.ippoan.org";
// handler は実 Date.now を使うため、seed する pairing も実時刻基準にして期限内に保つ。
const NOW = Math.floor(Date.now() / 1000);

function makeEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_CONFIG: createMockKV(),
    JWT_SECRET: SECRET,
    WORKER_ENV: ENV,
    ...overrides,
  } as unknown as Env;
}

function postJson(path: string, body?: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
}

function postForm(path: string, fields: Record<string, string>, headers: Record<string, string> = {}): Request {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) form.append(k, v);
  return new Request(`${ISSUER}${path}`, { method: "POST", headers, body: form });
}

function getReq(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, { method: "GET", headers });
}

async function opCookie(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
  const token = await signTestJwt({ tenant_id: "tenant-1", email: "op@example.com", env: ENV, ...claims }, SECRET);
  return { Cookie: `logi_auth_token=${token}` };
}

const ORIGIN = { Origin: ISSUER };

describe("handleDevicePairStart", () => {
  it("issues codes + verification URLs (201)", async () => {
    const res = await handleDevicePairStart(postJson("/device/pair/start", { label: "ohishi-data" }), makeEnv());
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.device_code).toBeTruthy();
    expect(body.user_code).toMatch(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
    expect(body.verification_uri).toBe(`${ISSUER}/device/pair/approve`);
    expect(body.verification_uri_complete).toContain("?user_code=");
    expect(typeof body.expires_in).toBe("number");
    expect(typeof body.interval).toBe("number");
  });

  it("defaults the label when body has no string label", async () => {
    const env = makeEnv();
    const res = await handleDevicePairStart(postJson("/device/pair/start", { label: 5 }), env);
    const body = (await res.json()) as Record<string, string>;
    const kv = env.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    const state = JSON.parse(kv._data[`devpair:dc:${body.device_code}`]!);
    expect(state.label).toBe("headless device");
  });
});

describe("handleDevicePairApprovePage", () => {
  it("redirects to /login without a session cookie", async () => {
    const res = await handleDevicePairApprovePage(getReq("/device/pair/approve?user_code=AAAA-AAAA"), makeEnv());
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("/login?redirect_uri=");
  });

  it("redirects when JWT_SECRET is unset", async () => {
    const res = await handleDevicePairApprovePage(
      getReq("/device/pair/approve", await opCookie()),
      makeEnv({ JWT_SECRET: undefined }),
    );
    expect(res.status).toBe(302);
  });

  it("redirects for a garbage cookie token", async () => {
    const res = await handleDevicePairApprovePage(
      getReq("/device/pair/approve", { Cookie: "logi_auth_token=garbage" }),
      makeEnv(),
    );
    expect(res.status).toBe(302);
  });

  it("redirects when the session has no tenant", async () => {
    const token = await signTestJwt({ email: "x@y", env: ENV }, SECRET);
    const res = await handleDevicePairApprovePage(
      getReq("/device/pair/approve", { Cookie: `logi_auth_token=${token}` }),
      makeEnv(),
    );
    expect(res.status).toBe(302);
  });

  it("400 for a malformed user_code", async () => {
    const res = await handleDevicePairApprovePage(
      getReq("/device/pair/approve?user_code=bad", await opCookie()),
      makeEnv(),
    );
    expect(res.status).toBe(400);
  });

  it("404 when the code is unknown", async () => {
    const res = await handleDevicePairApprovePage(
      getReq("/device/pair/approve?user_code=AAAA-AAAA", await opCookie()),
      makeEnv(),
    );
    expect(res.status).toBe(404);
  });

  it("renders the approval form for a pending code", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "ohishi-data", NOW);
    const res = await handleDevicePairApprovePage(
      getReq(`/device/pair/approve?user_code=${p.user_code}`, await opCookie()),
      env,
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(p.user_code);
    expect(html).toContain("ohishi-data");
    expect(html).toContain("op@example.com");
  });

  it("falls back to (unknown) when the session has no email", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    const token = await signTestJwt({ org: "org-9", env: ENV }, SECRET); // tenant via org, no email
    const res = await handleDevicePairApprovePage(
      getReq(`/device/pair/approve?user_code=${p.user_code}`, { Cookie: `logi_auth_token=${token}` }),
      env,
    );
    const html = await res.text();
    expect(html).toContain("(unknown)");
  });

  it("409 when the code is already approved", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    await approvePairing(env, p.user_code, "tenant-1", NOW);
    const res = await handleDevicePairApprovePage(
      getReq(`/device/pair/approve?user_code=${p.user_code}`, await opCookie()),
      env,
    );
    expect(res.status).toBe(409);
  });
});

describe("handleDevicePairApprove", () => {
  it("401 without a session", async () => {
    const res = await handleDevicePairApprove(postForm("/device/pair/approve", { user_code: "AAAA-AAAA", action: "approve" }, ORIGIN), makeEnv());
    expect(res.status).toBe(401);
  });

  it("403 on Origin mismatch", async () => {
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: "AAAA-AAAA", action: "approve" }, { ...(await opCookie()), Origin: "https://evil.example" }),
      makeEnv(),
    );
    expect(res.status).toBe(403);
  });

  it("400 when the body is not form-encoded", async () => {
    const res = await handleDevicePairApprove(
      postJson("/device/pair/approve", "not-a-form", { ...(await opCookie()), ...ORIGIN }),
      makeEnv(),
    );
    expect(res.status).toBe(400);
  });

  it("400 for a malformed user_code", async () => {
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: "bad", action: "approve" }, { ...(await opCookie()), ...ORIGIN }),
      makeEnv(),
    );
    expect(res.status).toBe(400);
  });

  it("400 when user_code field is absent", async () => {
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { action: "approve" }, { ...(await opCookie()), ...ORIGIN }),
      makeEnv(),
    );
    expect(res.status).toBe(400);
  });

  it("400 when action field is absent", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: p.user_code }, { ...(await opCookie()), ...ORIGIN }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("deny returns a 200 page without approving", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: p.user_code, action: "deny" }, { ...(await opCookie()), ...ORIGIN }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await getPairingByUserCode(env, p.user_code, NOW).then((s) => s?.status)).toBe("pending");
  });

  it("400 for an unknown action", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: p.user_code, action: "maybe" }, { ...(await opCookie()), ...ORIGIN }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("approves a pending code (200) and records tenant", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: p.user_code, action: "approve" }, { ...(await opCookie()), ...ORIGIN }),
      env,
    );
    expect(res.status).toBe(200);
    const st = await getPairingByUserCode(env, p.user_code, NOW);
    expect(st?.status).toBe("approved");
    expect(st?.tenant_id).toBe("tenant-1");
  });

  it("404 when approving an unknown code", async () => {
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: "AAAA-AAAA", action: "approve" }, { ...(await opCookie()), ...ORIGIN }),
      makeEnv(),
    );
    expect(res.status).toBe(404);
  });

  it("410 when the code expired", async () => {
    const env = makeEnv();
    // 過去の時刻で stamp して expires_at を実 Date.now より前にする → handler は期限切れ扱い。
    const p = await startPairing(env, "l", NOW - 10000);
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: p.user_code, action: "approve" }, { ...(await opCookie()), ...ORIGIN }),
      env,
    );
    expect(res.status).toBe(410);
  });

  it("409 when already approved", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    await approvePairing(env, p.user_code, "tenant-1", NOW);
    const res = await handleDevicePairApprove(
      postForm("/device/pair/approve", { user_code: p.user_code, action: "approve" }, { ...(await opCookie()), ...ORIGIN }),
      env,
    );
    expect(res.status).toBe(409);
  });
});

describe("handleDevicePairToken", () => {
  it("400 when device_code is missing", async () => {
    const res = await handleDevicePairToken(postJson("/device/pair/token", {}), makeEnv());
    expect(res.status).toBe(400);
  });

  it("400 on a malformed JSON body", async () => {
    const res = await handleDevicePairToken(postJson("/device/pair/token", "{bad"), makeEnv());
    expect(res.status).toBe(400);
  });

  it("400 on a non-object JSON body", async () => {
    const res = await handleDevicePairToken(postJson("/device/pair/token", "5"), makeEnv());
    expect(res.status).toBe(400);
  });

  it("pending before approval", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "l", NOW);
    const res = await handleDevicePairToken(postJson("/device/pair/token", { device_code: p.device_code }), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, string>).status).toBe("pending");
  });

  it("returns credential once after approval, then consumed (410)", async () => {
    const env = makeEnv();
    const p = await startPairing(env, "ohishi-data", NOW);
    await approvePairing(env, p.user_code, "tenant-9", NOW);

    const res1 = await handleDevicePairToken(postJson("/device/pair/token", { device_code: p.device_code }), env);
    expect(res1.status).toBe(200);
    const body1 = (await res1.json()) as Record<string, string>;
    expect(body1.status).toBe("approved");
    expect(body1.device_id).toBeTruthy();
    expect(body1.device_secret).toBeTruthy();
    expect(body1.tenant_id).toBe("tenant-9");
    expect(body1.label).toBe("ohishi-data");

    const res2 = await handleDevicePairToken(postJson("/device/pair/token", { device_code: p.device_code }), env);
    expect(res2.status).toBe(410);
    expect(((await res2.json()) as Record<string, string>).status).toBe("consumed");
  });

  it("410 when the device_code is unknown/expired", async () => {
    const res = await handleDevicePairToken(postJson("/device/pair/token", { device_code: "missing" }), makeEnv());
    expect(res.status).toBe(410);
    expect(((await res.json()) as Record<string, string>).status).toBe("expired");
  });
});
