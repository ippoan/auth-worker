import { describe, it, expect } from "vitest";
import {
  handleDevicePair,
  handleDevicePairInternal,
  handleDeviceToken,
  handleDeviceRevoke,
  handleDeviceHubToken,
  handleDeviceIntrospect,
  handleDeviceSiteBackfill,
} from "../../src/handlers/device";
import {
  createDeviceCredential,
  DEVICE_ROLE,
  DEVICE_ROLE_KIOSK,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_GATEWAY,
} from "../../src/lib/device";
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
    expect(body.role).toBe(DEVICE_ROLE); // role 省略 → 既定
  });

  it("honors an allowlisted role (kiosk)", async () => {
    const env = makeEnv();
    const res = await handleDevicePair(
      post("/device/pair", { label: "tablet", role: DEVICE_ROLE_KIOSK }, bearer(await opToken())),
      env,
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, string>;
    expect(body.role).toBe(DEVICE_ROLE_KIOSK);
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

describe("handleDevicePairInternal (rust-alc-api#434 caller #5)", () => {
  const INTERNAL = "internal-shared-secret-32chars!!";

  function internalEnv(overrides: Record<string, unknown> = {}): Env {
    return makeEnv({ INTERNAL_SHARED_SECRET: INTERNAL, ...overrides })
  }

  it("503 when no INTERNAL_SHARED_SECRET is bound", async () => {
    const res = await handleDevicePairInternal(
      post("/device/pair-internal", { tenant_id: "t1" }, { "X-Internal-Shared-Secret": INTERNAL }),
      makeEnv(),
    );
    expect(res.status).toBe(503);
  });

  it("401 without the shared secret header", async () => {
    const res = await handleDevicePairInternal(
      post("/device/pair-internal", { tenant_id: "t1" }),
      internalEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("401 on a wrong shared secret", async () => {
    const res = await handleDevicePairInternal(
      post("/device/pair-internal", { tenant_id: "t1" }, { "X-Internal-Shared-Secret": "wrong" }),
      internalEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("400 when tenant_id is missing", async () => {
    const res = await handleDevicePairInternal(
      post("/device/pair-internal", {}, { "X-Internal-Shared-Secret": INTERNAL }),
      internalEnv(),
    );
    expect(res.status).toBe(400);
  });

  it("issues a credential for the explicit tenant (201), no operator session needed", async () => {
    const env = internalEnv();
    const res = await handleDevicePairInternal(
      post(
        "/device/pair-internal",
        { tenant_id: "tenant-9", label: "alc-tablet" },
        { "X-Internal-Shared-Secret": INTERNAL },
      ),
      env,
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, string>;
    expect(body.device_id).toBeTruthy();
    expect(body.device_secret).toBeTruthy();
    expect(body.tenant_id).toBe("tenant-9");
    expect(body.role).toBe(DEVICE_ROLE);
    // 発行した credential が /device/token で device JWT に交換できる (= 実用可能)。
    const tok = await handleDeviceToken(
      post("/device/token", { device_id: body.device_id, device_secret: body.device_secret }),
      env,
    );
    expect(tok.status).toBe(200);
  });

  it("honors an allowlisted role (kiosk)", async () => {
    const res = await handleDevicePairInternal(
      post(
        "/device/pair-internal",
        { tenant_id: "t", role: DEVICE_ROLE_KIOSK },
        { "X-Internal-Shared-Secret": INTERNAL },
      ),
      internalEnv(),
    );
    const body = (await res.json()) as Record<string, string>;
    expect(body.role).toBe(DEVICE_ROLE_KIOSK);
  });

  describe("replace_label (Refs #495 PR2, kiosk re-pair)", () => {
    it("without replace_label, repeated calls mint independent (dormant) credentials", async () => {
      const env = internalEnv();
      const res1 = await handleDevicePairInternal(
        post(
          "/device/pair-internal",
          { tenant_id: "tenant-9", label: "kiosk-1" },
          { "X-Internal-Shared-Secret": INTERNAL },
        ),
        env,
      );
      const res2 = await handleDevicePairInternal(
        post(
          "/device/pair-internal",
          { tenant_id: "tenant-9", label: "kiosk-1" },
          { "X-Internal-Shared-Secret": INTERNAL },
        ),
        env,
      );
      const body1 = (await res1.json()) as Record<string, string>;
      const body2 = (await res2.json()) as Record<string, string>;
      expect(body1.device_id).not.toBe(body2.device_id);

      // 旧 credential は revoke されず生き残る (dormant credential 問題) —
      // 正しい secret のままなお有効であることで証明する
      const oldTok = await handleDeviceToken(
        post("/device/token", { device_id: body1.device_id, device_secret: body1.device_secret }),
        env,
      );
      expect(oldTok.status).toBe(200);
    });

    it("replace_label=true revokes the previous credential for the same tenant+label", async () => {
      const env = internalEnv();
      const res1 = await handleDevicePairInternal(
        post(
          "/device/pair-internal",
          { tenant_id: "tenant-9", label: "kiosk-1", replace_label: true },
          { "X-Internal-Shared-Secret": INTERNAL },
        ),
        env,
      );
      const body1 = (await res1.json()) as Record<string, string>;

      const res2 = await handleDevicePairInternal(
        post(
          "/device/pair-internal",
          { tenant_id: "tenant-9", label: "kiosk-1", replace_label: true },
          { "X-Internal-Shared-Secret": INTERNAL },
        ),
        env,
      );
      expect(res2.status).toBe(201);
      const body2 = (await res2.json()) as Record<string, string>;
      expect(body2.device_id).not.toBe(body1.device_id);

      // 新 credential は使える
      const newTok = await handleDeviceToken(
        post("/device/token", { device_id: body2.device_id, device_secret: body2.device_secret }),
        env,
      );
      expect(newTok.status).toBe(200);

      // 旧 credential は revoke 済みで使えない
      const oldTok = await handleDeviceToken(
        post("/device/token", { device_id: body1.device_id, device_secret: body1.device_secret }),
        env,
      );
      expect(oldTok.status).toBe(401);
    });

    it("replace_label=true with no prior credential for the label still mints (idempotent)", async () => {
      const res = await handleDevicePairInternal(
        post(
          "/device/pair-internal",
          { tenant_id: "tenant-fresh", label: "first-pair", replace_label: true },
          { "X-Internal-Shared-Secret": INTERNAL },
        ),
        internalEnv(),
      );
      expect(res.status).toBe(201);
      const body = (await res.json()) as Record<string, string>;
      expect(body.device_id).toBeTruthy();
    });

    it("replace_label only replaces credentials with the same tenant+label (different label untouched)", async () => {
      const env = internalEnv();
      const res1 = await handleDevicePairInternal(
        post(
          "/device/pair-internal",
          { tenant_id: "tenant-9", label: "kiosk-A", replace_label: true },
          { "X-Internal-Shared-Secret": INTERNAL },
        ),
        env,
      );
      const body1 = (await res1.json()) as Record<string, string>;

      // 別 label で replace_label=true を呼んでも kiosk-A の credential には影響しない
      await handleDevicePairInternal(
        post(
          "/device/pair-internal",
          { tenant_id: "tenant-9", label: "kiosk-B", replace_label: true },
          { "X-Internal-Shared-Secret": INTERNAL },
        ),
        env,
      );

      const stillValid = await handleDeviceToken(
        post("/device/token", { device_id: body1.device_id, device_secret: body1.device_secret }),
        env,
      );
      expect(stillValid.status).toBe(200);
    });
  });
})

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

describe("handleDeviceHubToken (Refs #406)", () => {
  it("400 when device_id, device_secret or nonce is missing", async () => {
    const res = await handleDeviceHubToken(post("/device/hub-token", { device_id: "x" }), makeEnv());
    expect(res.status).toBe(400);
  });

  it("401 for an invalid credential", async () => {
    const res = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: "nope", device_secret: "x", nonce: "n" }),
      makeEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("403 when the credential's role is not hub/gateway (e.g. kiosk)", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_KIOSK, "site-1");
    const res = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: cred.device_id, device_secret: cred.device_secret, nonce: "n" }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("403 when site_id is unset on an otherwise eligible (gateway) credential", async () => {
    // hub は createDeviceCredential が site_id 省略時に自分の device_id を既定にするため
    // (Refs #406 改訂)、この 403 分岐は auto-default 対象外の gateway で踏む。
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_GATEWAY); // no site_id
    const res = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: cred.device_id, device_secret: cred.device_secret, nonce: "n" }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("mints a nonce-bound hub token for a device-hub credential (site_id auto-defaults to its own device_id)", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_HUB);
    expect(cred.record.site_id).toBe(cred.device_id);
    const res = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: cred.device_id, device_secret: cred.device_secret, nonce: "abc" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.token_type).toBe("Bearer");
    expect(body.site_id).toBe(cred.device_id);
    const payload = await verifyJwt(body.access_token as string, SECRET, ENV);
    expect(payload?.aud).toBe("hub");
    expect(payload?.nonce).toBe("abc");
    expect(payload?.site_id).toBe(cred.device_id);
  });

  it("mints for a device-gateway credential with site_id", async () => {
    const env = makeEnv();
    const cred = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_GATEWAY, "site-1");
    const res = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: cred.device_id, device_secret: cred.device_secret, nonce: "abc" }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("503 when JWT_SECRET is unset (mint throws)", async () => {
    const kv = createMockKV();
    const seedEnv = { AUTH_CONFIG: kv, JWT_SECRET: SECRET, WORKER_ENV: ENV } as unknown as Env;
    const cred = await createDeviceCredential(seedEnv, "t", "l", 1700, DEVICE_ROLE_HUB, "site-1");
    const noSecretEnv = { AUTH_CONFIG: kv, JWT_SECRET: undefined, WORKER_ENV: ENV } as unknown as Env;
    const res = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: cred.device_id, device_secret: cred.device_secret, nonce: "n" }),
      noSecretEnv,
    );
    expect(res.status).toBe(503);
  });
});

describe("handleDeviceIntrospect (Refs #406)", () => {
  it("400 when required fields are missing", async () => {
    const res = await handleDeviceIntrospect(post("/device/introspect", { device_id: "x" }), makeEnv());
    expect(res.status).toBe(400);
  });

  it("401 for an invalid caller credential", async () => {
    const res = await handleDeviceIntrospect(
      post("/device/introspect", { device_id: "nope", device_secret: "x", token: "t" }),
      makeEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("401 when the caller credential's role is not hub/gateway", async () => {
    const env = makeEnv();
    const caller = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_KIOSK);
    const res = await handleDeviceIntrospect(
      post("/device/introspect", {
        device_id: caller.device_id,
        device_secret: caller.device_secret,
        token: "whatever",
      }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("valid:false for a garbage token", async () => {
    const env = makeEnv();
    const caller = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_HUB, "site-1");
    const res = await handleDeviceIntrospect(
      post("/device/introspect", {
        device_id: caller.device_id,
        device_secret: caller.device_secret,
        token: "garbage.not.a.jwt",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.valid).toBe(false);
  });

  it("valid:false for a normal device JWT (aud mismatch — not a hub token)", async () => {
    const env = makeEnv();
    const caller = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_HUB, "site-1");
    const other = await createDeviceCredential(env, "t", "l2", 1700, DEVICE_ROLE_HUB, "site-1");
    const otherTokenRes = await handleDeviceToken(
      post("/device/token", { device_id: other.device_id, device_secret: other.device_secret }),
      env,
    );
    const otherToken = ((await otherTokenRes.json()) as Record<string, string>).access_token;
    const res = await handleDeviceIntrospect(
      post("/device/introspect", {
        device_id: caller.device_id,
        device_secret: caller.device_secret,
        token: otherToken,
      }),
      env,
    );
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.valid).toBe(false);
  });

  it("validates a hub token minted by another device and returns its claims", async () => {
    const env = makeEnv();
    const gw = await createDeviceCredential(env, "t", "l", 1700, DEVICE_ROLE_GATEWAY, "site-1");
    const hubTokenRes = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: gw.device_id, device_secret: gw.device_secret, nonce: "n1" }),
      env,
    );
    const gwToken = ((await hubTokenRes.json()) as Record<string, string>).access_token;

    const hub = await createDeviceCredential(env, "t", "l2", 1700, DEVICE_ROLE_HUB, "site-1");
    const res = await handleDeviceIntrospect(
      post("/device/introspect", { device_id: hub.device_id, device_secret: hub.device_secret, token: gwToken }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.valid).toBe(true);
    expect(body.site_id).toBe("site-1");
    expect(body.role).toBe(DEVICE_ROLE_GATEWAY);
    expect((body.claims as Record<string, unknown>).nonce).toBe("n1");
  });
});

describe("handleDeviceSiteBackfill (Refs #406)", () => {
  const INTERNAL = "internal-shared-secret-32chars!!";

  function internalEnv(overrides: Record<string, unknown> = {}): Env {
    return makeEnv({ INTERNAL_SHARED_SECRET: INTERNAL, ...overrides });
  }

  it("503 when no INTERNAL_SHARED_SECRET is bound", async () => {
    const res = await handleDeviceSiteBackfill(
      post("/device/site/backfill", { device_id: "x", site_id: "s" }, { "X-Internal-Shared-Secret": INTERNAL }),
      makeEnv(),
    );
    expect(res.status).toBe(503);
  });

  it("401 without the shared secret header", async () => {
    const res = await handleDeviceSiteBackfill(
      post("/device/site/backfill", { device_id: "x", site_id: "s" }),
      internalEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("400 when device_id is missing", async () => {
    const res = await handleDeviceSiteBackfill(
      post("/device/site/backfill", { site_id: "s" }, { "X-Internal-Shared-Secret": INTERNAL }),
      internalEnv(),
    );
    expect(res.status).toBe(400);
  });

  it("site_id を省略すると device_id 自身を既定にする (Refs #406 改訂)", async () => {
    const env = internalEnv();
    const cred = await createDeviceCredential(env, "t", "cores3-1", 1700, DEVICE_ROLE_HUB);
    const res = await handleDeviceSiteBackfill(
      post("/device/site/backfill", { device_id: cred.device_id }, { "X-Internal-Shared-Secret": INTERNAL }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.site_id).toBe(cred.device_id);
  });

  it("404 for an unknown device", async () => {
    const res = await handleDeviceSiteBackfill(
      post(
        "/device/site/backfill",
        { device_id: "missing", site_id: "site-1" },
        { "X-Internal-Shared-Secret": INTERNAL },
      ),
      internalEnv(),
    );
    expect(res.status).toBe(404);
  });

  it("explicit site_id overrides the device's own auto-defaulted site_id", async () => {
    const env = internalEnv();
    const cred = await createDeviceCredential(env, "t", "cores3-1", 1700, DEVICE_ROLE_HUB);
    expect(cred.record.site_id).toBe(cred.device_id); // 発行時点で既に自動付与済み (Refs #406 改訂)
    const res = await handleDeviceSiteBackfill(
      post(
        "/device/site/backfill",
        { device_id: cred.device_id, site_id: "site-42" },
        { "X-Internal-Shared-Secret": INTERNAL },
      ),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.site_id).toBe("site-42");

    // hub-token が新しい site_id で mint されることを確認。
    const tokRes = await handleDeviceHubToken(
      post("/device/hub-token", { device_id: cred.device_id, device_secret: cred.device_secret, nonce: "n" }),
      env,
    );
    expect(tokRes.status).toBe(200);
    const tokBody = (await tokRes.json()) as Record<string, unknown>;
    expect(tokBody.site_id).toBe("site-42");
  });
});
