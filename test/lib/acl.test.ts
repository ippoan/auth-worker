import { describe, it, expect, beforeEach } from "vitest";
import {
  checkOrgAccess,
  checkAppTenant,
  isTenantInOrgAllowlist,
} from "../../src/lib/acl";
import { _clearAllowedOriginsCache } from "../../src/lib/config";
import { createMockEnv, createMockKV } from "../helpers/mock-env";

const OHISHI_ACL = JSON.stringify({ "ohishi-exp": ["tenant-a", "tenant-b"] });
const OHISHI_USER_ACL = JSON.stringify({ "ohishi-exp": ["alice@example.com"] });
const APP_ORGS = JSON.stringify({ "dtako-admin": "ohishi-exp", ohishi2: "ohishi-exp" });

describe("checkOrgAccess", () => {
  beforeEach(() => {
    _clearAllowedOriginsCache();
  });

  it("bypasses ACL for worktree origins regardless of tenant_id", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:wt": "https://wt.trycloudflare.com",
        "app-orgs": APP_ORGS,
      }),
      TENANT_ACL: OHISHI_ACL,
    });

    expect(await checkOrgAccess(env, "https://wt.trycloudflare.com", "")).toBe(true);
    expect(await checkOrgAccess(env, "https://wt.trycloudflare.com", "unknown-tenant")).toBe(true);
  });

  it("allows ippoan (default) origins for any tenant", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      TENANT_ACL: OHISHI_ACL,
    });

    expect(await checkOrgAccess(env, "https://alc-app.example", "")).toBe(true);
    expect(await checkOrgAccess(env, "https://anyapp.example", "random")).toBe(true);
  });

  it("allows ohishi-exp origin when tenant_id is in TENANT_ACL", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      TENANT_ACL: OHISHI_ACL,
    });

    expect(await checkOrgAccess(env, "https://dtako-admin.example", "tenant-a")).toBe(true);
    expect(await checkOrgAccess(env, "https://ohishi2.example", "tenant-b")).toBe(true);
  });

  it("denies ohishi-exp origin when tenant_id is empty", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      TENANT_ACL: OHISHI_ACL,
    });

    expect(await checkOrgAccess(env, "https://dtako-admin.example", "")).toBe(false);
  });

  it("denies ohishi-exp origin when tenant_id is not in allowlist", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      TENANT_ACL: OHISHI_ACL,
    });

    expect(await checkOrgAccess(env, "https://dtako-admin.example", "tenant-z")).toBe(false);
  });

  it("denies ohishi-exp when TENANT_ACL is missing (fail-closed)", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
    });

    expect(await checkOrgAccess(env, "https://dtako-admin.example", "tenant-a")).toBe(false);
  });

  it("denies ohishi-exp when TENANT_ACL is malformed JSON (fail-closed)", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      TENANT_ACL: "not-json",
    });

    expect(await checkOrgAccess(env, "https://dtako-admin.example", "tenant-a")).toBe(false);
  });

  it("allows when app-orgs KV is missing (origin treated as ippoan)", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({}),
      TENANT_ACL: OHISHI_ACL,
    });

    expect(await checkOrgAccess(env, "https://dtako-admin.example", "")).toBe(true);
  });

  it("allows ohishi-exp origin when email is in USER_ACL (tenant miss)", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      TENANT_ACL: OHISHI_ACL,
      USER_ACL: OHISHI_USER_ACL,
    });

    expect(
      await checkOrgAccess(env, "https://dtako-admin.example", "tenant-z", "alice@example.com"),
    ).toBe(true);
  });

  it("allows ohishi-exp origin via USER_ACL when TENANT_ACL is missing", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      USER_ACL: OHISHI_USER_ACL,
    });

    expect(
      await checkOrgAccess(env, "https://dtako-admin.example", "", "alice@example.com"),
    ).toBe(true);
  });

  it("email match is case-insensitive", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      USER_ACL: OHISHI_USER_ACL,
    });

    expect(
      await checkOrgAccess(env, "https://dtako-admin.example", "", "ALICE@Example.COM"),
    ).toBe(true);
  });

  it("denies ohishi-exp when neither tenant nor email matches", async () => {
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
      TENANT_ACL: OHISHI_ACL,
      USER_ACL: OHISHI_USER_ACL,
    });

    expect(
      await checkOrgAccess(env, "https://dtako-admin.example", "tenant-z", "bob@example.com"),
    ).toBe(false);
  });

  it("wt bypass wins over ohishi-exp classification", async () => {
    // An origin that is BOTH registered as wt AND matches an ohishi-exp token.
    const env = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:wt": "https://dtako-admin-wt.trycloudflare.com",
        "app-orgs": APP_ORGS,
      }),
      TENANT_ACL: OHISHI_ACL,
    });

    expect(await checkOrgAccess(env, "https://dtako-admin-wt.trycloudflare.com", "")).toBe(true);
  });
});

describe("isTenantInOrgAllowlist", () => {
  it("returns true when tenant is listed under the org", () => {
    const env = createMockEnv({ TENANT_ACL: OHISHI_ACL });
    expect(isTenantInOrgAllowlist(env, "ohishi-exp", "tenant-a")).toBe(true);
  });

  it("returns false for empty tenant_id", () => {
    const env = createMockEnv({ TENANT_ACL: OHISHI_ACL });
    expect(isTenantInOrgAllowlist(env, "ohishi-exp", "")).toBe(false);
  });

  it("returns false when org is not in the ACL", () => {
    const env = createMockEnv({ TENANT_ACL: OHISHI_ACL });
    expect(isTenantInOrgAllowlist(env, "other-org", "tenant-a")).toBe(false);
  });

  it("returns false when TENANT_ACL is missing", () => {
    const env = createMockEnv();
    expect(isTenantInOrgAllowlist(env, "ohishi-exp", "tenant-a")).toBe(false);
  });

  it("returns false when TENANT_ACL value for org is not an array", () => {
    const env = createMockEnv({ TENANT_ACL: JSON.stringify({ "ohishi-exp": "not-array" }) });
    expect(isTenantInOrgAllowlist(env, "ohishi-exp", "tenant-a")).toBe(false);
  });
});

describe("checkAppTenant", () => {
  const ICHIBANBOSHI = "https://ichibanboshi.ippoan.org";
  const ICHIBANBOSHI_STAGING = "https://ichibanboshi-staging.ippoan.org";
  const DTAKO_ADMIN = "https://dtako-admin.ippoan.org";
  const DEV_EMAIL = "m.tama.ramu@gmail.com";
  const PROD_TENANT = "536859de-d43e-4932-9d16-f60cac8fa426";

  it("passes when APP_TENANT_ACL is unset (no restriction configured)", () => {
    const env = createMockEnv();
    expect(checkAppTenant(env, ICHIBANBOSHI, "any-tenant", DEV_EMAIL)).toBe(true);
    expect(checkAppTenant(env, ICHIBANBOSHI, "")).toBe(true);
  });

  it("passes when origin has no entry in apps (opt-in)", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        apps: { [ICHIBANBOSHI]: [PROD_TENANT] },
      }),
    });
    // dtako-admin has no entry → unrestricted
    expect(checkAppTenant(env, DTAKO_ADMIN, "any-tenant")).toBe(true);
    expect(checkAppTenant(env, DTAKO_ADMIN, "")).toBe(true);
  });

  it("allows tenant listed for the origin", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        apps: { [ICHIBANBOSHI]: [PROD_TENANT, "tenant-b"] },
      }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, PROD_TENANT)).toBe(true);
    expect(checkAppTenant(env, ICHIBANBOSHI, "tenant-b")).toBe(true);
  });

  it("denies tenant not in the origin's allowlist", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        apps: { [ICHIBANBOSHI]: [PROD_TENANT] },
      }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, "tenant-z")).toBe(false);
  });

  it("wildcard '*' allows any tenant for that origin", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        apps: { [ICHIBANBOSHI_STAGING]: ["*"] },
      }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI_STAGING, "any-tenant")).toBe(true);
    expect(checkAppTenant(env, ICHIBANBOSHI_STAGING, "")).toBe(true);
  });

  it("denies empty tenant when origin has a concrete allowlist", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        apps: { [ICHIBANBOSHI]: [PROD_TENANT] },
      }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, "")).toBe(false);
  });

  it("bypass_emails allows the email past the tenant check (any app)", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        bypass_emails: [DEV_EMAIL],
        apps: {
          [ICHIBANBOSHI]: [PROD_TENANT],
          [ICHIBANBOSHI_STAGING]: [PROD_TENANT],
        },
      }),
    });
    // dev's tenant doesn't match, but bypass_emails passes them through.
    expect(checkAppTenant(env, ICHIBANBOSHI, "wrong-tenant", DEV_EMAIL)).toBe(true);
    expect(checkAppTenant(env, ICHIBANBOSHI_STAGING, "wrong-tenant", DEV_EMAIL)).toBe(true);
    // Also applies to origins with no entry (no-op there anyway).
    expect(checkAppTenant(env, DTAKO_ADMIN, "wrong-tenant", DEV_EMAIL)).toBe(true);
  });

  it("bypass_emails is case-insensitive", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        bypass_emails: [DEV_EMAIL],
        apps: { [ICHIBANBOSHI]: [PROD_TENANT] },
      }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, "wrong", "M.Tama.Ramu@GMAIL.com")).toBe(true);
  });

  it("non-bypass email still has to match tenant", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        bypass_emails: [DEV_EMAIL],
        apps: { [ICHIBANBOSHI]: [PROD_TENANT] },
      }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, "wrong-tenant", "other@example.com")).toBe(false);
    expect(checkAppTenant(env, ICHIBANBOSHI, PROD_TENANT, "other@example.com")).toBe(true);
  });

  it("bypass_emails works even when apps is absent", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({ bypass_emails: [DEV_EMAIL] }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, "any", DEV_EMAIL)).toBe(true);
    // No bypass, no apps entry → pass via opt-in
    expect(checkAppTenant(env, ICHIBANBOSHI, "any", "other@example.com")).toBe(true);
  });

  it("fail-open on malformed JSON", () => {
    const env = createMockEnv({ APP_TENANT_ACL: "not-json{" });
    expect(checkAppTenant(env, ICHIBANBOSHI, "tenant-a")).toBe(true);
    expect(checkAppTenant(env, ICHIBANBOSHI, "", DEV_EMAIL)).toBe(true);
  });

  it("passes when apps[origin] is not an array (treated as unregistered)", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        apps: { [ICHIBANBOSHI]: "tenant-a" },
      }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, "tenant-a")).toBe(true);
    expect(checkAppTenant(env, ICHIBANBOSHI, "tenant-z")).toBe(true);
  });

  it("passes when apps is missing entirely (only bypass_emails configured)", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({ bypass_emails: [] }),
    });
    expect(checkAppTenant(env, ICHIBANBOSHI, "tenant-z")).toBe(true);
  });

  it("origin key match is exact (trailing slash matters)", () => {
    const env = createMockEnv({
      APP_TENANT_ACL: JSON.stringify({
        apps: { [ICHIBANBOSHI]: [PROD_TENANT] },
      }),
    });
    // The canonical origin (no slash) is restricted.
    expect(checkAppTenant(env, ICHIBANBOSHI, "tenant-z")).toBe(false);
    // A variant with trailing slash does not match → falls through to pass.
    expect(checkAppTenant(env, `${ICHIBANBOSHI}/`, "tenant-z")).toBe(true);
  });
});
