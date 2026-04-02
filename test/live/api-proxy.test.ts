/**
 * Container 統合テスト: auth-worker REST proxy ハンドラ → rust-alc-api
 *
 * auth-worker のハンドラ関数を直接呼び出し、実際の rust-alc-api に fetch して
 * レスポンスの型・ステータスが正しいか検証する。
 *
 * 実行:
 *   docker compose -f docker-compose.test.yml up -d
 *   ALC_API_URL=http://localhost:18081 npx vitest run test/live/
 *   docker compose -f docker-compose.test.yml down
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  isLive,
  ALC_API_URL,
  waitForApi,
  makeJwt,
  apiFetch,
  DEL_INVITATION_ID,
  DEL_USER_ID,
} from "../helpers/live-env";
import type { Env } from "../../src/index";
import type {
  SsoConfigRow,
  BotConfigResponse,
  UserResponse,
  TenantAllowedEmail,
} from "../../src/types/alc-api";

// Skip all tests if ALC_API_URL is not set
const describeIf = isLive ? describe : describe.skip;

function liveEnv(): Env {
  return {
    GRPC_PROXY: {} as any,
    GOOGLE_CLIENT_ID: "dummy",
    GOOGLE_CLIENT_SECRET: "dummy",
    OAUTH_STATE_SECRET: "dummy",
    AUTH_WORKER_ORIGIN: "https://auth.test.example",
    ALLOWED_REDIRECT_ORIGINS: "https://app.test.example",
    ALC_API_ORIGIN: ALC_API_URL,
  };
}

function authRequest(path: string, init: RequestInit = {}): Request {
  return new Request(`https://auth.test.example${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${makeJwt()}`,
      "Content-Type": "application/json",
      ...init.headers,
    },
  });
}

describeIf("Live: REST proxy → rust-alc-api", () => {
  beforeAll(async () => {
    await waitForApi();
  });

  // --- SSO configs ---
  describe("api-sso", () => {
    it("GET /api/admin/sso/configs returns configs array", async () => {
      const { handleSsoList } = await import("../../src/handlers/api-sso");
      const res = await handleSsoList(
        authRequest("/api/sso/list", { method: "POST" }),
        liveEnv(),
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as { configs: unknown[] };
      expect(Array.isArray(data.configs)).toBe(true);
    });

    it("SSO upsert + delete round-trip", async () => {
      const { handleSsoUpsert, handleSsoDelete } = await import(
        "../../src/handlers/api-sso"
      );

      // Upsert
      const upsertRes = await handleSsoUpsert(
        authRequest("/api/sso/upsert", {
          method: "POST",
          body: JSON.stringify({
            provider: "lineworks",
            clientId: "test-client",
            clientSecret: "test-secret",
            externalOrgId: "test-org",
            enabled: true,
          }),
        }),
        liveEnv(),
      );
      expect(upsertRes.status).toBe(200);
      const upserted = (await upsertRes.json()) as {
        provider: string;
        clientId: string;
      };
      expect(upserted.provider).toBe("lineworks");
      expect(upserted.clientId).toBe("test-client");

      // Delete
      const delRes = await handleSsoDelete(
        authRequest("/api/sso/delete", {
          method: "POST",
          body: JSON.stringify({ provider: "lineworks" }),
        }),
        liveEnv(),
      );
      expect(delRes.status).toBe(200);
    });
  });

  // --- Users ---
  describe("api-users", () => {
    it("GET /api/admin/users returns users array", async () => {
      const { handleUsersList } = await import(
        "../../src/handlers/api-users"
      );
      const res = await handleUsersList(
        authRequest("/api/users/list", { method: "POST" }),
        liveEnv(),
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as { users: UserResponse[] };
      expect(Array.isArray(data.users)).toBe(true);
      if (data.users.length > 0) {
        // Verify shape matches ts-rs generated type
        const u = data.users[0];
        expect(typeof u.id).toBe("string");
        expect(typeof u.email).toBe("string");
        expect(typeof u.name).toBe("string");
        expect(typeof u.role).toBe("string");
      }
    });

    it("GET /api/admin/users/invitations returns invitations", async () => {
      const { handleInvitationsList } = await import(
        "../../src/handlers/api-users"
      );
      const res = await handleInvitationsList(
        authRequest("/api/users/invitations", { method: "POST" }),
        liveEnv(),
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as {
        invitations: TenantAllowedEmail[];
      };
      expect(Array.isArray(data.invitations)).toBe(true);
    });

    it("invite + delete invitation round-trip", async () => {
      const { handleInviteUser, handleDeleteInvitation } = await import(
        "../../src/handlers/api-users"
      );

      // Invite
      const invRes = await handleInviteUser(
        authRequest("/api/users/invite", {
          method: "POST",
          body: JSON.stringify({ email: "live-test@example.com", role: "admin" }),
        }),
        liveEnv(),
      );
      expect(invRes.status).toBe(200);
      const inv = (await invRes.json()) as TenantAllowedEmail;
      expect(inv.email).toBe("live-test@example.com");

      // Delete invitation
      const delRes = await handleDeleteInvitation(
        authRequest("/api/users/invite/delete", {
          method: "POST",
          body: JSON.stringify({ id: inv.id }),
        }),
        liveEnv(),
      );
      expect(delRes.status).toBe(200);
    });
  });

  // --- Unauthorized ---
  describe("auth enforcement", () => {
    it("SSO list without token returns 401", async () => {
      const { handleSsoList } = await import("../../src/handlers/api-sso");
      const res = await handleSsoList(
        new Request("https://auth.test.example/api/sso/list", {
          method: "POST",
        }),
        liveEnv(),
      );
      expect(res.status).toBe(401);
    });
  });

  // --- Type shape validation ---
  describe("response type validation", () => {
    it("SSO config fields match SsoConfigRow type", async () => {
      const { handleSsoUpsert, handleSsoDelete } = await import(
        "../../src/handlers/api-sso"
      );

      // Create a config to inspect
      await handleSsoUpsert(
        authRequest("/api/sso/upsert", {
          method: "POST",
          body: JSON.stringify({
            provider: "lineworks",
            clientId: "type-check",
            clientSecret: "secret",
            externalOrgId: "type-org",
            enabled: true,
          }),
        }),
        liveEnv(),
      );

      const { handleSsoList } = await import("../../src/handlers/api-sso");
      const res = await handleSsoList(
        authRequest("/api/sso/list", { method: "POST" }),
        liveEnv(),
      );
      const data = (await res.json()) as { configs: Record<string, unknown>[] };

      if (data.configs.length > 0) {
        const c = data.configs[0];
        // These field names must match SsoConfigRow from ts-rs
        expect("provider" in c).toBe(true);
        expect("clientId" in c).toBe(true); // auth-worker maps client_id → clientId
        expect("externalOrgId" in c).toBe(true);
        expect("enabled" in c).toBe(true);
        expect("createdAt" in c).toBe(true);
        expect("updatedAt" in c).toBe(true);
      }

      // Cleanup
      await handleSsoDelete(
        authRequest("/api/sso/delete", {
          method: "POST",
          body: JSON.stringify({ provider: "lineworks" }),
        }),
        liveEnv(),
      );
    });
  });
});
