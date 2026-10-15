/**
 * staging だけ、`/api/auth/me`・`/api/auth/logout`・`/api/my-orgs` を alc-auth-worker (`ALC_AUTH`) の
 * 内部口から組んで答える (Refs ohishi-exp/rust-leave-worker#1)。staging の会社は alc-auth-worker と
 * staging の DB が作るため、Cloud Run staging (rust-alc-api) の DB には無く、me が 500 になる。
 *
 * 切り替えは `ALC_AUTH_SESSION=1` かつ `fetchAlcAuth` が非 null (binding と secret が揃う)。
 * 分岐はこのファイルの 1 か所だけ。呼び手は helper を 1 回呼ぶだけで、フラグを見ない。
 * 値は検証済み JWT の claims からだけ作る (リクエストのヘッダ・body・query は写さない)。
 */
import type { Env } from "../index";
import { fetchAlcAuth } from "./alc-auth-fetch";

/** 検証済み JWT の claims (alc-proxy が読んでいるもの)。 */
export interface SessionClaims {
  tenantId: string;
  sub: string;
  email: string;
  role: string;
}

type AlcCall =
  | { kind: "skip" }
  | { kind: "failed" }
  | { kind: "res"; res: Response };

/** 切り替えが有効なら alc-auth-worker を 1 回叩く。無効 (フラグ無し・binding/secret 無し) は skip。 */
async function callAlcAuth(
  env: Env,
  path: string,
  init: { method: "GET" | "DELETE" },
): Promise<AlcCall> {
  if (env.ALC_AUTH_SESSION !== "1") return { kind: "skip" };
  try {
    const res = await fetchAlcAuth(env, path, init);
    return res ? { kind: "res", res } : { kind: "skip" };
  } catch {
    return { kind: "failed" };
  }
}

interface TenantInfo {
  id: string;
  name: string;
  slug: string | null;
  short_id: string;
}

type TenantLookup =
  | { kind: "skip" }
  | { kind: "ok"; tenant: TenantInfo }
  | { kind: "tenant_not_found" }
  | { kind: "error" };

/** `GET /internal/tenants/{id}`。404 は本文が `tenant_not_found` のときだけ「会社が無い」 (secret 不一致も 404 で本文が空)。 */
async function lookupTenant(env: Env, tenantId: string): Promise<TenantLookup> {
  const call = await callAlcAuth(env, `/internal/tenants/${encodeURIComponent(tenantId)}`, {
    method: "GET",
  });
  if (call.kind === "skip") return call;
  if (call.kind === "failed") return { kind: "error" };
  const body = (await call.res.json().catch(() => null)) as Record<string, unknown> | null;
  if (call.res.status === 404) {
    return body?.error === "tenant_not_found" ? { kind: "tenant_not_found" } : { kind: "error" };
  }
  if (
    !call.res.ok ||
    !body ||
    typeof body.id !== "string" ||
    typeof body.name !== "string" ||
    typeof body.short_id !== "string" ||
    (body.slug !== null && typeof body.slug !== "string")
  ) {
    return { kind: "error" };
  }
  return {
    kind: "ok",
    tenant: { id: body.id, name: body.name, slug: body.slug, short_id: body.short_id },
  };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const UPSTREAM_ERROR = (): Response => json(502, { error: "upstream_error" });

/**
 * `backendPath` が me (GET) / logout (POST) で切り替えが有効なら応答を返す。それ以外は null
 * (呼び手は従来の経路へ進む)。
 */
export async function handleSessionPath(
  env: Env,
  backendPath: string,
  method: string,
  claims: SessionClaims,
): Promise<Response | null> {
  if (backendPath === "/api/auth/me" && method === "GET") {
    const found = await lookupTenant(env, claims.tenantId);
    if (found.kind === "skip") return null;
    if (found.kind === "tenant_not_found") return json(401, { error: "tenant_not_found" });
    if (found.kind === "error") return UPSTREAM_ERROR();
    return json(200, {
      id: claims.sub,
      email: claims.email,
      name: "",
      tenant_id: claims.tenantId,
      tenant_short_id: found.tenant.short_id,
      role: claims.role,
    });
  }
  if (backendPath === "/api/auth/logout" && method === "POST") {
    const call = await callAlcAuth(
      env,
      `/internal/tenants/${encodeURIComponent(claims.tenantId)}/users/${encodeURIComponent(claims.sub)}/refresh-token`,
      { method: "DELETE" },
    );
    if (call.kind === "skip") return null;
    if (call.kind === "failed" || call.res.status !== 204) return UPSTREAM_ERROR();
    return new Response(null, { status: 204 });
  }
  return null;
}

/** `fetchMyOrgs` の結果。`ok: false` の `status` / `error` は呼び手がそのまま応答に使う。 */
export type MyOrgsResult =
  | { ok: true; data: unknown }
  | { ok: false; status: number; error: string };

/**
 * 所属組織の一覧。有効なら alc-auth-worker から現テナント 1 件を組み、無効なら従来の Cloud Run
 * `POST /api/my-orgs` を `identity` (検証済み identity ヘッダ) で呼ぶ。
 * Cloud Run 経路の通信例外はそのまま投げる (呼び手が従来どおり扱う)。
 */
export async function fetchMyOrgs(
  env: Env,
  identity: Record<string, string>,
): Promise<MyOrgsResult> {
  const found = await lookupTenant(env, identity["X-Tenant-ID"] ?? "");
  if (found.kind === "tenant_not_found") return { ok: true, data: { organizations: [] } };
  if (found.kind === "error") return { ok: false, status: 502, error: "upstream_error" };
  if (found.kind === "ok") {
    return {
      ok: true,
      data: {
        organizations: [
          {
            id: found.tenant.id,
            name: found.tenant.name,
            slug: found.tenant.slug ?? "",
            role: identity["X-User-Role"] ?? "",
          },
        ],
      },
    };
  }
  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/my-orgs`, {
    method: "POST",
    headers: identity,
  });
  if (!resp.ok) return { ok: false, status: resp.status, error: await resp.text() };
  return { ok: true, data: await resp.json() };
}
