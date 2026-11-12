/**
 * 点呼の届出の申請済みの控え (e-Gov の zip) を、MCP から到達番号で保存するための短命のアップロード先
 * (Refs ippoan/alc-app#676)。
 *
 * 控えの zip は 1 件 2 MB を超えるので MCP の引数 (= LLM の文脈) に載せない。MCP の
 * `filing_archive_upload_url` が KV に 1 回きりの id (256bit hex、TTL 10 分) を置いて URL を返し、
 * 呼び手は `curl -T <zip> <url>` (PUT) で本文を送る。`PUT /mcp/filing-upload/<id>` は id を消してから、
 * 発行した人のテナントと admin の名乗りで alc-tenko-worker の
 * `PUT /api/tenko/filing-archives/{到達番号}` へ転送し、その応答をそのまま返す。
 *
 * id を知り得るのは発行を受けた MCP セッションだけ (verify_screenshot の shot_url と同じ判断)。
 * 発行は MCP の allowlist と、本人がテナントの admin であることを通ったときだけ。
 */
import type { Env } from "../index";
import { forwardViaAlcBinding, resolveAlcBinding } from "./alc-backend-route";
import { generateDeviceCode } from "./mcp-codes";

export const FILING_UPLOAD_KV_PREFIX = "filing_upload:";
export const FILING_UPLOAD_TTL_SEC = 600;
/** e-Gov の到達番号 (16〜18 桁、末尾 1 字だけ英小文字のことがある)。alc-tenko-worker の is_arrive_id と同じ */
export const ARRIVE_ID_RE = /^\d{15,17}[0-9a-z]$/;
const UPLOAD_ID_RE = /^[0-9a-f]{64}$/;

/** KV に置く発行の中身 */
export interface FilingUpload {
  tenant_id: string;
  user_id: string;
  email: string;
  arrive_id: string;
  name: string;
}

/** 1 回きりのアップロード先を発行して URL を返す */
export async function issueFilingUpload(env: Env, upload: FilingUpload): Promise<string> {
  const id = generateDeviceCode();
  await env.MCP_OAUTH_KV!.put(`${FILING_UPLOAD_KV_PREFIX}${id}`, JSON.stringify(upload), {
    expirationTtl: FILING_UPLOAD_TTL_SEC,
  });
  const origin = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  return `${origin}/mcp/filing-upload/${id}`;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/** `PUT /mcp/filing-upload/<id>` — 本文の zip を、発行した人の名で控えの口へ転送する */
export async function handleFilingUpload(request: Request, env: Env, id: string): Promise<Response> {
  if (request.method !== "PUT") return json(405, { error: "method_not_allowed" });
  if (!env.MCP_OAUTH_KV) return json(503, { error: "server_error" });
  if (!UPLOAD_ID_RE.test(id)) return json(404, { error: "not_found" });
  const key = `${FILING_UPLOAD_KV_PREFIX}${id}`;
  const raw = await env.MCP_OAUTH_KV.get(key);
  if (!raw) return json(404, { error: "not_found" });
  // 1 回きり: 転送の成否にかかわらず先に消す (失敗したら発行し直す)
  await env.MCP_OAUTH_KV.delete(key);
  const upload = JSON.parse(raw) as FilingUpload;
  const backendPath = `/api/tenko/filing-archives/${upload.arrive_id}`;
  const binding = resolveAlcBinding(backendPath, env, "browser", "PUT");
  if (!binding) return json(503, { error: "not_configured" });
  const search = `?name=${encodeURIComponent(upload.name)}&meta=${encodeURIComponent(JSON.stringify({ via: "mcp" }))}`;
  const res = await forwardViaAlcBinding(binding, backendPath, search, {
    method: "PUT",
    headers: {
      "Content-Type": "application/zip",
      "X-Tenant-ID": upload.tenant_id,
      "X-User-ID": upload.user_id,
      "X-User-Email": upload.email,
      "X-User-Role": "admin",
    },
    body: await request.arrayBuffer(),
  });
  return new Response(await res.text(), {
    status: res.status,
    headers: { "Content-Type": res.headers.get("Content-Type") ?? "application/json", "Cache-Control": "no-store" },
  });
}
