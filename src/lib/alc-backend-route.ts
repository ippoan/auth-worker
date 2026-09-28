import type { Env } from "../index";

/**
 * rust-alc-api (Cloud Run monolith) を domain 別 Worker へ段階移行する (strangler) ための
 * 振り分け表。`alc-proxy` / `device-data-proxy` が認証・ACL・ヘッダ付け直しを終えた後、
 * backendPath がここに一致し、かつ env に binding が定義されていれば Service Binding へ流す。
 * 2 本目以降の worker はこの表に 1 行足すだけ (Env 型にも binding を足す)。
 */
export const ALC_BINDING_ROUTES: ReadonlyArray<{ prefix: string; binding: keyof Env }> = [
  { prefix: "/api/vein/", binding: "ALC_VEIN" },
];

/**
 * backendPath に対応する Service Binding を返す。表に一致し、かつ binding が
 * 定義されているときだけ Fetcher を返す (未定義は null = 従来どおり Cloud Run)。
 * prefix は末尾 `/` 付きで持ち、`/api/vein` 完全一致 or `/api/vein/` 始まりを一致とする。
 */
export function resolveAlcBinding(backendPath: string, env: Env): Fetcher | null {
  for (const { prefix, binding } of ALC_BINDING_ROUTES) {
    const bare = prefix.replace(/\/$/, "");
    if (backendPath !== bare && !backendPath.startsWith(prefix)) continue;
    const fetcher = env[binding] as Fetcher | undefined;
    return fetcher ?? null;
  }
  return null;
}

/** cf-flickr-cam-worker-proxy と同じ defense-in-depth (decode 後に別 path へ化けるのを防ぐ)。 */
export function isUnsafeBackendPath(backendPath: string): boolean {
  return backendPath.includes("%") || backendPath.includes("..") || backendPath.includes("\\");
}

/**
 * Service Binding 経由の転送。付け直し済みヘッダ (Authorization = Cloud Run 用 OIDC は
 * 含めない) と body をそのまま渡す。`redirect: "manual"` は cf-flickr と同じ理由 (binding 先の
 * 自己再呼び出し防止)。host `alc-vein` はダミー (binding は URL の host で経路が決まらない)。
 */
export function forwardViaAlcBinding(
  binding: Fetcher,
  backendPath: string,
  search: string,
  init: { method: string; headers: Record<string, string>; body: BodyInit | undefined },
): Promise<Response> {
  return binding.fetch(`https://alc-vein${backendPath}${search}`, {
    method: init.method,
    headers: init.headers,
    body: init.body,
    redirect: "manual",
  });
}
