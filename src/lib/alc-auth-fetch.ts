/**
 * alc-auth-worker (`ippoan/alc-auth-worker`、Service Binding `ALC_AUTH`) の内部口を 1 回叩く共用の client
 * (Refs ohishi-exp/rust-leave-worker#1)。機械用資格情報 (`lib/machine-credential.ts`) と
 * ログインの内部口・ロールの付け外し (`lib/alc-internal.ts`) がここを通る。
 *
 * alc-auth-worker の内部口は全部 `X-Internal-Shared-Secret` が要り、不一致は 404 (本文空)。
 */
import { resolveSecret, type SecretBinding } from "./secret";

/** host は名目 (Service Binding では行き先を決めない)。 */
const ALC_AUTH_ORIGIN = "https://alc-auth";

export interface AlcAuthEnv {
  /** alc-auth-worker への service binding。 */
  ALC_AUTH?: Fetcher;
  /** alc-auth-worker の内部口に付ける共有 secret。 */
  INTERNAL_SHARED_SECRET?: SecretBinding;
}

/**
 * `path` (`/internal/...`) を共有 secret 付きで叩き、応答をそのまま返す。
 * binding か secret が無ければ null (呼ばない)。通信の例外はそのまま投げる (扱いは呼び手が決める)。
 */
export async function fetchAlcAuth(
  env: AlcAuthEnv,
  path: string,
  init: { method: "GET" | "POST" | "PUT" | "DELETE"; body?: string } = { method: "GET" },
): Promise<Response | null> {
  if (!env.ALC_AUTH) return null;
  const secret = await resolveSecret(env.INTERNAL_SHARED_SECRET);
  if (!secret) return null;
  const headers = new Headers({ "X-Internal-Shared-Secret": secret });
  if (init.body !== undefined) headers.set("Content-Type", "application/json");
  return env.ALC_AUTH.fetch(
    new Request(`${ALC_AUTH_ORIGIN}${path}`, { method: init.method, headers, body: init.body }),
  );
}
