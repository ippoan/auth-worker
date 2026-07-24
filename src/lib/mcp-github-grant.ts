/**
 * GitHub login → MCP `binding_jwt` の一発発行を担う唯一の入口。
 *
 * 経緯: `mcp-pair-grant-via-github.ts` が `GITHUB_MCP_USER_ALLOWLIST` の
 * fail-closed ACL チェックを欠いたまま `signMcpJwt` を直接呼んでおり、
 * `read:user` scope を持つ任意の GitHub token 保有者 (org 所属不問) が
 * prod署名の `mcp.read mcp.write` binding_jwt を取得できる状態だった
 * (2026-07-24 発見)。同じ「GitHub identity proof → grant」の他 4 経路
 * (`mcp-pair-callback.ts` / `mcp-elevate.ts` / `mcp-auth-callback.ts` /
 * `mcp-device-callback.ts`) は全てこの ACL を個別に実装しており、
 * 5 箇所目の追加時に 1 箇所だけ実装を落とすというヒューマンエラーが起きた。
 *
 * 再発防止として、**GitHub login から binding_jwt を直接 mint する経路は
 * 必ずこの関数を経由する**運用にする — ACL チェックを `signMcpJwt` 呼び出し
 * 自体に内蔵することで、新しい one-shot grant endpoint を追加する時に
 * チェックを書き忘れる余地を構造的に減らす (`signMcpJwt` を直接呼べば
 * 理論上は迂回できるが、その場合はこの関数を使わなかったことがコード
 * レビューで一目で分かる)。
 */
import type { Env } from "../index";
import { signMcpJwt } from "./mcp-jwt";
import { resolveSecret } from "./secret";

/** ACL parse は fail-closed: JSON 不正 / 非 array / 文字列以外混在 → 空配列 (= deny all)。 */
export function parseGithubMcpAllowlist(raw: string | undefined | null): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.every((x) => typeof x === "string") ? (parsed as string[]) : [];
  } catch {
    return [];
  }
}

/** `login` が `GITHUB_MCP_USER_ALLOWLIST` に含まれるか判定する (fail-closed)。 */
export async function isGithubLoginAllowed(env: Env, login: string): Promise<boolean> {
  const allowlist = parseGithubMcpAllowlist(
    (await resolveSecret(env.GITHUB_MCP_USER_ALLOWLIST)) ?? undefined,
  );
  return allowlist.includes(login);
}

/**
 * headless (ブラウザの同意を経ない) binding_jwt 発行/bind 経路 3 つ
 * (`grant-via-oat` / `grant-via-github` / `register-via-github-comment`) の
 * 共通 kill switch (issue #432)。
 *
 * 従来この 3 経路は `MCP_OAUTH_KV` を prod に intentionally unbind すること
 * (wrangler.toml 参照) で副作用的に無効化されていた。だがこれは「守りたい
 * のは人間の同意を経ない発行経路の遮断であって、KV の所在ではない」という
 * 実際の意図とズレた実装で、prod に `MCP_OAUTH_KV` を bind した瞬間 (#432
 * rollout でいずれ行う) 無警告で 3 経路とも開いてしまう。本 flag を KV bind
 * の有無から独立させ、未設定 = fail-closed (503) を維持したまま KV だけ
 * 先に bind できるようにする。
 *
 * 有効化してよいのは「ブラウザの同意なしの binding_jwt 発行」を運用上許容
 * した env のみ (現状 staging のみ、MCP スタックは staging を実運用として
 * 扱う)。prod で立てる際は #432 のロールアウト手順 (新規 KV namespace 作成
 * → secrets 投入確認 → 本 flag 有効化 → curl で 503→200 遷移確認) を踏むこと。
 */
export function isHeadlessGrantEnabled(env: Env): boolean {
  return env.MCP_HEADLESS_GRANT_ENABLED === "1";
}

export interface GrantMcpBindingJwtParams {
  login: string;
  scope: string;
  aud: string;
  ttlSec: number;
}

export type GrantMcpBindingJwtResult =
  | { ok: true; jwt: string }
  | { ok: false; reason: "not_allowed" };

/**
 * `login` が allowlist に含まれる時だけ binding_jwt を mint する。
 * 含まれなければ mint 自体が起きない (`{ ok: false, reason: "not_allowed" }`)。
 */
export async function grantMcpBindingJwtForGithubLogin(
  env: Env,
  jwtSecret: string,
  params: GrantMcpBindingJwtParams,
): Promise<GrantMcpBindingJwtResult> {
  if (!(await isGithubLoginAllowed(env, params.login))) {
    return { ok: false, reason: "not_allowed" };
  }
  const jwt = await signMcpJwt(
    {
      sub: `github:${params.login}`,
      github_login: params.login,
      scope: params.scope,
      aud: params.aud,
      iss: env.AUTH_WORKER_ORIGIN,
    },
    jwtSecret,
    params.ttlSec,
  );
  return { ok: true, jwt };
}
