/**
 * `GET /mcp/pair/<pair_code>` (issue #144 + issue #157) — ブラウザが踏む
 * 1-click pair 完了 URL + 30 日 refresh_token mint。
 *
 * Flow:
 *   1. cookie `mcp_pair_session` を verify
 *      - 無い / expired → GitHub OAuth に redirect (state に `pair_code` を埋める)
 *      - 有る → session.github_login を取得
 *   2. KV `mcp/pair/<code>` lookup
 *      - 不在 / expired → 404 HTML "code expired"
 *      - claim_login !== session.github_login → 403 HTML "user mismatch"
 *   3. binding_jwt を mint (`signMcpJwt`, aud=github-mcp-server-rs, ttl=24h)
 *      - `scope` claim は record.requested_scope (legacy record は
 *        `"mcp.read mcp.write"` に default)
 *   4. issue #157: opaque refresh_token (32 byte base64url) を mint し、
 *      `mcp/pair_refresh/<sha256(token)>` に 30 日 TTL で保存。
 *      pair record にも `refresh_token` + `refresh_token_expires_at` を焼き込み、
 *      WS upgrade で `Pair-Refresh-Token` header に乗せて binary に渡す。
 *   5. KV record を status="approved" + binding_jwt (+ refresh_token) に更新
 *   6. 200 HTML "paired, you may close this window"
 *
 * binary 側 WS upgrade (`/u/<login>/connect`) は `Authorization: Bearer <pair_code>`
 * を受け取り、KV を引いて status="approved" を確認したら binding_jwt に内部置換して
 * DO に forward する (mcp-relay-connect.ts 側で扱う)。
 */

import type { Env } from "../index";
import { resolveMcpJwtSecret, signMcpJwt } from "../lib/mcp-jwt";
import {
  PAIR_REFRESH_TTL_SEC,
  approvePair,
  generatePairRefreshToken,
  getPair,
  hashRefreshToken,
  putPairRefresh,
  type PairRefreshRecord,
} from "../lib/mcp-pair";
import { mcpToGithubScope, parseMcpScope } from "../lib/mcp-scope";
import { resolveSecret } from "../lib/resolve-secret";
import {
  PAIR_SESSION_COOKIE_NAME,
  readPairSessionCookie,
  verifyPairSession,
} from "../lib/mcp-session";
import { generateOAuthState } from "../lib/security";

/** binding_jwt の TTL。device flow と異なり再認証はブラウザ pair の再踏みで簡単なので
 *  24h で十分。binary 側 reconnect はこの TTL 内なら無認証で復帰できる。 */
const BINDING_JWT_TTL_SEC = 60 * 60 * 24;

const MCP_AUD = "github-mcp-server-rs";

/** legacy PairRecord (`requested_scope` 無し) を読んだ時の fallback。
 *  PR #62 (auth-worker) 以前に putPair された record の挙動を維持する。 */
const LEGACY_DEFAULT_SCOPE = "mcp.read mcp.write";

function htmlResponse(html: string, status: number): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function page(opts: {
  title: string;
  body: string;
  status: number;
  color: string;
}): Response {
  const html = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(opts.title)} — MCP pair</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem; color: #1f2937; }
  h1 { color: ${opts.color}; font-size: 1.5rem; }
  code { background: #f3f4f6; padding: .15rem .35rem; border-radius: .25rem; font-size: .9em; }
  .muted { color: #6b7280; font-size: .9em; margin-top: 1.5rem; }
</style></head><body>
<h1>${escapeHtml(opts.title)}</h1>
${opts.body}
</body></html>`;
  return htmlResponse(html, opts.status);
}

export async function handleMcpPairClaim(
  request: Request,
  env: Env,
  pair_code: string,
): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────
  const jwtSecret = await resolveMcpJwtSecret(env.MCP_JWT_SECRET);
  if (
    !env.MCP_OAUTH_KV ||
    !jwtSecret ||
    !env.SESSION_COOKIE_SECRET ||
    !env.OAUTH_STATE_SECRET ||
    !env.GITHUB_MCP_CLIENT_ID ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return page({
      title: "Service unavailable",
      body: "<p>MCP OAuth Provider is not configured.</p>",
      status: 503,
      color: "#b91c1c",
    });
  }

  // ── cookie verify ────────────────────────────────────────────────────
  const cookieRaw = readPairSessionCookie(request.headers.get("Cookie"));
  const session = cookieRaw
    ? await verifyPairSession(cookieRaw, env.SESSION_COOKIE_SECRET)
    : null;

  if (!session) {
    // GitHub OAuth に飛ばす。state に pair_code を埋め込み、callback で
    // cookie set + /mcp/pair/<pair_code> に redirect させる。
    const issuer = env.AUTH_WORKER_ORIGIN;
    const callbackUri = `${issuer}/mcp/pair_callback`;
    const state = await generateOAuthState(callbackUri, env.OAUTH_STATE_SECRET, {
      provider: "github_mcp_pair",
      pair_code,
    });
    const ghClientId = await resolveSecret(env.GITHUB_MCP_CLIENT_ID);
    if (!ghClientId) {
      return page({
        title: "Service unavailable",
        body: "<p>GitHub OAuth client_id not resolvable.</p>",
        status: 503,
        color: "#b91c1c",
      });
    }
    const ghAuthorize = new URL("https://github.com/login/oauth/authorize");
    ghAuthorize.searchParams.set("client_id", ghClientId);
    ghAuthorize.searchParams.set("redirect_uri", callbackUri);
    ghAuthorize.searchParams.set(
      "scope",
      // pair 用は scope = "" (login 取得のみ) で十分だが、device/auth flow と
      // 同じ scope を要求して GitHub 側 cookie session を再利用しやすくする。
      // record.requested_scope が `mcp.admin` だけでも `mcpToGithubScope` が
      // `repo` を返すため branch protection API も叩ける。
      mcpToGithubScope(parseMcpScope("mcp.read mcp.write")),
    );
    ghAuthorize.searchParams.set("state", state);
    return Response.redirect(ghAuthorize.toString(), 302);
  }

  // ── pair record lookup ──────────────────────────────────────────────
  const rec = await getPair(env, pair_code);
  if (!rec) {
    return page({
      title: "Pair code expired",
      body: `<p>This pair link has expired or is invalid. Re-run <code>install-mcp.sh</code> on the binary side to get a new link.</p>`,
      status: 404,
      color: "#b91c1c",
    });
  }

  if (rec.claim_login !== session.github_login) {
    return page({
      title: "User mismatch",
      body: `<p>You signed in as <code>${escapeHtml(session.github_login)}</code>, but this pair link is for <code>${escapeHtml(rec.claim_login)}</code>. Make sure you started the binary while logged into the same GitHub account.</p>`,
      status: 403,
      color: "#b91c1c",
    });
  }

  // ── already approved? (idempotency: ブラウザ reload で 2 回目踏まれた場合) ──
  if (rec.status === "approved") {
    return page({
      title: "Paired ✓",
      body: `<p>You may close this window. The MCP relay should already be active for <code>${escapeHtml(session.github_login)}</code>.</p>
<p class="muted">If the binary still shows "waiting", retry within ${Math.max(60, Math.floor((rec.expires_at - Date.now()) / 1000))}s.</p>`,
      status: 200,
      color: "#15803d",
    });
  }

  // ── mint binding_jwt + approve ──────────────────────────────────────
  const scope = rec.requested_scope ?? LEGACY_DEFAULT_SCOPE;
  const binding_jwt = await signMcpJwt(
    {
      sub: `github:${session.github_login}`,
      github_login: session.github_login,
      scope,
      aud: MCP_AUD,
    },
    jwtSecret,
    BINDING_JWT_TTL_SEC,
  );

  // ── issue #157: 30 日 refresh_token を mint。pair record に焼き込んでおき
  //    WS upgrade で binary に渡す。本体は別 key (sha256 lookup) に保管。 ──
  const refreshToken = generatePairRefreshToken();
  const refreshHash = await hashRefreshToken(refreshToken);
  const now = Date.now();
  const refreshExpiresAt = now + PAIR_REFRESH_TTL_SEC * 1000;
  const refreshRec: PairRefreshRecord = {
    github_login: session.github_login,
    requested_scope: scope,
    created_at: now,
    expires_at: refreshExpiresAt,
    last_used_at: null,
    revoked: false,
  };
  await putPairRefresh(env, refreshHash, refreshRec);

  const approved = await approvePair(env, pair_code, binding_jwt, {
    token: refreshToken,
    expires_at: refreshExpiresAt,
  });
  if (!approved) {
    // race: TTL 切れがちょうど発生した。refresh record は KV に残るが、binary
    // 側に token は渡らないので参照不能 (= dangling だが 30 日で消える、害なし)。
    return page({
      title: "Pair code expired",
      body: "<p>This pair link expired while approving. Please retry from the binary.</p>",
      status: 404,
      color: "#b91c1c",
    });
  }

  // issue #155: pair 完了境界で `notifications/tools/list_changed` を broadcast
  // するよう DO に通知する。pair-claim 時点では binary 側 WS はまだ attach されて
  // いない可能性が高いが、もし stub MCP server を踏みつつ Claude session を維持して
  // いる client がいれば「再 tools/list せよ」のシグナルを早めに渡しておくことで
  // pair 直後の UX 反応が滑らかになる。
  //
  // best-effort — DO binding 未設定 / fetch 失敗は無視 (本流の pair 成立を阻害しない)。
  if (env.MCP_SESSION_DO) {
    const stub = env.MCP_SESSION_DO.get(
      env.MCP_SESSION_DO.idFromName(session.github_login),
    );
    await stub
      .fetch(
        new Request("https://do.invalid/__notify_tools_list_changed", {
          method: "POST",
        }),
      )
      .catch((e: unknown) => {
        console.warn(
          "mcp-pair-claim: tools/list_changed broadcast failed (best-effort):",
          e,
        );
      });
  }

  return page({
    title: "Paired ✓",
    body: `<p>Signed in as <code>${escapeHtml(session.github_login)}</code>. The MCP relay will start within ~5 seconds.</p>
<p>You may close this window.</p>
<p class="muted">Cookie name: <code>${PAIR_SESSION_COOKIE_NAME}</code>. Session is valid for 30 minutes. Scope: <code>${escapeHtml(scope)}</code>.</p>`,
    status: 200,
    color: "#15803d",
  });
}
