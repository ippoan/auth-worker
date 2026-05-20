/**
 * `POST /mcp/pair/register-via-github-comment` — GitHub issue comment を
 * identity proof として OAT_hash → github_login mapping を KV に書き込む
 * (issue ippoan/auth-worker#174)。
 *
 * 設計背景:
 *   CCoW container 内で `mcp__github__add_issue_comment` を呼ぶと Anthropic
 *   proxy が user 自身の GitHub access_token を attach し、GitHub server-side
 *   で `comment.user.login` が enforce される。これを root-of-trust に使って
 *   container 内のみで完結する identity binding を実現する。
 *
 * Flow:
 *   1. Container 内 Claude が `mcp__github__add_issue_comment` を本 tracking
 *      issue (#174) に投稿する。body = `oat-binding: <oat_hash> <nonce>`。
 *   2. Comment_id (or comment_url) を取得して本 endpoint に POST する。
 *   3. auth-worker は comment を anonymous GitHub API で fetch、
 *      `comment.user.login` を取得、body 内に期待行を含むことを確認、
 *      KV に `oat_hash:<hash>` → { github_login, ... } を 30d TTL で書く。
 *
 * Body:
 *   {
 *     "comment_url": "https://api.github.com/repos/<owner>/<repo>/issues/comments/<id>",
 *     "oat_hash":    "<64-char hex sha256 of OAT>",
 *     "nonce":       "<8-128 url-safe chars>"
 *   }
 *
 * Response:
 *   200 → { github_login, bound: true }
 *   400 → invalid_request    (body 不正 / comment_url 不正な host・形式 / hash・nonce 形式違反)
 *   400 → binding_mismatch   (comment body が期待 line を含まない)
 *   403 → comment_forbidden  (GitHub が anonymous fetch を reject 401/403)
 *   404 → comment_not_found  (comment が削除済み / 不存在)
 *   429 → rate_limited       (per source IP)
 *   502 → upstream_error     (api.github.com 5xx / network / response 不正)
 *   503 → server_error       (KV 未設定)
 *
 * Security:
 *   - 偽装攻撃: `comment.user.login` は GitHub server-side で enforce、第三者は
 *     書けない。auth-worker は API を直接叩いて検証するため、client-supplied
 *     login claim を信用しない。
 *   - URL injection: `comment_url` は `https://api.github.com/repos/<o>/<r>/
 *     issues/comments/<id>` 形に strict regex 検証 (open redirect / SSRF を遮断)。
 *   - 自分の OAT_hash を yhonda-ohishi の comment に書いた風に偽造: comment は
 *     一意 `comment_url` でしか取れず、`user.login` が attacker login で記録さ
 *     れるため、attacker login にしか bind しない (自爆)。
 *   - replay 防止: nonce は per-binding で client が生成、KV に保存しない (1
 *     回の commit でしか使われないため再利用も無害)。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { OAT_BINDING_TTL_SEC, putOatBinding } from "../lib/mcp-oat-binding";
import { checkAndBumpRateLimit } from "../lib/mcp-pair";

interface RegisterRequest {
  comment_url?: unknown;
  oat_hash?: unknown;
  nonce?: unknown;
}

interface GithubCommentResponse {
  user?: { login?: string };
  body?: string;
}

/** `comment_url` の strict regex。GitHub の comment API の唯一の正規 form のみ
 *  許可する (SSRF / open redirect 遮断)。owner / repo は `[A-Za-z0-9_.-]+` に
 *  抑える (GitHub 仕様)。 */
const COMMENT_URL_RE =
  /^https:\/\/api\.github\.com\/repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/issues\/comments\/\d+$/;

/** SHA-256 hex (64 chars lowercase)。`hashOat` の出力 format と完全一致を要求。 */
const OAT_HASH_RE = /^[0-9a-f]{64}$/;

/** Client が生成する random nonce。8-128 chars、url-safe charset のみ許可。 */
const NONCE_RE = /^[A-Za-z0-9_-]{8,128}$/;

export async function handleMcpPairRegisterViaGithubComment(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return jsonResponse(
      { error: "server_error", error_description: "MCP_OAUTH_KV not bound" },
      503,
    );
  }

  // ── per-IP rate limit (10/min) — anonymous endpoint なので必須 ──
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const okRate = await checkAndBumpRateLimit(env, ip, Date.now());
  if (!okRate) {
    return jsonResponse(
      {
        error: "rate_limited",
        error_description: "too many register requests; retry in 1 minute",
      },
      429,
    );
  }

  // ── parse body ───────────────────────────────────────────────────────
  const ct = request.headers.get("Content-Type") ?? "";
  if (!ct.includes("application/json")) {
    return jsonResponse(
      {
        error: "invalid_request",
        error_description: "Content-Type must be application/json",
      },
      400,
    );
  }
  let body: RegisterRequest;
  try {
    body = (await request.json()) as RegisterRequest;
  } catch {
    return jsonResponse(
      { error: "invalid_request", error_description: "invalid JSON body" },
      400,
    );
  }

  const commentUrl = typeof body.comment_url === "string" ? body.comment_url : "";
  const oatHash =
    typeof body.oat_hash === "string" ? body.oat_hash.toLowerCase() : "";
  const nonce = typeof body.nonce === "string" ? body.nonce : "";

  if (!COMMENT_URL_RE.test(commentUrl)) {
    return jsonResponse(
      {
        error: "invalid_request",
        error_description:
          "comment_url must match https://api.github.com/repos/<owner>/<repo>/issues/comments/<id>",
      },
      400,
    );
  }
  if (!OAT_HASH_RE.test(oatHash)) {
    return jsonResponse(
      {
        error: "invalid_request",
        error_description: "oat_hash must be 64-char lowercase hex sha256",
      },
      400,
    );
  }
  if (!NONCE_RE.test(nonce)) {
    return jsonResponse(
      {
        error: "invalid_request",
        error_description: "nonce must be 8-128 url-safe chars ([A-Za-z0-9_-])",
      },
      400,
    );
  }

  // ── fetch comment from GitHub API ───────────────────────────────────
  let comment: GithubCommentResponse;
  try {
    const res = await fetch(commentUrl, {
      headers: {
        "User-Agent": "ippoan-auth-worker/mcp-pair-register-via-github-comment",
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (res.status === 404) {
      return jsonResponse(
        {
          error: "comment_not_found",
          error_description: "GitHub comment not found (deleted or wrong id)",
        },
        404,
      );
    }
    if (res.status === 401 || res.status === 403) {
      return jsonResponse(
        {
          error: "comment_forbidden",
          error_description: `GitHub rejected anonymous fetch (status=${res.status})`,
        },
        403,
      );
    }
    if (!res.ok) {
      return jsonResponse(
        {
          error: "upstream_error",
          error_description: `api.github.com status=${res.status}`,
        },
        502,
      );
    }
    comment = (await res.json()) as GithubCommentResponse;
  } catch (e) {
    return jsonResponse(
      {
        error: "upstream_error",
        error_description: `api.github.com fetch failed: ${(e as Error).message}`,
      },
      502,
    );
  }

  // ── verify shape + binding line ─────────────────────────────────────
  const login = comment.user?.login;
  const commentBody = comment.body;
  if (typeof login !== "string" || login.length === 0) {
    return jsonResponse(
      {
        error: "upstream_error",
        error_description: "comment.user.login missing in GitHub response",
      },
      502,
    );
  }
  if (typeof commentBody !== "string") {
    return jsonResponse(
      {
        error: "upstream_error",
        error_description: "comment.body missing in GitHub response",
      },
      502,
    );
  }
  // body には複数行 / 余計な markdown が含まれてよい。期待 line を含むかどうかだけ
  // 確認する (Claude が orchestrate する際に prefix / suffix を付ける余地)。
  const expected = `oat-binding: ${oatHash} ${nonce}`;
  if (!commentBody.includes(expected)) {
    return jsonResponse(
      {
        error: "binding_mismatch",
        error_description:
          "comment body does not contain expected `oat-binding: <hash> <nonce>` line",
      },
      400,
    );
  }

  // ── write KV ─────────────────────────────────────────────────────────
  const now = Date.now();
  await putOatBinding(env, oatHash, {
    github_login: login,
    bound_at: now,
    expires_at: now + OAT_BINDING_TTL_SEC * 1000,
  });

  return jsonResponse({ github_login: login, bound: true });
}
