/**
 * `POST /mcp/pair/register-via-github-comment` — GitHub issue comment を
 * identity proof として OAT_hash / org_uuid → github_login mapping を KV に
 * 書き込む (issues ippoan/auth-worker#174, #176)。
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
 *      `Authorization: Bearer <OAT>` を付ければ container reclaim 越しに
 *      stable な org_uuid binding も作成される (#176)。
 *   3. auth-worker は comment を anonymous GitHub API で fetch、
 *      `comment.user.login` を取得、body 内に期待行を含むことを確認、
 *      KV に `oat_hash:<hash>` と (optional) `org_uuid:<uuid>` →
 *      { github_login, ... } を 30d TTL で書く。
 *
 * Body:
 *   {
 *     "comment_url": "https://api.github.com/repos/<owner>/<repo>/issues/comments/<id>",
 *     "oat_hash":    "<64-char hex sha256 of OAT>",
 *     "nonce":       "<8-128 url-safe chars>"
 *   }
 *
 * Optional headers (#176):
 *   Authorization: Bearer <OAT>   — OAT 自身を Bearer に乗せれば auth-worker
 *     が `/v1/models` で verify + org_uuid を抽出し、`org_uuid:<uuid>` key にも
 *     binding を書く。container reclaim 越しに stable な silent bootstrap を
 *     実現するために必須。legacy clients (Bearer 無し) は oat_hash key のみで
 *     bind するため後続 container で再 register が必要 (#174 behavior)。
 *
 * Response:
 *   200 → { github_login, bound: true, org_uuid_bound?: bool }
 *   400 → invalid_request    (body 不正 / comment_url 不正な host・形式 / hash・nonce 形式違反)
 *   400 → oat_hash_mismatch  (Bearer OAT の sha256 が body.oat_hash と一致しない)
 *   400 → binding_mismatch   (comment body が期待 line を含まない)
 *   401 → invalid_token      (Bearer 付きで Anthropic API が OAT を reject)
 *   403 → comment_forbidden  (GitHub が anonymous fetch を reject 401/403)
 *   403 → access_denied      (`GITHUB_MCP_USER_ALLOWLIST` に comment.user.login が無い)
 *   404 → comment_not_found  (comment が削除済み / 不存在)
 *   429 → rate_limited       (per source IP)
 *   502 → upstream_error     (api.github.com or api.anthropic.com 5xx / network / response 不正)
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
 *   - **2026-07-24 修正**: `comment_url` の regex は owner/repo を特定の org
 *     tracking issue に限定しておらず、任意の public repo/issue にマッチする。
 *     つまり ACL が無いと「自分の OAT + 自分の GitHub アカウントで任意の
 *     public repo にコメント投稿」するだけで誰でも自己 binding を作れて
 *     しまっていた (org 所属チェックの欠落)。`GITHUB_MCP_USER_ALLOWLIST`
 *     fail-closed チェックを追加し、org 外の login は binding 自体を書かせ
 *     ない (`grant-via-oat.ts` 側の mint-time チェックが最終防衛線、ここは
 *     早期拒否)。
 *   - Bearer/hash mismatch: Bearer が付いていれば sha256(OAT) === body.oat_hash
 *     を verify。不一致は confused-deputy 攻撃 (他人の OAT で他人の comment に
 *     書かれた hash を自分の org に bind しようとする) を遮断するため 400 拒否。
 *   - replay 防止: nonce は per-binding で client が生成、KV に保存しない (1
 *     回の commit でしか使われないため再利用も無害)。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import { isGithubLoginAllowed } from "../lib/mcp-github-grant";
import {
  extractOrgUuidFromResponse,
  hashOat,
  OAT_BINDING_TTL_SEC,
  putOatBinding,
  putOrgBinding,
} from "../lib/mcp-oat-binding";
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

  // ── optional Authorization: Bearer <OAT> for #176 org_uuid binding ──
  // 付いていれば: /v1/models で OAT verify → header から org_uuid 抽出 →
  // sha256(OAT) を後段で body.oat_hash と突合 → org_uuid:<uuid> にも write。
  // 付いていなければ legacy #174 oat_hash-only path にそのまま乗る。
  let bearerOat: string | null = null;
  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (m && m[1]) {
    bearerOat = m[1].trim();
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

  // ── ACL check (fail-closed、GITHUB_MCP_USER_ALLOWLIST) ────────────────
  // 2026-07-24: `comment_url` は任意の GitHub repo/issue にマッチするため、
  // これが無いと誰でも「自分の OAT + 自分の GitHub アカウントで任意の
  // public repo にコメント投稿」するだけで自己 binding を作れてしまう。
  // grant-via-oat 側の mint-time チェック (`grantMcpBindingJwtForGithubLogin`)
  // が最終防衛線だが、ここでも早期に拒否して無意味な binding を KV に残さない。
  if (!(await isGithubLoginAllowed(env, login))) {
    return jsonResponse(
      {
        error: "access_denied",
        error_description: "Your GitHub account is not authorized to use this MCP server.",
      },
      403,
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

  // ── Bearer OAT processing (#176, optional) ──────────────────────────
  // Bearer が付いていれば: (1) hash 突合で confused-deputy 遮断、(2) Anthropic
  // API で OAT verify + org_uuid header 抽出。失敗すれば binding を一切書かず
  // 即 error 返却 (= attacker が自分の Bearer で他人の comment 経由 binding を
  // 作る経路を遮断)。
  let orgUuid: string | null = null;
  if (bearerOat) {
    const bearerHash = await hashOat(bearerOat);
    if (bearerHash !== oatHash) {
      return jsonResponse(
        {
          error: "oat_hash_mismatch",
          error_description:
            "sha256(Bearer OAT) does not match body.oat_hash; refusing to bind",
        },
        400,
      );
    }
    try {
      const res = await fetch("https://api.anthropic.com/v1/models", {
        headers: {
          Authorization: `Bearer ${bearerOat}`,
          "anthropic-version": "2023-06-01",
          "User-Agent":
            "ippoan-auth-worker/mcp-pair-register-via-github-comment",
        },
      });
      if (res.status === 401 || res.status === 403) {
        return jsonResponse(
          {
            error: "invalid_token",
            error_description: `Anthropic rejected OAT (status=${res.status})`,
          },
          401,
        );
      }
      if (!res.ok) {
        return jsonResponse(
          {
            error: "upstream_error",
            error_description: `api.anthropic.com status=${res.status}`,
          },
          502,
        );
      }
      orgUuid = extractOrgUuidFromResponse(res);
    } catch (e) {
      return jsonResponse(
        {
          error: "upstream_error",
          error_description: `api.anthropic.com fetch failed: ${(e as Error).message}`,
        },
        502,
      );
    }
  }

  // ── write KV: oat_hash (always) + org_uuid (#176, if available) ─────
  const now = Date.now();
  const rec = {
    github_login: login,
    bound_at: now,
    expires_at: now + OAT_BINDING_TTL_SEC * 1000,
  };
  await putOatBinding(env, oatHash, rec);
  let orgUuidBound = false;
  if (orgUuid) {
    try {
      await putOrgBinding(env, orgUuid, rec);
      orgUuidBound = true;
    } catch {
      // org_uuid format validation 失敗等。oat_hash は既に bind 済みなので
      // 全失敗にせず graceful — response で orgUuidBound:false を返して
      // 呼び出し側が再 register / 別 path を選べるようにする。
    }
  }

  return jsonResponse({
    github_login: login,
    bound: true,
    org_uuid_bound: orgUuidBound,
  });
}
