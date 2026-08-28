/**
 * verify_screenshot — MCP tool から Browser Run (browser binding) で
 * *.ippoan.org のページを「ログイン済み状態」で screenshot する (PR merge 後の
 * 本番検証用、dev-login #423/#424/#433 の系列)。
 *
 * 流れ (2026-08-28 に scratch worker で実測済みの経路をそのまま製品化):
 *  1. 呼び出し側 (mcp-tools.ts) が `mintDevToken` で dev JWT を server 内 mint
 *     (gate は dev-login と同一: allowlist + google_sub cache。token は MCP
 *     応答に出さない — Claude 経由で token を運ばない)
 *  2. `logi_auth_token` cookie (Domain=.ippoan.org) としてブラウザに注入
 *  3. 対象ページへ遷移。CF Access 配下のホストでも auth-worker 自身が Access の
 *     OIDC IdP なので cookie だけで Access セッションが張られる。ただし Access の
 *     ログインページは `#data[data-auto-redirect-url]` を JS で読んで遷移する作りで、
 *     JS を実行しないエンジン (kitesurf) はそこで停止する — その場合は属性から
 *     authorize URL を読んで明示的に 1 hop 遷移する (`shouldFollowAccessHop`)
 *  4. PNG は MCP_OAUTH_KV に TTL 5 分の base64 で置き、短命 URL
 *     (`GET /mcp/shot/<id>`) を返す (PNG を MCP body に載せない —
 *     cdp-relay の browser_stash / shot_url と同じ作法)
 *
 * SSRF 境界: 認証 cookie を積んだブラウザを任意 URL に向けられると cookie 漏洩の
 * 口になるため、遷移先 (初期 URL / Access hop 先) は `isAllowedVerifyTarget`
 * (https + ippoan.org 配下のみ) で fail-closed に検査する。リダイレクト追従で
 * cloudflareaccess.com 等へ出るのは通常のブラウジングと同じで許容する。
 */
import puppeteer, { type BrowserWorker } from "@cloudflare/puppeteer";
import type { Env } from "../index";
import { base64Encode } from "./lineworks-crypto";
import { generateDeviceCode } from "./mcp-codes";

/** shot の KV TTL (秒)。Cloudflare KV の expirationTtl 最小値 60 の上で短めに。 */
export const VERIFY_SHOT_TTL_SEC = 300;
/** KV key prefix (`MCP_OAUTH_KV` 同居。既存 prefix 系統と衝突しないこと)。 */
export const VERIFY_SHOT_KV_PREFIX = "verify_shot:";
/** 1 回の tool call で撮れる URL 数の上限 (Browser Run の無料枠を守る)。 */
export const VERIFY_SHOT_MAX_URLS = 5;

export type VerifyEngine = "chromium" | "kitesurf";

export class VerifyShotError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "VerifyShotError";
  }
}

/**
 * screenshot 対象 / Access hop 先として許可する URL か。
 * https 限定 + hostname が ippoan.org そのもの or `.ippoan.org` で終わるもののみ
 * (`evil-ippoan.org` や末尾ドット FQDN は dot 境界 / 完全一致で弾かれる。
 *  `URL.hostname` は userinfo を含まないので `https://a.ippoan.org@evil/` 型も安全)。
 */
export function isAllowedVerifyTarget(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  const host = u.hostname.toLowerCase();
  return host === "ippoan.org" || host.endsWith(".ippoan.org");
}

/**
 * Access ログインページで止まった時に踏んでよい hop 先を返す (だめなら null)。
 *  - 現在地が `<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/login/...` であること
 *  - hop 先 (data-auto-redirect-url 由来) が `isAllowedVerifyTarget` を通ること
 */
export function shouldFollowAccessHop(
  pageUrl: string,
  hopUrl: string | null,
  teamDomain: string | undefined,
): string | null {
  if (!hopUrl || !teamDomain) return null;
  let cur: URL;
  try {
    cur = new URL(pageUrl);
  } catch {
    return null;
  }
  if (cur.hostname.toLowerCase() !== teamDomain.toLowerCase()) return null;
  if (!cur.pathname.startsWith("/cdn-cgi/access/login")) return null;
  if (!isAllowedVerifyTarget(hopUrl)) return null;
  return hopUrl;
}

export interface VerifyShotRow {
  url: string;
  final_url: string;
  title: string;
  /** Access ログインページを明示 hop した回数 (chromium は通常 0)。 */
  access_hops: number;
  /** 短命 (TTL 5 分) の PNG 取得 URL。`curl -o shot.png <url>` → 画像を確認。 */
  shot_url: string;
}

export interface VerifyShotOutcome {
  engine: VerifyEngine;
  expires_in: number;
  results: VerifyShotRow[];
}

/**
 * dev JWT を cookie 注入して各 URL を screenshot する本体。
 * 呼び出し側で URL は検証済みの前提だが、防御的に再検査する (fail-closed)。
 */
export async function runVerifyShots(
  env: Env,
  opts: { urls: string[]; engine: VerifyEngine; cookieValue: string },
): Promise<VerifyShotOutcome> {
  const browserBinding: BrowserWorker | undefined = env.BROWSER;
  if (!browserBinding) {
    throw new VerifyShotError(503, "browser_binding_not_configured");
  }
  if (!env.MCP_OAUTH_KV) {
    throw new VerifyShotError(503, "MCP_OAUTH_KV not bound");
  }
  for (const raw of opts.urls) {
    if (!isAllowedVerifyTarget(raw)) {
      throw new VerifyShotError(400, `url not allowed (https://*.ippoan.org only): ${raw}`);
    }
  }

  const browser =
    opts.engine === "kitesurf"
      ? await puppeteer.launch(browserBinding, { browser: "kitesurf" })
      : await puppeteer.launch(browserBinding);
  const results: VerifyShotRow[] = [];
  try {
    for (const target of opts.urls) {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.setCookie({
        name: "logi_auth_token",
        value: opts.cookieValue,
        domain: ".ippoan.org",
        path: "/",
        secure: true,
      });
      await page.goto(target, { waitUntil: "networkidle0", timeout: 30_000 });

      // Access ログインページの auto-redirect を JS 抜きで再現する (header コメント
      // 参照)。正常系は 1 hop で抜けるが、state 再発行等で戻るケースに備え 2 回まで。
      let accessHops = 0;
      for (let i = 0; i < 2; i++) {
        const candidate = (await page.evaluate(
          `(() => {
            const el = document.querySelector("#data");
            return el ? el.getAttribute("data-auto-redirect-url") : null;
          })()`,
        )) as string | null;
        const hop = shouldFollowAccessHop(page.url(), candidate, env.ACCESS_TEAM_DOMAIN);
        if (!hop) break;
        accessHops++;
        await page.goto(hop, { waitUntil: "networkidle0", timeout: 30_000 });
      }

      const png = (await page.screenshot()) as Buffer;
      const id = generateDeviceCode();
      await env.MCP_OAUTH_KV.put(
        `${VERIFY_SHOT_KV_PREFIX}${id}`,
        base64Encode(new Uint8Array(png)),
        { expirationTtl: VERIFY_SHOT_TTL_SEC },
      );
      const origin = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
      results.push({
        url: target,
        final_url: page.url(),
        title: await page.title(),
        access_hops: accessHops,
        shot_url: `${origin}/mcp/shot/${id}`,
      });
      await page.close();
    }
  } finally {
    await browser.close();
  }
  return { engine: opts.engine, expires_in: VERIFY_SHOT_TTL_SEC, results };
}
