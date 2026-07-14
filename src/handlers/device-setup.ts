/**
 * /device/setup — alc-app-s3 デバイス (CoreS3 統合ハブ / AtomS3 印刷ブリッジ) の
 * USB provisioning ページ (Refs #365、機種分離は ippoan/alc-app-s3#38)。
 *
 * Wi-Fi の Improv 設定と同じ「セットアップは USB 前提」思想:
 * operator がログイン済みブラウザで本ページを開き、WebSerial (Chrome/Edge) で
 * CoreS3 に device credential を注入する。QR/承認ページのフローは使わない
 * (operator が既にログイン済みのため)。
 *
 *   GET  /device/setup       — login-gated HTML (WebSerial JS 入り)
 *   POST /device/setup/pair  — cookie session + Origin check で credential を mint
 *                              (role は body.kind → DEVICE_KINDS で決まる:
 *                              cores3 = device-hub / atoms3-print = device-print。
 *                              replace_label で同一 (tenant, label) の旧
 *                              credential を revoke → 再発行)
 *
 * 注入手順 (ページ JS が自動実行):
 *   1. POST /device/setup/pair → { device_id, device_secret, tenant_id }
 *   2. シリアル: AUTH SET <id> <secret> <tenant>
 *   3. シリアル: AUTH URL <このページの origin>
 *      測定記録の送り先 (WS URL) はページの origin から自動判定 —
 *      staging で開いていれば staging recorder を注入、それ以外は送らず
 *      ファームウェア既定 (prod recorder) のまま。operator には訊かない
 *   4. シリアル: AUTH TOKEN → `EVT AUTH_TOKEN OK` で疎通確認完了
 */

import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { verifyJwt } from "../lib/jwt";
import { clearAuthCookieVariants, getAuthCookie } from "../lib/cookies";
import { escapeHtml } from "../lib/html";
import {
  createDeviceCredential,
  createDeviceCredentialReplacingLabel,
  getDeviceRecord,
  listDeviceRecordsByTenant,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_PRINT,
} from "../lib/device";

function jsonNoStore(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function issuerOf(env: Env): string {
  return env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
}

/** alc-app-s3 CI が GitHub Pages に公開する firmware の置き場。 */
const PAGES_BASE = "https://ippoan.github.io/alc-app-s3";

/** 本ページで管理する機種 (kind)。role・firmware・manifest を機種単位で束ねる。 */
export interface DeviceKind {
  /** credential の role (= 誤配布防止 gate の単位) */
  role: string;
  /** デバイスラベルの既定値 */
  labelDefault: string;
  /** OTA する app 単体イメージの既定 URL (build.yml の "Save OTA app image") */
  appUrl: string;
  /**
   * dev ビルド (mem-hud 付き) の app イメージ URL (alc-app-s3#44)。
   * developer アカウントの「dev ビルドを配信」選択が OTA URL をこれに
   * 切り替える。dev バリアントを持たない機種は undefined
   */
  devAppUrl?: string;
  /** 公開中バージョンを載せた manifest (CI が `<version>+<sha>` を書く) */
  manifestUrl: string;
  /** 表示名 */
  display: string;
}

/**
 * dev ビルド配信の選択 UI を表示する developer アカウント
 * (lib/admin-html.ts の DEVELOPER_EMAILS と同方式)。
 * OTA URL 欄自体は従来どおり誰でも自由編集できるため、これはあくまで
 * UI 上の出し分け — サーバ側の追加 enforcement は不要。
 */
const DEVELOPER_EMAILS = ["m.tama.ramu@gmail.com"];

/**
 * kind → 機種定義。**role と firmware はここで 1:1 に対応**させ、
 * CoreS3 firmware を印刷ブリッジへ push するような取り違えを構造的に防ぐ
 * (ippoan/alc-app-s3#38)。
 */
export const DEVICE_KINDS: Readonly<Record<string, DeviceKind>> = {
  cores3: {
    role: DEVICE_ROLE_HUB,
    labelDefault: "cores3",
    appUrl: `${PAGES_BASE}/firmware/alc-hub-cores3-app.bin`,
    devAppUrl: `${PAGES_BASE}/firmware/alc-hub-cores3-dev-app.bin`,
    manifestUrl: `${PAGES_BASE}/manifest.json`,
    display: "CoreS3 統合ハブ",
  },
  "atoms3-print": {
    role: DEVICE_ROLE_PRINT,
    labelDefault: "atoms3-print",
    appUrl: `${PAGES_BASE}/firmware/alc-hub-atoms3-print-app.bin`,
    manifestUrl: `${PAGES_BASE}/manifest-atoms3-print.json`,
    display: "AtomS3 印刷ブリッジ",
  },
};

/** role → kind 名の逆引き (一覧表示・OTA gate 用)。 */
function kindNameForRole(role: string | undefined): string | null {
  for (const [name, k] of Object.entries(DEVICE_KINDS)) {
    if (k.role === role) return name;
  }
  return null;
}

interface OperatorSession {
  tenantId: string;
  email: string;
}

/** cookie (logi_auth_token) の session JWT から operator の tenant/email を返す。不正なら null。 */
async function cookieSession(request: Request, env: Env): Promise<OperatorSession | null> {
  const token = getAuthCookie(request);
  if (!token) return null;
  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) return null;
  const payload = await verifyJwt(token, secret, env.WORKER_ENV);
  if (!payload) return null;
  const tenantId =
    (payload.tenant_id as string | undefined) || (payload.org as string | undefined) || "";
  if (!tenantId) return null;
  return { tenantId, email: (payload.email as string | undefined) || "" };
}

/** GET /device/setup — WebSerial provisioning ページ (要ログイン)。 */
export async function handleDeviceSetupPage(request: Request, env: Env): Promise<Response> {
  const issuer = issuerOf(env);
  const session = await cookieSession(request, env);
  if (!session) {
    // cookie が「有るのに検証に落ちる」場合 (期限切れ・env 不一致・組織未選択で
    // tenant_id 無し) に /login へ 302 すると、ログイン済みブラウザでは
    // login → (自動) callback → 本ページ → login … の無限リダイレクトになる。
    // cookie 有りの失敗はリダイレクトせず理由を表示して止める。
    if (getAuthCookie(request)) {
      // Refs #387: 検証に落ちた cookie はこの応答で破棄する (Domain 付き /
      // host-only の両方)。次のリロードで cookie 無し → /login への正常な
      // redirect に入り、手動 logout なしで回復できる
      const headers = new Headers({
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      });
      for (const c of clearAuthCookieVariants(new URL(request.url).hostname)) {
        headers.append("Set-Cookie", c);
      }
      return new Response(sessionErrorPage(issuer), { status: 403, headers });
    }
    const back = `${issuer}/device/setup`;
    return Response.redirect(`${issuer}/login?redirect_uri=${encodeURIComponent(back)}`, 302);
  }
  return new Response(setupPage(issuer, session.email), {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

/** cookie はあるがセッションとして使えない場合の案内 (リダイレクトループ防止)。 */
function sessionErrorPage(issuer: string): string {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>セッションを確認できません</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}.muted{color:#666;font-size:.9rem}a{color:#1a56db}</style></head>
<body><h1>セッションを確認できません</h1>
<p>ログインセッションが期限切れか、組織が未選択の可能性があります。</p>
<ul>
<li><a href="${escapeHtml(issuer)}/top">/top で組織を確認・選択する</a></li>
<li><a href="${escapeHtml(issuer)}/logout">一度ログアウトしてやり直す</a></li>
</ul>
<p class="muted">${escapeHtml(issuer)}</p></body></html>`;
}

/**
 * POST /device/setup/pair — operator の cookie session で device credential を発行する。
 * `/device/pair` (Bearer 限定) と違い browser から叩くため Origin を検証する (CSRF 対策)。
 * role は body.kind → DEVICE_KINDS で決める (本ページで管理する機種以外は mint しない)。
 */
export async function handleDeviceSetupPair(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  if (request.headers.get("Origin") !== issuerOf(env)) {
    return jsonNoStore({ error: "bad_origin" }, 403);
  }

  let body: Record<string, unknown> = {};
  try {
    const v = await request.json();
    if (v && typeof v === "object") body = v as Record<string, unknown>;
  } catch {
    // 空 body は既定値で続行
  }
  const kindName = typeof body.kind === "string" && body.kind ? body.kind : "cores3";
  const kind = DEVICE_KINDS[kindName];
  if (!kind) return jsonNoStore({ error: "unknown kind" }, 400);
  const label = typeof body.label === "string" && body.label ? body.label : kind.labelDefault;
  const replaceLabel = body.replace_label === true;

  const now = Math.floor(Date.now() / 1000);
  const cred = replaceLabel
    ? await createDeviceCredentialReplacingLabel(env, session.tenantId, label, now, kind.role)
    : await createDeviceCredential(env, session.tenantId, label, now, kind.role);

  return jsonNoStore(
    {
      device_id: cred.device_id,
      device_secret: cred.device_secret,
      tenant_id: cred.record.tenant_id,
      label: cred.record.label,
      role: cred.record.role,
      kind: kindName,
      note: "store device_secret now; it is not retrievable later",
    },
    201,
  );
}

/**
 * GET /device/setup/list — operator の tenant に登録済みの管理対象デバイス
 * (DEVICE_KINDS の role = device-hub / device-print) 一覧。
 *
 * **role を DEVICE_KINDS に絞る**: dtako-scraper / uploader 等の別種デバイスを
 * 混ぜて表示すると、その行の「更新」で誤った firmware を配布する事故になる。
 * 応答の kind は行ごとの firmware/manifest の選択に使う。
 * secret は KV に hash しか無いため応答に含まれない (含められない)。
 */
export async function handleDeviceSetupList(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  const devices = (await listDeviceRecordsByTenant(env, session.tenantId))
    .filter((r) => kindNameForRole(r.role) !== null)
    .map((r) => ({
      device_id: r.device_id,
      label: r.label,
      role: r.role ?? "",
      kind: kindNameForRole(r.role) ?? "",
      created_at: r.created_at,
    }));
  return jsonNoStore({ devices });
}

/**
 * cf-alc-recorder の内部 HTTP API を service binding 経由で叩く。
 * recorder 側は `Authorization: <INTERNAL_SHARED_SECRET>` (生値) を要求する
 * (auth-worker と同じ Secrets Store entry を共有)。binding / secret 未設定は
 * null (caller が 503)。
 */
async function recorderFetch(
  env: Env,
  path: string,
  init: RequestInit,
): Promise<Response | null> {
  // await を跨ぐと env.ALC_RECORDER の narrowing が失われるためローカルに束ねる
  const recorder = env.ALC_RECORDER;
  if (!recorder) return null;
  const secret = await resolveSecret(env.INTERNAL_SHARED_SECRET);
  if (!secret) return null;
  const headers = new Headers(init.headers);
  headers.set("Authorization", secret);
  // service binding fetch は host を無視するが path は recorder の route と
  // 一致させる必要がある
  return recorder.fetch(`https://alc-recorder.internal${path}`, { ...init, headers });
}

/**
 * device_id が本当にこの operator の tenant の管理対象デバイスか確認し、
 * その機種 (DeviceKind) を返す (詐称防止 + 誤配布防止に必須)。
 * 他 tenant / revoked / DEVICE_KINDS 外の role は null (fail-closed)。
 */
async function managedDeviceKind(
  env: Env,
  tenantId: string,
  deviceId: string,
): Promise<DeviceKind | null> {
  const rec = await getDeviceRecord(env, deviceId);
  if (!rec || rec.tenant_id !== tenantId || rec.revoked) return null;
  const kindName = kindNameForRole(rec.role);
  return (kindName && DEVICE_KINDS[kindName]) || null;
}

/**
 * POST /device/setup/ota — 登録済みデバイスへ OTA 更新指示を push する。
 * body: `{ device_id, url }` (url は http(s) の firmware app イメージ)。
 * recorder の下り command API に `{action:"ota", url}` を投げ、返ってきた
 * command id を返す (web はこの id で進捗をポーリングする)。
 */
export async function handleDeviceSetupOta(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  if (request.headers.get("Origin") !== issuerOf(env)) {
    return jsonNoStore({ error: "bad_origin" }, 403);
  }

  let body: Record<string, unknown> = {};
  try {
    const v = await request.json();
    if (v && typeof v === "object") body = v as Record<string, unknown>;
  } catch {
    // 空 body → 検証で弾く
  }
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const url = typeof body.url === "string" ? body.url : "";
  if (!deviceId || !/^https?:\/\//.test(url)) {
    return jsonNoStore({ error: "device_id と http(s) url が必要です" }, 400);
  }
  // device がこの operator の tenant の管理対象か確認 (他テナントのデバイスを
  // 更新させない — recorder は tenant 単位 DO だが、二重に fail-closed)
  if (!(await managedDeviceKind(env, session.tenantId, deviceId))) {
    return jsonNoStore({ error: "not_your_device" }, 403);
  }

  const res = await recorderFetch(
    env,
    `/tenants/${encodeURIComponent(session.tenantId)}/devices/${encodeURIComponent(deviceId)}/command`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload: { action: "ota", url } }),
    },
  );
  if (!res) return jsonNoStore({ error: "recorder_unconfigured" }, 503);
  if (res.status === 404) {
    // デバイスが WS 未接続 (recorder に居ない)
    return jsonNoStore({ error: "device_not_connected" }, 409);
  }
  if (!res.ok) return jsonNoStore({ error: `recorder_${res.status}` }, 502);
  const data = (await res.json()) as { id?: string };
  return jsonNoStore({ id: data.id ?? "" });
}

/**
 * GET /device/setup/ota/:id — OTA 進捗の取得。デバイスが command_result として
 * push した最新の進捗 payload (`{phase, received, total}` / `{phase:"ok"}` /
 * `{phase:"error"}`) を返す。まだ何も無ければ 404 相当の `{phase:"pending"}`。
 */
export async function handleDeviceSetupOtaStatus(
  request: Request,
  env: Env,
  commandId: string,
): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);

  const res = await recorderFetch(
    env,
    `/tenants/${encodeURIComponent(session.tenantId)}/commands/${encodeURIComponent(commandId)}/result`,
    { method: "GET" },
  );
  if (!res) return jsonNoStore({ error: "recorder_unconfigured" }, 503);
  if (res.status === 404) return jsonNoStore({ phase: "pending" });
  if (!res.ok) return jsonNoStore({ error: `recorder_${res.status}` }, 502);
  const stored = (await res.json()) as { payload?: unknown };
  const payload =
    stored.payload && typeof stored.payload === "object" ? stored.payload : { phase: "pending" };
  return jsonNoStore(payload);
}

/**
 * GET /device/setup/connected — この tenant で今 WS 接続中の device_id 一覧。
 * recorder の `GET /tenants/:t/devices` を透過 (接続中デバイスの UI 表示・OTA
 * ボタンの活性判定に使う)。
 */
export async function handleDeviceSetupConnected(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  const res = await recorderFetch(
    env,
    `/tenants/${encodeURIComponent(session.tenantId)}/devices`,
    { method: "GET" },
  );
  if (!res) return jsonNoStore({ devices: [] }); // recorder 未設定 = 接続情報なし
  if (!res.ok) return jsonNoStore({ devices: [] });
  const data = (await res.json()) as { devices?: unknown };
  const devices = Array.isArray(data.devices) ? data.devices : [];
  return jsonNoStore({ devices });
}

/**
 * GET /device/setup/events — recorder `GET /tenants/:t/events` (SSE) の透過。
 * ページの「接続」列を WS 接続/切断のたびに live 更新するための push。
 * recorder 側のストリームをそのまま browser へ中継する (buffering しない)。
 */
export async function handleDeviceSetupEvents(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  const res = await recorderFetch(
    env,
    `/tenants/${encodeURIComponent(session.tenantId)}/events`,
    { method: "GET" },
  );
  if (!res || !res.ok || !res.body) return jsonNoStore({ error: "recorder_unconfigured" }, 503);
  return new Response(res.body, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
    },
  });
}

/**
 * POST /device/setup/version — 接続中デバイスへ現在バージョンの照会を送る。
 * recorder の command API に `{action:"version"}` を投げ command id を返す
 * (web は `/device/setup/ota/:id` で結果 `{version, slot}` をポーリングする)。
 */
export async function handleDeviceSetupVersion(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  if (request.headers.get("Origin") !== issuerOf(env)) {
    return jsonNoStore({ error: "bad_origin" }, 403);
  }
  let body: Record<string, unknown> = {};
  try {
    const v = await request.json();
    if (v && typeof v === "object") body = v as Record<string, unknown>;
  } catch {
    // 空 body は検証で弾く
  }
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  if (!deviceId) return jsonNoStore({ error: "device_id が必要です" }, 400);
  if (!(await managedDeviceKind(env, session.tenantId, deviceId))) {
    return jsonNoStore({ error: "not_your_device" }, 403);
  }
  const res = await recorderFetch(
    env,
    `/tenants/${encodeURIComponent(session.tenantId)}/devices/${encodeURIComponent(deviceId)}/command`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload: { action: "version" } }),
    },
  );
  if (!res) return jsonNoStore({ error: "recorder_unconfigured" }, 503);
  if (res.status === 404) return jsonNoStore({ error: "device_not_connected" }, 409);
  if (!res.ok) return jsonNoStore({ error: `recorder_${res.status}` }, 502);
  const data = (await res.json()) as { id?: string };
  return jsonNoStore({ id: data.id ?? "" });
}

/**
 * GET /device/setup/latest?kind= — 公開中の最新 firmware バージョン (Pages の
 * 機種別 manifest の `version`)。web が device のバージョンと突き合わせて
 * 「更新必要か」を判定する。kind 省略時は cores3 (後方互換)。取得不可は
 * version:null、未知 kind は 400。
 */
export async function handleDeviceSetupLatest(request: Request, env: Env): Promise<Response> {
  const session = await cookieSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);
  const kindName = new URL(request.url).searchParams.get("kind") || "cores3";
  const kind = DEVICE_KINDS[kindName];
  if (!kind) return jsonNoStore({ error: "unknown kind" }, 400);
  try {
    const res = await fetch(kind.manifestUrl);
    if (!res.ok) return jsonNoStore({ version: null });
    const data = (await res.json()) as { version?: unknown };
    const version = typeof data.version === "string" ? data.version : null;
    return jsonNoStore({ version });
  } catch {
    return jsonNoStore({ version: null });
  }
}

/** セットアップページ本体。WebSerial は Chrome/Edge のみ。 */
function setupPage(issuer: string, email: string): string {
  // developer のみ: CoreS3 の OTA URL を dev ビルド (mem-hud 付き) に切り替える
  // チェックボックス。開発機を /device/setup から更新すると本番ビルドになり
  // メモリ使用率 HUD が消える問題への対処 (alc-app-s3#44)
  const isDeveloper = DEVELOPER_EMAILS.includes(email.toLowerCase());
  // checkbox はページ共通 CSS の input{width:14rem} を width:auto で打ち消し、
  // flex でラベル文と 1 行に並べる (崩れの実害あり 2026-07-14)
  const devToggleHtml = isDeveloper
    ? `<label for="dev-build-cores3" style="display:flex;align-items:center;gap:.45rem;margin:.3rem 0 .8rem;font-size:.85rem;color:#92400e;cursor:pointer"><input type="checkbox" id="dev-build-cores3" style="width:auto;margin:0">CoreS3 は dev ビルド (mem-hud = メモリ使用率 HUD 付き) を配信する</label>`
    : "";
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>デバイス登録</title>
<style>
body{font-family:system-ui,sans-serif;max-width:36rem;margin:2.5rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}
button{font-size:1rem;padding:.6rem 1.2rem;border-radius:.4rem;border:0;cursor:pointer;background:#1a7f37;color:#fff}
button:disabled{background:#9ca3af;cursor:default}
input{font-size:1rem;padding:.4rem .6rem;border:1px solid #ccc;border-radius:.4rem;width:14rem}
label{display:block;margin:.8rem 0 .3rem;color:#444;font-size:.9rem}
pre{background:#f6f8fa;border:1px solid #e2e5e9;border-radius:.4rem;padding:.8rem;font-size:.82rem;
    height:16rem;overflow-y:auto;white-space:pre-wrap}
.muted{color:#666;font-size:.85rem}
.ok{color:#1a7f37;font-weight:600}.ng{color:#b91c1c;font-weight:600}
h2{font-size:1.05rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border:1px solid #e2e5e9;padding:.35rem .6rem;text-align:left}
th{background:#f6f8fa;color:#444;font-weight:600}
button.small{font-size:.8rem;padding:.3rem .6rem;background:#1a56db}
button.small.update{background:#b91c1c}
button.small:disabled{background:#9ca3af}
.ota-cell{white-space:nowrap}
.ota-note{font-size:.85rem;color:#666}
.ota-note.latest{color:#166534;font-weight:600}
.bar{height:.5rem;background:#e2e5e9;border-radius:.25rem;overflow:hidden;margin-top:.3rem;width:10rem}
.bar>span{display:block;height:100%;background:#1a7f37;width:0}
.ota-msg{font-size:.8rem;color:#555;margin-top:.2rem}
.dot{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.3rem;vertical-align:middle}
.dot.on{background:#1a7f37}.dot.off{background:#9ca3af}
.tag{font-size:.75rem;padding:.1rem .4rem;border-radius:.25rem;margin-left:.3rem}
.tag.new{background:#fef3c7;color:#92400e}.tag.cur{background:#dcfce7;color:#166534}
.did{font-family:monospace;font-size:.75rem;color:#666}
</style></head>
<body>
<h1>デバイス登録 (USB)</h1>
<p class="muted">デバイスを USB で接続し「セットアップ実行」を押してください。まず現在の登録状態を
表示し (登録済みなら上書き確認)、credential の発行 (テナント: このアカウント
${escapeHtml(email)})、シリアル注入、疎通確認まで自動で行います。Chrome / Edge のみ (WebSerial)。</p>
<label for="kind">機種</label>
<select id="kind" style="font-size:1rem;padding:.4rem .6rem;border:1px solid #ccc;border-radius:.4rem">
  <option value="cores3">CoreS3 統合ハブ</option>
  <option value="atoms3-print">AtomS3 印刷ブリッジ</option>
</select>
<label for="label">デバイスラベル (同名は旧 credential を自動失効)</label>
<input id="label" value="cores3" pattern="[A-Za-z0-9._-]+">
<p><button id="run">セットアップ実行</button></p>
<p id="result"></p>
<pre id="log"></pre>
<h2>登録済みデバイス</h2>
<label for="ota-url-cores3">OTA firmware URL — CoreS3 統合ハブ (app イメージ)</label>
<input id="ota-url-cores3" value="${escapeHtml(DEVICE_KINDS.cores3?.appUrl ?? "")}" style="width:100%;max-width:32rem">
${devToggleHtml}
<label for="ota-url-atoms3-print">OTA firmware URL — AtomS3 印刷ブリッジ (app イメージ)</label>
<input id="ota-url-atoms3-print" value="${escapeHtml(DEVICE_KINDS["atoms3-print"]?.appUrl ?? "")}" style="width:100%;max-width:32rem">
<p class="muted">「更新」は WS 接続中のデバイスにのみ届きます (LAN/Wi-Fi)。接続中のデバイスは
バージョンを自動照会し、その機種の公開中の最新版と違えば「更新あり」を表示します。
「再登録」は firmware の再インストール等で credential が消えたデバイスの復旧用です —
デバイスを USB で接続してから押すと、その行のラベルのまま再発行・注入します (旧 credential は失効)。</p>
<p id="latest" class="muted"></p>
<p id="devices-status" class="muted">読み込み中...</p>
<table id="devices" style="display:none">
<thead><tr><th>ラベル</th><th>種別</th><th>接続</th><th>バージョン</th><th>更新</th><th>再登録</th></tr></thead>
<tbody id="devices-body"></tbody>
</table>
<script>
"use strict";
const ISSUER = ${JSON.stringify(issuer)};
// 機種 → 表示名 (サーバ側 DEVICE_KINDS と対。list 応答の kind をキーに使う)
const KIND_DISPLAY = ${JSON.stringify(
    Object.fromEntries(Object.entries(DEVICE_KINDS).map(([k, v]) => [k, v.display])),
  )};
const logEl = document.getElementById("log");
const resultEl = document.getElementById("result");
const runBtn = document.getElementById("run");
function log(line) {
  logEl.textContent += line + "\\n";
  logEl.scrollTop = logEl.scrollHeight;
}
// 機種を切り替えたらラベル既定値も追随させる (手で編集済みならそのまま)
const kindSel = document.getElementById("kind");
const labelInput = document.getElementById("label");
kindSel.addEventListener("change", () => {
  const defaults = { cores3: "cores3", "atoms3-print": "atoms3-print" };
  if (Object.values(defaults).includes(labelInput.value)) {
    labelInput.value = defaults[kindSel.value] || kindSel.value;
  }
});
// CoreS3 は ESP-IDF ログが混在するため既知プレフィックス行のみ解釈する
const KNOWN = /^(OK|ERR|AUTH|EVT|WS|STATUS|PONG|CFG)\\b/;

// dev ビルド切り替え (developer のみ checkbox が描画される)。チェックで
// OTA URL 欄を dev app イメージへ、外すと prod へ書き戻す
const PROD_APP_URL_CORES3 = ${JSON.stringify(DEVICE_KINDS.cores3?.appUrl ?? "")};
const DEV_APP_URL_CORES3 = ${JSON.stringify(DEVICE_KINDS.cores3?.devAppUrl ?? "")};
const devToggle = document.getElementById("dev-build-cores3");
if (devToggle) {
  devToggle.addEventListener("change", () => {
    document.getElementById("ota-url-cores3").value =
      devToggle.checked ? DEV_APP_URL_CORES3 : PROD_APP_URL_CORES3;
  });
}

const LATEST = {}; // kind → 公開中の最新 firmware バージョン
// device_id → 行の DOM 参照 (SSE の接続/切断イベントで、一覧を読み直さず
// その行だけ更新するために使う)。
const ROWS = new Map();
let knownConnected = new Set(); // 直近の接続中 device_id (SSE payload との差分検出用)
// OTA 進行中の device_id (再起動による瞬断は OTA フロー側が自分で管理するため、
// applyConnected の disconnect 分岐で進捗表示を上書きしないためのガード)。
const OTA_BUSY = new Set();

// 登録済み CoreS3 一覧 + 接続状態 + 最新版を読み込んで描画する。
// ページ表示時 + セットアップ成功後 + SSE で未知の device_id を見た時に読み直す。
async function loadDevices() {
  const statusEl = document.getElementById("devices-status");
  const latestEl = document.getElementById("latest");
  const table = document.getElementById("devices");
  const body = document.getElementById("devices-body");
  try {
    const [listRes, connRes, latestCoreRes, latestPrintRes] = await Promise.all([
      fetch(ISSUER + "/device/setup/list", { credentials: "include" }),
      fetch(ISSUER + "/device/setup/connected", { credentials: "include" }),
      fetch(ISSUER + "/device/setup/latest?kind=cores3", { credentials: "include" }),
      fetch(ISSUER + "/device/setup/latest?kind=atoms3-print", { credentials: "include" }),
    ]);
    if (!listRes.ok) throw new Error("HTTP " + listRes.status);
    const data = await listRes.json();
    const connected = new Set(((connRes.ok ? await connRes.json() : {}).devices) || []);
    knownConnected = connected;
    LATEST["cores3"] = (latestCoreRes.ok ? await latestCoreRes.json() : {}).version || null;
    LATEST["atoms3-print"] = (latestPrintRes.ok ? await latestPrintRes.json() : {}).version || null;
    const latestParts = [];
    if (LATEST["cores3"]) latestParts.push("CoreS3: " + LATEST["cores3"]);
    if (LATEST["atoms3-print"]) latestParts.push("印刷ブリッジ: " + LATEST["atoms3-print"]);
    latestEl.textContent = latestParts.length ? "公開中の最新版 — " + latestParts.join(" / ") : "";

    body.textContent = "";
    ROWS.clear();
    if (!data.devices || data.devices.length === 0) {
      table.style.display = "none";
      statusEl.textContent = "登録済みデバイスはありません";
      return;
    }
    for (const d of data.devices) {
      const isConn = connected.has(d.device_id);
      const tr = document.createElement("tr");

      // ラベル (+ デバイスID を小さく)
      const labelTd = document.createElement("td");
      labelTd.textContent = d.label;
      const did = document.createElement("div");
      did.className = "did";
      did.textContent = d.device_id;
      labelTd.appendChild(did);
      tr.appendChild(labelTd);

      // 種別 (list 応答の kind。DEVICE_KINDS 外の role は list 側で除外済み)
      const kindTd = document.createElement("td");
      kindTd.textContent = KIND_DISPLAY[d.kind] || d.kind || "?";
      tr.appendChild(kindTd);

      // 接続
      const connTd = document.createElement("td");
      const dot = document.createElement("span");
      dot.className = "dot " + (isConn ? "on" : "off");
      const connText = document.createTextNode(isConn ? "接続中" : "未接続");
      connTd.appendChild(dot);
      connTd.appendChild(connText);
      tr.appendChild(connTd);

      // バージョン (接続中は自動照会 / 未接続は照会不可)
      const verTd = document.createElement("td");
      const verSpan = document.createElement("span");
      verSpan.textContent = isConn ? "照会中..." : "—";
      verTd.appendChild(verSpan);
      tr.appendChild(verTd);

      // 更新セル: 更新あり時のみ赤ボタン / 最新なら「最新」表示 + 進捗
      const otaTd = document.createElement("td");
      otaTd.className = "ota-cell";
      const btn = document.createElement("button");
      btn.className = "small update";
      btn.textContent = "更新";
      // 更新要否が判明するまでの状態表示 (照会中は「確認中」、最新なら「最新」)
      const otaNote = document.createElement("span");
      otaNote.className = "ota-note";
      const bar = document.createElement("div");
      bar.className = "bar";
      bar.style.display = "none";
      const barFill = document.createElement("span");
      bar.appendChild(barFill);
      const msg = document.createElement("div");
      msg.className = "ota-msg";
      btn.addEventListener("click", () => startOta(d.device_id, d.kind, btn, bar, barFill, msg, verSpan, otaNote));
      // 強制インストール: 版一致 (「最新」) でも、選択中の OTA URL
      // (dev/prod チェックボックスに追従) を今すぐ書き込む。dev ⇄ prod は
      // 版が同じで通常「更新」ボタンが出ないため、接続中は常時この経路で
      // 押せるようにする (firmware/サーバとも版ゲート無し)。
      const forceBtn = document.createElement("button");
      forceBtn.className = "small";
      forceBtn.textContent = "強制";
      forceBtn.style.marginLeft = ".35rem";
      forceBtn.style.display = "none";
      forceBtn.title = "版に関わらず、選択中の OTA URL (dev/prod) を今すぐ書き込みます";
      forceBtn.addEventListener("click", () => startOta(d.device_id, d.kind, forceBtn, bar, barFill, msg, verSpan, otaNote));
      if (isConn) {
        // 接続中: バージョン照会が終わるまでボタンは出さず「確認中」を表示。
        // queryVersion が最新/更新ありを判定してボタン or「最新」を出し分ける。
        btn.style.display = "none";
        otaNote.textContent = "確認中...";
        forceBtn.style.display = "";
      } else {
        // 未接続: バージョン照会できず更新不可 (無効ボタン表示、赤にはしない)
        btn.disabled = true;
        btn.classList.remove("update");
        btn.title = "未接続のため更新できません";
      }
      otaTd.appendChild(btn);
      otaTd.appendChild(forceBtn);
      otaTd.appendChild(otaNote);
      otaTd.appendChild(bar);
      otaTd.appendChild(msg);
      tr.appendChild(otaTd);

      // 再登録: この行の label/kind のまま USB provisioning を再実行する。
      // firmware 再インストール (Web インストーラーは NVS ごと消す) で
      // credential が飛んだデバイスの復旧用。replace_label により旧
      // credential は自動失効するので、同じ行が二重登録になることはない。
      // WS 接続状態とは無関係に USB さえ繋げば実行できるため常に活性。
      const reregTd = document.createElement("td");
      const reregBtn = document.createElement("button");
      reregBtn.className = "small";
      reregBtn.textContent = "再登録";
      reregBtn.title = "USB 接続したデバイスへ credential を再発行・注入します (旧 credential は失効)";
      reregBtn.addEventListener("click", () => {
        kindSel.value = d.kind;
        labelInput.value = d.label;
        runBtn.scrollIntoView({ behavior: "smooth", block: "center" });
        run();
      });
      reregTd.appendChild(reregBtn);
      tr.appendChild(reregTd);

      body.appendChild(tr);
      ROWS.set(d.device_id, { kind: d.kind, dot, connText, verSpan, btn, forceBtn, bar, barFill, msg, otaNote });
      if (isConn) queryVersion(d.device_id, d.kind, verSpan, btn, otaNote);
    }
    statusEl.textContent = "";
    table.style.display = "";
  } catch (e) {
    table.style.display = "none";
    statusEl.textContent = "一覧の取得に失敗しました";
  }
}

// SSE で 1 device の接続/切断を反映する (一覧は読み直さず、その行だけ更新)。
function applyConnected(deviceId, isConn) {
  const row = ROWS.get(deviceId);
  if (!row) return; // 未知 device (別タブでの新規登録等) は onDevicesEvent 側で loadDevices() する
  row.dot.className = "dot " + (isConn ? "on" : "off");
  row.connText.textContent = isConn ? "接続中" : "未接続";
  if (OTA_BUSY.has(deviceId)) return; // OTA フロー (startOta/pollOta/refreshVersionAfterReboot) が進捗表示を管理中
  if (isConn) {
    row.verSpan.textContent = "照会中...";
    row.btn.style.display = "none";
    row.btn.disabled = true;
    row.otaNote.textContent = "確認中...";
    row.otaNote.style.display = "";
    row.otaNote.classList.remove("latest");
    if (row.forceBtn) row.forceBtn.style.display = "";
    queryVersion(deviceId, row.kind, row.verSpan, row.btn, row.otaNote);
  } else {
    row.verSpan.textContent = "—";
    row.btn.disabled = true;
    row.btn.classList.remove("update");
    row.btn.style.display = "";
    row.btn.title = "未接続のため更新できません";
    row.otaNote.textContent = "";
    row.otaNote.style.display = "none";
    row.bar.style.display = "none";
    row.msg.textContent = "";
    if (row.forceBtn) row.forceBtn.style.display = "none";
  }
}

// recorder からの \`devices\` SSE event (接続中 device_id の全量) を現在の行と突き合わせる。
function onDevicesEvent(deviceIds) {
  const next = new Set(deviceIds);
  for (const id of next) {
    if (!ROWS.has(id)) {
      // 未知 device (他タブでの新規登録直後 等) — 一覧ごと読み直す
      loadDevices();
      knownConnected = next;
      return;
    }
  }
  for (const id of ROWS.keys()) {
    const was = knownConnected.has(id);
    const now = next.has(id);
    if (was !== now) applyConnected(id, now);
  }
  knownConnected = next;
}

// device/setup/events (recorder /tenants/:t/events の SSE 透過) に接続する。
// EventSource は切断時に自動再接続するため、再接続処理は明示的に書かない。
function startDeviceEventStream() {
  const es = new EventSource(ISSUER + "/device/setup/events", { withCredentials: true });
  es.addEventListener("devices", (ev) => {
    try {
      const payload = JSON.parse(ev.data);
      if (Array.isArray(payload.devices)) onDevicesEvent(payload.devices);
    } catch {
      // 壊れた event は無視 (次の event / 再接続で復帰)
    }
  });
}

// 接続中デバイスへ version コマンドを送り、結果 (version) をセルに表示。
// 最新版と比較し「最新」/「更新あり」タグを付ける。
// 戻り値: version を取得できたら true (OTA 後の再照会リトライ判定に使う #389)。
async function queryVersion(deviceId, kind, verSpan, otaBtn, otaNote) {
  verSpan.textContent = "照会中...";
  // 「更新あり」: 赤ボタンを出し「最新」表示を消す
  const showUpdatable = () => {
    if (otaNote) { otaNote.textContent = ""; otaNote.classList.remove("latest"); otaNote.style.display = "none"; }
    if (otaBtn) { otaBtn.disabled = false; otaBtn.classList.add("update"); otaBtn.style.display = ""; }
  };
  // 「最新」: ボタンは出さず「最新」テキストを表示
  const showLatest = () => {
    if (otaBtn) otaBtn.style.display = "none";
    if (otaNote) { otaNote.textContent = "最新"; otaNote.classList.add("latest"); otaNote.style.display = ""; }
  };
  try {
    const res = await fetch(ISSUER + "/device/setup/version", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ device_id: deviceId }),
    });
    if (!res.ok) { verSpan.textContent = "照会失敗"; showUpdatable(); return false; }
    const { id } = await res.json();
    if (!id) { verSpan.textContent = "照会失敗"; showUpdatable(); return false; }
    // 結果ポーリング (最大 20s)。version が返るまで待つ
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 1500));
      let p;
      try {
        const pr = await fetch(ISSUER + "/device/setup/ota/" + encodeURIComponent(id), { credentials: "include" });
        if (!pr.ok) continue;
        p = await pr.json();
      } catch { continue; }
      if (p && typeof p.version === "string") {
        verSpan.textContent = p.version + (p.slot ? " (" + p.slot + ")" : "");
        const latest = LATEST[kind] || null;
        if (latest) {
          const tag = document.createElement("span");
          if (p.version === latest) { tag.className = "tag cur"; tag.textContent = "最新"; }
          else { tag.className = "tag new"; tag.textContent = "更新あり"; }
          verSpan.appendChild(tag);
        }
        // 更新セル: 最新ならボタンを出さず「最新」、それ以外 (最新版不明含む) は赤ボタン
        if (latest && p.version === latest) showLatest();
        else showUpdatable();
        return true;
      }
    }
    verSpan.textContent = "照会タイムアウト";
    showUpdatable();
    return false;
  } catch {
    verSpan.textContent = "照会失敗";
    showUpdatable();
    return false;
  }
}

// OTA を開始し、command id で進捗をポーリングして表示する。
async function startOta(deviceId, kind, btn, bar, barFill, msg, verSpan, otaNote) {
  // 機種別の URL 入力を使う (未知 kind は cores3 側にフォールバックしない —
  // list が DEVICE_KINDS 外を除外しているため来ない想定だが fail-closed)
  const urlInput = document.getElementById("ota-url-" + kind);
  if (!urlInput) { msg.textContent = "未知の機種です"; return; }
  const url = urlInput.value.trim();
  if (!/^https?:\\/\\//.test(url)) { msg.textContent = "URL が不正です"; return; }
  btn.disabled = true;
  bar.style.display = "";
  barFill.style.width = "0";
  msg.textContent = "デバイスへ指示を送信中...";
  OTA_BUSY.add(deviceId); // 完了/失敗/タイムアウトで pollOta 側が delete する
  try {
    const res = await fetch(ISSUER + "/device/setup/ota", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ device_id: deviceId, url }),
    });
    if (res.status === 409) { msg.textContent = "デバイスが未接続です (WS 接続を確認)"; btn.disabled = false; OTA_BUSY.delete(deviceId); return; }
    if (!res.ok) { msg.textContent = "送信失敗: HTTP " + res.status; btn.disabled = false; OTA_BUSY.delete(deviceId); return; }
    const { id } = await res.json();
    if (!id) { msg.textContent = "command id を取得できませんでした"; btn.disabled = false; OTA_BUSY.delete(deviceId); return; }
    msg.textContent = "更新を開始しました...";
    pollOta(id, deviceId, kind, btn, barFill, msg, verSpan, otaNote);
  } catch (e) {
    msg.textContent = "送信エラー";
    btn.disabled = false;
    OTA_BUSY.delete(deviceId);
  }
}

// OTA 完了後、デバイスの再起動 → WS 再接続を待ってから、その行の
// バージョンだけを再照会して更新する (全リストは読み直さない)。
// 再起動 (~15s) + WS 再接続を見込んで、未接続の間は少し待ってリトライする。
//
// #389: デバイスは再起動時に WS を close フレーム無しで落とすため、recorder
// にはゾンビ接続がしばらく残り /connected は「接続中」を返す。その間に送った
// version command は宛先喪失でタイムアウトする (実機の再接続は reboot +
// ネットワーク + TLS + JWT mint で 30 秒超かかり得る)。1 回で諦めず、
// 期限内は queryVersion が成功するまでリトライする。
async function refreshVersionAfterReboot(deviceId, kind, verSpan, msg, btn, otaNote) {
  verSpan.textContent = "再起動待ち...";
  const deadline = Date.now() + 120 * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 4000));
    // まだ接続が戻っていないと version トリガが 409 になる。接続を確認してから照会。
    let connected = false;
    try {
      const cr = await fetch(ISSUER + "/device/setup/connected", { credentials: "include" });
      if (cr.ok) connected = (((await cr.json()).devices) || []).includes(deviceId);
    } catch { /* retry */ }
    if (!connected) continue;
    msg.textContent = "更新完了 (再接続を確認)";
    // その行のバージョンだけ更新 (更新後は最新になるので「最新」表示に切り替わる)。
    // ゾンビ WS 宛てで失敗した場合は次周でもう一度照会する
    if (await queryVersion(deviceId, kind, verSpan, btn, otaNote)) {
      OTA_BUSY.delete(deviceId);
      return;
    }
  }
  verSpan.textContent = "照会タイムアウト (リロードで再確認できます)";
  OTA_BUSY.delete(deviceId);
}

// 進捗ポーリング (2s 間隔、最大 5 分)。phase = pending/download/ok/error。
async function pollOta(id, deviceId, kind, btn, barFill, msg, verSpan, otaNote) {
  const deadline = Date.now() + 5 * 60 * 1000;
  for (;;) {
    if (Date.now() > deadline) { msg.textContent = "タイムアウト (デバイスの状態を確認してください)"; btn.disabled = false; OTA_BUSY.delete(deviceId); return; }
    await new Promise((r) => setTimeout(r, 2000));
    let p;
    try {
      const res = await fetch(ISSUER + "/device/setup/ota/" + encodeURIComponent(id), { credentials: "include" });
      if (!res.ok) continue;
      p = await res.json();
    } catch { continue; }
    if (p.phase === "download") {
      const pct = p.total > 0 ? Math.floor((p.received / p.total) * 100) : 0;
      barFill.style.width = pct + "%";
      msg.textContent = "ダウンロード中 " + pct + "% (" + p.received + "/" + p.total + ")";
    } else if (p.phase === "ok") {
      barFill.style.width = "100%";
      msg.textContent = "完了 — デバイスの再起動を待っています (" + (p.bytes || "?") + " bytes)";
      btn.disabled = false;
      // デバイスは再起動 → 新スロットで WS 再接続する。**その行だけ**
      // バージョンを再照会して更新 (全リストは読み直さない)。再接続まで
      // リトライしてから照会する。
      if (verSpan) void refreshVersionAfterReboot(deviceId, kind, verSpan, msg, btn, otaNote);
      return;
    } else if (p.phase === "error") {
      msg.textContent = "失敗: " + (p.message || "不明なエラー");
      btn.disabled = false;
      OTA_BUSY.delete(deviceId);
      return;
    }
    // pending はそのまま次のポーリングへ
  }
}

async function run() {
  runBtn.disabled = true;
  resultEl.textContent = "";
  try {
    if (!("serial" in navigator)) throw new Error("このブラウザは WebSerial 非対応です (Chrome/Edge を使用)");
    const port = await navigator.serial.requestPort();
    await port.open({ baudRate: 115200 });
    // ポート open で ESP32-S3 が DTR/RTS トグルによりリセットする実装があるため、
    // 信号を落としてリセットを抑止する (対応しないボードでは無害)。
    // ただしこれに頼らず、下の PING/PONG で実際の起動完了を待つ
    try { await port.setSignals({ dataTerminalReady: false, requestToSend: false }); } catch {}
    const writer = port.writable.getWriter();
    const reader = port.readable.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    const lines = [];
    (async () => {
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let i;
          while ((i = buf.search(/[\\r\\n]/)) >= 0) {
            const line = buf.slice(0, i).trim();
            buf = buf.slice(i + 1);
            if (line && KNOWN.test(line)) { lines.push(line); log("<< " + line); }
          }
        }
      } catch { /* port closed */ }
    })();
    const send = async (cmd, secretParts) => {
      log(">> " + (secretParts ? cmd.split(" ").slice(0, 2).join(" ") + " …(伏せ字)" : cmd));
      await writer.write(new TextEncoder().encode(cmd + "\\n"));
    };
    const waitLine = async (re, timeoutMs) => {
      const deadline = Date.now() + timeoutMs;
      let idx = 0;
      for (;;) {
        while (idx < lines.length) {
          const line = lines[idx++];
          if (re.test(line)) return line;
          if (/^ERR\\b/.test(line)) throw new Error(line);
        }
        if (Date.now() > deadline) throw new Error("応答タイムアウト: " + re);
        await new Promise((r) => setTimeout(r, 100));
      }
    };

    // --- 準備ハンドシェイク (根本対策) ---
    // ポート open 時のリセットで最初のコマンドが起動中に飲まれる問題を、固定
    // 待ちやリトライ回数ではなく「PONG が返るまで PING を打ち続ける」ことで
    // 確実に解消する。デバイスが応答可能になった時点で必ず抜ける。
    // 起動 (Wi-Fi/BLE 初期化含む) を見込んで全体 20 秒、PING は 700ms 間隔。
    log("デバイスの起動を待機中 ...");
    const readyDeadline = Date.now() + 20000;
    let ready = false;
    while (Date.now() < readyDeadline) {
      const before = lines.length;
      await writer.write(new TextEncoder().encode("PING\\n"));
      // 700ms 以内に PONG が来たか (この PING への応答)
      const until = Date.now() + 700;
      while (Date.now() < until) {
        if (lines.slice(before).some((l) => /^PONG/.test(l))) { ready = true; break; }
        await new Promise((r) => setTimeout(r, 50));
      }
      if (ready) break;
    }
    if (!ready) throw new Error("デバイスが応答しません (USB 接続とファームウェアを確認してください)");
    log("デバイス応答 OK — 現在の登録状態を確認します");
    // 起動中に溜まったログ行は捨て、以降のコマンド応答だけを見る
    lines.length = 0;

    // 現在の登録状態を先に表示する (既存登録の黙殺・黙って上書きをしない)
    await send("AUTH STATUS");
    const current = await waitLine(/^AUTH (PAIRED|UNPAIRED)/, 5000);
    if (/^AUTH PAIRED/.test(current)) {
      const parts = current.split(" ");
      const msg = "このデバイスは登録済みです:\\n  デバイスID: " + (parts[3] || "?") +
        "\\n  テナント: " + (parts[2] || "?") +
        "\\n\\n上書き登録しますか? (旧 credential は失効します)";
      if (!confirm(msg)) throw new Error("キャンセルしました (既存の登録を維持)");
    } else {
      log("未登録のデバイスです — 新規登録します");
    }

    const kind = kindSel.value;
    const label = labelInput.value || kind;
    log("credential を発行中 (label=" + label + ") ...");
    const res = await fetch(ISSUER + "/device/setup/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ label, replace_label: true, kind }),
    });
    if (!res.ok) throw new Error("credential 発行に失敗: HTTP " + res.status);
    const cred = await res.json();
    log("credential 発行 OK (device_id=" + cred.device_id + ")");

    await send("AUTH SET " + cred.device_id + " " + cred.device_secret + " " + cred.tenant_id, true);
    await waitLine(/^OK AUTH SET/, 5000);
    await send("AUTH URL " + ISSUER);
    await waitLine(/^OK AUTH URL/, 5000);
    // 測定記録の送り先はページの origin から自動判定する (operator に訊かない):
    // staging で開いていれば staging recorder、それ以外は送らずデバイス既定
    // (本番 recorder) のまま
    if (location.hostname.includes("staging")) {
      await send("WS URL wss://alc-recorder-staging.m-tama-ramu.workers.dev/ws");
      await waitLine(/^OK WS URL/, 5000);
    }
    // AUTH TOKEN は HTTPS 疎通確認。デバイス側が Wi-Fi 再接続 (ポート open の
    // リセット後 ~30 秒) を内部で待ってから mint するため、余裕をもって待つ
    await send("AUTH TOKEN");
    const evt = await waitLine(/^EVT AUTH_TOKEN (OK|NG)/, 60000);
    if (!/^EVT AUTH_TOKEN OK/.test(evt)) throw new Error(evt);
    await send("WS STATUS");
    await waitLine(/^WS /, 5000);

    resultEl.innerHTML = '<span class="ok">登録完了 — デバイスは auth-worker と疎通済みです</span>';
    writer.releaseLock();
    await reader.cancel().catch(() => {});
    await port.close().catch(() => {});
    loadDevices();
  } catch (e) {
    resultEl.innerHTML = '<span class="ng">失敗: ' +
      String(e && e.message ? e.message : e).replace(/[<>&]/g, "") + "</span>";
  } finally {
    runBtn.disabled = false;
  }
}
runBtn.addEventListener("click", run);
loadDevices();
startDeviceEventStream();
</script>
<p class="muted">${escapeHtml(issuer)}</p>
</body></html>`;
}
