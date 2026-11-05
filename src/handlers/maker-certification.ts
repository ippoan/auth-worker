/**
 * 一歩庵点呼の認定申請 (開発者専用、`/maker/certification`)。
 *
 * - `GET /maker/certification` — ページ (申請者の入力と、様式ごとの「記入済みをダウンロード」)
 * - `GET /maker/certification/data` — `{applicant, product, forms}` (product は tenko-forms の設定。読めなければ `product_error`)
 * - `POST /maker/certification/applicant` — 申請者を保存 (Origin を検証)
 * - `POST /maker/certification/overview` — 様式2 の文面 (機器の概要・導入費用・運用費用) を保存 (Origin を検証)
 * - `GET /maker/certification/form?id=<様式>&date=YYYY-MM-DD` — 記入済みの docx
 *
 * どれも **開発者アカウントが Google でログインした cookie session** だけ (`isDeveloperGoogleSession`。
 * dev ログイン・device-key の token、LINE のログインは通さない)。ページは未ログインなら /login へ。
 */
import type { Env } from "../index";
import { cookieSession, issuerOf } from "./device-setup";
import { isDeveloperGoogleSession } from "../lib/developer";
import { escapeHtml } from "../lib/html";
import {
  APPLICANT_FIELDS,
  DEFAULT_OVERVIEW,
  MAKER_FORMS,
  OVERVIEW_FIELDS,
  buildMakerForm,
  deviceName,
  fetchProduct,
  loadApplicant,
  loadOverview,
  parseApplicant,
  parseOverview,
  saveApplicant,
  saveOverview,
} from "../lib/maker-certification";

const PAGE_PATH = "/maker/certification";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/** 開発者でなければ 403 の応答、開発者なら null */
async function denyUnlessDeveloper(request: Request, env: Env): Promise<Response | null> {
  const session = await cookieSession(request, env);
  if (!session) return json({ error: "unauthorized" }, 401);
  if (!isDeveloperGoogleSession(session)) return json({ error: "developer_google_session_required" }, 403);
  return null;
}

/** JST の今日 (YYYY-MM-DD) */
function todayJst(now = Date.now()): string {
  return new Date(now + 9 * 3600_000).toISOString().slice(0, 10);
}

export async function handleMakerCertificationPage(request: Request, env: Env): Promise<Response> {
  const issuer = issuerOf(env);
  const session = await cookieSession(request, env);
  if (!session) {
    const back = `${issuer}${PAGE_PATH}`;
    return Response.redirect(`${issuer}/login?redirect_uri=${encodeURIComponent(back)}`, 302);
  }
  if (!isDeveloperGoogleSession(session)) {
    return new Response(deniedPage(), {
      status: 403,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }
  return new Response(page(todayJst()), {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export async function handleMakerCertificationData(request: Request, env: Env): Promise<Response> {
  const denied = await denyUnlessDeveloper(request, env);
  if (denied) return denied;
  const [applicant, overview] = await Promise.all([loadApplicant(env), loadOverview(env)]);
  const forms = MAKER_FORMS.map((f) => ({ id: f.id, label: f.label }));
  const base = { applicant, overview, overview_default: DEFAULT_OVERVIEW, forms };
  try {
    const product = await fetchProduct();
    return json({ ...base, product, device_name: deviceName(product) });
  } catch (e) {
    return json({ ...base, product: null, product_error: e instanceof Error ? e.message : "製品の設定を読めません" });
  }
}

/** 開発者・同じ Origin の JSON 本文。だめなら応答 */
async function developerBody(request: Request, env: Env): Promise<{ body: unknown } | Response> {
  const denied = await denyUnlessDeveloper(request, env);
  if (denied) return denied;
  if (request.headers.get("Origin") !== issuerOf(env)) return json({ error: "bad_origin" }, 403);
  try {
    return { body: await request.json() };
  } catch {
    return json({ error: "invalid_body" }, 400);
  }
}

export async function handleMakerCertificationSave(request: Request, env: Env): Promise<Response> {
  const got = await developerBody(request, env);
  if (got instanceof Response) return got;
  const applicant = parseApplicant(got.body);
  if (!applicant) return json({ error: "invalid_body" }, 400);
  await saveApplicant(env, applicant);
  return json({ applicant });
}

export async function handleMakerCertificationOverviewSave(request: Request, env: Env): Promise<Response> {
  const got = await developerBody(request, env);
  if (got instanceof Response) return got;
  const overview = parseOverview(got.body);
  if (!overview) return json({ error: "invalid_body" }, 400);
  await saveOverview(env, overview);
  return json({ overview });
}

export async function handleMakerCertificationForm(request: Request, env: Env): Promise<Response> {
  const denied = await denyUnlessDeveloper(request, env);
  if (denied) return denied;
  const url = new URL(request.url);
  const form = MAKER_FORMS.find((f) => f.id === url.searchParams.get("id"));
  if (!form) return json({ error: "unknown_form" }, 400);
  const date = url.searchParams.get("date") ?? "";
  if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({ error: "invalid_date" }, 400);
  try {
    const [applicant, product, overview] = await Promise.all([loadApplicant(env), fetchProduct(), loadOverview(env)]);
    const { bytes, filename } = await buildMakerForm(form, applicant, { ...product, overview }, date || todayJst());
    return new Response(bytes as unknown as BodyInit, {
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
        "Cache-Control": "no-store",
      },
    });
  } catch (e) {
    // 理由の文は様式の版のずれ・取得の失敗など固定の語 (値は含まない)
    return json({ error: "form_failed", message: e instanceof Error ? e.message : "様式を作れませんでした" }, 422);
  }
}

function deniedPage(): string {
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>開くことができません</title><style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}</style></head>
<body><h1>開くことができません</h1><p>このページは一歩庵点呼の製作元 (開発者アカウントの Google ログイン) だけが使えます。</p></body></html>`;
}

function page(today: string): string {
  const fields = APPLICANT_FIELDS.map(
    ([key, label, autocomplete]) =>
      `<label>${escapeHtml(label)}<input name="${key}" data-field="${key}" autocomplete="${autocomplete}" maxlength="500"></label>`,
  ).join("");
  const overviewFields = OVERVIEW_FIELDS.map(
    ([key, label]) =>
      `<label>${escapeHtml(label)}<textarea name="${key}" data-overview="${key}" rows="${key === "overview" ? 18 : 5}" maxlength="5000"></textarea></label>`,
  ).join("");
  return `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>自動点呼機器の認定申請</title>
<style>
body{font-family:system-ui,sans-serif;max-width:56rem;margin:1.5rem auto;padding:0 1rem;color:#1a1a1a;background:#f8fafc}
section{background:#fff;border-radius:.75rem;padding:1rem 1.2rem;margin:1rem 0;box-shadow:0 1px 2px rgba(0,0,0,.06)}
h1{font-size:1.3rem}h2{font-size:1.05rem;margin:.2rem 0 .8rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(16rem,1fr));gap:.6rem 1rem}
label{display:flex;flex-direction:column;font-size:.85rem;color:#555;gap:.2rem}
textarea{font-size:.9rem;padding:.4rem .5rem;border:1px solid #cbd5e1;border-radius:.4rem;font-family:inherit;margin-bottom:.6rem}
input{font-size:.95rem;padding:.4rem .5rem;border:1px solid #cbd5e1;border-radius:.4rem}
button{background:#2563eb;color:#fff;border:0;border-radius:.4rem;padding:.45rem .9rem;font-size:.9rem;cursor:pointer}
button:disabled{opacity:.5}
ul{list-style:none;padding:0;margin:0}li{display:flex;justify-content:space-between;align-items:center;padding:.5rem 0;border-top:1px solid #eee}
.muted{color:#666;font-size:.85rem}.err{color:#b91c1c;font-size:.9rem}.ok{color:#15803d;font-size:.9rem}
table{border-collapse:collapse;font-size:.85rem}td,th{border-top:1px solid #eee;padding:.3rem .6rem;text-align:left}
</style></head><body>
<h1>自動点呼機器の認定申請 (一歩庵点呼)</h1>
<p class="muted">製作元として国交省 物流・自動車局 安全政策課へメールで出す様式を、下の値と製品の設定 (ippoan/tenko-forms の product/ippoan-tenko.json) を書き込んだ状態で作ります。版を上げると名称が切り替わります。</p>

<section id="product"><h2>製品</h2><div id="product-body" class="muted">読み込み中…</div></section>

<section><h2>申請者 (一歩庵)</h2>
<form id="applicant" autocomplete="on"><div class="grid">${fields}</div>
<p><button type="submit" id="save">保存</button> <span id="save-msg"></span></p></form></section>

<section><h2>様式2 の文面</h2>
<p class="muted">1 行ずつ様式の欄に書きます。{機器の名称} は版の付いた名称 (例 一歩庵点呼 v1) に置き換わります。金額は税抜で、様式の 2・3 の見出しに「（すべて税抜）」を添えます。</p>
<form id="overview">${overviewFields}
<p><button type="submit" id="ov-save">保存</button> <button type="button" id="ov-default">既定の文面に戻す</button> <span id="ov-msg"></span></p></form></section>

<section><h2>記入済みの様式をダウンロード</h2>
<label style="max-width:12rem">申請日<input type="date" id="date" value="${today}"></label>
<ul id="forms"></ul>
<p class="muted">様式3-1・3-2 は、製品の設定の self_check に書いた項目だけ適否・詳細・根拠資料を入れます。様式5 は history に 2 件以上 (変更後と認定済みの版) あるときに作れます。</p>
<p id="dl-msg" class="err"></p></section>

<script>
const $ = (s) => document.querySelector(s);
function esc(s) { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]); }
async function load() {
  const res = await fetch("${PAGE_PATH}/data", { credentials: "same-origin" });
  const d = await res.json();
  for (const [k, v] of Object.entries(d.applicant || {})) { const el = document.querySelector('[data-field="' + k + '"]'); if (el) el.value = v ?? ""; }
  overviewDefault = d.overview_default || {};
  setOverview(d.overview || {});
  if (d.product) {
    const p = d.product, c = p.certification || {};
    const hist = (p.history || []).map((h) => "<tr><td>" + esc(h.version) + "</td><td>" + esc(h.date) + "</td><td>" + esc(h.summary) + "</td></tr>").join("");
    $("#product-body").innerHTML = "<p><b>" + esc(d.device_name) + "</b>　認定番号: 業務前 " + esc(c.pre || "未") + " / 業務後 " + esc(c.post || "未") + "</p><p class='muted'>機器の概要の URL (様式2): " + esc(p.product_url || "未設定") + "</p><table><tr><th>版</th><th>時期</th><th>内容</th></tr>" + hist + "</table>";
  } else {
    $("#product-body").innerHTML = '<span class="err">' + esc(d.product_error) + "</span>";
  }
  $("#forms").innerHTML = d.forms.map((f) => '<li><span>' + esc(f.label) + '</span><button type="button" data-form="' + esc(f.id) + '">記入済みをダウンロード</button></li>').join("");
}
let overviewDefault = {};
function setOverview(o) { document.querySelectorAll("[data-overview]").forEach((el) => { el.value = o[el.dataset.overview] ?? ""; }); }
$("#ov-default").addEventListener("click", () => { setOverview(overviewDefault); $("#ov-msg").className = "muted"; $("#ov-msg").textContent = "既定の文面にしました (保存はまだ)"; });
$("#overview").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {};
  document.querySelectorAll("[data-overview]").forEach((el) => { body[el.dataset.overview] = el.value; });
  $("#ov-save").disabled = true; $("#ov-msg").textContent = "";
  try {
    const res = await fetch("${PAGE_PATH}/overview", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    $("#ov-msg").className = res.ok ? "ok" : "err";
    $("#ov-msg").textContent = res.ok ? "保存しました" : "保存できませんでした (" + res.status + ")";
  } finally { $("#ov-save").disabled = false; }
});
$("#applicant").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {};
  document.querySelectorAll("[data-field]").forEach((el) => { body[el.dataset.field] = el.value; });
  $("#save").disabled = true; $("#save-msg").textContent = "";
  try {
    const res = await fetch("${PAGE_PATH}/applicant", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    $("#save-msg").className = res.ok ? "ok" : "err";
    $("#save-msg").textContent = res.ok ? "保存しました" : "保存できませんでした (" + res.status + ")";
  } finally { $("#save").disabled = false; }
});
$("#forms").addEventListener("click", async (e) => {
  const id = e.target.dataset && e.target.dataset.form; if (!id) return;
  e.target.disabled = true; $("#dl-msg").textContent = "";
  try {
    const res = await fetch("${PAGE_PATH}/form?id=" + encodeURIComponent(id) + "&date=" + encodeURIComponent($("#date").value), { credentials: "same-origin" });
    if (!res.ok) { const j = await res.json().catch(() => ({})); $("#dl-msg").textContent = j.message || ("作れませんでした (" + res.status + ")"); return; }
    const cd = res.headers.get("Content-Disposition") || "";
    const name = decodeURIComponent((/filename\\*=UTF-8''([^;]+)/.exec(cd) || [])[1] || id + ".docx");
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } finally { e.target.disabled = false; }
});
load();
</script></body></html>`;
}
