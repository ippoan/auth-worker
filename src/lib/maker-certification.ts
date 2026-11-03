/**
 * 一歩庵点呼 (自動点呼機器) の認定申請の様式を記入済みで作る (開発者専用ページ `/maker/certification`)。
 *
 * - 製品の名称・版・認定番号・版の履歴・自己チェック表の答えは ippoan/tenko-forms の
 *   `product/ippoan-tenko.json` (public) から読む。版を上げると名称が切り替わる
 * - 申請者 (一歩庵) の名称・住所・連絡先は public repo に書けないので `AUTH_CONFIG` KV に 1 件だけ持つ
 *   (key に環境名。`AUTH_CONFIG` は本番と staging で同じ namespace)
 * - 様式の原本は tenko-forms の `manifest.json` の `forms.<id>.latest`
 *
 * 書く位置は様式ごとの関数 (`fillYoshiki1` など) に持つ。テナントの届出 (e-Gov の参考様式・別紙7) は
 * alc-app の管理画面の受け持ちで、ここは製作元の手続 (認定申請・仕様変更・自己チェック・廃止) だけ。
 */
import type { Env } from "../index";
import { DocxBody, fillDocx } from "./docx-fill";

export const TENKO_FORMS_RAW = "https://raw.githubusercontent.com/ippoan/tenko-forms/main/";
export const PRODUCT_PATH = "product/ippoan-tenko.json";

/** 申請者 (一歩庵) の値。どれも空なら null */
export interface Applicant {
  name: string | null;
  kana: string | null;
  address: string | null;
  contact_name: string | null;
  contact_dept: string | null;
  contact_phone: string | null;
  contact_fax: string | null;
  contact_email: string | null;
  product_url: string | null;
}

export const APPLICANT_FIELDS: ReadonlyArray<[keyof Applicant, string]> = [
  ["name", "氏名又は名称 (製作事業者名)"],
  ["kana", "フリガナ"],
  ["address", "住所 (〒 から)"],
  ["contact_name", "担当者名"],
  ["contact_dept", "所属・役職"],
  ["contact_phone", "電話番号"],
  ["contact_fax", "FAX (様式5)"],
  ["contact_email", "メールアドレス"],
  ["product_url", "機器の概要のウェブサイトの URL (様式2)"],
];

export interface SelfCheckAnswer {
  ok?: string | null;
  detail?: string | null;
  evidence?: string | null;
}

export interface ProductConfig {
  product: string;
  version: string;
  certification?: { pre?: string | null; post?: string | null };
  history?: Array<{ version: string; date?: string | null; summary?: string | null; impact?: string | null }>;
  self_check?: { pre?: Record<string, SelfCheckAnswer>; post?: Record<string, SelfCheckAnswer> };
  discontinue?: { date?: string | null; reason?: string | null };
}

export function emptyApplicant(): Applicant {
  return {
    name: null,
    kana: null,
    address: null,
    contact_name: null,
    contact_dept: null,
    contact_phone: null,
    contact_fax: null,
    contact_email: null,
    product_url: null,
  };
}

/** 本文の値から申請者を作る (知らない欄は捨て、前後の空白を落とし、空は null、1 欄 500 文字まで) */
export function parseApplicant(body: unknown): Applicant | null {
  if (!body || typeof body !== "object") return null;
  const src = body as Record<string, unknown>;
  const out = emptyApplicant();
  for (const [key] of APPLICANT_FIELDS) {
    const v = src[key];
    if (v === undefined || v === null) continue;
    if (typeof v !== "string") return null;
    const t = v.trim();
    if (t.length > 500) return null;
    out[key] = t || null;
  }
  return out;
}

function applicantKey(env: Env): string {
  return `maker-certification:applicant:${env.WORKER_ENV || "unknown"}`;
}

export async function loadApplicant(env: Env): Promise<Applicant> {
  const raw = await env.AUTH_CONFIG.get(applicantKey(env));
  if (!raw) return emptyApplicant();
  try {
    return parseApplicant(JSON.parse(raw)) ?? emptyApplicant();
  } catch {
    return emptyApplicant();
  }
}

export async function saveApplicant(env: Env, a: Applicant): Promise<void> {
  await env.AUTH_CONFIG.put(applicantKey(env), JSON.stringify(a));
}

/** 製品の設定を読む。形が合わなければ例外 */
export async function fetchProduct(fetcher: typeof fetch = fetch): Promise<ProductConfig> {
  const res = await fetcher(`${TENKO_FORMS_RAW}${PRODUCT_PATH}`, { cf: { cacheTtl: 0 } } as RequestInit);
  if (!res.ok) throw new Error(`製品の設定を取得できませんでした (${res.status})`);
  const cfg = (await res.json()) as ProductConfig;
  if (!cfg || typeof cfg.product !== "string" || typeof cfg.version !== "string") {
    throw new Error("製品の設定の形が想定と違います (product・version が要ります)");
  }
  return cfg;
}

/** 機器の名称 (製品番号)。例 `一歩庵点呼 v1` */
export function deviceName(cfg: ProductConfig, version = cfg.version): string {
  return `${cfg.product} ${version}`;
}

/** 名称に認定番号を添えたもの (様式5・様式7 の「名称 (製品番号・認定番号)」) */
export function certifiedLabel(cfg: ProductConfig, version = cfg.version): string {
  const certs = [
    cfg.certification?.pre ? `業務前 ${cfg.certification.pre}` : "",
    cfg.certification?.post ? `業務後 ${cfg.certification.post}` : "",
  ].filter(Boolean);
  return certs.length ? `${deviceName(cfg, version)}（認定番号 ${certs.join("・")}）` : deviceName(cfg, version);
}

/** 国交省の様式の日付 (令和 n 年 m 月 d 日)。読めなければ空欄のまま */
export function reiwaDate(date: string | null | undefined): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date ?? "");
  if (!m || Number(m[1]) < 2019) return "令和　　年　　月　　日";
  return `令和${Number(m[1]) - 2018}年${Number(m[2])}月${Number(m[3])}日`;
}

const DATE_RE = /令和[\s　]*年[\s　]*月[\s　]*日/;

/** 「ラベル　　　」の段落を「ラベル　値」にする (値が無ければそのまま) */
function afterLabel(label: string, value: string | null | undefined): (now: string) => string {
  return (now) => {
    if (!value) return now;
    const i = now.indexOf(label);
    return `${now.slice(0, i + label.length)}　${value}`;
  };
}

function circle(word: string): (now: string) => string {
  return (now) => now.replace(word, `○${word}`);
}

/** 申請者の住所と名称 (様式1・5・7 の冒頭) と日付の段落 */
function header(b: DocxBody, a: Applicant, date: string, at: { date: number; address: number; name: number }): void {
  b.setText(b.child(at.date), (now) => now.replace(DATE_RE, reiwaDate(date)), "令和");
  b.setText(b.child(at.address), afterLabel("住所", a.address), "住所");
  b.setText(b.child(at.name), afterLabel("氏名又は名称", a.name), "氏名又は名称");
}

/** 連絡先の 4 行 (担当者名・所属・電話・メール)。`first` は担当者名の行 */
function contacts(b: DocxBody, tbl: Element, a: Applicant, first: number, fax = false): void {
  b.setText(b.cellPara(tbl, first, 1), afterLabel("担当者名", a.contact_name), "担当者名");
  b.setText(b.cellPara(tbl, first + 1, 1), afterLabel("所属・役職", a.contact_dept), "所属・役職");
  b.setText(b.cellPara(tbl, first + 2, 1), afterLabel("電話番号", a.contact_phone), "電話番号");
  if (fax) b.setText(b.cellPara(tbl, first + 2, 2), afterLabel("ＦＡＸ", a.contact_fax), "ＦＡＸ");
  b.setText(b.cellPara(tbl, first + 3, 1), afterLabel("メールアドレス", a.contact_email), "メールアドレス");
}

/** 様式1 自動点呼機器認定申請書。機器の種類は業務前・業務後の両方に ○、添付 1〜6 に ○ */
export function fillYoshiki1(b: DocxBody, a: Applicant, cfg: ProductConfig, date: string): void {
  b.setText(b.child(0), (now) => now.replace(DATE_RE, reiwaDate(date)), "令和");
  b.setText(b.child(4), afterLabel("住所", a.address), "住所");
  b.setText(b.child(5), afterLabel("氏名又は名称", a.name), "氏名又は名称");
  const who = b.table(0);
  b.setText(b.cellPara(who, 0, 1), (now) => (a.kana ? `（フリガナ）${a.kana}` : now), "フリガナ");
  if (a.name) b.setText(b.cellPara(who, 1, 1), () => a.name!);
  if (a.address) {
    const addr = a.address;
    b.setText(b.cellPara(who, 2, 1), () => (addr.startsWith("〒") ? addr : `〒${addr}`), "〒");
  }
  contacts(b, who, a, 3);
  const dev = b.table(1);
  b.setText(
    b.cellPara(dev, 0, 1),
    (now) => circle("業務後自動点呼機器")(circle("業務前自動点呼機器")(now)),
    "業務前自動点呼機器",
  );
  b.setText(b.cellPara(dev, 1, 1), () => deviceName(cfg));
  for (let i = 0; i < 6; i++) {
    b.setText(b.cellPara(dev, 2, 1, i), (now) => now.replace(/（[\s　]*）/, "（○）"), "１２３４５６"[i]);
  }
}

/** 様式2 自動点呼機器の概要。被点呼対象者 ① 運転者のみ・被実施場所 ① 営業所又は車庫に限る */
export function fillYoshiki2(b: DocxBody, a: Applicant, cfg: ProductConfig): void {
  const t = b.table(0);
  b.setText(b.cellPara(t, 0, 1), () => deviceName(cfg));
  b.setText(b.cellPara(t, 1, 1), circle("①運転者のみ"), "①運転者のみ");
  b.setText(b.cellPara(t, 2, 1), circle("①営業所又は車庫に限る"), "①営業所又は車庫に限る");
  b.setText(b.cellPara(t, 3, 1), () => a.name ?? "");
  b.setText(b.cellPara(t, 4, 1), () => a.product_url ?? "");
}

/** 自己チェック表の行の項目 (`一`〜`二十三`、`（ア）…` は `ア`) */
export function selfCheckKey(label: string): string {
  const kana = /^（(.)）/.exec(label.trim());
  return kana ? kana[1]! : label.trim();
}

/** 様式3-1・3-2 自己チェック表。設定に答えのある項目だけ、適否・詳細・根拠資料 (資料番号の後ろ) を書く */
export function fillSelfCheck(b: DocxBody, answers: Record<string, SelfCheckAnswer> | undefined): number {
  const t = b.table(0);
  b.setText(b.cellPara(t, 0, 0), (now) => now, "自己チェック表");
  let written = 0;
  b.rows(t).forEach((_, r) => {
    let key: string;
    try {
      key = selfCheckKey(DocxBody.text(b.cellPara(t, r, 0)));
    } catch {
      return;
    }
    const ans = answers?.[key];
    if (!ans) return;
    if (ans.ok) b.setText(b.cellPara(t, r, 2), () => ans.ok!);
    if (ans.detail) b.setText(b.cellPara(t, r, 3), () => ans.detail!);
    if (ans.evidence) b.setText(b.cellPara(t, r, 4), (now) => `${now}　${ans.evidence}`, "資料番号");
    written++;
  });
  return written;
}

/** 様式5 仕様変更申請書。history の先頭 = 変更後、2 件目 = 認定済みの版 */
export function fillYoshiki5(b: DocxBody, a: Applicant, cfg: ProductConfig, date: string): void {
  const [next, prev] = cfg.history ?? [];
  if (!next || !prev) throw new Error("版の履歴が 1 件だけなので、仕様変更申請書は作れません (history の先頭に変更後の版を足してください)");
  header(b, a, date, { date: 2, address: 10, name: 11 });
  const t = b.table(0);
  b.setText(b.cellPara(t, 0, 1), () => certifiedLabel(cfg, prev.version));
  b.setText(b.cellPara(t, 1, 1), () => `${deviceName(cfg, prev.version)} → ${deviceName(cfg, next.version)}：${next.summary ?? ""}`);
  b.setText(b.cellPara(t, 2, 1), () => (next.date ? reiwaDate(next.date) : ""));
  b.setText(b.cellPara(t, 3, 1), () => next.impact ?? "");
  contacts(b, t, a, 4, true);
}

/** 様式7 認定廃止届出書 */
export function fillYoshiki7(b: DocxBody, a: Applicant, cfg: ProductConfig, date: string): void {
  header(b, a, date, { date: 2, address: 10, name: 11 });
  const t = b.table(0);
  b.setText(b.cellPara(t, 0, 1), () => certifiedLabel(cfg));
  b.setText(b.cellPara(t, 1, 1), () => (cfg.discontinue?.date ? reiwaDate(cfg.discontinue.date) : ""));
  b.setText(b.cellPara(t, 2, 1), () => cfg.discontinue?.reason ?? "");
  contacts(b, t, a, 3);
}

export interface MakerForm {
  id: string;
  label: string;
  fill: (b: DocxBody, a: Applicant, cfg: ProductConfig, date: string) => void;
}

export const MAKER_FORMS: MakerForm[] = [
  { id: "nintei-yoshiki1-shinsei", label: "様式1 自動点呼機器認定申請書", fill: fillYoshiki1 },
  { id: "nintei-yoshiki2-gaiyo", label: "様式2 自動点呼機器の概要", fill: (b, a, cfg) => fillYoshiki2(b, a, cfg) },
  {
    id: "nintei-yoshiki3-1-gyomumae-check",
    label: "様式3-1 業務前自動点呼機器の自己チェック表",
    fill: (b, _a, cfg) => void fillSelfCheck(b, cfg.self_check?.pre),
  },
  {
    id: "nintei-yoshiki3-2-gyomugo-check",
    label: "様式3-2 業務後自動点呼機器の自己チェック表",
    fill: (b, _a, cfg) => void fillSelfCheck(b, cfg.self_check?.post),
  },
  { id: "nintei-yoshiki5-shiyo-henko", label: "様式5 仕様変更申請書 (版を上げるとき)", fill: fillYoshiki5 },
  { id: "nintei-yoshiki7-haishi", label: "様式7 認定廃止届出書", fill: fillYoshiki7 },
];

/** 最新版の様式を取り、値を書いた docx とファイル名を返す */
export async function buildMakerForm(
  form: MakerForm,
  a: Applicant,
  cfg: ProductConfig,
  date: string,
  fetcher: typeof fetch = fetch,
): Promise<{ bytes: Uint8Array; filename: string }> {
  const res = await fetcher(`${TENKO_FORMS_RAW}manifest.json`, { cf: { cacheTtl: 0 } } as RequestInit);
  if (!res.ok) throw new Error(`様式の一覧を取得できませんでした (${res.status})`);
  const manifest = (await res.json()) as { forms?: Record<string, { latest?: string }> };
  const path = manifest.forms?.[form.id]?.latest;
  if (!path) throw new Error(`様式 ${form.id} が一覧にありません`);
  const file = await fetcher(`${TENKO_FORMS_RAW}${path}`, { cf: { cacheTtl: 0 } } as RequestInit);
  if (!file.ok) throw new Error(`様式を取得できませんでした (${file.status})`);
  const bytes = fillDocx(new Uint8Array(await file.arrayBuffer()), (b) => form.fill(b, a, cfg, date));
  const version = /(\d{4}-\d{2}-\d{2})\.\w+$/.exec(path)?.[1] ?? "latest";
  return { bytes, filename: `${form.id}_${cfg.version}_${version}_記入済み.docx` };
}
