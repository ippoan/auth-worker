/**
 * 一歩庵点呼 (自動点呼機器) の認定申請の様式を記入済みで作る (開発者専用ページ `/maker/certification`)。
 *
 * - 製品の名称・版・認定番号・版の履歴・自己チェック表の答えは ippoan/tenko-forms の
 *   `product/ippoan-tenko.json` (public) から読む。版を上げると名称が切り替わる
 * - 様式2 の機器の概要の URL も製品の設定 (`product_url`。GitHub Pages の操作マニュアル)
 * - 申請者 (一歩庵) の名称・住所・連絡先は public repo に書けないので `AUTH_CONFIG` KV に 1 件だけ持つ
 *   (key に環境名。`AUTH_CONFIG` は本番と staging で同じ namespace)
 * - 様式の原本は tenko-forms の `manifest.json` の `forms.<id>.latest`
 *
 * 書く位置は様式ごとの関数 (`fillYoshiki1` など) に持つ。テナントの届出 (e-Gov の参考様式・別紙7) は
 * alc-app の管理画面の受け持ちで、ここは製作元の手続 (認定申請・仕様変更・自己チェック・廃止) だけ。
 */
import type { Env } from "../index";
import type { XmlElement } from "@xmldom/xmldom/lib/index.js";
import { DocxBody, fillDocx } from "./docx-fill";

export const TENKO_FORMS_RAW = "https://raw.githubusercontent.com/ippoan/tenko-forms/main/";
export const PRODUCT_PATH = "product/ippoan-tenko.json";

/** 申請者 (一歩庵) の値。どれも空なら null */
export interface Applicant {
  name: string | null;
  kana: string | null;
  postal_code: string | null;
  prefecture: string | null;
  city: string | null;
  street: string | null;
  building: string | null;
  contact_name: string | null;
  contact_dept: string | null;
  contact_phone: string | null;
  contact_fax: string | null;
  contact_email: string | null;
}

/**
 * 申請者の欄 (key・見出し・ブラウザの自動入力の `autocomplete`)。住所は Chrome の自動入力が欄ごとに入れるよう
 * 郵便番号・都道府県・市区町村・番地・建物名に分ける (様式の冒頭の住所は `writeAddress` が 2 行で書く)
 */
export const APPLICANT_FIELDS: ReadonlyArray<[keyof Applicant, string, string]> = [
  ["name", "氏名又は名称 (製作事業者名)", "organization"],
  ["kana", "フリガナ", "off"],
  ["postal_code", "郵便番号", "postal-code"],
  ["prefecture", "都道府県", "address-level1"],
  ["city", "市区町村", "address-level2"],
  ["street", "町名・番地", "address-line1"],
  ["building", "建物名・部屋番号", "address-line2"],
  ["contact_name", "担当者名", "name"],
  ["contact_dept", "所属・役職", "organization-title"],
  ["contact_phone", "電話番号", "tel"],
  ["contact_fax", "FAX (様式5)", "off"],
  ["contact_email", "メールアドレス", "email"],
];

/** 都道府県から建物名までをつないだ住所 (郵便番号は含めない)。どれも空なら null */
export function applicantStreet(a: Applicant): string | null {
  const s = [a.prefecture, a.city, a.street].map((v) => v ?? "").join("");
  const full = a.building ? `${s}　${a.building}` : s;
  return full.trim() || null;
}


export interface SelfCheckAnswer {
  ok?: string | null;
  detail?: string | null;
  evidence?: string | null;
}

/**
 * 様式2 の「1. 機器の概要」「2. 導入費用 (1)(2)」「3. 運用にかかる費用の見込み」の文面 (改行で行を分ける)。
 * 画面で直して `AUTH_CONFIG` KV に保存し、保存が無ければ {@link DEFAULT_OVERVIEW}。`{機器の名称}` は
 * 版の付いた名称 (例 `一歩庵点呼 v1`) に置き換える (版を上げると切り替わる)
 */
export interface Overview {
  overview: string;
  cost_device: string;
  cost_accessories: string;
  cost_running: string;
}

/** 文面の欄 (key・見出し) */
export const OVERVIEW_FIELDS: ReadonlyArray<[keyof Overview, string]> = [
  ["overview", "1. 機器の概要 (機器の構成、使用方法等)"],
  ["cost_device", "2. 導入費用 (1) 機器本体の価格"],
  ["cost_accessories", "2. 導入費用 (2) 付属品の価格"],
  ["cost_running", "3. 運用にかかる費用の見込み"],
];

/** 様式2 の既定の文面 (金額は税抜。様式の 2・3 の見出しに「（すべて税抜）」を添える) */
export const DEFAULT_OVERVIEW: Overview = {
  overview: [
    "(1) 機器の構成",
    "{機器の名称} は、営業所に設置する点呼端末と、クラウド上の点呼システムで構成する。",
    "・点呼端末 PC (ブラウザで点呼画面を表示、カメラ・マイク付き): 点呼手順の案内、運転者の映像・音声の記録、各機器の測定値の集約",
    "・制御装置 (Vein Base): 指静脈認証装置と NFC リーダーを内蔵し、点呼端末 PC と USB でつなぐ。機器の接続管理と、端末の認証 (署名付き通信)",
    "・指静脈認証装置 (制御装置に内蔵): 運転者の本人確認 (なりすまし防止)",
    "・NFC リーダー (制御装置に内蔵): 運転免許証を読み取り、有効性と乗務員マスタとの一致を確認",
    "・アルコール検知器 (FC-1200): 呼気中アルコール濃度を測定。結果は自動で記録し、手入力・修正はできない",
    "・体温計・血圧計 (Bluetooth 接続): 疾病・疲労等の確認に用いる測定値を自動で取得",
    "・監視カメラ (ネットワークカメラ): 点呼場所で運転者の全身を撮影・録画し、点呼の時間帯の映像を点呼記録と結び付けて保存 (運行管理者等が全身を明瞭に確認できる)",
    "・点呼システム (一歩庵点呼サーバ): 点呼記録の改ざんできない形での保存 (1 年以上)、運行管理者への通知、記録の閲覧・出力",
    "(2) 使用方法",
    "1. 運転者は点呼端末で指静脈認証を行い、運転免許証を NFC リーダーにかざして本人確認をする。",
    "2. 端末の案内に従い、体温・血圧の測定、疾病・疲労・睡眠不足等の自己申告、日常点検結果の入力、アルコール検知器による測定を行う。",
    "3. システムは測定値と申告内容をあらかじめ定めた基準と照合し、乗務の可否を判定する。基準を外れた場合や異常がある場合は乗務させず、運行管理者に直ちに通知する。",
    "4. 指示事項は画面に表示し、運転者の確認を記録する。",
    "5. 点呼の日時、運転者、各測定値と判定結果、アルコール検知器使用時の静止画又は動画、監視カメラの点呼の時間帯の映像、指示事項と確認の記録は自動で保存され、運行管理者が管理画面で確認できる。",
    "6. 業務後も同様に本人確認・アルコール測定・申告 (運行の状況、車両の状況等) を行い、記録する。",
    "※ 外観図・構造図・システム図は別添資料として添付する。",
  ].join("\n"),
  cost_device: "点呼端末一式 (制御装置・指静脈認証装置・NFC リーダー) 20,000 円/台",
  cost_accessories: [
    "・アルコール検知器 FC-1200 50,000 円",
    "・体温計 ニプロ 非接触体温計 NT-100B 11,273 円",
    "・血圧計 オムロン 全自動血圧計 HCR-1902T2 29,819 円",
    "・監視カメラ (ネットワークカメラ) 32,000 円",
    "・端末 PC 利用者が用意",
    "・初期設定費 10,000 円",
  ].join("\n"),
  cost_running: ["・システム利用料 30,000 円/月", "・アルコール検知器の定期点検・センサー交換 14,000 円/回 (年 1 回)"].join("\n"),
};

export interface ProductConfig {
  product: string;
  version: string;
  /** 機器の概要が載ったウェブサイトの URL (様式2。国交省のウェブサイトに載る。いまは GitHub Pages の操作マニュアル) */
  product_url?: string | null;
  certification?: { pre?: string | null; post?: string | null };
  history?: Array<{ version: string; date?: string | null; summary?: string | null; impact?: string | null }>;
  self_check?: { pre?: Record<string, SelfCheckAnswer>; post?: Record<string, SelfCheckAnswer> };
  discontinue?: { date?: string | null; reason?: string | null };
  /** 様式2 の文面 (tenko-forms ではなく KV。ページが {@link loadOverview} の値を足す) */
  overview?: Overview;
}

export function emptyApplicant(): Applicant {
  return {
    name: null,
    kana: null,
    postal_code: null,
    prefecture: null,
    city: null,
    street: null,
    building: null,
    contact_name: null,
    contact_dept: null,
    contact_phone: null,
    contact_fax: null,
    contact_email: null,
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

function overviewKey(env: Env): string {
  return `maker-certification:overview:${env.WORKER_ENV || "unknown"}`;
}

/** 本文の値から様式2 の文面を作る (知らない欄は捨て、改行は \n にそろえ、1 欄 5000 文字まで)。形が違えば null */
export function parseOverview(body: unknown): Overview | null {
  if (!body || typeof body !== "object") return null;
  const src = body as Record<string, unknown>;
  const out = { ...DEFAULT_OVERVIEW };
  for (const [key] of OVERVIEW_FIELDS) {
    const v = src[key];
    if (typeof v !== "string" || v.length > 5000) return null;
    out[key] = v.replace(/\r\n?/g, "\n").trim();
  }
  return out;
}

/** 保存した様式2 の文面。無ければ (読めなければ) 既定の文面 */
export async function loadOverview(env: Env): Promise<Overview> {
  const raw = await env.AUTH_CONFIG.get(overviewKey(env));
  if (!raw) return { ...DEFAULT_OVERVIEW };
  try {
    return parseOverview(JSON.parse(raw)) ?? { ...DEFAULT_OVERVIEW };
  } catch {
    return { ...DEFAULT_OVERVIEW };
  }
}

export async function saveOverview(env: Env, o: Overview): Promise<void> {
  await env.AUTH_CONFIG.put(overviewKey(env), JSON.stringify(o));
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

/**
 * 冒頭の「住所」の段落 (様式1 は「申請者　住所」)。1 行目に「住所　〒郵便番号」、2 行目に都道府県から先を書き、
 * どの行も同じ位置から始まるよう字下げを寄せる (1 行目だけ右へ寄せた段落なので、1 行に書くと 2 行目が左端へ戻る)
 */
function writeAddress(b: DocxBody, p: XmlElement, label: string, a: Applicant): void {
  const now = DocxBody.text(p);
  if (!now.includes(label)) throw new Error(`様式の版が想定と違います (「${label}」の位置が合いません)`);
  const street = applicantStreet(a);
  const postal = a.postal_code ? `〒${a.postal_code.replace(/^〒/, "")}` : "";
  if (!street && !postal) return;
  const head = now.slice(0, now.indexOf(label) + label.length).trim();
  const lines = [[head, postal].filter(Boolean).join("　"), ...(street ? [street] : [])];
  b.setLines(p, lines);
  b.fitIndent(p, lines);
}

/** 申請者の住所と名称 (様式1・5・7 の冒頭) と日付の段落 */
function header(b: DocxBody, a: Applicant, date: string, at: { date: number; address: number; name: number }): void {
  b.setText(b.child(at.date), (now) => now.replace(DATE_RE, reiwaDate(date)), "令和");
  writeAddress(b, b.child(at.address), "住所", a);
  b.setText(b.child(at.name), afterLabel("氏名又は名称", a.name), "氏名又は名称");
}

/** 連絡先の 4 行 (担当者名・所属・電話・メール)。`first` は担当者名の行 */
function contacts(b: DocxBody, tbl: XmlElement, a: Applicant, first: number, fax = false): void {
  b.setText(b.cellPara(tbl, first, 1), afterLabel("担当者名", a.contact_name), "担当者名");
  b.setText(b.cellPara(tbl, first + 1, 1), afterLabel("所属・役職", a.contact_dept), "所属・役職");
  b.setText(b.cellPara(tbl, first + 2, 1), afterLabel("電話番号", a.contact_phone), "電話番号");
  if (fax) b.setText(b.cellPara(tbl, first + 2, 2), afterLabel("ＦＡＸ", a.contact_fax), "ＦＡＸ");
  b.setText(b.cellPara(tbl, first + 3, 1), afterLabel("メールアドレス", a.contact_email), "メールアドレス");
}

/** 様式1 自動点呼機器認定申請書。機器の種類は業務前・業務後の両方に ○、添付 1〜6 に ○ */
export function fillYoshiki1(b: DocxBody, a: Applicant, cfg: ProductConfig, date: string): void {
  b.setText(b.child(0), (now) => now.replace(DATE_RE, reiwaDate(date)), "令和");
  writeAddress(b, b.child(4), "住所", a);
  b.setText(b.child(5), afterLabel("氏名又は名称", a.name), "氏名又は名称");
  const who = b.table(0);
  b.setText(b.cellPara(who, 0, 1), (now) => (a.kana ? `（フリガナ）${a.kana}` : now), "フリガナ");
  if (a.name) b.setText(b.cellPara(who, 1, 1), () => a.name!);
  // 住所の欄は 1 段目が「〒」、2 段目が空の段落
  if (a.postal_code) b.setText(b.cellPara(who, 2, 1), () => `〒${a.postal_code!.replace(/^〒/, "")}`, "〒");
  const street = applicantStreet(a);
  if (street) b.setText(b.cellPara(who, 2, 1, 1), () => street);
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
  b.setText(b.cellPara(t, 4, 1), () => cfg.product_url ?? "");
  const o = cfg.overview;
  if (!o) return;
  const name = deviceName(cfg);
  const box = b.table(1);
  b.setText(b.cellPara(box, 0, 0), (now) => now, "機器の概要");
  fillBox(b, b.cellParas(box, 1, 0), o.overview.replaceAll("{機器の名称}", name));
  const cost = b.table(2);
  b.setText(b.cellPara(cost, 0, 0), (now) => `${now.trim()}（すべて税抜）`, "導入費用");
  b.setText(b.cellPara(cost, 1, 0), (now) => now, "機器本体の価格");
  fillBox(b, b.cellParas(cost, 1, 1), o.cost_device.replaceAll("{機器の名称}", name));
  b.setText(b.cellPara(cost, 2, 0), (now) => now, "付属品の価格");
  fillBox(b, b.cellParas(cost, 2, 1), o.cost_accessories.replaceAll("{機器の名称}", name));
  b.setText(b.cellPara(cost, 3, 0), (now) => `${now.trim()}（すべて税抜）`, "運用にかかる費用の見込み");
  // 3. は欄が「（例：システム利用料等）」の 1 段落だけなので、例を消して書く
  const running = o.cost_running.replaceAll("{機器の名称}", name);
  if (running) b.setLines(b.cellPara(cost, 4, 0), running.split("\n"), "例");
}

/**
 * 空の段落を並べた欄に、1 行ずつ段落へ書く。行が段落より多ければ、残りは最後の段落に改行で足す。
 * 折り返しで増える行の分だけ使わなかった段落を消し、枠の高さをおおよそ保つ。空でない段落があれば
 * 様式の版のずれとして例外
 */
function fillBox(b: DocxBody, paras: XmlElement[], text: string): void {
  if (!paras.length || paras.some((p) => DocxBody.text(p) !== "")) {
    throw new Error("様式の版が想定と違います (様式2 の記入欄が空ではありません)");
  }
  if (!text) return;
  const lines = text.split("\n");
  const last = paras.length - 1;
  lines.slice(0, last).forEach((line, i) => b.setText(paras[i]!, () => line));
  if (lines.length > last) b.setLines(paras[last]!, lines.slice(last));
  b.dropWrapped(paras, lines);
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
