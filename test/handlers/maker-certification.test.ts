// 一歩庵点呼の認定申請ページ (開発者専用)。値は架空。
import { describe, it, expect, vi, afterEach } from "vitest";
import { strToU8, zipSync } from "fflate";
import {
  handleMakerCertificationData,
  handleMakerCertificationForm,
  handleMakerCertificationPage,
  handleMakerCertificationSave,
} from "../../src/handlers/maker-certification";
import { DEVELOPER_EMAILS } from "../../src/lib/developer";
import { createMockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "maker-certification-test-secret";
const ENV = "staging";
const ISSUER = "https://auth.ippoan.org";
const DEV = DEVELOPER_EMAILS[0]!;

function makeEnv(): Env {
  return { AUTH_CONFIG: createMockKV(), JWT_SECRET: SECRET, WORKER_ENV: ENV } as unknown as Env;
}

async function cookie(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
  const token = await signTestJwt({ tenant_id: "tenant-1", email: DEV, idp: "google", env: ENV, ...claims }, SECRET);
  return { Cookie: `logi_auth_token=${token}` };
}

const get = (path: string, headers: Record<string, string> = {}) => new Request(`${ISSUER}${path}`, { headers });
const post = (path: string, body: string, headers: Record<string, string> = {}) =>
  new Request(`${ISSUER}${path}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body });

const PRODUCT = { product: "一歩庵点呼", version: "v1", history: [{ version: "v1", summary: "初版" }] };
const Y2 = zipSync({
  "word/document.xml": strToU8(
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/><w:p/><w:p/><w:tbl>' +
      ["", "①運転者のみ", "①営業所又は車庫に限る", "", ""]
        .map((t) => `<w:tr><w:tc><w:p/></w:tc><w:tc><w:p>${t ? `<w:r><w:t>${t}</w:t></w:r>` : ""}</w:p></w:tc></w:tr>`)
        .join("") +
      "</w:tbl></w:body></w:document>",
  ),
});

function stubFetch(product: Response | null = null) {
  const f = vi.fn(async (url: string) => {
    if (url.endsWith("product/ippoan-tenko.json")) return product ?? new Response(JSON.stringify(PRODUCT));
    if (url.endsWith("manifest.json")) {
      return new Response(JSON.stringify({ forms: { "nintei-yoshiki2-gaiyo": { latest: "forms/nintei-yoshiki2-gaiyo/2026-11-03.docx" } } }));
    }
    return new Response(Y2 as BodyInit);
  });
  vi.stubGlobal("fetch", f);
  return f;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GET /maker/certification", () => {
  it("未ログインは /login へ、開発者の Google ログインでなければ 403、開発者ならページ", async () => {
    const env = makeEnv();
    const anon = await handleMakerCertificationPage(get("/maker/certification"), env);
    expect(anon.status).toBe(302);
    expect(anon.headers.get("Location")).toBe(`${ISSUER}/login?redirect_uri=${encodeURIComponent(`${ISSUER}/maker/certification`)}`);
    for (const claims of [{ email: "op@example.com" }, { idp: "line" }, { token_kind: "dev" }]) {
      const res = await handleMakerCertificationPage(get("/maker/certification", await cookie(claims)), env);
      expect(res.status).toBe(403);
      expect(await res.text()).toContain("製作元");
    }
    const ok = await handleMakerCertificationPage(get("/maker/certification", await cookie()), env);
    expect(ok.status).toBe(200);
    const html = await ok.text();
    expect(html).toContain("自動点呼機器の認定申請");
    expect(html).toContain('data-field="contact_fax"');
    expect(html).toContain('data-field="postal_code" autocomplete="postal-code"');
    expect(html).toContain('data-field="prefecture" autocomplete="address-level1"');
    expect(html).toMatch(/id="date" value="\d{4}-\d{2}-\d{2}"/);
  });
});

describe("GET /maker/certification/data", () => {
  it("開発者でなければ 401/403。開発者には申請者・製品・様式の一覧を返す", async () => {
    const env = makeEnv();
    expect((await handleMakerCertificationData(get("/x"), env)).status).toBe(401);
    expect((await handleMakerCertificationData(get("/x", await cookie({ email: "op@example.com" })), env)).status).toBe(403);
    stubFetch();
    const d = (await (await handleMakerCertificationData(get("/x", await cookie()), env)).json()) as Record<string, unknown>;
    expect(d.device_name).toBe("一歩庵点呼 v1");
    expect((d.forms as unknown[]).length).toBe(6);
    expect((d.applicant as Record<string, unknown>).name).toBeNull();
  });

  it("製品の設定が読めなければ理由を添えて返す", async () => {
    stubFetch(new Response("", { status: 404 }));
    const d = (await (await handleMakerCertificationData(get("/x", await cookie()), makeEnv())).json()) as Record<string, unknown>;
    expect([d.product, d.product_error]).toEqual([null, "製品の設定を取得できませんでした (404)"]);
  });
});

describe("POST /maker/certification/applicant", () => {
  it("開発者・同じ Origin・正しい本文だけ保存する", async () => {
    const env = makeEnv();
    const origin = { Origin: ISSUER };
    expect((await handleMakerCertificationSave(post("/x", "{}"), env)).status).toBe(401);
    expect((await handleMakerCertificationSave(post("/x", "{}", { ...(await cookie({ token_kind: "dev" })), ...origin }), env)).status).toBe(403);
    expect((await handleMakerCertificationSave(post("/x", "{}", { ...(await cookie()), Origin: "https://evil.example" }), env)).status).toBe(403);
    expect((await handleMakerCertificationSave(post("/x", "{", { ...(await cookie()), ...origin }), env)).status).toBe(400);
    expect((await handleMakerCertificationSave(post("/x", '{"name":1}', { ...(await cookie()), ...origin }), env)).status).toBe(400);
    const res = await handleMakerCertificationSave(post("/x", '{"name":" 架空製作所 "}', { ...(await cookie()), ...origin }), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { applicant: { name: string } }).applicant.name).toBe("架空製作所");
    expect(JSON.parse((await env.AUTH_CONFIG.get("maker-certification:applicant:staging"))!).name).toBe("架空製作所");
  });
});

describe("GET /maker/certification/form", () => {
  it("開発者でなければ 401。様式・日付が外れたら 400", async () => {
    const env = makeEnv();
    expect((await handleMakerCertificationForm(get("/maker/certification/form?id=x"), env)).status).toBe(401);
    expect((await handleMakerCertificationForm(get("/maker/certification/form?id=x", await cookie()), env)).status).toBe(400);
    const bad = await handleMakerCertificationForm(get("/maker/certification/form?id=nintei-yoshiki2-gaiyo&date=11/3", await cookie()), env);
    expect([bad.status, ((await bad.json()) as { error: string }).error]).toEqual([400, "invalid_date"]);
  });

  it("記入済みの docx を添付で返す (日付の省略は今日)", async () => {
    stubFetch();
    const res = await handleMakerCertificationForm(get("/maker/certification/form?id=nintei-yoshiki2-gaiyo", await cookie()), makeEnv());
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    expect(decodeURIComponent(res.headers.get("Content-Disposition")!)).toContain("nintei-yoshiki2-gaiyo_v1_2026-11-03_記入済み.docx");
    expect(new Uint8Array(await res.arrayBuffer()).slice(0, 2)).toEqual(new Uint8Array([0x50, 0x4b]));
  });

  it("作れなければ 422 と理由 (様式5 で履歴が 1 件など)", async () => {
    stubFetch();
    const res = await handleMakerCertificationForm(get("/maker/certification/form?id=nintei-yoshiki5-shiyo-henko&date=2026-11-03", await cookie()), makeEnv());
    expect(res.status).toBe(422);
    expect(((await res.json()) as { message: string }).message).toContain("一覧にありません");
  });
});
