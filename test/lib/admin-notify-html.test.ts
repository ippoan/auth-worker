import { describe, it, expect } from "vitest";
import { LOGIN_SOURCE_LABELS, renderAdminNotifyPage } from "../../src/lib/admin-notify-html";

describe("renderAdminNotifyPage", () => {
  const ORIGIN = "https://alc-api.test.example";

  it("returns an HTML string", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
  });

  it("contains page title", () => {
    expect(renderAdminNotifyPage(ORIGIN)).toContain("通知管理");
  });

  it("embeds the alc-api origin via JSON.stringify", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain(JSON.stringify(ORIGIN));
  });

  it("safely escapes an origin containing a quote", () => {
    const malicious = 'https://evil.test";alert(1);//';
    const html = renderAdminNotifyPage(malicious);
    expect(html).toContain(JSON.stringify(malicious));
    expect(html).not.toContain('"https://evil.test";');
  });

  it("contains 4 tabs (LINE WORKS / Recipients / Groups / ログイン状況)", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("LINE WORKS から追加");
    expect(html).toContain("受信者一覧");
    expect(html).toContain("グループ管理");
    expect(html).toContain("ログイン状況");
  });

  it("#474: 共通門番 (cookie → sessionStorage) を使い、無ければ /login へ飛ばす", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("__adminAuth.requireToken('/admin/notify/callback')");
    // 門番は cookie を先に見る (fragment 無し cookie 配送でループしないこと)
    expect(html).toContain("document.cookie");
    expect(html).toContain("logi_auth_token");
    // sessionStorage は後方互換として残す
    expect(html).toContain("sessionStorage.getItem('auth_token')");
  });

  it("calls the expected rust-alc-api endpoints", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("/notify/lineworks/users");
    expect(html).toContain("/notify/recipients");
    expect(html).toContain("/notify/recipients/bulk");
    expect(html).toContain("/notify/groups");
    expect(html).toContain("/notify/test-distribute");
  });

  it("renders a per-recipient テスト送信 button with rec-test class", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("rec-test");
    expect(html).toContain("テスト送信");
  });

  it("sends a fixed message template including [テスト通知] prefix", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("[テスト通知]");
    expect(html).toContain("recipient_ids: [id]");
  });

  it("routes fetch through same-origin /admin/notify/api forward proxy (#434, rust 直叩きを廃止)", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    // #434: rust 直叩き (ALC_API + '/api') は tenant header 不在で 401 になるため、
    // 同一オリジンの forward proxy 経由 (auth-worker が JWT 検証 + X-Tenant-ID 注入) に変更。
    expect(html).toContain("'/admin/notify/api' + path");
    expect(html).not.toContain("ALC_API + '/api' + path");
  });

  it("shows directory.read scope guidance when LINE WORKS returns 403", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("directory.read");
  });

  it("#540: ログイン状況タブが login-activity endpoint を N 日しきい値付きで叩く", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("/notify/lineworks/login-activity?days=");
    expect(html).toContain('id="la-days"');
    expect(html).toContain('value="3"');
  });

  it("#540: audit.read scope 不足時の 403 ガイダンスを表示する", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("audit.read");
  });

  it("#540: 根拠の絞り込み select の option value は rust の last_login_source リテラル + none", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    const select = html.match(/<select id="la-source">([\s\S]*?)<\/select>/);
    expect(select).not.toBeNull();
    const options = [...(select?.[1] ?? "").matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)].map(
      (m) => [m[1], m[2]],
    );
    // "auth" / "message" / "board" は rust-alc-api lineworks_login_activity.rs の
    // activity_source が返すリテラル。"" = すべて、"none" = last_login_at が無い行。
    expect(options).toEqual([
      ["", "すべて"],
      ["auth", "ログイン"],
      ["message", "メッセージ送信"],
      ["board", "掲示板既読"],
      ["none", "記録なし"],
    ]);
  });

  it("#540: 根拠列のラベル表が script に同じ値で埋まり、表に無い値は「—」でセルは esc() を通す", () => {
    expect(LOGIN_SOURCE_LABELS).toEqual({
      auth: "ログイン",
      message: "メッセージ送信",
      board: "掲示板既読",
    });
    const html = renderAdminNotifyPage(ORIGIN);
    const embedded = html.match(/var LA_SOURCE_LABELS = (\{.*?\});/);
    expect(embedded).not.toBeNull();
    expect(JSON.parse(embedded?.[1] ?? "null") as Record<string, string>).toEqual(LOGIN_SOURCE_LABELS);
    expect(html).toContain("hasOwnProperty.call(LA_SOURCE_LABELS, source) ? LA_SOURCE_LABELS[source] : '—'");
    expect(html).toContain("esc(laSourceLabel(r.last_login_source))");
    expect(html).not.toMatch(/'\s*\+\s*r\.last_login_source\s*\+/);
  });

  it("#540: ログイン状況は 5 列 (最終活動 / 根拠) で、絞り込みの変更は再取得せず再描画だけ", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("<th>名前</th><th>メール</th><th>最終活動</th><th>根拠</th><th>状態</th>");
    expect(html).toContain("getElementById('la-source').addEventListener('change', renderLoginActivity)");
  });
});
