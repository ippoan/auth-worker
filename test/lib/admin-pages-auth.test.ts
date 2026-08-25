/**
 * admin 系ページが **全て** 共通門番 (`__adminAuth`) を通っていることの回帰テスト。
 *
 * Refs #474: cookie 配送 (fragment 無し) に対応していないページが 1 枚でも残ると、
 * そのページだけログイン無限ループに戻る。門番の実装は
 * `admin-auth-script.test.ts` が検証するので、ここでは「6 ページ全部が
 * その門番を使っているか」だけを見る。
 */
import { describe, it, expect } from "vitest";
import { renderAdminSsoPage } from "../../src/lib/admin-html";
import { renderAdminUsersPage } from "../../src/lib/admin-users-html";
import { renderAdminRichMenuPage } from "../../src/lib/admin-rich-menu-html";
import { renderAdminRequestsPage } from "../../src/lib/admin-requests-html";
import { renderAdminLineUsersPage } from "../../src/lib/admin-line-users-html";
import { renderAdminNotifyPage } from "../../src/lib/admin-notify-html";
import { AUTH_COOKIE } from "../../src/lib/cookies";

const PAGES: Array<[string, () => string]> = [
  ["/admin/sso", () => renderAdminSsoPage(["https://app.example"], "/top")],
  ["/admin/users", () => renderAdminUsersPage()],
  ["/admin/rich-menu", () => renderAdminRichMenuPage()],
  ["/admin/requests", () => renderAdminRequestsPage()],
  ["/admin/line-users", () => renderAdminLineUsersPage(["https://app.example"], "https://auth.example", "/top")],
  ["/admin/notify", () => renderAdminNotifyPage("https://alc-api.example")],
];

describe("admin ページ共通の門番 (#474)", () => {
  for (const [name, render] of PAGES) {
    describe(name, () => {
      it("共通門番スクリプトを埋め込む", () => {
        const html = render();
        expect(html).toContain("window.__adminAuth =");
        expect(html).toContain(JSON.stringify(AUTH_COOKIE));
      });

      it("token 解決を門番に委ね、独自の cookie 正規表現を残していない", () => {
        const html = render();
        expect(html).toMatch(/__adminAuth\.(requireToken|readToken)\(/);
        expect(html).not.toContain("document.cookie.match(");
      });
    });
  }
});
