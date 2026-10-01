import { describe, it, expect, vi } from "vitest";
import {
  handleDeviceSetupPage,
  handleDeviceSetupPair,
  handleDeviceSetupList,
  handleDeviceSetupOta,
  handleDeviceSetupOtaStatus,
  handleDeviceSetupSerialOta,
  handleDeviceSetupConnected,
  handleDeviceSetupEvents,
  handleDeviceSetupVersion,
  handleDeviceSetupGw,
  handleDeviceSetupBus5v,
  handleDeviceSetupBpStatus,
  handleDeviceSetupBpUnbond,
  handleDeviceSetupReboot,
  handleDeviceSetupSite,
  handleDeviceSetupBattery,
  DEVICE_KINDS,
} from "../../src/handlers/device-setup";
import {
  createDeviceCredential,
  getDeviceRecord,
  revokeDeviceCredential,
} from "../../src/lib/device";
import { DEVELOPER_EMAILS } from "../../src/lib/developer";
import { createMockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "device-setup-test-secret";
const ENV = "staging";
const ISSUER = "https://auth.ippoan.org";

function makeEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_CONFIG: createMockKV(),
    JWT_SECRET: SECRET,
    WORKER_ENV: ENV,
    ...overrides,
  } as unknown as Env;
}

async function opCookie(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
  const token = await signTestJwt(
    { tenant_id: "tenant-1", email: "op@example.com", env: ENV, ...claims },
    SECRET,
  );
  return { Cookie: `logi_auth_token=${token}` };
}

function getReq(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, { method: "GET", headers });
}

function postJson(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

/** POST /device/setup/pair の応答 (成功時)。 */
interface PairResponse {
  device_id: string;
  device_secret: string;
  tenant_id: string;
  label: string;
  role: string;
  site_id?: string;
}

describe("handleDeviceSetupPage", () => {
  it("redirects to /login when not authenticated", async () => {
    const res = await handleDeviceSetupPage(getReq("/device/setup"), makeEnv());
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("/login?redirect_uri=");
  });

  it("セッションエラーページは毒 cookie を破棄する Set-Cookie を返す (Refs #387)", async () => {
    const badToken = await signTestJwt({ tenant_id: "t", email: "e@x", env: ENV }, "wrong-secret");
    const res = await handleDeviceSetupPage(
      getReq("/device/setup", { Cookie: `logi_auth_token=${badToken}` }),
      makeEnv(),
    );
    expect(res.status).toBe(403);
    const setCookies = res.headers.getSetCookie();
    expect(setCookies.length).toBe(2);
    for (const c of setCookies) {
      expect(c).toContain("logi_auth_token=;");
      expect(c).toContain("Max-Age=0");
    }
  });

  it("shows an error page (no redirect) when a cookie exists but fails verification", async () => {
    // 期限切れ/不正 cookie で /login へ 302 すると、ログイン済みブラウザで
    // login → callback → 本ページ → login … の無限リダイレクトになるため
    const res = await handleDeviceSetupPage(
      getReq("/device/setup", { Cookie: "logi_auth_token=broken" }),
      makeEnv(),
    );
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("セッションを確認できません");
  });

  it("shows the error page for a session without tenant_id (org unselected)", async () => {
    const token = await signTestJwt({ email: "op@example.com", env: ENV }, SECRET);
    const res = await handleDeviceSetupPage(
      getReq("/device/setup", { Cookie: `logi_auth_token=${token}` }),
      makeEnv(),
    );
    expect(res.status).toBe(403);
  });

  it("serves the WebSerial setup page for an operator session", async () => {
    const res = await handleDeviceSetupPage(getReq("/device/setup", await opCookie()), makeEnv());
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("navigator.serial");
    expect(html).toContain("AUTH SET");
    // 測定記録の送り先は origin から自動判定 (operator への入力欄は無い)
    expect(html).not.toContain('id="wsurl"');
    expect(html).toContain("alc-recorder-staging");
    // 実行前に現在の登録状態を表示し、登録済みなら上書き確認する
    expect(html).toContain("AUTH STATUS");
    expect(html).toContain("上書き登録しますか");
    // ポート open 時のリセット対策: PING/PONG で起動完了を待ってから進む
    expect(html).toContain("PONG");
    expect(html).toContain("setSignals");
    // operator の email を表示 (どのテナントで登録されるかの確認用)
    expect(html).toContain("op@example.com");
    // Web インストーラー (GitHub Pages) への導線 — 機種ごとに 1 本ずつ
    expect(html).toContain("Web インストーラー");
    expect(html).toContain('href="https://ippoan.github.io/alc-app-s3/"');
    expect(html).toContain('href="https://ippoan.github.io/alc-app-s3/atoms3-print.html"');
    expect(html).toContain('href="https://github.com/ippoan/alc-gw-p4/releases/latest"');
    // 登録済みデバイス一覧 (ページ表示時に /device/setup/list を読む)
    expect(html).toContain("登録済みデバイス");
    expect(html).toContain("/device/setup/list");
    // OTA UI: URL 欄 + 更新トリガ + 進捗ポーリング
    expect(html).toContain("/device/setup/ota");
    expect(html).toContain("alc-hub-cores3-app.bin");
    expect(html).toContain("startOta");
    // 接続状態 + バージョン照会 + 最新版
    expect(html).toContain("/device/setup/connected");
    expect(html).toContain("/device/setup/version");
    expect(html).toContain("/device/setup/latest");
    expect(html).toContain("queryVersion");
    // 版 (Wi-Fi / LAN) を version 照会の net から出す (ippoan/alc-app-s3#278)
    expect(html).toContain('p.net === "wifi" ? "Wi-Fi"');
    // 血圧計ボンド状態の列 (Refs #574): version と同じく接続中のみ自動照会し、
    // 4 状態 (ボンド済み/未ボンド/まだ確認できていない/未対応) を出し分ける —
    // bp_read=false (未確認) や空 ack (未対応) を「未ボンド」と混同しない
    // (isOldFirmwareResult を bus5v/reboot と共用)
    expect(html).toContain("血圧計ボンド");
    expect(html).toContain("/device/setup/bp_status");
    expect(html).toContain("queryBpStatus");
    expect(html).toContain("ボンド済み");
    expect(html).toContain("未ボンド");
    expect(html).toContain("まだ確認できていません");
    expect(html).toContain("未対応 (OTA が必要)");
    // 未接続の端末は照会しない (version と同じ isConn ガード)
    expect(html).toContain('if (isConn) queryBpStatus(d.device_id, bpSpan);');
    // 血圧計のボンドを外すボタン (Refs ippoan/alc-app#401): 文言・確認・送信口・結果の出し分け。
    // 出す条件は血圧計の照会と同じ (接続中だけ。applyConnected で切り替える)
    expect(html).toContain("血圧計のボンドを外す");
    expect(html).toContain(
      "この端末の血圧計のボンドを外しますか? (外すと、もう一度ペアリングするまで、この端末で自動点呼を使えません)",
    );
    expect(html).toContain("/device/setup/bp_unbond");
    expect(html).toContain("外す指示を送りました");
    expect(html).toContain("点呼中または更新中のため外せません。終わってからもう一度押してください");
    expect(html).toContain("setTimeout(() => queryBpStatus(deviceId, bpSpan), 3000);");
    expect(html).toContain('bpUnbondBtn.style.display = isConn ? "" : "none";');
    expect(html).toContain('if (row.bpUnbondBtn) row.bpUnbondBtn.style.display = "";');
    expect(html).toContain('if (row.bpUnbondBtn) row.bpUnbondBtn.style.display = "none";');
    // dev ビルド選択は developer 以外には表示しない (alc-app-s3#44)
    expect(html).not.toContain('id="dev-build-cores3"');
    // AtomS3 印刷ブリッジのプリンター宛先 (PRINTER ADDR) 設定 UI (Refs #395、
    // WS push 印刷 ippoan/alc-app-s3#38)。kind=atoms3-print の時だけ表示する
    expect(html).toContain('id="printer-addr"');
    expect(html).toContain("PRINTER ADDR ");
    expect(html).toContain("syncPrinterRow");
    // テスト印刷ボタン: printer 宛先を保存し /print/test.pdf を印字する
    // (Refs #395、URL 方式で配線・IP を確認)
    expect(html).toContain('id="print-test"');
    expect(html).toContain("runPrintTest");
    expect(html).toContain("/print/test.pdf");
  });

  it("機種 select の option を DEVICE_KINDS から生成する (#509)", async () => {
    const res = await handleDeviceSetupPage(getReq("/device/setup", await opCookie()), makeEnv());
    const html = await res.text();
    const select = html.match(/<select id="kind"[^>]*>([\s\S]*?)<\/select>/)?.[1] ?? "";
    const options = [...select.matchAll(/<option value="([^"]+)">([^<]*)<\/option>/g)].map((m) => [
      m[1],
      m[2],
    ]);
    // registry の pairRole を持つ機種が、キー順 (= 先頭が既定選択の cores3) で
    // そのまま並ぶこと。#508 で timecard を足したとき、ハードコードだった
    // ここだけ追随しなかった。pairRole を持たない機種 (血圧測定台・警告デバイス) は
    // credential を発行しないので select には出ない (Refs #353)
    expect(options).toEqual(
      Object.entries(DEVICE_KINDS)
        .filter(([, k]) => k.pairRole)
        .map(([name, k]) => [name, k.display]),
    );
    expect(options).toContainEqual(["timecard", "NFC タイムカード端末"]);
    expect(options[0]?.[0]).toBe("cores3");
    // ラベル既定値の追随も registry 由来 (機種を足したらラベルも追随する)
    expect(html).toContain('"timecard":"timecard"');
  });

  it("血圧測定台・警告デバイス (role を持たない機種) は Web インストーラーのリンクには出るが、機種 select には出ない (Refs #353)", async () => {
    const res = await handleDeviceSetupPage(getReq("/device/setup", await opCookie()), makeEnv());
    const html = await res.text();
    // Web インストーラー導線には両方出る
    expect(html).toContain('href="https://ippoan.github.io/alc-app-s3/atoms3-nfc.html"');
    expect(html).toContain('href="https://ippoan.github.io/alc-app-s3/alarm.html"');
    // 機種 select にはどちらも出ない (credential を発行しない機種のため)
    const select = html.match(/<select id="kind"[^>]*>([\s\S]*?)<\/select>/)?.[1] ?? "";
    expect(select).not.toContain('value="bp-station"');
    expect(select).not.toContain('value="alarm"');
  });

  it("developer アカウントには dev ビルド (mem-hud) 配信の選択を表示する (alc-app-s3#44)", async () => {
    const cookie = await opCookie({ email: "m.tama.ramu@gmail.com" });
    const res = await handleDeviceSetupPage(getReq("/device/setup", cookie), makeEnv());
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('id="dev-build-cores3"');
    // チェックで OTA URL 欄を dev app イメージへ切り替える
    expect(html).toContain("alc-hub-cores3-dev-app.bin");
    expect(html).toContain("DEV_APP_URL_CORES3");
  });
});

describe("handleDeviceSetupList", () => {
  it("rejects without session (401)", async () => {
    const res = await handleDeviceSetupList(getReq("/device/setup/list"), makeEnv());
    expect(res.status).toBe(401);
  });

  it("returns only the operator tenant's active credentials, newest first", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    // tenant-1 に 2 台 (同 label replace で 1 台は revoke) + 別 label 1 台
    const revoked = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-a", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    const current = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-a", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    const other = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-b" }, headers),
        env,
      )
    ).json()) as PairResponse;
    // 他テナントの credential は一覧に出ない
    const otherTenantCookie = await opCookie({ tenant_id: "tenant-2" });
    await handleDeviceSetupPair(
      postJson("/device/setup/pair", { label: "cores3-x" }, { ...otherTenantCookie, Origin: ISSUER }),
      env,
    );

    const res = await handleDeviceSetupList(getReq("/device/setup/list", await opCookie()), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      devices: Array<{ device_id: string; label: string; role: string; created_at: number }>;
    };
    const ids = body.devices.map((d) => d.device_id);
    expect(ids).toContain(current.device_id);
    expect(ids).toContain(other.device_id);
    expect(ids).not.toContain(revoked.device_id); // revoke 済みは出ない
    expect(ids.length).toBe(2);
    for (const d of body.devices) {
      expect(d.role).toBe("device-hub"); // この test は hub のみ発行している
      expect(d.created_at).toBeGreaterThan(0);
      // secret は KV に hash しか無く、応答にも含まれない
      expect(d).not.toHaveProperty("device_secret");
      expect(d).not.toHaveProperty("secret_hash");
    }
    // 発行日時降順
    const times = body.devices.map((d) => d.created_at);
    expect([...times].sort((a, b) => b - a)).toEqual(times);
  });

  it("site_id を含めて返す (Refs #406、hub は明示指定が無ければ自分の device_id)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const withSite = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "a", site_id: "site-1" }, headers), env)
    ).json()) as PairResponse;
    const autoSite = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "b" }, headers), env)
    ).json()) as PairResponse;

    const res = await handleDeviceSetupList(getReq("/device/setup/list", await opCookie()), env);
    const body = (await res.json()) as { devices: Array<{ device_id: string; site_id: string }> };
    const byId = new Map(body.devices.map((d) => [d.device_id, d]));
    expect(byId.get(withSite.device_id)?.site_id).toBe("site-1");
    expect(byId.get(autoSite.device_id)?.site_id).toBe(autoSite.device_id);
  });

  it("returns an empty list for a tenant with no devices", async () => {
    const res = await handleDeviceSetupList(
      getReq("/device/setup/list", await opCookie({ tenant_id: "tenant-empty" })),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: [] });
  });

  it("管理対象外の role (dtako-ingest 等) は一覧に出さず、hub/print は kind 付きで出す", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    // CoreS3 ハブ (device-hub) + AtomS3 印刷ブリッジ (device-print) を 1 台ずつ
    const hub = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    const print = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "printer-1", kind: "atoms3-print" }, headers),
        env,
      )
    ).json()) as PairResponse;
    // 同 tenant の別種デバイス (直接 KV に device-dtako-ingest で発行)
    const now = Math.floor(Date.now() / 1000);
    const other = await createDeviceCredential(env, "tenant-1", "scraper", now, "device-dtako-ingest");

    const res = await handleDeviceSetupList(getReq("/device/setup/list", await opCookie()), env);
    const body = (await res.json()) as {
      devices: Array<{ device_id: string; role: string; kind: string }>;
    };
    const ids = body.devices.map((d) => d.device_id);
    expect(ids).toContain(hub.device_id);
    expect(ids).toContain(print.device_id); // 印刷ブリッジも一覧に出る
    expect(ids).not.toContain(other.device_id); // 管理対象外は除外
    const kinds = new Map(body.devices.map((d) => [d.device_id, d.kind]));
    expect(kinds.get(hub.device_id)).toBe("cores3");
    expect(kinds.get(print.device_id)).toBe("atoms3-print");
  });
});

describe("handleDeviceSetupPair", () => {
  it("rejects without session (401) and with wrong origin (403)", async () => {
    const env = makeEnv();
    const res = await handleDeviceSetupPair(postJson("/device/setup/pair", {}), env);
    expect(res.status).toBe(401);

    const cookie = await opCookie();
    const bad = await handleDeviceSetupPair(
      postJson("/device/setup/pair", {}, { ...cookie, Origin: "https://evil.example" }),
      env,
    );
    expect(bad.status).toBe(403);
  });

  it("mints a device-hub credential bound to the operator tenant", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { label: "cores3-abc" }, headers),
      env,
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as PairResponse;
    expect(body.device_id).toBeTruthy();
    expect(body.device_secret).toBeTruthy();
    expect(body.tenant_id).toBe("tenant-1");
    expect(body.role).toBe("device-hub");
    expect(body.label).toBe("cores3-abc");
    const record = await getDeviceRecord(env, body.device_id);
    expect(record?.tenant_id).toBe("tenant-1");
    expect(record?.role).toBe("device-hub");
  });

  it("site_id を渡すと credential に付与される (Refs #406)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { label: "cores3-abc", site_id: "site-1" }, headers),
      env,
    );
    const body = (await res.json()) as PairResponse;
    expect(body.site_id).toBe("site-1");
    const record = await getDeviceRecord(env, body.device_id);
    expect(record?.site_id).toBe("site-1");
  });

  it("site_id を省略すると cores3 (hub) は自分の device_id が既定になる (Refs #406 改訂)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3-abc" }, headers), env);
    const body = (await res.json()) as PairResponse;
    expect(body.site_id).toBe(body.device_id);
  });

  it("site_id を省略しても atoms3-print (非hub) には付与されない", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { label: "printer-1", kind: "atoms3-print" }, headers),
      env,
    );
    const body = (await res.json()) as PairResponse;
    expect(body.site_id).toBeUndefined();
  });

  it("kind=atoms3-print は device-print role で mint する (機種分離 alc-app-s3#38)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { kind: "atoms3-print" }, headers),
      env,
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as PairResponse & { kind?: string };
    expect(body.role).toBe("device-print");
    expect(body.kind).toBe("atoms3-print");
    expect(body.label).toBe("atoms3-print"); // 機種別の label 既定
    const record = await getDeviceRecord(env, body.device_id);
    expect(record?.role).toBe("device-print");
  });

  it("kind=timecard は device-timecard role で mint する (機種分離 alc-app-s3#134)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { kind: "timecard" }, headers),
      env,
    );
    expect(res.status).toBe(201);
    const body = (await res.json()) as PairResponse & { kind?: string };
    // role が device-print に落ちると打刻機へ印刷ブリッジを push できてしまう
    expect(body.role).toBe("device-timecard");
    expect(body.kind).toBe("timecard");
    expect(body.label).toBe("timecard"); // 機種別の label 既定
    const record = await getDeviceRecord(env, body.device_id);
    expect(record?.role).toBe("device-timecard");
  });

  it("未知の kind は 400 (誤配布防止 — 管理対象機種以外を mint しない)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { kind: "toaster" }, headers),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("kind=bp-station は 400 で拒否し credential を発行しない (role を持たない機種、Refs #353)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { kind: "bp-station" }, headers),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error?: string };
    expect(body.error).toBe("kind_not_pairable");
  });

  it("kind=alarm は 400 で拒否し credential を発行しない (role を持たない機種、Refs #353)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupPair(
      postJson("/device/setup/pair", { kind: "alarm" }, headers),
      env,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error?: string };
    expect(body.error).toBe("kind_not_pairable");
  });

  it("defaults the label and tolerates an empty body", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const req = new Request(`${ISSUER}/device/setup/pair`, {
      method: "POST",
      headers,
    });
    const res = await handleDeviceSetupPair(req, env);
    expect(res.status).toBe(201);
    const body = (await res.json()) as PairResponse;
    expect(body.label).toBe("cores3");
  });

  it("replace_label revokes the previous credential for the same label", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const first = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-abc", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    const second = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3-abc", replace_label: true }, headers),
        env,
      )
    ).json()) as PairResponse;
    expect(second.device_id).not.toBe(first.device_id);
    // 旧 credential は revoke され、新しい方だけが有効
    const oldRecord = await getDeviceRecord(env, first.device_id);
    expect(oldRecord?.revoked).toBe(true);
    const newRecord = await getDeviceRecord(env, second.device_id);
    expect(newRecord?.revoked).toBe(false);
    expect(newRecord?.role).toBe("device-hub");
  });
});

describe("handleDeviceSetupOta / handleDeviceSetupOtaStatus", () => {
  /** ALC_RECORDER の service binding を模した Fetcher。呼び出しを記録する。 */
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string; method: string; auth: string | null; body: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({
          url: req.url,
          method: req.method,
          auth: req.headers.get("Authorization"),
          body: init?.body ? String(init.body) : "",
        });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  /** OTA 用 env: recorder binding + shared secret + operator の device を仕込む。 */
  async function otaEnv(recorder: unknown) {
    const env = makeEnv({
      ALC_RECORDER: recorder,
      INTERNAL_SHARED_SECRET: "shared-abc",
    });
    // tenant-1 の有効な device を 1 台発行しておく
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    return { env, deviceId: cred.device_id };
  }

  it("OTA トリガ: recorder に action:ota を shared secret 付きで転送し id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "cmd-1", delivered: 1 }), { status: 202 }),
    );
    const { env, deviceId } = await otaEnv(fetcher);

    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: deviceId, url: "https://x/app.bin" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "cmd-1" });
    expect(calls.length).toBe(1);
    const call = calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.auth).toBe("shared-abc");
    expect(call.url).toContain(`/tenants/tenant-1/devices/${deviceId}/command`);
    expect(JSON.parse(call.body)).toEqual({ payload: { action: "ota", url: "https://x/app.bin" } });
  });

  it("他テナントの device_id は 403 (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await otaEnv(fetcher);
    // 別テナントで発行した device
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "x" }, otherHeaders), env)
    ).json()) as PairResponse;

    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: other.device_id, url: "https://x/app.bin" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect(calls.length).toBe(0);
  });

  it("不正入力・認証: session なし 401 / bad origin 403 / url 不正 400 / device 未接続 409", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 404 }));
    const { env, deviceId } = await otaEnv(fetcher);

    expect(
      (await handleDeviceSetupOta(postJson("/device/setup/ota", {}), env)).status,
    ).toBe(401);
    expect(
      (
        await handleDeviceSetupOta(
          postJson("/device/setup/ota", {}, { ...(await opCookie()), Origin: "https://evil" }),
          env,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await handleDeviceSetupOta(
          postJson(
            "/device/setup/ota",
            { device_id: deviceId, url: "ftp://x" },
            { ...(await opCookie()), Origin: ISSUER },
          ),
          env,
        )
      ).status,
    ).toBe(400);
    // recorder が 404 (device not connected) → 409
    const notConn = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: deviceId, url: "https://x/app.bin" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(notConn.status).toBe(409);
  });

  it("recorder binding 未設定は 503", async () => {
    const env = makeEnv({ INTERNAL_SHARED_SECRET: "s" });
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", {}, headers), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: cred.device_id, url: "https://x/app.bin" },
        headers,
      ),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("進捗ポーリング: recorder の command_result payload を透過する", async () => {
    const { fetcher } = mockRecorder(
      () =>
        new Response(
          JSON.stringify({ payload: { phase: "download", received: 65536, total: 1831920 } }),
          { status: 200 },
        ),
    );
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupOtaStatus(
      getReq("/device/setup/ota/cmd-1", await opCookie()),
      env,
      "cmd-1",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ phase: "download", received: 65536, total: 1831920 });
  });

  it("進捗ポーリング: recorder 404 (まだ結果なし) は phase:pending", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 404 }));
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupOtaStatus(
      getReq("/device/setup/ota/cmd-x", await opCookie()),
      env,
      "cmd-x",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ phase: "pending" });
  });

  it("接続一覧: recorder /tenants/:t/devices を透過する", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ devices: ["dev-a", "dev-b"] }), { status: 200 }),
    );
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupConnected(
      getReq("/device/setup/connected", await opCookie()),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: ["dev-a", "dev-b"] });
    expect(calls[0]!.url).toContain("/tenants/tenant-1/devices");
    expect(calls[0]!.auth).toBe("shared-abc");
  });

  it("接続一覧: recorder 未設定は空配列 (fail-open)", async () => {
    const res = await handleDeviceSetupConnected(
      getReq("/device/setup/connected", await opCookie()),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: [] });
  });

  it("live update: recorder /tenants/:t/events の SSE ストリームを透過する", async () => {
    const sseBody = 'event: devices\ndata: {"devices":["dev-a"]}\n\n';
    const { fetcher, calls } = mockRecorder(
      () =>
        new Response(sseBody, {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        }),
    );
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupEvents(
      getReq("/device/setup/events", await opCookie()),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
    expect(await res.text()).toBe(sseBody);
    expect(calls[0]!.url).toContain("/tenants/tenant-1/events");
    expect(calls[0]!.auth).toBe("shared-abc");
  });

  it("live update: 未ログインは 401", async () => {
    const res = await handleDeviceSetupEvents(getReq("/device/setup/events"), makeEnv());
    expect(res.status).toBe(401);
  });

  it("live update: recorder 未設定は 503", async () => {
    const res = await handleDeviceSetupEvents(
      getReq("/device/setup/events", await opCookie()),
      makeEnv(),
    );
    expect(res.status).toBe(503);
  });

  it("バージョン照会: recorder に action:version を送り id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "ver-1" }), { status: 202 }),
    );
    const { env, deviceId } = await otaEnv(fetcher);
    const res = await handleDeviceSetupVersion(
      postJson(
        "/device/setup/version",
        { device_id: deviceId },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "ver-1" });
    expect(JSON.parse(calls[0]!.body)).toEqual({ payload: { action: "version" } });
  });

  it("バージョン照会: 他テナントの device は 403", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await otaEnv(fetcher);
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "y" }, otherHeaders), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupVersion(
      postJson(
        "/device/setup/version",
        { device_id: other.device_id },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(403);
  });
});

describe("handleDeviceSetupSerialOta (Vein Station 一斉シリアル OTA, Refs alc-app-s3#279)", () => {
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string; method: string; auth: string | null; body: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({
          url: req.url,
          method: req.method,
          auth: req.headers.get("Authorization"),
          body: init?.body ? String(init.body) : "",
        });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  it("正常系: recorder へ POST /tenants/:t/serial-ota を shared secret 付きで送り {sent} を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ sent: 3 }), { status: 200 }),
    );
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupSerialOta(
      postJson("/device/setup/serial-ota", {}, { ...(await opCookie()), Origin: ISSUER }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ sent: 3 });
    expect(calls.length).toBe(1);
    const call = calls[0]!;
    expect(call.method).toBe("POST");
    expect(call.auth).toBe("shared-abc");
    expect(call.url).toContain("/tenants/tenant-1/serial-ota");
    expect(JSON.parse(call.body)).toEqual({ target: "timecard-station" });
  });

  it("0 台のときも {sent: 0} を返す", async () => {
    const { fetcher } = mockRecorder(() => new Response(JSON.stringify({ sent: 0 }), { status: 200 }));
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupSerialOta(
      postJson("/device/setup/serial-ota", {}, { ...(await opCookie()), Origin: ISSUER }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ sent: 0 });
  });

  it("未ログインは 401", async () => {
    const env = makeEnv({ ALC_RECORDER: mockRecorder(() => new Response("{}")).fetcher, INTERNAL_SHARED_SECRET: "s" });
    const res = await handleDeviceSetupSerialOta(postJson("/device/setup/serial-ota", {}), env);
    expect(res.status).toBe(401);
  });

  it("Origin 不一致は 403 (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}"));
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "s" });
    const res = await handleDeviceSetupSerialOta(
      postJson("/device/setup/serial-ota", {}, { ...(await opCookie()), Origin: "https://evil" }),
      env,
    );
    expect(res.status).toBe(403);
    expect(calls.length).toBe(0);
  });

  it.each(["dev", "device-key"])("token_kind=%s は 403 (recorder を叩かない)", async (tokenKind) => {
    const { fetcher, calls } = mockRecorder(() => new Response(JSON.stringify({ sent: 1 })));
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupSerialOta(
      postJson(
        "/device/setup/serial-ota",
        {},
        { ...(await opCookie({ token_kind: tokenKind })), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
    expect(calls.length).toBe(0);
  });

  it("recorder binding 未設定は 503", async () => {
    const env = makeEnv({ INTERNAL_SHARED_SECRET: "s" });
    const res = await handleDeviceSetupSerialOta(
      postJson("/device/setup/serial-ota", {}, { ...(await opCookie()), Origin: ISSUER }),
      env,
    );
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "recorder_unconfigured" });
  });

  it("shared secret 未設定も 503", async () => {
    const { fetcher } = mockRecorder(() => new Response(JSON.stringify({ sent: 1 })));
    const env = makeEnv({ ALC_RECORDER: fetcher });
    const res = await handleDeviceSetupSerialOta(
      postJson("/device/setup/serial-ota", {}, { ...(await opCookie()), Origin: ISSUER }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("recorder の非 2xx は 502", async () => {
    const { fetcher } = mockRecorder(() => new Response("boom", { status: 500 }));
    const env = makeEnv({ ALC_RECORDER: fetcher, INTERNAL_SHARED_SECRET: "shared-abc" });
    const res = await handleDeviceSetupSerialOta(
      postJson("/device/setup/serial-ota", {}, { ...(await opCookie()), Origin: ISSUER }),
      env,
    );
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: "recorder_500" });
  });
});

describe("handleDeviceSetupGw", () => {
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string; method: string; auth: string | null; body: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({
          url: req.url,
          method: req.method,
          auth: req.headers.get("Authorization"),
          body: init?.body ? String(init.body) : "",
        });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  async function gwEnv(recorder: unknown) {
    const env = makeEnv({
      ALC_RECORDER: recorder,
      INTERNAL_SHARED_SECRET: "shared-abc",
    });
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    return { env, deviceId: cred.device_id };
  }

  it("url あり: recorder に action:gw_url を転送し id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "gw-1" }), { status: 202 }),
    );
    const { env, deviceId } = await gwEnv(fetcher);
    const res = await handleDeviceSetupGw(
      postJson(
        "/device/setup/gw",
        { device_id: deviceId, url: "ws://192.168.11.5:9000" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "gw-1" });
    expect(calls.length).toBe(1);
    expect(calls[0]!.auth).toBe("shared-abc");
    expect(calls[0]!.url).toContain(`/tenants/tenant-1/devices/${deviceId}/command`);
    expect(JSON.parse(calls[0]!.body)).toEqual({
      payload: { action: "gw_url", url: "ws://192.168.11.5:9000" },
    });
  });

  it("url なし: action:gw_status を転送する (接続状態の照会)", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "gw-2" }), { status: 202 }),
    );
    const { env, deviceId } = await gwEnv(fetcher);
    const res = await handleDeviceSetupGw(
      postJson("/device/setup/gw", { device_id: deviceId }, { ...(await opCookie()), Origin: ISSUER }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "gw-2" });
    expect(JSON.parse(calls[0]!.body)).toEqual({ payload: { action: "gw_status" } });
  });

  it("不正入力・認証: session なし 401 / bad origin 403 / ws 以外の url 400 / device_id なし 400 / 未接続 409", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 404 }));
    const { env, deviceId } = await gwEnv(fetcher);
    expect((await handleDeviceSetupGw(postJson("/device/setup/gw", {}), env)).status).toBe(401);
    expect(
      (
        await handleDeviceSetupGw(
          postJson("/device/setup/gw", {}, { ...(await opCookie()), Origin: "https://evil" }),
          env,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await handleDeviceSetupGw(
          postJson(
            "/device/setup/gw",
            { device_id: deviceId, url: "http://192.168.11.5:9000" },
            { ...(await opCookie()), Origin: ISSUER },
          ),
          env,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await handleDeviceSetupGw(
          postJson("/device/setup/gw", { url: "ws://x:9000" }, { ...(await opCookie()), Origin: ISSUER }),
          env,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await handleDeviceSetupGw(
          postJson(
            "/device/setup/gw",
            { device_id: deviceId, url: "ws://192.168.11.5:9000" },
            { ...(await opCookie()), Origin: ISSUER },
          ),
          env,
        )
      ).status,
    ).toBe(409);
  });

  it("他テナントの device_id は 403 (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await gwEnv(fetcher);
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "z" }, otherHeaders), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupGw(
      postJson(
        "/device/setup/gw",
        { device_id: other.device_id, url: "ws://192.168.11.5:9000" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect(calls.length).toBe(0);
  });

  it("recorder binding 未設定は 503", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupGw(
      postJson("/device/setup/gw", { device_id: cred.device_id, url: "ws://x:9000" }, headers),
      env,
    );
    expect(res.status).toBe(503);
  });
});

describe("handleDeviceSetupSite (Refs #406)", () => {
  it("rejects without session (401) and with wrong origin (403)", async () => {
    const env = makeEnv();
    const res = await handleDeviceSetupSite(postJson("/device/setup/site", {}), env);
    expect(res.status).toBe(401);

    const cookie = await opCookie();
    const bad = await handleDeviceSetupSite(
      postJson("/device/setup/site", {}, { ...cookie, Origin: "https://evil.example" }),
      env,
    );
    expect(bad.status).toBe(403);
  });

  it("400 when device_id is missing", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupSite(postJson("/device/setup/site", {}, headers), env);
    expect(res.status).toBe(400);
  });

  it("管理対象外の role (DEVICE_KINDS に無い機種) の端末は 403 not_your_device", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    // 既定の role (uploader) は本ページの機種表に無い
    const uploader = await createDeviceCredential(env, "tenant-1", "uploader", 1_700_000_000);
    const res = await handleDeviceSetupSite(
      postJson("/device/setup/site", { device_id: uploader.device_id }, headers),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "not_your_device" });
    expect(await getDeviceRecord(env, uploader.device_id)).not.toHaveProperty("site_id");
  });

  it("site_id を省略すると device_id 自身を既定にする (Refs #406 改訂、UIの「設定」ボタンが叩く経路)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    // /device/setup/pair 自体が既に site_id を自動付与するため、テストとして
    // 「後から未設定を埋める」経路を踏むには KV を直接書き換えて未設定状態を作る。
    const record = await getDeviceRecord(env, cred.device_id);
    delete (record as { site_id?: string }).site_id;
    await (env.AUTH_CONFIG as unknown as { put: (k: string, v: string) => Promise<void> }).put(
      `device:${cred.device_id}`,
      JSON.stringify(record),
    );
    expect((await getDeviceRecord(env, cred.device_id))?.site_id).toBeUndefined();

    const res = await handleDeviceSetupSite(
      postJson("/device/setup/site", { device_id: cred.device_id }, headers),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { device_id: string; site_id: string };
    expect(body.site_id).toBe(cred.device_id);
  });

  it("sets site_id on a device owned by the operator's tenant", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;

    const res = await handleDeviceSetupSite(
      postJson("/device/setup/site", { device_id: cred.device_id, site_id: "site-1" }, headers),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { device_id: string; site_id: string };
    expect(body.site_id).toBe("site-1");
    const record = await getDeviceRecord(env, cred.device_id);
    expect(record?.site_id).toBe("site-1");
  });

  it("403 for a device belonging to another tenant (not_your_device)", async () => {
    const env = makeEnv();
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "z" }, otherHeaders), env)
    ).json()) as PairResponse;

    const res = await handleDeviceSetupSite(
      postJson(
        "/device/setup/site",
        { device_id: other.device_id, site_id: "site-1" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("403 for an unknown device_id (managedDeviceKind は不在も他 tenant と区別しない)", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const res = await handleDeviceSetupSite(
      postJson("/device/setup/site", { device_id: "missing", site_id: "site-1" }, headers),
      env,
    );
    expect(res.status).toBe(403);
  });
});

/**
 * BUS5V (M-Bus 5V 出力) の照会と再起動 (Refs ippoan/alc-app-s3#202)。
 * 認可の 3 段 (session / Origin / managedDeviceKind) は共通前処理
 * `deviceCommandRequest` + `sendDeviceCommand` 由来なので、両 handler で確かめる。
 */
describe("handleDeviceSetupBus5v / handleDeviceSetupReboot", () => {
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string; method: string; auth: string | null; body: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({
          url: req.url,
          method: req.method,
          auth: req.headers.get("Authorization"),
          body: init?.body ? String(init.body) : "",
        });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  async function bus5vEnv(recorder: unknown) {
    const env = makeEnv({
      ALC_RECORDER: recorder,
      INTERNAL_SHARED_SECRET: "shared-abc",
    });
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    return { env, deviceId: cred.device_id };
  }

  async function okHeaders(): Promise<Record<string, string>> {
    return { ...(await opCookie()), Origin: ISSUER };
  }

  it("常に action:bus5v_status を転送する (mode が来ても無視、設定は持たない)", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "b5-q" }), { status: 202 }),
    );
    const { env, deviceId } = await bus5vEnv(fetcher);
    for (const body of [{ device_id: deviceId }, { device_id: deviceId, mode: "on" }]) {
      const res = await handleDeviceSetupBus5v(
        postJson("/device/setup/bus5v", body, await okHeaders()),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ id: "b5-q" });
    }
    expect(calls.length).toBe(2);
    expect(calls[0]!.auth).toBe("shared-abc");
    expect(calls[0]!.url).toContain(`/tenants/tenant-1/devices/${deviceId}/command`);
    for (const call of calls) {
      expect(JSON.parse(call.body)).toEqual({ payload: { action: "bus5v_status" } });
    }
  });

  it("不正入力・認証: session なし 401 / bad origin 403 / device_id なし 400", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env, deviceId } = await bus5vEnv(fetcher);
    expect(
      (await handleDeviceSetupBus5v(postJson("/device/setup/bus5v", { device_id: deviceId }), env))
        .status,
    ).toBe(401);
    expect(
      (
        await handleDeviceSetupBus5v(
          postJson(
            "/device/setup/bus5v",
            { device_id: deviceId },
            { ...(await opCookie()), Origin: "https://evil.example" },
          ),
          env,
        )
      ).status,
    ).toBe(403);
    expect(
      (await handleDeviceSetupBus5v(postJson("/device/setup/bus5v", {}, await okHeaders()), env))
        .status,
    ).toBe(400);
    expect(calls.length).toBe(0);
  });

  it("壊れた body / object でない body も 400 (前処理の JSON 化)", async () => {
    const { env } = await bus5vEnv(mockRecorder(() => new Response("{}", { status: 202 })).fetcher);
    const headers = await okHeaders();
    const broken = new Request(`${ISSUER}/device/setup/bus5v`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: "{ not json",
    });
    expect((await handleDeviceSetupBus5v(broken, env)).status).toBe(400);
    // JSON としては妥当だが object ではない body
    expect(
      (await handleDeviceSetupBus5v(postJson("/device/setup/bus5v", 42, headers), env)).status,
    ).toBe(400);
  });

  it("他テナントの device_id は 403 (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await bus5vEnv(fetcher);
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "z" }, otherHeaders), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupBus5v(
      postJson("/device/setup/bus5v", { device_id: other.device_id }, await okHeaders()),
      env,
    );
    expect(res.status).toBe(403);
    expect(calls.length).toBe(0);
  });

  it("device 未接続 (recorder 404) は 409、recorder binding 未設定は 503", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 404 }));
    const { env, deviceId } = await bus5vEnv(fetcher);
    expect(
      (
        await handleDeviceSetupBus5v(
          postJson("/device/setup/bus5v", { device_id: deviceId }, await okHeaders()),
          env,
        )
      ).status,
    ).toBe(409);

    const bare = makeEnv();
    const headers = await okHeaders();
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), bare)
    ).json()) as PairResponse;
    expect(
      (
        await handleDeviceSetupBus5v(
          postJson("/device/setup/bus5v", { device_id: cred.device_id }, headers),
          bare,
        )
      ).status,
    ).toBe(503);
  });

  it("再起動: action:reboot を転送し id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "rb-1" }), { status: 202 }),
    );
    const { env, deviceId } = await bus5vEnv(fetcher);
    const res = await handleDeviceSetupReboot(
      postJson("/device/setup/reboot", { device_id: deviceId }, await okHeaders()),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "rb-1" });
    expect(calls.length).toBe(1);
    expect(calls[0]!.url).toContain(`/tenants/tenant-1/devices/${deviceId}/command`);
    expect(JSON.parse(calls[0]!.body)).toEqual({ payload: { action: "reboot" } });
  });

  it("再起動: session なし 401 / bad origin 403 / device_id なし 400 / 他テナント 403", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env, deviceId } = await bus5vEnv(fetcher);
    expect(
      (await handleDeviceSetupReboot(postJson("/device/setup/reboot", { device_id: deviceId }), env))
        .status,
    ).toBe(401);
    expect(
      (
        await handleDeviceSetupReboot(
          postJson(
            "/device/setup/reboot",
            { device_id: deviceId },
            { ...(await opCookie()), Origin: "https://evil.example" },
          ),
          env,
        )
      ).status,
    ).toBe(403);
    expect(
      (await handleDeviceSetupReboot(postJson("/device/setup/reboot", {}, await okHeaders()), env))
        .status,
    ).toBe(400);

    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "z" }, otherHeaders), env)
    ).json()) as PairResponse;
    expect(
      (
        await handleDeviceSetupReboot(
          postJson("/device/setup/reboot", { device_id: other.device_id }, await okHeaders()),
          env,
        )
      ).status,
    ).toBe(403);
    expect(calls.length).toBe(0);
  });
});

/**
 * 血圧計のボンドを外す指示 (Refs ippoan/alc-app#401)。reboot と同型の書き込み系:
 * 認可は共通前処理 `deviceCommandRequest` (read-only の token の拒否は token_kind 別の
 * 網羅のブロックで検査)。結果 (`{ok:true}` / `{ok:false,error:"busy"}` / 空 ack) の
 * 出し分けは client JS (`unbondBp`) の責務で、recorder の payload は不透過に通る。
 */
describe("handleDeviceSetupBpUnbond", () => {
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string; body: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({ url: req.url, body: init?.body ? String(init.body) : "" });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  async function okHeaders(): Promise<Record<string, string>> {
    return { ...(await opCookie()), Origin: ISSUER };
  }

  async function unbondEnv(recorder: unknown) {
    const env = makeEnv({ ALC_RECORDER: recorder, INTERNAL_SHARED_SECRET: "shared-abc" });
    const cred = (await (
      await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "cores3" }, await okHeaders()),
        env,
      )
    ).json()) as PairResponse;
    return { env, deviceId: cred.device_id };
  }

  it("テナント管理者: action:bp_unbond (引数なし) を 1 回転送し command id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "ub-1" }), { status: 202 }),
    );
    const { env, deviceId } = await unbondEnv(fetcher);
    const res = await handleDeviceSetupBpUnbond(
      postJson("/device/setup/bp_unbond", { device_id: deviceId }, await okHeaders()),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "ub-1" });
    expect(calls.length).toBe(1);
    expect(calls[0]!.url).toContain(`/tenants/tenant-1/devices/${deviceId}/command`);
    expect(JSON.parse(calls[0]!.body)).toEqual({ payload: { action: "bp_unbond" } });
  });

  it("session なし 401 / bad origin 403 / device_id なし 400 (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env, deviceId } = await unbondEnv(fetcher);
    expect(
      (await handleDeviceSetupBpUnbond(postJson("/device/setup/bp_unbond", { device_id: deviceId }), env))
        .status,
    ).toBe(401);
    expect(
      (
        await handleDeviceSetupBpUnbond(
          postJson(
            "/device/setup/bp_unbond",
            { device_id: deviceId },
            { ...(await opCookie()), Origin: "https://evil.example" },
          ),
          env,
        )
      ).status,
    ).toBe(403);
    expect(
      (await handleDeviceSetupBpUnbond(postJson("/device/setup/bp_unbond", {}, await okHeaders()), env))
        .status,
    ).toBe(400);
    expect(calls.length).toBe(0);
  });

  it("他テナントの device_id は 403 not_your_device (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await unbondEnv(fetcher);
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "z" }, otherHeaders), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupBpUnbond(
      postJson("/device/setup/bp_unbond", { device_id: other.device_id }, await okHeaders()),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "not_your_device" });
    expect(calls.length).toBe(0);
  });
});

/**
 * 血圧計のボンド状態照会 (Refs #574, ippoan/alc-app-s3#250)。version/battery/bus5v と
 * 完全に同型: 認可の 3 段は共通前処理 `deviceCommandRequest` + `sendDeviceCommand` 由来。
 * ★ 4 状態 (ボンド済み/未ボンド/まだ確認できていない/未対応) の出し分けは client JS
 * (`queryBpStatus`) の責務なので、ここでは「サーバが action:bp_status を forward し
 * command id を返す」ところまでを確認する (recorder の command_result 中身は不透過に
 * 通す既存の `getCommandResult`/`handleDeviceSetupOtaStatus` が既にカバーしている)。
 */
describe("handleDeviceSetupBpStatus", () => {
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string; method: string; auth: string | null; body: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({
          url: req.url,
          method: req.method,
          auth: req.headers.get("Authorization"),
          body: init?.body ? String(init.body) : "",
        });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  async function bpEnv(recorder: unknown) {
    const env = makeEnv({
      ALC_RECORDER: recorder,
      INTERNAL_SHARED_SECRET: "shared-abc",
    });
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    return { env, deviceId: cred.device_id };
  }

  async function okHeaders(): Promise<Record<string, string>> {
    return { ...(await opCookie()), Origin: ISSUER };
  }

  it("action:bp_status を転送し command id を返す", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "bp-1" }), { status: 202 }),
    );
    const { env, deviceId } = await bpEnv(fetcher);
    const res = await handleDeviceSetupBpStatus(
      postJson("/device/setup/bp_status", { device_id: deviceId }, await okHeaders()),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "bp-1" });
    expect(calls.length).toBe(1);
    expect(calls[0]!.auth).toBe("shared-abc");
    expect(calls[0]!.url).toContain(`/tenants/tenant-1/devices/${deviceId}/command`);
    expect(JSON.parse(calls[0]!.body)).toEqual({ payload: { action: "bp_status" } });
  });

  it("不正入力・認証: session なし 401 / bad origin 403 / device_id なし 400", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env, deviceId } = await bpEnv(fetcher);
    expect(
      (
        await handleDeviceSetupBpStatus(postJson("/device/setup/bp_status", { device_id: deviceId }), env)
      ).status,
    ).toBe(401);
    expect(
      (
        await handleDeviceSetupBpStatus(
          postJson(
            "/device/setup/bp_status",
            { device_id: deviceId },
            { ...(await opCookie()), Origin: "https://evil.example" },
          ),
          env,
        )
      ).status,
    ).toBe(403);
    expect(
      (await handleDeviceSetupBpStatus(postJson("/device/setup/bp_status", {}, await okHeaders()), env))
        .status,
    ).toBe(400);
    expect(calls.length).toBe(0);
  });

  it("他テナントの device_id は 403 (recorder を叩かない)", async () => {
    const { fetcher, calls } = mockRecorder(() => new Response("{}", { status: 202 }));
    const { env } = await bpEnv(fetcher);
    const otherHeaders = { ...(await opCookie({ tenant_id: "tenant-2" })), Origin: ISSUER };
    const other = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "z" }, otherHeaders), env)
    ).json()) as PairResponse;
    const res = await handleDeviceSetupBpStatus(
      postJson("/device/setup/bp_status", { device_id: other.device_id }, await okHeaders()),
      env,
    );
    expect(res.status).toBe(403);
    expect(calls.length).toBe(0);
  });

  it("device 未接続 (recorder 404) は 409、recorder binding 未設定は 503", async () => {
    const { fetcher } = mockRecorder(() => new Response("{}", { status: 404 }));
    const { env, deviceId } = await bpEnv(fetcher);
    expect(
      (
        await handleDeviceSetupBpStatus(
          postJson("/device/setup/bp_status", { device_id: deviceId }, await okHeaders()),
          env,
        )
      ).status,
    ).toBe(409);

    const bare = makeEnv();
    const headers = await okHeaders();
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), bare)
    ).json()) as PairResponse;
    expect(
      (
        await handleDeviceSetupBpStatus(
          postJson("/device/setup/bp_status", { device_id: cred.device_id }, headers),
          bare,
        )
      ).status,
    ).toBe(503);
  });

  /**
   * ★ 受け入れ条件の 4 状態テスト本体。recorder の command_result 経路
   * (`getCommandResult` → `handleDeviceSetupOtaStatus`) は action 名を問わず
   * payload を不透過に返すため、`{bp_bonded:true,bp_read:true}` /
   * `{bp_bonded:false,bp_read:true}` / `{bp_read:false}` (bp_bonded キー自体が
   * 無い、まだ確認できていない) / 空 `{}` (古い firmware の既定 ack、未対応) の
   * どれでもそのまま素通しされることを確認する。「bp_read:false = 未ボンド」
   * 「空 = 未ボンド」に丸めないこと自体は client の `queryBpStatus`/
   * `isOldFirmwareResult` (bus5v/reboot と共用) の責務 — ここではサーバがその
   * 判定材料 (4 種の payload) を握り潰さず届けることを保証する。
   */
  it.each([
    [{ bp_bonded: true, bp_read: true }, "ボンド済み相当のペイロード"],
    [{ bp_bonded: false, bp_read: true }, "未ボンド相当のペイロード (空と誤認してはいけない)"],
    [{ bp_read: false }, "まだ確認できていない (bp_bonded キー自体が無い、未ボンドと混同してはいけない)"],
    [{}, "古い firmware の空 ack (未対応 = 未ボンド/未確認と混同してはいけない)"],
  ])("command_result %o (%s) を素通しする", async (payload: unknown, _label: string) => {
    const { env, deviceId } = await bpEnv(
      mockRecorder(() => new Response(JSON.stringify({ id: "bp-poll" }), { status: 202 })).fetcher,
    );
    const pollRecorder = {
      async fetch(): Promise<Response> {
        return new Response(JSON.stringify({ payload }), { status: 200 });
      },
    };
    const pollEnv = { ...env, ALC_RECORDER: pollRecorder } as unknown as Env;
    void deviceId;
    const res = await handleDeviceSetupOtaStatus(
      getReq("/device/setup/ota/bp-poll", await okHeaders()),
      pollEnv,
      "bp-poll",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(payload);
  });
});

/**
 * dev-login (`token_kind: "dev"`) / device-key (`token_kind: "device-key"`) の
 * cookie では `/device/setup/*` の書き込む口を 403 で弾く。
 * `/alc-proxy` の read-only enforcement (issue #433) は `/device/setup/*` を
 * 経由しないため別途ここで持つ — 読み取りの照会 (battery/version/bus5v/gw の
 * 状態照会) は今までどおり通ることも合わせて確認する。
 */
describe("dev / device-key token: /device/setup の書き込み口を弾く", () => {
  function mockRecorder(handler: (req: Request) => Response) {
    const calls: Array<{ url: string }> = [];
    const fetcher = {
      async fetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
        const req = new Request(input as string, init);
        calls.push({ url: req.url });
        return handler(req);
      },
    };
    return { fetcher, calls };
  }

  /** 通常の admin session で 1 台発行しておく (dev/device-key token 自身には pair を許さないため)。 */
  async function envWithDevice(recorder: unknown) {
    const env = makeEnv({ ALC_RECORDER: recorder, INTERNAL_SHARED_SECRET: "shared-abc" });
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const cred = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "cores3" }, headers), env)
    ).json()) as PairResponse;
    return { env, deviceId: cred.device_id };
  }

  async function tokenHeaders(tokenKind: string): Promise<Record<string, string>> {
    return { ...(await opCookie({ token_kind: tokenKind })), Origin: ISSUER };
  }

  it.each(["dev", "device-key"])(
    "POST /device/setup/pair (登録系) は token_kind=%s で 403",
    async (tokenKind) => {
      const env = makeEnv();
      const res = await handleDeviceSetupPair(
        postJson("/device/setup/pair", { label: "x" }, await tokenHeaders(tokenKind)),
        env,
      );
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
    },
  );

  it.each(["dev", "device-key"])("POST /device/setup/ota は token_kind=%s で 403", async (tokenKind) => {
    const { fetcher, calls } = mockRecorder(() => new Response(JSON.stringify({ id: "x" }), { status: 202 }));
    const { env, deviceId } = await envWithDevice(fetcher);
    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: deviceId, url: "https://fw.example.com/app.bin" },
        await tokenHeaders(tokenKind),
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
    expect(calls.length).toBe(0);
  });

  // 書き込み系 (ボンドを外す)。照会 (bp_status) と違い read-only の token は拒否する。
  it.each(["dev", "device-key"])("POST /device/setup/bp_unbond は token_kind=%s で 403", async (tokenKind) => {
    const { fetcher, calls } = mockRecorder(() => new Response(JSON.stringify({ id: "x" }), { status: 202 }));
    const { env, deviceId } = await envWithDevice(fetcher);
    const res = await handleDeviceSetupBpUnbond(
      postJson("/device/setup/bp_unbond", { device_id: deviceId }, await tokenHeaders(tokenKind)),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
    expect(calls.length).toBe(0);
  });

  it.each(["dev", "device-key"])("POST /device/setup/reboot は token_kind=%s で 403", async (tokenKind) => {
    const { fetcher, calls } = mockRecorder(() => new Response(JSON.stringify({ id: "x" }), { status: 202 }));
    const { env, deviceId } = await envWithDevice(fetcher);
    const res = await handleDeviceSetupReboot(
      postJson("/device/setup/reboot", { device_id: deviceId }, await tokenHeaders(tokenKind)),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
    expect(calls.length).toBe(0);
  });

  it.each(["dev", "device-key"])("POST /device/setup/site は token_kind=%s で 403", async (tokenKind) => {
    const { env, deviceId } = await envWithDevice(mockRecorder(() => new Response("{}")).fetcher);
    const before = await getDeviceRecord(env, deviceId);
    const res = await handleDeviceSetupSite(
      postJson(
        "/device/setup/site",
        { device_id: deviceId, site_id: "new-site" },
        await tokenHeaders(tokenKind),
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
    const after = await getDeviceRecord(env, deviceId);
    expect(after?.site_id).toBe(before?.site_id);
    expect(after?.site_id).not.toBe("new-site");
  });

  it.each(["dev", "device-key"])(
    "POST /device/setup/gw は url あり (gw_url 保存) だと token_kind=%s で 403",
    async (tokenKind) => {
      const { fetcher, calls } = mockRecorder(() => new Response(JSON.stringify({ id: "x" }), { status: 202 }));
      const { env, deviceId } = await envWithDevice(fetcher);
      const res = await handleDeviceSetupGw(
        postJson(
          "/device/setup/gw",
          { device_id: deviceId, url: "ws://192.168.11.5:9000" },
          await tokenHeaders(tokenKind),
        ),
        env,
      );
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
      expect(calls.length).toBe(0);
    },
  );

  it.each(["dev", "device-key"])(
    "POST /device/setup/gw は url なし (gw_status 照会) なら token_kind=%s でも通る",
    async (tokenKind) => {
      const { fetcher, calls } = mockRecorder(() => new Response(JSON.stringify({ id: "gw-ok" }), { status: 202 }));
      const { env, deviceId } = await envWithDevice(fetcher);
      const res = await handleDeviceSetupGw(
        postJson("/device/setup/gw", { device_id: deviceId }, await tokenHeaders(tokenKind)),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ id: "gw-ok" });
      expect(calls.length).toBe(1);
    },
  );

  it.each(["dev", "device-key"])(
    "POST /device/setup/battery (読み取りの照会) は token_kind=%s でも通る",
    async (tokenKind) => {
      const { fetcher } = mockRecorder(() => new Response(JSON.stringify({ id: "bat-ok" }), { status: 202 }));
      const { env, deviceId } = await envWithDevice(fetcher);
      const res = await handleDeviceSetupBattery(
        postJson("/device/setup/battery", { device_id: deviceId }, await tokenHeaders(tokenKind)),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ id: "bat-ok" });
    },
  );

  it.each(["dev", "device-key"])(
    "POST /device/setup/version (読み取りの照会) は token_kind=%s でも通る",
    async (tokenKind) => {
      const { fetcher } = mockRecorder(() => new Response(JSON.stringify({ id: "ver-ok" }), { status: 202 }));
      const { env, deviceId } = await envWithDevice(fetcher);
      const res = await handleDeviceSetupVersion(
        postJson("/device/setup/version", { device_id: deviceId }, await tokenHeaders(tokenKind)),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ id: "ver-ok" });
    },
  );

  it.each(["dev", "device-key"])(
    "POST /device/setup/bus5v (読み取りの照会) は token_kind=%s でも通る",
    async (tokenKind) => {
      const { fetcher } = mockRecorder(() => new Response(JSON.stringify({ id: "b5v-ok" }), { status: 202 }));
      const { env, deviceId } = await envWithDevice(fetcher);
      const res = await handleDeviceSetupBus5v(
        postJson("/device/setup/bus5v", { device_id: deviceId }, await tokenHeaders(tokenKind)),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ id: "b5v-ok" });
    },
  );

  it.each(["dev", "device-key"])(
    "POST /device/setup/bp_status (読み取りの照会) は token_kind=%s でも通る (Refs #574)",
    async (tokenKind) => {
      const { fetcher } = mockRecorder(() => new Response(JSON.stringify({ id: "bp-ok" }), { status: 202 }));
      const { env, deviceId } = await envWithDevice(fetcher);
      const res = await handleDeviceSetupBpStatus(
        postJson("/device/setup/bp_status", { device_id: deviceId }, await tokenHeaders(tokenKind)),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ id: "bp-ok" });
    },
  );

  it("GET /device/setup/ota/:id (進捗ポーリング) は token_kind=dev でも通る", async () => {
    const { fetcher } = mockRecorder(() => new Response(JSON.stringify({ id: "ota-1" }), { status: 202 }));
    const { env, deviceId } = await envWithDevice(fetcher);
    // command_result 未 push (recorder 404) = pending としてポーリングが通ることを確認
    const pollRecorder = {
      async fetch(): Promise<Response> {
        return new Response("{}", { status: 404 });
      },
    };
    const pollEnv = { ...env, ALC_RECORDER: pollRecorder } as unknown as Env;
    void deviceId;
    const res = await handleDeviceSetupOtaStatus(
      getReq("/device/setup/ota/cmd-1", await tokenHeaders("dev")),
      pollEnv,
      "cmd-1",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ phase: "pending" });
  });

  it("通常の admin session (token_kind 無し) は書き込む口 (ota) も今までどおり通る (回帰確認)", async () => {
    const { fetcher, calls } = mockRecorder(
      () => new Response(JSON.stringify({ id: "ota-admin" }), { status: 202 }),
    );
    const { env, deviceId } = await envWithDevice(fetcher);
    const res = await handleDeviceSetupOta(
      postJson(
        "/device/setup/ota",
        { device_id: deviceId, url: "https://example.com/fw.bin" },
        { ...(await opCookie()), Origin: ISSUER },
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "ota-admin" });
    expect(calls.length).toBe(1);
  });
});

/**
 * 開発用かどうかは鍵を発行する時点 (`POST /device/setup/pair` の `dev_device`) で決まる
 * (Refs ippoan/alc-app#387)。明示できるのは「開発者アカウントが Google でログインした session」だけ。
 * 開発者のメールアドレスの値はテストに書かない (登録簿の先頭を借りる)。
 */
describe("handleDeviceSetupPair の dev_device (Refs ippoan/alc-app#387)", () => {
  const DEV_EMAIL = DEVELOPER_EMAILS[0]!;
  const PATH = "/device/setup/pair";

  /** 開発者が Google で入った session (dev_device を明示できる唯一の形)。 */
  async function devHeaders(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
    return { ...(await opCookie({ email: DEV_EMAIL, idp: "google", ...claims })), Origin: ISSUER };
  }
  /** 開発者でない管理者の session。 */
  async function opHeaders(): Promise<Record<string, string>> {
    return { ...(await opCookie({ idp: "google" })), Origin: ISSUER };
  }
  async function pair(env: Env, body: Record<string, unknown>, headers: Record<string, string>) {
    return handleDeviceSetupPair(postJson(PATH, body, headers), env);
  }
  /** KV に在る device record の数 (拒否された request が何も作らないことの確認用)。 */
  async function deviceRecordCount(env: Env): Promise<number> {
    return (await env.AUTH_CONFIG.list({ prefix: "device:" })).keys.length;
  }

  it("開発者 + dev_device:true → 新しい record が dev (新規でも置き換えでも)", async () => {
    const env = makeEnv();
    const fresh = (await (await pair(env, { label: "a", dev_device: true }, await devHeaders())).json()) as PairResponse;
    expect((await getDeviceRecord(env, fresh.device_id))?.dev_device).toBe(true);

    // 本番の端末を、開発用として書き直す (旧 record は revoke)
    const prod = (await (await pair(env, { label: "b", replace_label: true }, await opHeaders())).json()) as PairResponse;
    expect(await getDeviceRecord(env, prod.device_id)).not.toHaveProperty("dev_device");
    const res = await pair(env, { label: "b", replace_label: true, dev_device: true }, await devHeaders());
    expect(res.status).toBe(201);
    const next = (await res.json()) as PairResponse;
    expect(next.device_id).not.toBe(prod.device_id);
    expect((await getDeviceRecord(env, next.device_id))?.dev_device).toBe(true);
    expect((await getDeviceRecord(env, prod.device_id))?.revoked).toBe(true);
  });

  it("開発者 + dev_device:false + 置き換えで旧が dev → 新は本番 (欄ごと無い)、旧は revoke", async () => {
    const env = makeEnv();
    const dev = (await (
      await pair(env, { label: "a", replace_label: true, dev_device: true }, await devHeaders())
    ).json()) as PairResponse;
    const next = (await (
      await pair(env, { label: "a", replace_label: true, dev_device: false }, await devHeaders())
    ).json()) as PairResponse;
    expect(await getDeviceRecord(env, next.device_id)).not.toHaveProperty("dev_device");
    expect((await getDeviceRecord(env, next.device_id))?.revoked).toBe(false);
    expect((await getDeviceRecord(env, dev.device_id))?.revoked).toBe(true);
  });

  it.each([
    ["開発者でない管理者 (Google ログイン)", { email: "op@example.com", idp: "google" }],
    ["開発者の email だが idp なし (LINE WORKS のログイン・古い cookie)", { email: DEV_EMAIL }],
    ["開発者の email だが idp が別の値", { email: DEV_EMAIL, idp: "lineworks" }],
    ["email の無い session", { email: "", idp: "google" }],
  ])("%s が dev_device を送ると true でも false でも 403、record は作られず旧 record も失効しない", async (_name, claims) => {
    const env = makeEnv();
    const old = (await (
      await pair(env, { label: "a", replace_label: true, dev_device: true }, await devHeaders())
    ).json()) as PairResponse;
    const before = await deviceRecordCount(env);
    for (const dev of [true, false]) {
      const res = await pair(
        env,
        { label: "a", replace_label: true, dev_device: dev },
        { ...(await opCookie(claims)), Origin: ISSUER },
      );
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "developer_google_session_required" });
    }
    expect(await deviceRecordCount(env)).toBe(before);
    const still = await getDeviceRecord(env, old.device_id);
    expect(still?.revoked).toBe(false);
    expect(still?.dev_device).toBe(true);
  });

  it.each(["dev", "device-key"])(
    "開発者の email + idp=google でも token_kind=%s は 403 dev_token_write_forbidden (今までどおり)",
    async (tokenKind) => {
      const env = makeEnv();
      const res = await pair(env, { label: "a", dev_device: true }, await devHeaders({ token_kind: tokenKind }));
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
      expect(await deviceRecordCount(env)).toBe(0);
    },
  );

  it("明示なし + 置き換えで旧が dev → 新も dev (引き継ぎ。開発者でない運用者の再ペアリング)", async () => {
    const env = makeEnv();
    const dev = (await (
      await pair(env, { label: "a", replace_label: true, dev_device: true }, await devHeaders())
    ).json()) as PairResponse;
    const res = await pair(env, { label: "a", replace_label: true }, await opHeaders());
    expect(res.status).toBe(201);
    const next = (await res.json()) as PairResponse;
    expect((await getDeviceRecord(env, next.device_id))?.dev_device).toBe(true);
    expect((await getDeviceRecord(env, dev.device_id))?.revoked).toBe(true);
  });

  it("明示なし + 置き換えで旧が dev かつ失効済み → 新は本番 (失効済みからは引き継がない)", async () => {
    const env = makeEnv();
    const dev = (await (
      await pair(env, { label: "cores3", replace_label: true, dev_device: true }, await devHeaders())
    ).json()) as PairResponse;
    await revokeDeviceCredential(env, dev.device_id);
    // 開発者でない管理者が、同じ (既定の) ラベルで別の機体を通常ペアリングする
    const res = await pair(env, { label: "cores3", replace_label: true }, await opHeaders());
    expect(res.status).toBe(201);
    const next = (await res.json()) as PairResponse;
    expect(await getDeviceRecord(env, next.device_id)).not.toHaveProperty("dev_device");
  });

  it("明示なし + 置き換えで旧が本番 → 新も本番 / 明示なし + 新規 → 本番 (開発者の session でも)", async () => {
    const env = makeEnv();
    await pair(env, { label: "a", replace_label: true }, await opHeaders());
    const replaced = (await (await pair(env, { label: "a", replace_label: true }, await opHeaders())).json()) as PairResponse;
    expect(await getDeviceRecord(env, replaced.device_id)).not.toHaveProperty("dev_device");
    for (const headers of [await opHeaders(), await devHeaders()]) {
      const fresh = (await (await pair(env, { label: "b" }, headers)).json()) as PairResponse;
      expect(await getDeviceRecord(env, fresh.device_id)).not.toHaveProperty("dev_device");
    }
  });

  it.each([
    ["文字列 \"true\"", "true"],
    ["数値 1", 1],
    ["null", null],
  ])("dev_device が boolean でない (%s) は 400 (record は作られない)", async (_name, value) => {
    const env = makeEnv();
    const res = await pair(env, { label: "a", dev_device: value }, await devHeaders());
    expect(res.status).toBe(400);
    expect(await deviceRecordCount(env)).toBe(0);
  });

  it("監査ログは明示したときだけ。登録簿の種別と真偽だけ (鍵の id・tenant・メールアドレスを出さない)", async () => {
    const env = makeEnv();
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await pair(env, { label: "a", replace_label: true }, await devHeaders());
      await pair(env, { label: "a", replace_label: true, dev_device: "true" }, await devHeaders());
      await pair(env, { label: "a", replace_label: true, dev_device: true }, await opHeaders());
      expect(spy.mock.calls).toEqual([]);
      await pair(env, { label: "a", replace_label: true, dev_device: true }, await devHeaders());
      // 明示なしの引き継ぎ (dev のまま) では出ない
      await pair(env, { label: "a", replace_label: true }, await opHeaders());
      await pair(env, { label: "a", replace_label: true, dev_device: false }, await devHeaders());
      expect(spy.mock.calls.map((c) => String(c[0]))).toEqual([
        JSON.stringify({ event: "dev_device_set", registry: "device", dev_device: true }),
        JSON.stringify({ event: "dev_device_set", registry: "device", dev_device: false }),
      ]);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("dev_device の表示 (一覧の応答と画面、Refs ippoan/alc-app#387)", () => {
  const DEV_EMAIL = DEVELOPER_EMAILS[0]!;

  it("GET /device/setup/list は各行に dev_device を boolean で返す", async () => {
    const env = makeEnv();
    const headers = { ...(await opCookie()), Origin: ISSUER };
    const plain = (await (
      await handleDeviceSetupPair(postJson("/device/setup/pair", { label: "plain" }, headers), env)
    ).json()) as PairResponse;
    const dev = (await (
      await handleDeviceSetupPair(
        postJson(
          "/device/setup/pair",
          { label: "dev", dev_device: true },
          { ...(await opCookie({ email: DEV_EMAIL, idp: "google" })), Origin: ISSUER },
        ),
        env,
      )
    ).json()) as PairResponse;
    const res = await handleDeviceSetupList(getReq("/device/setup/list", await opCookie()), env);
    const body = (await res.json()) as { devices: Array<{ device_id: string; dev_device: unknown }> };
    const byId = Object.fromEntries(body.devices.map((d) => [d.device_id, d.dev_device]));
    expect(byId[dev.device_id]).toBe(true);
    expect(byId[plain.device_id]).toBe(false);
  });

  it("画面: 開発者の email なら IS_DEVELOPER = true、そうでなければ false", async () => {
    const devHtml = await (
      await handleDeviceSetupPage(getReq("/device/setup", await opCookie({ email: DEV_EMAIL })), makeEnv())
    ).text();
    expect(devHtml).toContain("const IS_DEVELOPER = true;");

    const opHtml = await (
      await handleDeviceSetupPage(getReq("/device/setup", await opCookie()), makeEnv())
    ).text();
    expect(opHtml).toContain("const IS_DEVELOPER = false;");
    expect(opHtml).not.toContain("const IS_DEVELOPER = true;");
  });

  it("画面: 「開発用」の印は既存のバッジを使い、全員に出す", async () => {
    for (const claims of [{ email: DEV_EMAIL }, {}]) {
      const html = await (
        await handleDeviceSetupPage(getReq("/device/setup", await opCookie(claims)), makeEnv())
      ).text();
      // 印は .tag.new のバッジ (inline の fontSize / color は持たない)
      const mark = html.slice(html.indexOf("function devDeviceMark()"), html.indexOf("function findKioskKeysFor("));
      expect(mark).toContain('mark.className = "tag new";');
      expect(mark).toContain('mark.textContent = "開発用";');
      expect(mark).not.toContain("fontSize");
      expect(mark).not.toContain("style.color");
      expect(html).toContain(".tag.new{background:#fef3c7;color:#92400e}");
      // 2 つの表の行に印を置く
      expect(html.split("appendChild(devDeviceMark())").length - 1).toBe(2);
    }
  });

  it("画面: client script が構文として通る", async () => {
    const html = await (
      await handleDeviceSetupPage(getReq("/device/setup", await opCookie({ email: DEV_EMAIL })), makeEnv())
    ).text();
    const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
      .map((m) => m[1] ?? "")
      .filter((s) => s.trim() !== "");
    expect(scripts.length).toBeGreaterThan(0);
    // 本体は実行しない (関数に包んで parse だけさせる)
    for (const s of scripts) expect(() => new Function(s)).not.toThrow();
  });
});

describe("端末と署名鍵の食い違いの警告 (画面、Refs ippoan/alc-app#387)", () => {
  const DEV_EMAIL = DEVELOPER_EMAILS[0]!;
  const pageHtml = async () =>
    (await handleDeviceSetupPage(getReq("/device/setup", await opCookie({ email: DEV_EMAIL })), makeEnv())).text();
  /** 開発者でないアカウントの画面。 */
  const opPageHtml = async () =>
    (await handleDeviceSetupPage(getReq("/device/setup", await opCookie()), makeEnv())).text();
  // script から関数 1 つの本体を取り出す (次の top-level の function / コメント行までを 1 塊として切る)
  const extractFn = (html: string, name: string): string => {
    const start = html.indexOf(`function ${name}(`);
    expect(start).toBeGreaterThanOrEqual(0);
    const end = html.indexOf("\n}\n", start);
    return html.slice(start, end + 3);
  };
  type Dev = { device_id: string; label: string; kind: string };
  type Key = { fingerprint: string; label: string; usage: string; revoked_at?: number | null };

  it("script に相方を探す関数・警告の文言・.tag.warn が在る (開発者でないアカウントにも)", async () => {
    for (const html of [await pageHtml(), await opPageHtml()]) {
      expect(html).toContain("function findKioskKeysFor(");
      expect(html).toContain("function findHubDevicesFor(");
      expect(html).toContain("署名鍵が本番のまま — キオスクの画面の記録は本番に入ります");
      expect(html).toContain("署名鍵が開発用のまま — キオスクの画面の記録は開発用になり、本番に入りません");
      expect(html).toContain("端末が本番のまま — 本体からの記録は本番に入ります");
      expect(html).toContain("鍵が本番のまま — キオスクの画面の記録は本番に入ります");
      expect(html).toContain(".tag.warn{background:#fee2e2;color:#991b1b}");
      // バッジは既存の .tag で、文言は textContent で入れる
      const tag = extractFn(html, "pairWarnTag");
      expect(tag).toContain('tag.className = "tag warn";');
      expect(tag).toContain("tag.textContent = text;");
      expect(tag).not.toContain("innerHTML");
      // 警告の描き直しは行を作らず、置き場の span の中身だけを入れ替える
      const refresh = extractFn(html, "refreshPairWarnings");
      expect(refresh).not.toContain("createElement");
      expect(refresh).not.toContain("ROWS");
      // 2 つの表のどちらを読み直しても描き直す
      expect(extractFn(html, "loadDevices")).toContain("refreshPairWarnings();");
      expect(extractFn(html, "loadAlarmKeys")).toContain("refreshPairWarnings();");
    }
  });

  it("登録簿の旗を後から倒す口は画面に無い (切替ボタン・連動・口の path)", async () => {
    for (const html of [await pageHtml(), await opPageHtml()]) {
      expect(html).not.toContain("/device/setup/dev-device");
      expect(html).not.toContain("/device/setup/alarm-key/dev-device");
      expect(html).not.toContain("dev-device");
      for (const gone of ["setDevDevice", "postDevDevice", "devDeviceButton", "partnerOfDevice", "partnerOfKey"]) {
        expect(html).not.toContain(gone);
      }
      expect(html).not.toContain("開発用にする");
      expect(html).not.toContain("開発用を外す");
      expect(html).not.toContain("一緒に切り替えます");
    }
  });

  it("画面: client script が構文として通る", async () => {
    const html = await pageHtml();
    const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
      .map((m) => m[1] ?? "")
      .filter((s) => s.trim() !== "");
    for (const s of scripts) expect(() => new Function(s)).not.toThrow();
  });

  describe("相方を探す純関数 (script から取り出して実行)", () => {
    const load = async () => {
      const html = await pageHtml();
      const src = extractFn(html, "findKioskKeysFor") + extractFn(html, "findHubDevicesFor");
      return new Function(`${src}; return { findKioskKeysFor, findHubDevicesFor };`)() as {
        findKioskKeysFor: (label: string, keys: Key[]) => Key[];
        findHubDevicesFor: (label: string, devs: Dev[]) => Dev[];
      };
    };
    const key = (fp: string, label: string, usage = "kiosk", revoked_at: number | null = null): Key => ({
      fingerprint: fp, label, usage, revoked_at,
    });
    const dev = (id: string, label: string, kind = "cores3"): Dev => ({ device_id: id, label, kind });

    it("findKioskKeysFor: 一致 1 件 → その 1 件 / 0 件 → 空 / 2 件 → 2 件", async () => {
      const { findKioskKeysFor } = await load();
      expect(findKioskKeysFor("a", [key("k1", "a"), key("k2", "b")]).map((k) => k.fingerprint)).toEqual(["k1"]);
      expect(findKioskKeysFor("a", [key("k2", "b")])).toEqual([]);
      expect(findKioskKeysFor("a", [])).toEqual([]);
      expect(findKioskKeysFor("a", [key("k1", "a"), key("k2", "a")])).toHaveLength(2);
    });

    it("findKioskKeysFor: 失効済み・用途が kiosk 以外・ラベルが部分一致のみ、は除く", async () => {
      const { findKioskKeysFor } = await load();
      expect(findKioskKeysFor("a", [key("k1", "a", "kiosk", 100)])).toEqual([]);
      expect(findKioskKeysFor("a", [key("k1", "a", "tenko-manager"), key("k2", "a", "bp-station")])).toEqual([]);
      expect(findKioskKeysFor("a", [key("k1", "a 2"), key("k2", "A")])).toEqual([]);
    });

    it("ラベルが空 (空文字・undefined) のときは相方なし", async () => {
      const { findKioskKeysFor, findHubDevicesFor } = await load();
      expect(findKioskKeysFor("", [key("k1", "")])).toEqual([]);
      expect(findKioskKeysFor(undefined as unknown as string, [key("k1", undefined as unknown as string)])).toEqual([]);
      expect(findHubDevicesFor("", [dev("d1", "")])).toEqual([]);
      expect(findHubDevicesFor(undefined as unknown as string, [dev("d1", undefined as unknown as string)])).toEqual([]);
    });

    it("findHubDevicesFor: 一致 1 件 / 0 件 / 2 件、kind が cores3 以外は除く", async () => {
      const { findHubDevicesFor } = await load();
      expect(findHubDevicesFor("a", [dev("d1", "a"), dev("d2", "b")]).map((d) => d.device_id)).toEqual(["d1"]);
      expect(findHubDevicesFor("a", [dev("d2", "b")])).toEqual([]);
      expect(findHubDevicesFor("a", [dev("d1", "a"), dev("d2", "a")])).toHaveLength(2);
      for (const kind of ["atoms3-print", "p4-gw", "timecard"]) {
        expect(findHubDevicesFor("a", [dev("d1", "a", kind)])).toEqual([]);
      }
    });
  });
});

/**
 * 切り替えの入口は 1 つ —「接続中の機体を開発用 / 本番として書き直す」(開発者にだけ出す)。
 * 既存のペアリングの手順 (run) と署名鍵の登録の手順 (registerAlarmKey) を引数で再利用する。
 */
describe("接続中の機体を書き直す (画面、Refs ippoan/alc-app#387)", () => {
  const DEV_EMAIL = DEVELOPER_EMAILS[0]!;
  const pageHtml = async (claims: Record<string, unknown> = { email: DEV_EMAIL }) =>
    (await handleDeviceSetupPage(getReq("/device/setup", await opCookie(claims)), makeEnv())).text();
  const extractFn = (html: string, name: string): string => {
    const start = html.indexOf(`function ${name}(`);
    expect(start).toBeGreaterThanOrEqual(0);
    return html.slice(start, html.indexOf("\n}\n", start) + 3);
  };

  it("開発者の画面: ボタン 1 組と、DEVICE_KINDS の全機種の select が在る", async () => {
    const html = await pageHtml();
    expect(html).toContain('<button id="rewrite-dev" type="button"');
    expect(html).toContain(">接続中の機体を開発用として書き直す</button>");
    expect(html).toContain('<button id="rewrite-prod" type="button"');
    expect(html).toContain(">接続中の機体を本番として書き直す</button>");
    const select = html.slice(html.indexOf('<select id="rewrite-kind"'));
    const options = select.slice(0, select.indexOf("</select>"));
    for (const name of Object.keys(DEVICE_KINDS)) expect(options).toContain(`value="${name}"`);
    // ペアリングの画面・署名鍵の登録の画面に「開発用」のチェックは足さない
    expect(html).not.toMatch(/type="checkbox"[^>]*dev[_-]device/);
  });

  it("開発者でないアカウントの画面には、書き直すボタンも機種の select も無い", async () => {
    const html = await pageHtml({});
    expect(html).not.toContain('id="rewrite-dev"');
    expect(html).not.toContain('id="rewrite-prod"');
    expect(html).not.toContain('id="rewrite-kind"');
    expect(html).not.toContain("接続中の機体を開発用として書き直す");
    expect(html).not.toContain("接続中の機体を本番として書き直す");
    // ボタンを探すのは IS_DEVELOPER のときだけ (無い要素に addEventListener しない)
    expect(html).toMatch(/if \(IS_DEVELOPER\) \{\s+const rewriteDevBtn = document\.getElementById\("rewrite-dev"\);/);
  });

  it("confirm と完了の文言", async () => {
    const html = await pageHtml();
    const fn = extractFn(html, "rewriteConnectedDevice");
    expect(fn).toContain('"接続中の機体を" + (devDevice ? "開発用" : "本番") +');
    expect(fn).toContain('"として書き直しますか? (端末の鍵と署名鍵を作り直します。古い鍵は使えなくなります)"');
    // 機体の選択 (許可ダイアログ) → confirm → 書き込み、の順
    expect(fn.indexOf("navigator.serial.requestPort()")).toBeLessThan(fn.indexOf("confirm("));
    expect(fn.indexOf("confirm(")).toBeLessThan(fn.indexOf("await run("));
    expect(html).toContain(
      "書き直しました。キオスクの画面を再読み込みしてください。ファームが古い端末は、書き直した後に電源を入れ直してください",
    );
    expect(fn).toContain("REWRITE_DONE");
    // 済んだら 2 つの表を読み直す
    expect(fn).toContain("loadDevices();");
    expect(fn).toContain("loadAlarmKeys();");
  });

  it("端末の鍵 → 署名鍵の順に既存の手順を再利用し、機種で通す手順を決める", async () => {
    const html = await pageHtml();
    const fn = extractFn(html, "rewriteConnectedDevice");
    expect(html).toContain(
      `const PAIRABLE_KINDS = ${JSON.stringify(
        Object.entries(DEVICE_KINDS).filter(([, k]) => k.pairRole).map(([name]) => name),
      )};`,
    );
    // credential を発行する機種だけ端末の鍵の手順、P4 GW 以外は署名鍵の手順
    expect(fn).toContain("paired: PAIRABLE_KINDS.includes(kind)");
    expect(fn).toContain("if (rewrite.paired) {");
    expect(fn).toContain("if (!(await run(undefined, rewrite))) return;");
    expect(fn).toContain('if (kind !== "p4-gw" && !(await registerAlarmKey(rewrite))) return;');
    expect(fn.indexOf("await run(undefined, rewrite)")).toBeLessThan(fn.indexOf("await registerAlarmKey(rewrite)"));
    // 手順の複製を作らない: シリアルの手順 (PING の準備・AUTH SET) は既存の 2 か所 + 署名鍵の 1 か所のまま
    expect(html.split('"AUTH SET "').length - 1).toBe(1);
    expect(html.split('"cred set "').length - 1).toBe(1);
    expect(html.split("AUTH KEYGEN").length - 1).toBe(html.split("async function registerAlarmKey(").length - 1 + 2);
  });

  it("端末の鍵: pair の body に dev_device を足す (書き直しのときだけ)。ラベルは一覧の行から引く", async () => {
    const html = await pageHtml();
    for (const name of ["runCoreS3OrPrint", "runP4Gateway"]) {
      const fn = extractFn(html, name);
      expect(fn).toContain("rewrite ? { dev_device: rewrite.devDevice } : {}");
      expect(fn).toContain("replace_label: true");
      expect(fn).toContain("const row = rewrite ? rewriteRowOf(");
      expect(fn).toContain("const label = row ? row.label : labelInput.value ||");
      expect(fn).toContain("throw await pairError(res);");
    }
    expect(extractFn(html, "pairError")).toContain("Google でログインし直してください");
    expect(extractFn(html, "pairError")).toContain('"credential 発行に失敗: HTTP " + res.status');
    // 書き直し以外 (セットアップ実行・再登録) は dev_device を送らない
    expect(html).toContain('runBtn.addEventListener("click", () => run());');
    expect(html).toContain('run(d.kind === "p4-gw" ? d.site_id : undefined);');
  });

  it("rewriteRowOf: 一覧に在る機体はその行、無い機体・機種違いは止める (script から取り出して実行)", async () => {
    const html = await pageHtml();
    const rowOf = new Function(
      "LAST_DEVICES",
      "KIND_DISPLAY",
      `${extractFn(html, "rewriteRowOf")}; return rewriteRowOf;`,
    )([{ device_id: "d1", label: "a", kind: "cores3" }], { cores3: "CoreS3 統合ハブ" }) as (
      id: string,
      kind: string,
    ) => { label: string };
    expect(rowOf("d1", "cores3").label).toBe("a");
    expect(() => rowOf("d2", "cores3")).toThrow("登録簿に見つかりません");
    expect(() => rowOf("", "cores3")).toThrow("登録簿に見つかりません");
    expect(() => rowOf("d1", "timecard")).toThrow("選んだ機種が、接続中の機体 (CoreS3 統合ハブ) と違います");
  });

  it("署名鍵: 古い公開鍵を控えて AUTH KEYGEN FORCE、replaces_pubkey と dev_device で差し替える", async () => {
    const html = await pageHtml();
    const fn = extractFn(html, "registerAlarmKey");
    expect(fn).toContain('await send(rewrite ? "AUTH KEYGEN FORCE" : "AUTH KEYGEN");');
    expect(fn).toContain(
      "body: JSON.stringify({ pubkey, replaces_pubkey: oldPubkey, dev_device: rewrite.devDevice }),",
    );
    // 古い公開鍵 (AUTH PUBKEY) → 作り直し、の順。控えた応答行は捨ててから作り直す
    expect(fn.indexOf("oldPubkey = (await waitLine(")).toBeLessThan(fn.indexOf('"AUTH KEYGEN FORCE"'));
    // 今までの登録 (ラベルと用途を聞く) の body は変えない
    expect(fn).toContain("body: JSON.stringify({ pubkey, label, usage }),");
    expect(html).toContain('alarmKeyRegisterBtn.addEventListener("click", () => registerAlarmKey());');
    // 失敗の文言
    expect(fn).toContain(
      "この機体の署名鍵は登録簿に見つかりませんでした。下の「署名鍵の登録」から登録してください",
    );
    expect(fn).toContain('err === "replaced_key_not_found"');
    expect(fn).toContain("署名鍵の登録に失敗しました。もう一度書き直してください");
    // 署名鍵を持たない機体: 端末の鍵を書き直した後なら何もせず済み、署名鍵だけの機種なら止める
    expect(fn).toContain("if (!rewrite.paired) throw new Error(");
  });

  it("画面: client script が構文として通る (開発者・開発者でないアカウントの両方)", async () => {
    for (const html of [await pageHtml(), await pageHtml({})]) {
      const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
        .map((m) => m[1] ?? "")
        .filter((s) => s.trim() !== "");
      expect(scripts.length).toBeGreaterThan(0);
      for (const s of scripts) expect(() => new Function(s)).not.toThrow();
    }
  });
});
