import { describe, it, expect, vi, afterEach } from "vitest";
import {
  MACHINE_TICKET_TTL_SECONDS,
  issueTicket,
  verifyTicket,
  type MachineTicketEnv,
} from "../../src/lib/machine-ticket";
import { createMachineCredential, revokeMachineCredential } from "../../src/lib/machine-credential";
import { decodeJwtPayload, signJwt, verifyJwt } from "../../src/lib/jwt";
import { FAKE_ALC_AUTH_SECRET, createFakeAlcAuth, type FakeAlcAuth } from "../helpers/fake-alc-auth";

/** テスト固有のダミー値 (本番の値ではない)。 */
const SECRET = "test-jwt-secret-for-machine-ticket";
const TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const PURPOSE = "leave-scan";
const SHA = "a".repeat(64);
const SHA2 = "b".repeat(64);

function env(name: string | null = "prod", fake: FakeAlcAuth = createFakeAlcAuth()): MachineTicketEnv & { fake: FakeAlcAuth } {
  return {
    ALC_AUTH: fake.fetcher,
    INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
    MACHINE_CRED_ENV: name ?? undefined,
    JWT_SECRET: SECRET,
    fake,
  };
}

function basic(username: string, password: string): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}

async function setup(e: MachineTicketEnv & { fake: FakeAlcAuth } = env(), tenant = TENANT_A) {
  const c = await createMachineCredential(e, tenant, PURPOSE, "複合機");
  if (!c) throw new Error("create failed");
  return { e, c, auth: basic(c.username, c.password) };
}

/** payload の 1 か所を書き換えて、正しい派生鍵で署名し直したチケットを作る (署名以外の検査を通すため)。 */
async function resign(e: MachineTicketEnv, ticket: string, patch: Record<string, unknown>): Promise<string> {
  // 派生鍵は外に出していないので、同じ HKDF をテスト側で再現する。
  const enc = new TextEncoder();
  const ikm = await crypto.subtle.importKey("raw", enc.encode(SECRET), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(`machine-ticket-v1:${e.MACHINE_CRED_ENV}`) },
    ikm,
    256,
  );
  const key = Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, "0")).join("");
  const payload = { ...decodeJwtPayload(ticket)!, ...patch };
  for (const [k, v] of Object.entries(patch)) if (v === undefined) delete payload[k];
  return signJwt(payload, key);
}

afterEach(() => {
  vi.useRealTimers();
});

describe("issueTicket", () => {
  it("Basic が通れば tenant・username とチケット (payload の形を固定)", async () => {
    const { e, c, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    expect(r).toMatchObject({ tenantId: TENANT_A, username: c.username });
    const p = decodeJwtPayload(r!.ticket)!;
    expect(Object.keys(p).sort()).toEqual(
      ["env", "exp", "iat", "purpose", "sha256", "tenant_id", "username", "v"].sort(),
    );
    expect(p).toMatchObject({ v: 1, env: "prod", tenant_id: TENANT_A, username: c.username, purpose: PURPOSE, sha256: SHA });
    expect((p.exp as number) - (p.iat as number)).toBe(MACHINE_TICKET_TTL_SECONDS);
    expect(MACHINE_TICKET_TTL_SECONDS).toBe(7 * 24 * 3600);
  });

  it("★ 派生鍵で署名する: JWT_SECRET そのものでは検証が通らない (ブラウザ JWT と混ざらない)", async () => {
    const { e, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    expect(await verifyJwt(r!.ticket, SECRET)).toBeNull();
  });

  it.each<[string, string]>([
    ["大文字", "A".repeat(64)],
    ["63 桁", "a".repeat(63)],
    ["65 桁", "a".repeat(65)],
    ["hex でない", "g".repeat(64)],
    ["空", ""],
  ])("sha256 が %s → null", async (_n, sha) => {
    const { e, auth } = await setup();
    expect(await issueTicket(e, auth, PURPOSE, sha)).toBeNull();
  });

  it("sha256 が文字列でない → null", async () => {
    const { e, auth } = await setup();
    expect(await issueTicket(e, auth, PURPOSE, 1 as unknown as string)).toBeNull();
  });

  it("Basic が通らない (password 違い / 用途違い / 失効) → null", async () => {
    const { e, c, auth } = await setup();
    expect(await issueTicket(e, basic(c.username, "wrong"), PURPOSE, SHA)).toBeNull();
    expect(await issueTicket(e, auth, "other", SHA)).toBeNull();
    await revokeMachineCredential(e, TENANT_A, c.username);
    expect(await issueTicket(e, auth, PURPOSE, SHA)).toBeNull();
  });

  it("環境名なし・JWT_SECRET なし → null", async () => {
    const { e, auth } = await setup();
    expect(await issueTicket({ ...e, MACHINE_CRED_ENV: undefined }, auth, PURPOSE, SHA)).toBeNull();
    expect(await issueTicket({ ...e, JWT_SECRET: undefined }, auth, PURPOSE, SHA)).toBeNull();
  });
});

describe("verifyTicket", () => {
  it("発行したチケット → {tenantId, username, sha256}", async () => {
    const { e, c, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    expect(await verifyTicket(e, r!.ticket, PURPOSE)).toEqual({
      tenantId: TENANT_A,
      username: c.username,
      sha256: SHA,
    });
  });

  it("★ sha256 を書き換えたチケットは null (署名が合わない)", async () => {
    const { e, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    const [h, , s] = r!.ticket.split(".");
    const p = decodeJwtPayload(r!.ticket)!;
    const forged = btoa(JSON.stringify({ ...p, sha256: SHA2 })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyTicket(e, `${h}.${forged}.${s}`, PURPOSE)).toBeNull();
  });

  it("★ revoke した資格情報のチケットは null (発行済みでも)", async () => {
    const { e, c, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    await revokeMachineCredential(e, TENANT_A, c.username);
    expect(await verifyTicket(e, r!.ticket, PURPOSE)).toBeNull();
  });

  it("★ staging の鍵で作ったチケットは prod で null (同じ JWT_SECRET・同じ資格情報が prod に在っても)", async () => {
    const staging = env("staging");
    const prod = env("prod");
    const { c, auth } = await setup(staging);
    const r = await issueTicket(staging, auth, PURPOSE, SHA);
    expect(await verifyTicket(staging, r!.ticket, PURPOSE)).not.toBeNull();
    expect(await verifyTicket(prod, r!.ticket, PURPOSE)).toBeNull();

    // 鍵の違いだけでも落ちる: prod 側に同じ username の有効な資格情報を置き、
    // payload の env を prod に書き換えても、staging の鍵の署名は prod では通らない。
    prod.fake.rows.set(c.username, { ...staging.fake.rows.get(c.username)! });
    const envSwapped = await resign(staging, r!.ticket, { env: "prod" });
    expect(await verifyTicket(prod, envSwapped, PURPOSE)).toBeNull();
    // 対照: prod の鍵で署名し直せば通る (= 上の null は鍵の違いによる)
    const prodSigned = await resign(prod, r!.ticket, { env: "prod" });
    expect(await verifyTicket(prod, prodSigned, PURPOSE)).not.toBeNull();
  });

  it("期限切れ → null", async () => {
    const { e, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + (MACHINE_TICKET_TTL_SECONDS + 1) * 1000);
    expect(await verifyTicket(e, r!.ticket, PURPOSE)).toBeNull();
  });

  it("用途違い・環境名なし・JWT_SECRET なし・空や非文字列のチケット・壊れたチケット → null", async () => {
    const { e, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    expect(await verifyTicket(e, r!.ticket, "other")).toBeNull();
    expect(await verifyTicket({ ...e, MACHINE_CRED_ENV: undefined }, r!.ticket, PURPOSE)).toBeNull();
    expect(await verifyTicket({ ...e, JWT_SECRET: undefined }, r!.ticket, PURPOSE)).toBeNull();
    expect(await verifyTicket(e, "", PURPOSE)).toBeNull();
    expect(await verifyTicket(e, 1 as unknown as string, PURPOSE)).toBeNull();
    expect(await verifyTicket(e, "not.a.jwt", PURPOSE)).toBeNull();
  });

  it.each<[string, Record<string, unknown>]>([
    ["v が 1 でない", { v: 2 }],
    ["env が違う", { env: "staging" }],
    ["purpose が違う", { purpose: "other" }],
    ["tenant_id が文字列でない", { tenant_id: 1 }],
    ["username が文字列でない", { username: 1 }],
    ["sha256 が文字列でない", { sha256: 1 }],
    ["sha256 の形が違う", { sha256: "xyz" }],
    ["tenant_id が資格情報と食い違う", { tenant_id: TENANT_B }],
    ["username が存在しない", { username: "mc_aaaaaaaaaaaaaaaa" }],
  ])("正しい鍵で署名されていても %s → null", async (_n, patch) => {
    const { e, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    expect(await verifyTicket(e, await resign(e, r!.ticket, patch), PURPOSE)).toBeNull();
  });

  it("資格情報の purpose が後から食い違っていたら null", async () => {
    const { e, c, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    e.fake.rows.get(c.username)!.purpose = "other";
    expect(await verifyTicket(e, r!.ticket, PURPOSE)).toBeNull();
  });

  it("★ alc-auth-worker に届かない (binding なし・5xx) → 発行も検証も null (fail-closed)", async () => {
    const { e, auth } = await setup();
    const r = await issueTicket(e, auth, PURPOSE, SHA);
    expect(r).not.toBeNull();
    const noBinding = { ...e, ALC_AUTH: undefined };
    expect(await issueTicket(noBinding, auth, PURPOSE, SHA)).toBeNull();
    expect(await verifyTicket(noBinding, r!.ticket, PURPOSE)).toBeNull();
    const down = { ...e, ALC_AUTH: createFakeAlcAuth({ override: () => new Response("", { status: 503 }) }).fetcher };
    expect(await issueTicket(down, auth, PURPOSE, SHA)).toBeNull();
    expect(await verifyTicket(down, r!.ticket, PURPOSE)).toBeNull();
  });
});
