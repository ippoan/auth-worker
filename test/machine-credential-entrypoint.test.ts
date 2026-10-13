import { describe, it, expect, vi, afterEach } from "vitest";
import { createMockEnv } from "./helpers/mock-env";
import { FAKE_ALC_AUTH_SECRET, createFakeAlcAuth } from "./helpers/fake-alc-auth";
import type { Env } from "../src/index";
import { MachineCredentialEntrypoint } from "../src/machine-credential-entrypoint";
import { createMachineCredential, revokeMachineCredential } from "../src/lib/machine-credential";

/** テスト固有のダミー UUID (本番の値ではない)。 */
const TENANT = "77777777-7777-7777-7777-777777777777";
const PURPOSE = "leave-scan";
const SHA = "c".repeat(64);

function env(overrides: Partial<Env> = {}): Env {
  return createMockEnv({
    ALC_AUTH: createFakeAlcAuth().fetcher,
    INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
    MACHINE_CRED_ENV: "staging",
    ...overrides,
  });
}

/** `[[services]] entrypoint = "MachineCredentialEntrypoint"` 越しの呼び出しを再現する。 */
function rpc(e: Env): MachineCredentialEntrypoint {
  return new MachineCredentialEntrypoint({} as unknown as ExecutionContext, e);
}

async function setup(e: Env = env()) {
  const c = await createMachineCredential(e, TENANT, PURPOSE, "複合機");
  return { e, c: c!, auth: `Basic ${btoa(`${c!.username}:${c!.password}`)}` };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("MachineCredentialEntrypoint (ohishi-exp/rust-leave-worker#1)", () => {
  it("RPC で呼べるメソッドは issueTicket / verifyTicket の 2 つだけ", () => {
    const own = Object.getOwnPropertyNames(MachineCredentialEntrypoint.prototype).filter(
      (n) => n !== "constructor",
    );
    expect(own.sort()).toEqual(["issueTicket", "verifyTicket"]);
  });

  it("issueTicket → verifyTicket が往復する (戻り値は素のオブジェクト)", async () => {
    const { e, c, auth } = await setup();
    const issued = await rpc(e).issueTicket(auth, PURPOSE, SHA);
    expect(issued).toEqual({ ticket: expect.any(String), tenantId: TENANT, username: c.username });
    expect(Object.getPrototypeOf(issued)).toBe(Object.prototype);
    const verified = await rpc(e).verifyTicket(issued!.ticket, PURPOSE);
    expect(verified).toEqual({ tenantId: TENANT, username: c.username, sha256: SHA });
    expect(Object.getPrototypeOf(verified)).toBe(Object.prototype);
  });

  it("★ 失敗の理由は区別せず null (password 違い / 不在 / sha256 不正 / 用途違い)", async () => {
    const { e, c, auth } = await setup();
    const results = await Promise.all([
      rpc(e).issueTicket(`Basic ${btoa(`${c.username}:wrong`)}`, PURPOSE, SHA),
      rpc(e).issueTicket(`Basic ${btoa("mc_aaaaaaaaaaaaaaaa:x")}`, PURPOSE, SHA),
      rpc(e).issueTicket(auth, PURPOSE, "nothex"),
      rpc(e).issueTicket(auth, "other", SHA),
    ]);
    expect(results).toEqual([null, null, null, null]);
  });

  it("★ revoke 後はチケットの検証が null", async () => {
    const { e, c, auth } = await setup();
    const issued = await rpc(e).issueTicket(auth, PURPOSE, SHA);
    await revokeMachineCredential(e, TENANT, c.username);
    expect(await rpc(e).verifyTicket(issued!.ticket, PURPOSE)).toBeNull();
  });

  it("引数が文字列でなければ alc-auth-worker を引かずに null", async () => {
    const e = env();
    const get = vi.spyOn(e.ALC_AUTH!, "fetch");
    const x = rpc(e) as unknown as {
      issueTicket: (...a: unknown[]) => Promise<unknown>;
      verifyTicket: (...a: unknown[]) => Promise<unknown>;
    };
    expect(await x.issueTicket(undefined, PURPOSE, SHA)).toBeNull();
    expect(await x.issueTicket("Basic x", 1, SHA)).toBeNull();
    expect(await x.verifyTicket(null, PURPOSE)).toBeNull();
    expect(await x.verifyTicket("t", {})).toBeNull();
    expect(get).not.toHaveBeenCalled();
  });

  it("★ alc-auth-worker が throw しても throw せず、発行は null・検証は { error: \"unavailable\" } (log は出ない)", async () => {
    const { e, auth } = await setup();
    const issued = await rpc(e).issueTicket(auth, PURPOSE, SHA);
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(e.ALC_AUTH!, "fetch").mockRejectedValue(new TypeError("network"));
    expect(await rpc(e).issueTicket(auth, PURPOSE, SHA)).toBeNull();
    expect(await rpc(e).verifyTicket(issued!.ticket, PURPOSE)).toEqual({ error: "unavailable" });
    expect(errSpy).not.toHaveBeenCalled();
  });

  it("★ alc-auth-worker が 500・壊れた JSON・binding / secret 無しなら verifyTicket は { error: \"unavailable\" }、404・失効は null", async () => {
    const { e, auth } = await setup();
    const issued = await rpc(e).issueTicket(auth, PURPOSE, SHA);
    const unavailable = { error: "unavailable" };
    const via = (f: () => Response) => ({ ...e, ALC_AUTH: createFakeAlcAuth({ override: f }).fetcher }) as Env;
    expect(await rpc(via(() => new Response("", { status: 500 }))).verifyTicket(issued!.ticket, PURPOSE)).toEqual(unavailable);
    expect(await rpc(via(() => new Response("{oops", { status: 200 }))).verifyTicket(issued!.ticket, PURPOSE)).toEqual(unavailable);
    expect(await rpc({ ...e, ALC_AUTH: undefined } as Env).verifyTicket(issued!.ticket, PURPOSE)).toEqual(unavailable);
    expect(await rpc({ ...e, INTERNAL_SHARED_SECRET: undefined } as Env).verifyTicket(issued!.ticket, PURPOSE)).toEqual(unavailable);
    expect(await rpc(via(() => new Response(null, { status: 404 }))).verifyTicket(issued!.ticket, PURPOSE)).toBeNull();
  });

  it("下の層が throw しても throw せず (発行は null・検証は { error: \"unavailable\" })、例外の種類だけ log、資格情報は出さない", async () => {
    const { e, auth } = await setup();
    const issued = await rpc(e).issueTicket(auth, PURPOSE, SHA);
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    // チケットの鍵の派生 (HKDF) は資格情報の層の外なので、ここで throw させて entrypoint の catch を通す。
    vi.spyOn(crypto.subtle, "importKey").mockRejectedValue(new TypeError("crypto down"));
    expect(await rpc(e).issueTicket(auth, PURPOSE, SHA)).toBeNull();
    expect(await rpc(e).verifyTicket(issued!.ticket, PURPOSE)).toEqual({ error: "unavailable" });
    const logged = errSpy.mock.calls.map((a) => String(a[0]));
    expect(logged).toEqual([
      JSON.stringify({ event: "machine_ticket_issue_failed", error: "TypeError" }),
      JSON.stringify({ event: "machine_ticket_verify_failed", error: "TypeError" }),
    ]);
    for (const line of logged) {
      expect(line).not.toContain(auth);
      expect(line).not.toContain(issued!.ticket);
    }
  });

  it("Error でない throw も unknown として log して null", async () => {
    const { e, auth } = await setup();
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(crypto.subtle, "importKey").mockImplementation(() => {
      throw "boom";
    });
    expect(await rpc(e).issueTicket(auth, PURPOSE, SHA)).toBeNull();
    expect(String(errSpy.mock.calls[0]?.[0])).toContain('"error":"unknown"');
  });

  it("MACHINE_CRED_ENV が無い環境では発行も検証も null", async () => {
    const { e, auth } = await setup();
    const issued = await rpc(e).issueTicket(auth, PURPOSE, SHA);
    const unset = { ...e, MACHINE_CRED_ENV: undefined } as Env;
    expect(await rpc(unset).issueTicket(auth, PURPOSE, SHA)).toBeNull();
    expect(await rpc(unset).verifyTicket(issued!.ticket, PURPOSE)).toBeNull();
  });
});
