import { describe, it, expect, vi, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import {
  _clearGithubJwksCache,
  GITHUB_OIDC_ISSUER,
  GITHUB_OIDC_JWKS_URL,
  GithubOidcError,
  verifyGithubOidcToken,
} from "../../src/lib/github-oidc";

// Refs ippoan/ci-dashboard#520: 発行口のテスト (test/handlers/ci-staging-token.test.ts) で通らない
// JWKS の取得失敗・cache の期限・claim の形の分岐をここで固定する。鍵は生成し、fetch は差し替える。
const AUD = "auth-worker-staging-ci";
const OPTS = { audience: AUD, allowedRepositories: ["ippoan/alc-app"], repositoryOwner: "ippoan" };
const KID = "k1";

let keyPair: CryptoKeyPair;
let jwk: JsonWebKey;
const originalFetch = globalThis.fetch;

beforeAll(async () => {
  keyPair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
});
afterAll(() => {
  globalThis.fetch = originalFetch;
});
beforeEach(() => _clearGithubJwksCache());
afterEach(() => vi.useRealTimers());

const b64url = (data: string | Uint8Array) =>
  Buffer.from(typeof data === "string" ? new TextEncoder().encode(data) : data).toString("base64url");

async function sign(payloadPart: string, kid = KID): Promise<string> {
  const unsigned = `${b64url(JSON.stringify({ alg: "RS256", kid }))}.${payloadPart}`;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keyPair.privateKey, new TextEncoder().encode(unsigned));
  return `${unsigned}.${b64url(new Uint8Array(sig))}`;
}

function claims(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: GITHUB_OIDC_ISSUER,
    aud: AUD,
    repository: "ippoan/alc-app",
    repository_owner: "ippoan",
    iat: now,
    exp: now + 300,
    ...overrides,
  };
}

const token = (overrides: Record<string, unknown> = {}, kid = KID) =>
  sign(b64url(JSON.stringify(claims(overrides))), kid);

function mockFetch(impl: () => Promise<Response>) {
  const fn = vi.fn(async (input: RequestInfo | URL) => {
    expect(String(input)).toBe(GITHUB_OIDC_JWKS_URL);
    return impl();
  });
  globalThis.fetch = fn as unknown as typeof fetch;
  return fn;
}
const okJwks = (keys: unknown[] = [{ ...jwk, kid: KID }]) =>
  mockFetch(async () => new Response(JSON.stringify({ keys })));

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(GithubOidcError);
    return (e as GithubOidcError).reason;
  }
  throw new Error("expected rejection");
}

describe("verifyGithubOidcToken", () => {
  it("aud が配列でも含まれていれば通り、run_id / ref が無ければ undefined", async () => {
    okJwks();
    const c = await verifyGithubOidcToken(await token({ aud: ["x", AUD] }), OPTS);
    expect(c).toMatchObject({ repository: "ippoan/alc-app", run_id: undefined, ref: undefined });
  });

  it("JWKS の取得が throw → jwks_fetch", async () => {
    mockFetch(async () => {
      throw new Error("network");
    });
    expect(await reason(verifyGithubOidcToken(await token(), OPTS))).toBe("jwks_fetch");
  });

  it("JWKS が JSON でない / keys が配列でない → jwks_fetch", async () => {
    mockFetch(async () => new Response("not json"));
    expect(await reason(verifyGithubOidcToken(await token(), OPTS))).toBe("jwks_fetch");
    mockFetch(async () => new Response(JSON.stringify({ keys: "x" })));
    expect(await reason(verifyGithubOidcToken(await token(), OPTS))).toBe("jwks_fetch");
  });

  it("RSA でない鍵・欠けた鍵は JWKS から捨てる", async () => {
    okJwks([{ kty: "EC", kid: KID }, { kty: "RSA", kid: KID }, null]);
    expect(await reason(verifyGithubOidcToken(await token(), OPTS))).toBe("unknown_kid");
  });

  it("知らない kid: 取得から 5 分以内は取り直さず、過ぎたら 1 回取り直す (鍵の入れ替え)", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const fetchMock = okJwks();
    await verifyGithubOidcToken(await token(), OPTS);
    expect(await reason(verifyGithubOidcToken(await token({}, "k2"), OPTS))).toBe("unknown_kid");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    vi.setSystemTime(Date.now() + 6 * 60 * 1000);
    const fetchMock2 = okJwks([{ ...jwk, kid: "k2" }]);
    await verifyGithubOidcToken(await token({}, "k2"), OPTS);
    expect(fetchMock2).toHaveBeenCalledTimes(1);
  });

  it("cache は 1 時間で切れて取り直す", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    okJwks();
    await verifyGithubOidcToken(await token(), OPTS);
    vi.setSystemTime(Date.now() + 61 * 60 * 1000);
    const fetchMock = okJwks();
    await verifyGithubOidcToken(await token(), OPTS);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("JWKS の鍵が壊れている → signature", async () => {
    okJwks([{ kty: "RSA", kid: KID, n: "!!", e: "AQAB" }]);
    expect(await reason(verifyGithubOidcToken(await token(), OPTS))).toBe("signature");
  });

  it("署名は正しいが payload が JSON でない / object でない → payload", async () => {
    okJwks();
    expect(await reason(verifyGithubOidcToken(await sign(b64url("not json")), OPTS))).toBe("payload");
    expect(await reason(verifyGithubOidcToken(await sign(b64url("[1]")), OPTS))).toBe("payload");
  });

  it("header が JSON でない → shape、空の部分がある → shape", async () => {
    expect(await reason(verifyGithubOidcToken(`${b64url("x")}.${b64url("{}")}.sig`, OPTS))).toBe("shape");
    expect(await reason(verifyGithubOidcToken(`a..c`, OPTS))).toBe("shape");
  });

  it("exp / iat が数でない、nbf が数でない → それぞれの理由", async () => {
    okJwks();
    expect(await reason(verifyGithubOidcToken(await token({ exp: "x" }), OPTS))).toBe("exp");
    expect(await reason(verifyGithubOidcToken(await token({ nbf: "x" }), OPTS))).toBe("nbf");
    expect(await reason(verifyGithubOidcToken(await token({ iat: undefined }), OPTS))).toBe("iat");
  });

  it("時計ずれ 60 秒以内の期限切れは通す", async () => {
    okJwks();
    const now = Math.floor(Date.now() / 1000);
    await expect(verifyGithubOidcToken(await token({ exp: now - 30 }), OPTS)).resolves.toBeTruthy();
  });

  it("audience の設定が空なら通さない", async () => {
    okJwks();
    expect(await reason(verifyGithubOidcToken(await token({ aud: "" }), { ...OPTS, audience: "" }))).toBe("aud");
  });

  it("repository / repository_owner が文字列でない", async () => {
    okJwks();
    expect(await reason(verifyGithubOidcToken(await token({ repository_owner: 1 }), OPTS))).toBe(
      "repository_owner",
    );
    expect(await reason(verifyGithubOidcToken(await token({ repository: 1 }), OPTS))).toBe("repository");
  });
});
