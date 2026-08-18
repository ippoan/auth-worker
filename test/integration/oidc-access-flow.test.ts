/**
 * Cloudflare Access が実際に踏む経路を端から端まで通す。
 *
 *   既存 logi_auth_token あり
 *     → GET /oidc/authorize   (IdP に飛ばず code が出る = 追加ログインゼロ)
 *     → POST /oidc/token      (client_secret 認証 → id_token)
 *     → JWKS の公開鍵で id_token を検証   (Access がやることと同じ)
 *     → GET /oidc/userinfo    (access_token で identity)
 *
 * 個々の handler の分岐は各 unit test 側で見る。ここは「4 つが噛み合っていること」
 * だけを見る。
 */
import { describe, it, expect } from "vitest";
import { handleOidcAuthorize } from "../../src/handlers/oidc-authorize";
import { handleOidcToken } from "../../src/handlers/oidc-token";
import { handleOidcUserinfo } from "../../src/handlers/oidc-userinfo";
import { handleOidcJwks } from "../../src/handlers/oidc-jwks";
import { signJwt } from "../../src/lib/jwt";
import { createMockEnv, createMockKV, TEST_JWT_SECRET } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const REDIRECT_URI = "https://team.cloudflareaccess.com/cdn-cgi/access/callback";

async function generatePrivateJwk(): Promise<Record<string, string>> {
  const { privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  return { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y!, d: jwk.d! };
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function decodeSegment(seg: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(seg))) as Record<string, unknown>;
}

/** JWKS から kid で鍵を選んで id_token を検証する — Access の検証手順そのもの。 */
async function verifyWithJwks(
  idToken: string,
  jwks: { keys: Array<Record<string, string>> },
): Promise<boolean> {
  const [h, p, sig] = idToken.split(".");
  const kid = decodeSegment(h!).kid as string;
  const jwk = jwks.keys.find((k) => k.kid === kid);
  if (!jwk) return false;
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    b64urlToBytes(sig!),
    new TextEncoder().encode(`${h}.${p}`),
  );
}

async function makeEnv(signingKeys: Array<Record<string, string>>): Promise<Env> {
  return createMockEnv({
    MCP_OAUTH_KV: createMockKV(),
    ACCESS_OIDC_SIGNING_KEY: JSON.stringify(signingKeys),
    ACCESS_OIDC_CLIENTS: JSON.stringify([
      { client_id: "cf-access", client_secret: "s3cret", redirect_uris: [REDIRECT_URI] },
    ]),
  });
}

async function sessionCookie(): Promise<string> {
  return signJwt(
    {
      exp: Math.floor(Date.now() / 1000) + 3600,
      sub: "user-1",
      email: "taro@ippoan.org",
      name: "大石 太郎",
      tenant_id: "tenant-1",
      role: "admin",
      env: "prod",
    },
    TEST_JWT_SECRET,
  );
}

describe("Cloudflare Access ↔ auth-worker OIDC flow", () => {
  it("takes an existing session all the way to a JWKS-verifiable id_token", async () => {
    const jwk = await generatePrivateJwk();
    const env = await makeEnv([jwk]);
    const cookie = await sessionCookie();

    // 1. authorize — 既存セッションがあるので IdP に飛ばず、その場で code が出る。
    const authorizeUrl =
      "https://auth.test.example/oidc/authorize" +
      `?response_type=code&client_id=cf-access&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
      "&state=st-1&scope=openid%20email&nonce=n-1";
    const authRes = await handleOidcAuthorize(
      new Request(authorizeUrl, { headers: { Cookie: `logi_auth_token=${cookie}` } }),
      env,
    );
    expect(authRes.status).toBe(302);
    const back = new URL(authRes.headers.get("Location")!);
    expect(back.origin + back.pathname).toBe(REDIRECT_URI);
    expect(back.searchParams.get("state")).toBe("st-1");
    const code = back.searchParams.get("code")!;
    expect(code).toBeTruthy();

    // 2. token — client_secret で認証して id_token を受け取る。
    const tokenRes = await handleOidcToken(
      new Request("https://auth.test.example/oidc/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          client_id: "cf-access",
          client_secret: "s3cret",
        }).toString(),
      }),
      env,
    );
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { id_token: string; access_token: string };

    // 3. Access と同じ手順で検証 — JWKS を引き、kid で鍵を選び、署名を検証する。
    const jwks = (await (
      await handleOidcJwks(new Request("https://auth.test.example/oidc/.well-known/jwks.json"), env)
    ).json()) as { keys: Array<Record<string, string>> };
    expect(await verifyWithJwks(tokens.id_token, jwks)).toBe(true);

    const claims = decodeSegment(tokens.id_token.split(".")[1]!);
    expect(claims.iss).toBe("https://auth.test.example/oidc");
    expect(claims.aud).toBe("cf-access");
    expect(claims.email).toBe("taro@ippoan.org");
    expect(claims.name).toBe("大石 太郎");
    expect(claims.nonce).toBe("n-1");
    // Access のポリシーで組織 / 権限を絞れるようにする custom claim。
    expect(claims.tenant_id).toBe("tenant-1");
    expect(claims.role).toBe("admin");

    // 4. userinfo — 同じ identity が引ける。
    const uiRes = await handleOidcUserinfo(
      new Request("https://auth.test.example/oidc/userinfo", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      }),
      env,
    );
    expect(uiRes.status).toBe(200);
    expect((await uiRes.json() as { email: string }).email).toBe("taro@ippoan.org");
  });

  it("survives a key rotation — a token signed by the new key verifies via JWKS", async () => {
    const fresh = await generatePrivateJwk();
    const retired = await generatePrivateJwk();
    // ローテーション中の状態: 新鍵が先頭、旧鍵も JWKS に残っている。
    const env = await makeEnv([fresh, retired]);
    const cookie = await sessionCookie();

    const authRes = await handleOidcAuthorize(
      new Request(
        "https://auth.test.example/oidc/authorize?response_type=code&client_id=cf-access" +
          `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=s`,
        { headers: { Cookie: `logi_auth_token=${cookie}` } },
      ),
      env,
    );
    const code = new URL(authRes.headers.get("Location")!).searchParams.get("code")!;

    const tokenRes = await handleOidcToken(
      new Request("https://auth.test.example/oidc/token", {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          client_id: "cf-access",
          client_secret: "s3cret",
        }).toString(),
      }),
      env,
    );
    const { id_token } = (await tokenRes.json()) as { id_token: string };

    const jwks = (await (
      await handleOidcJwks(new Request("https://auth.test.example/oidc/.well-known/jwks.json"), env)
    ).json()) as { keys: Array<Record<string, string>> };
    expect(jwks.keys).toHaveLength(2); // 旧鍵も残っているので検証の窓が開かない
    expect(await verifyWithJwks(id_token, jwks)).toBe(true);
  });

  it("sends a user with no session to /login and back to the same authorize request", async () => {
    const env = await makeEnv([await generatePrivateJwk()]);
    const authorizeUrl =
      "https://auth.test.example/oidc/authorize?response_type=code&client_id=cf-access" +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=st-1`;
    const res = await handleOidcAuthorize(new Request(authorizeUrl), env);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.pathname).toBe("/login");
    // login 後に戻ってくる先が、いま来た authorize リクエストそのものであること。
    expect(loc.searchParams.get("redirect_uri")).toBe(authorizeUrl);
  });
});
