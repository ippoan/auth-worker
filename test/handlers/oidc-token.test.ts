import { describe, it, expect } from "vitest";
import { handleOidcToken } from "../../src/handlers/oidc-token";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import { putOidcCode, type OidcCodeRecord } from "../../src/lib/oidc-authcode";
import { toPublicJwk, type OidcJwk } from "../../src/lib/oidc-signing-key";
import type { Env } from "../../src/index";

const REDIRECT_URI = "https://team.cloudflareaccess.com/cdn-cgi/access/callback";
const CLIENTS = JSON.stringify([
  { client_id: "cf-access", client_secret: "s3cret", redirect_uris: [REDIRECT_URI] },
  { client_id: "other", client_secret: "other-secret", redirect_uris: ["https://b.example/cb"] },
]);

async function generateJwk(): Promise<OidcJwk> {
  const { privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  return { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y!, d: jwk.d! };
}

const BASE_RECORD: OidcCodeRecord = {
  client_id: "cf-access",
  redirect_uri: REDIRECT_URI,
  scope: "openid email",
  claims: {
    sub: "u1",
    email: "taro@ippoan.org",
    name: "大石 太郎",
    tenant_id: "t1",
    role: "admin",
    org_slug: "ippoan",
  },
};

async function setup(
  record: Partial<OidcCodeRecord> = {},
  envOverrides: Partial<Env> = {},
): Promise<{ env: Env; kv: KVNamespace; jwk: OidcJwk }> {
  const kv = createMockKV();
  const jwk = await generateJwk();
  await putOidcCode(kv, "code-1", { ...BASE_RECORD, ...record });
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    ACCESS_OIDC_CLIENTS: CLIENTS,
    ACCESS_OIDC_SIGNING_KEY: JSON.stringify([jwk]),
    ...envOverrides,
  });
  return { env, kv, jwk };
}

function tokenRequest(
  form: Record<string, string>,
  headers: Record<string, string> = {},
): Request {
  return new Request("https://auth.test.example/oidc/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(form).toString(),
  });
}

const VALID_FORM = {
  grant_type: "authorization_code",
  code: "code-1",
  redirect_uri: REDIRECT_URI,
  client_id: "cf-access",
  client_secret: "s3cret",
};

function decodeSegment(seg: string): Record<string, unknown> {
  const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

/** id_token を JWKS の公開鍵で実際に検証する (Access がやることと同じ)。 */
async function verifyIdToken(idToken: string, jwk: OidcJwk): Promise<boolean> {
  const [h, p, sig] = idToken.split(".");
  const pub = await toPublicJwk(jwk);
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const b64 = sig!.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)),
    new TextEncoder().encode(`${h}.${p}`),
  );
}

describe("POST /oidc/token — happy path", () => {
  it("returns an id_token that verifies against the published public key", async () => {
    const { env, jwk } = await setup();
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { id_token: string };
    expect(await verifyIdToken(body.id_token, jwk)).toBe(true);
  });

  it("carries the session identity into the id_token claims", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    const body = (await res.json()) as { id_token: string };
    const claims = decodeSegment(body.id_token.split(".")[1]!);
    expect(claims.iss).toBe("https://auth.test.example/oidc");
    expect(claims.aud).toBe("cf-access");
    expect(claims.sub).toBe("u1");
    expect(claims.email).toBe("taro@ippoan.org");
    expect(claims.email_verified).toBe(true);
    // 多バイトの name が化けずに届くこと (verifyJwt の decoder は UTF-8 非対応)。
    expect(claims.name).toBe("大石 太郎");
    expect(claims.tenant_id).toBe("t1");
    expect(claims.role).toBe("admin");
    expect(claims.org_slug).toBe("ippoan");
  });

  it("sets a short exp and a matching iat", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    const { id_token } = (await res.json()) as { id_token: string };
    const claims = decodeSegment(id_token.split(".")[1]!) as { iat: number; exp: number };
    expect(claims.exp - claims.iat).toBe(300);
    expect(claims.iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
  });

  it("echoes nonce into the id_token when the authorize request carried one", async () => {
    const { env } = await setup({ nonce: "n-42" });
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    const { id_token } = (await res.json()) as { id_token: string };
    expect(decodeSegment(id_token.split(".")[1]!).nonce).toBe("n-42");
  });

  it("omits nonce when the authorize request had none", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    const { id_token } = (await res.json()) as { id_token: string };
    expect("nonce" in decodeSegment(id_token.split(".")[1]!)).toBe(false);
  });

  it("omits optional claims the identity does not carry", async () => {
    const { env } = await setup({ claims: { sub: "u2", email: "b@x" } });
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    const { id_token } = (await res.json()) as { id_token: string };
    const claims = decodeSegment(id_token.split(".")[1]!);
    expect("name" in claims).toBe(false);
    expect("tenant_id" in claims).toBe(false);
    expect("role" in claims).toBe(false);
    expect("org_slug" in claims).toBe(false);
  });

  it("signs with the first key in the rotation list", async () => {
    const active = await generateJwk();
    const retired = await generateJwk();
    const kv = createMockKV();
    await putOidcCode(kv, "code-1", BASE_RECORD);
    const env = createMockEnv({
      MCP_OAUTH_KV: kv,
      ACCESS_OIDC_CLIENTS: CLIENTS,
      ACCESS_OIDC_SIGNING_KEY: JSON.stringify([active, retired]),
    });
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    const { id_token } = (await res.json()) as { id_token: string };
    expect(decodeSegment(id_token.split(".")[0]!).kid).toBe((await toPublicJwk(active)).kid);
    expect(await verifyIdToken(id_token, active)).toBe(true);
  });

  it("returns a bearer access_token usable at userinfo, plus the granted scope", async () => {
    const { env, kv } = await setup();
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    const body = (await res.json()) as {
      access_token: string;
      token_type: string;
      expires_in: number;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(300);
    expect(body.scope).toBe("openid email");
    expect((kv as unknown as MockKV)._data[`oidc:at:${body.access_token}`]).toBeTruthy();
  });

  it("accepts client_secret_basic as well as client_secret_post", async () => {
    const { env } = await setup();
    const { client_id, client_secret, ...rest } = VALID_FORM;
    const res = await handleOidcToken(
      tokenRequest(rest, {
        Authorization: `Basic ${btoa(`${client_id}:${client_secret}`)}`,
      }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("form-decodes Basic credentials (RFC 6749 §2.3.1)", async () => {
    const kv = createMockKV();
    const jwk = await generateJwk();
    await putOidcCode(kv, "code-1", { ...BASE_RECORD, client_id: "sp ace" });
    const env = createMockEnv({
      MCP_OAUTH_KV: kv,
      ACCESS_OIDC_CLIENTS: JSON.stringify([
        { client_id: "sp ace", client_secret: "p@ss", redirect_uris: [REDIRECT_URI] },
      ]),
      ACCESS_OIDC_SIGNING_KEY: JSON.stringify([jwk]),
    });
    const res = await handleOidcToken(
      tokenRequest(
        { grant_type: "authorization_code", code: "code-1", redirect_uri: REDIRECT_URI },
        { Authorization: `Basic ${btoa("sp%20ace:p%40ss")}` },
      ),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("verifies PKCE when the authorize request used it", async () => {
    // S256(verifier) を実際に計算して challenge にする。
    const verifier = "a".repeat(43);
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier),
    );
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const { env } = await setup({ code_challenge: challenge });
    const res = await handleOidcToken(
      tokenRequest({ ...VALID_FORM, code_verifier: verifier }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("POST /oidc/token — rejections", () => {
  it("rejects a wrong client_secret with 401", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(
      tokenRequest({ ...VALID_FORM, client_secret: "wrong" }),
      env,
    );
    expect(res.status).toBe(401);
    expect((await res.json() as { error: string }).error).toBe("invalid_client");
  });

  it("gives an unknown client the same response as a bad secret (no client_id oracle)", async () => {
    const { env } = await setup();
    const unknown = await handleOidcToken(
      tokenRequest({ ...VALID_FORM, client_id: "ghost", client_secret: "x" }),
      env,
    );
    const badSecret = await handleOidcToken(
      tokenRequest({ ...VALID_FORM, client_secret: "wrong" }),
      env,
    );
    expect(unknown.status).toBe(badSecret.status);
    expect(await unknown.json()).toEqual(await badSecret.json());
  });

  it("falls back to body credentials when the Basic header is malformed", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(
      tokenRequest(VALID_FORM, { Authorization: "Basic !!!not-base64!!!" }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("treats a Basic header with no colon as absent credentials", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(
      tokenRequest(VALID_FORM, { Authorization: `Basic ${btoa("nocolon")}` }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("rejects a request carrying no credentials at all", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(
      tokenRequest({
        grant_type: "authorization_code",
        code: "code-1",
        redirect_uri: REDIRECT_URI,
      }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("rejects a request whose body cannot be read", async () => {
    const { env } = await setup();
    const body = new ReadableStream({
      start(controller) {
        controller.error(new Error("stream broke"));
      },
    });
    const res = await handleOidcToken(
      new Request("https://auth.test.example/oidc/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
        // @ts-expect-error — undici はストリーム body に duplex を要求する
        duplex: "half",
      }),
      env,
    );
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe("invalid_request");
  });

  it("rejects a missing redirect_uri (it must match the authorization request)", async () => {
    const { env } = await setup();
    const { redirect_uri, ...rest } = VALID_FORM;
    const res = await handleOidcToken(tokenRequest(rest), env);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects an unsupported grant_type", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(
      tokenRequest({ ...VALID_FORM, grant_type: "refresh_token" }),
      env,
    );
    expect((await res.json() as { error: string }).error).toBe("unsupported_grant_type");
  });

  it("rejects a missing code", async () => {
    const { env } = await setup();
    const { code, ...rest } = VALID_FORM;
    const res = await handleOidcToken(tokenRequest(rest), env);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects an unknown code", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(tokenRequest({ ...VALID_FORM, code: "nope" }), env);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects a replayed code — codes are single-use", async () => {
    const { env } = await setup();
    expect((await handleOidcToken(tokenRequest(VALID_FORM), env)).status).toBe(200);
    const replay = await handleOidcToken(tokenRequest(VALID_FORM), env);
    expect(replay.status).toBe(400);
    expect((await replay.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("refuses to hand a code to the client it was not issued to", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(
      tokenRequest({
        ...VALID_FORM,
        client_id: "other",
        client_secret: "other-secret",
        redirect_uri: "https://b.example/cb",
      }),
      env,
    );
    expect((await res.json() as { error_description: string }).error_description).toContain(
      "different client",
    );
  });

  it("rejects a redirect_uri that differs from the authorization request", async () => {
    const { env } = await setup();
    const res = await handleOidcToken(
      tokenRequest({ ...VALID_FORM, redirect_uri: "https://evil.example/cb" }),
      env,
    );
    expect((await res.json() as { error_description: string }).error_description).toContain(
      "redirect_uri",
    );
  });

  it("rejects a wrong PKCE verifier", async () => {
    const { env } = await setup({ code_challenge: "some-challenge" });
    const res = await handleOidcToken(
      tokenRequest({ ...VALID_FORM, code_verifier: "wrong" }),
      env,
    );
    expect((await res.json() as { error_description: string }).error_description).toContain("PKCE");
  });

  it("rejects a missing PKCE verifier when the code was bound to a challenge", async () => {
    const { env } = await setup({ code_challenge: "some-challenge" });
    const res = await handleOidcToken(tokenRequest(VALID_FORM), env);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("returns 503 when KV is not bound", async () => {
    const { env } = await setup({}, { MCP_OAUTH_KV: undefined });
    expect((await handleOidcToken(tokenRequest(VALID_FORM), env)).status).toBe(503);
  });

  it("returns 503 when the client registry is not configured", async () => {
    const { env } = await setup({}, { ACCESS_OIDC_CLIENTS: undefined });
    expect((await handleOidcToken(tokenRequest(VALID_FORM), env)).status).toBe(503);
  });

  it("returns 503 when the signing key is not configured", async () => {
    const { env } = await setup({}, { ACCESS_OIDC_SIGNING_KEY: undefined });
    expect((await handleOidcToken(tokenRequest(VALID_FORM), env)).status).toBe(503);
  });
});
