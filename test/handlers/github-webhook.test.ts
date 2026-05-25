import { describe, expect, test, vi } from "vitest";
import { handleGithubWebhook } from "../../src/handlers/github-webhook";
import type { Env } from "../../src/index";

/** GitHub webhook の HMAC-SHA256 を再現する。本実装と同じアルゴリズムで sign。
 *  body は `BufferSource` を受けて WebCrypto に通す (Uint8Array / ArrayBuffer 両対応)。 */
async function sign(secret: string, body: BufferSource): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, body);
  let hex = "";
  const bytes = new Uint8Array(sig);
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] ?? 0).toString(16).padStart(2, "0");
  }
  return `sha256=${hex}`;
}

function mockMcpSessionDO(stubFetch: (req: Request) => Promise<Response>): {
  ns: DurableObjectNamespace;
  idFromNameCalls: string[];
  fetchCalls: Request[];
} {
  const idFromNameCalls: string[] = [];
  const fetchCalls: Request[] = [];
  const stub = {
    fetch: async (req: Request) => {
      fetchCalls.push(req);
      return stubFetch(req);
    },
  } as unknown as DurableObjectStub;
  const ns = {
    idFromName: (name: string) => {
      idFromNameCalls.push(name);
      return { name } as unknown as DurableObjectId;
    },
    get: () => stub,
  } as unknown as DurableObjectNamespace;
  return { ns, idFromNameCalls, fetchCalls };
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  const { ns } = mockMcpSessionDO(
    async () =>
      new Response(JSON.stringify({ delivered: 0, dead: 0, total: 0 }), {
        status: 200,
      }),
  );
  return {
    GOOGLE_CLIENT_ID: "",
    GOOGLE_CLIENT_SECRET: "",
    OAUTH_STATE_SECRET: "",
    AUTH_WORKER_ORIGIN: "",
    ALC_API_ORIGIN: "",
    VERSION: "test",
    WORKER_ENV: "test",
    JWT_SECRET: "test-secret",
    SSO_ENCRYPTION_KEY: "test-key",
    LINEWORKS_WEBHOOK_DO: {} as unknown as DurableObjectNamespace,
    AUTH_CONFIG: {} as unknown as KVNamespace,
    GITHUB_WEBHOOK_SECRET: "shhh",
    MCP_SESSION_DO: ns,
    ...overrides,
  } as Env;
}

const ISSUE_PAYLOAD = {
  action: "created",
  issue: { number: 42, title: "test issue", state: "open" },
  repository: { name: "cc-relay", owner: { login: "ippoan" } },
  comment: {
    id: 1,
    user: { login: "yhonda-ohishi" },
    body: "hello",
    html_url: "https://github.com/ippoan/cc-relay/issues/42#issuecomment-1",
  },
};

describe("handleGithubWebhook", () => {
  test("returns 405 for non-POST", async () => {
    const env = makeEnv();
    const req = new Request("https://mcp.test/webhooks/github", { method: "GET" });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(405);
  });

  test("returns 503 when GITHUB_WEBHOOK_SECRET not set", async () => {
    const env = makeEnv({ GITHUB_WEBHOOK_SECRET: undefined });
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body: "{}",
      headers: { "X-Hub-Signature-256": "sha256=00", "X-GitHub-Event": "issues" },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(503);
  });

  test("returns 401 when signature missing", async () => {
    const env = makeEnv();
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body: "{}",
      headers: { "X-GitHub-Event": "issues" },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(401);
  });

  test("returns 400 when X-GitHub-Event missing", async () => {
    const env = makeEnv();
    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign(env.GITHUB_WEBHOOK_SECRET as string, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: { "X-Hub-Signature-256": sig },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(400);
  });

  test("returns 401 when signature mismatches", async () => {
    const env = makeEnv();
    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign("wrong-secret", new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issue_comment",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(401);
  });

  test("ignores unsupported event types with 200", async () => {
    const env = makeEnv();
    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign(env.GITHUB_WEBHOOK_SECRET as string, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "push",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(200);
    const json = (await resp.json()) as { ignored?: boolean };
    expect(json.ignored).toBe(true);
  });

  test("routes valid issue_comment to IssueRoomDO and returns 200", async () => {
    const fetchSpy = vi.fn(
      async (_req: Request) =>
        new Response(JSON.stringify({ delivered: 1, dead: 0, total: 1 }), {
          status: 200,
        }),
    );
    const { ns, idFromNameCalls, fetchCalls } = mockMcpSessionDO(fetchSpy);
    const env = makeEnv({ MCP_SESSION_DO: ns });

    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign(env.GITHUB_WEBHOOK_SECRET as string, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issue_comment",
        "X-GitHub-Delivery": "test-delivery-uuid",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(200);

    // multiplex: routing key = repository.owner.login
    expect(idFromNameCalls).toEqual(["ippoan"]);
    expect(fetchCalls).toHaveLength(1);

    const forwarded = fetchCalls[0] as Request;
    expect(new URL(forwarded.url).pathname).toBe("/__push_event");

    const forwardedJson = (await forwarded.json()) as {
      event_type?: string;
      delivery_id?: string;
      owner?: string;
      repo?: string;
      issue_number?: number;
    };
    expect(forwardedJson.event_type).toBe("issue_comment.created");
    expect(forwardedJson.delivery_id).toBe("test-delivery-uuid");
    expect(forwardedJson.owner).toBe("ippoan");
    expect(forwardedJson.repo).toBe("cc-relay");
    expect(forwardedJson.issue_number).toBe(42);
  });

  test("ADR-006: routes org-owned repo to mapped github_login via AUTH_CONFIG KV", async () => {
    const fetchSpy = vi.fn(
      async (_req: Request) =>
        new Response(JSON.stringify({ delivered: 0, dead: 0, total: 0, queued: true, queue_size: 1 }), {
          status: 200,
        }),
    );
    const { ns, idFromNameCalls } = mockMcpSessionDO(fetchSpy);
    const kvGets: string[] = [];
    const authConfig = {
      get: async (key: string) => {
        kvGets.push(key);
        return key === "gh_org:ippoan" ? "yhonda-ohishi" : null;
      },
    } as unknown as KVNamespace;
    const env = makeEnv({ MCP_SESSION_DO: ns, AUTH_CONFIG: authConfig });

    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign(env.GITHUB_WEBHOOK_SECRET as string, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issue_comment",
        "X-GitHub-Delivery": "org-map-delivery",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(200);

    expect(kvGets).toEqual(["gh_org:ippoan"]);
    // doKey は org login ではなく mapped github_login であること
    expect(idFromNameCalls).toEqual(["yhonda-ohishi"]);
  });

  test("ADR-006: ignores malformed mapping value and falls back to owner", async () => {
    const { ns, idFromNameCalls } = mockMcpSessionDO(
      async () =>
        new Response(JSON.stringify({ delivered: 0, dead: 0, total: 0 }), { status: 200 }),
    );
    const authConfig = {
      get: async () => "not a valid github login!!", // 不正な login pattern
    } as unknown as KVNamespace;
    const env = makeEnv({ MCP_SESSION_DO: ns, AUTH_CONFIG: authConfig });

    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign(env.GITHUB_WEBHOOK_SECRET as string, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issue_comment",
        "X-GitHub-Delivery": "bad-map-delivery",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(200);
    // 不正値は無視して owner へ fallback
    expect(idFromNameCalls).toEqual(["ippoan"]);
  });

  test("ADR-006: tolerates KV throwing (binding cast as {}) and falls back to owner", async () => {
    const { ns, idFromNameCalls } = mockMcpSessionDO(
      async () =>
        new Response(JSON.stringify({ delivered: 0, dead: 0, total: 0 }), { status: 200 }),
    );
    // AUTH_CONFIG が `{}` cast の既存テストパターン: `.get` が throw する。
    const env = makeEnv({ MCP_SESSION_DO: ns });

    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign(env.GITHUB_WEBHOOK_SECRET as string, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issue_comment",
        "X-GitHub-Delivery": "kv-throw-delivery",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(200);
    expect(idFromNameCalls).toEqual(["ippoan"]);
  });

  test("Refs #206: accepts SecretsStoreSecret binding (calls .get()) and verifies signature", async () => {
    // PR #205 で GITHUB_WEBHOOK_SECRET を Secrets Store binding に移行した際の
    // 退行を再現するテスト。binding を `{ get(): Promise<string> }` shape で渡し、
    // 内部で `.get()` が呼ばれて plain string と同じ HMAC が計算されることを確認する。
    const secretValue = "secrets-store-value";
    const binding = {
      get: async () => secretValue,
    } as unknown as SecretsStoreSecret;
    const env = makeEnv({ GITHUB_WEBHOOK_SECRET: binding });
    const body = JSON.stringify(ISSUE_PAYLOAD);
    const sig = await sign(secretValue, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issue_comment",
        "X-GitHub-Delivery": "secrets-store-delivery",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    // `.get()` が呼ばれず binding object 自体を toString する旧バグでは
    // HMAC 比較が外れて 401 になる。`.get()` 経由で string 化されていれば 200。
    expect(resp.status).toBe(200);
  });

  test("returns 200 ignored when payload lacks owner/repo/issue", async () => {
    const env = makeEnv();
    const body = JSON.stringify({ action: "edited" });
    const sig = await sign(env.GITHUB_WEBHOOK_SECRET as string, new TextEncoder().encode(body));
    const req = new Request("https://mcp.test/webhooks/github", {
      method: "POST",
      body,
      headers: {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "issues",
      },
    });
    const resp = await handleGithubWebhook(req, env);
    expect(resp.status).toBe(200);
    const json = (await resp.json()) as { ignored?: boolean };
    expect(json.ignored).toBe(true);
  });
});
