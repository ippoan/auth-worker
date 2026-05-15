import { describe, expect, test, vi } from "vitest";
import { handleGithubWebhook } from "../../src/handlers/github-webhook";
import type { Env } from "../../src/index";

/** GitHub webhook の HMAC-SHA256 を再現する。本実装と同じアルゴリズムで sign。 */
async function sign(secret: string, body: ArrayBuffer): Promise<string> {
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

function mockIssueRoomDO(stubFetch: (req: Request) => Promise<Response>): {
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
  const { ns } = mockIssueRoomDO(
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
    ISSUE_ROOM_DO: ns,
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
    const { ns, idFromNameCalls, fetchCalls } = mockIssueRoomDO(fetchSpy);
    const env = makeEnv({ ISSUE_ROOM_DO: ns });

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

    expect(idFromNameCalls).toEqual(["issue:ippoan/cc-relay#42"]);
    expect(fetchCalls).toHaveLength(1);

    const forwarded = fetchCalls[0] as Request;
    expect(new URL(forwarded.url).pathname).toBe("/__push_event");

    const forwardedJson = (await forwarded.json()) as {
      v?: number;
      event_type?: string;
      delivery_id?: string;
      owner?: string;
      repo?: string;
      issue_number?: number;
    };
    expect(forwardedJson.v).toBe(1);
    expect(forwardedJson.event_type).toBe("issue_comment.created");
    expect(forwardedJson.delivery_id).toBe("test-delivery-uuid");
    expect(forwardedJson.owner).toBe("ippoan");
    expect(forwardedJson.repo).toBe("cc-relay");
    expect(forwardedJson.issue_number).toBe(42);
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
