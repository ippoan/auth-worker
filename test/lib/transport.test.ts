import { describe, it, expect, vi, beforeEach } from "vitest";

interface TransportOpts {
  baseUrl: string;
  fetch: (input: string, init?: RequestInit) => Promise<Response>;
  interceptors: Array<(next: (req: unknown) => Promise<unknown>) => (req: unknown) => Promise<unknown>>;
}

const { mockCreateGrpcWebTransport } = vi.hoisted(() => ({
  mockCreateGrpcWebTransport: vi.fn(
    (opts: TransportOpts) => {
      return { _opts: opts } as unknown;
    },
  ),
}));

vi.mock("@connectrpc/connect-web", () => ({
  createGrpcWebTransport: mockCreateGrpcWebTransport,
}));

import { createTransport, createTransportWithAuth } from "../../src/lib/transport";

describe("transport", () => {
  const mockProxyFetch = vi.fn();
  const mockGrpcProxy = {
    fetch: mockProxyFetch,
  } as unknown as Fetcher;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("createTransport", () => {
    it("calls createTransportWithAuth without token", () => {
      createTransport(mockGrpcProxy);
      expect(mockCreateGrpcWebTransport).toHaveBeenCalledOnce();
      const opts = mockCreateGrpcWebTransport.mock.calls[0]![0]!;
      expect(opts.baseUrl).toBe("https://cf-grpc-proxy");
      expect(opts.interceptors).toHaveLength(0);
    });
  });

  describe("createTransportWithAuth", () => {
    it("wrappedFetch converts redirect 'error' to 'manual'", async () => {
      mockProxyFetch.mockResolvedValue(new Response("ok"));

      createTransportWithAuth(mockGrpcProxy);
      const opts = mockCreateGrpcWebTransport.mock.calls[0]![0]!;
      const wrappedFetch = opts.fetch;

      await wrappedFetch("https://example.com", { redirect: "error" as string });

      expect(mockProxyFetch).toHaveBeenCalledWith(
        "https://example.com",
        expect.objectContaining({ redirect: "manual" }),
      );
      // Ensure "error" key is removed
      const calledInit = mockProxyFetch.mock.calls[0]![1]!;
      expect(calledInit.redirect).toBe("manual");
    });

    it("wrappedFetch passes through other inits unchanged", async () => {
      mockProxyFetch.mockResolvedValue(new Response("ok"));

      createTransportWithAuth(mockGrpcProxy);
      const opts = mockCreateGrpcWebTransport.mock.calls[0]![0]!;
      const wrappedFetch = opts.fetch;

      await wrappedFetch("https://example.com", { method: "POST" });

      expect(mockProxyFetch).toHaveBeenCalledWith("https://example.com", { method: "POST" });
    });

    it("wrappedFetch works with no init", async () => {
      mockProxyFetch.mockResolvedValue(new Response("ok"));

      createTransportWithAuth(mockGrpcProxy);
      const opts = mockCreateGrpcWebTransport.mock.calls[0]![0]!;
      const wrappedFetch = opts.fetch;

      await wrappedFetch("https://example.com", undefined);

      expect(mockProxyFetch).toHaveBeenCalledWith("https://example.com", undefined);
    });

    it("adds token interceptor when token is provided", async () => {
      createTransportWithAuth(mockGrpcProxy, "my-jwt-token");
      const opts = mockCreateGrpcWebTransport.mock.calls[0]![0]!;
      expect(opts.interceptors).toHaveLength(1);

      // Execute the interceptor to verify it sets the header
      const interceptor = opts.interceptors[0]!;
      const mockHeader = new Headers();
      const mockReq = { header: mockHeader };
      const mockNext = vi.fn().mockResolvedValue("response");

      const handler = interceptor(mockNext);
      await handler(mockReq);

      expect(mockHeader.get("x-auth-token")).toBe("my-jwt-token");
      expect(mockNext).toHaveBeenCalledWith(mockReq);
    });

    it("does not add interceptor when token is undefined", () => {
      createTransportWithAuth(mockGrpcProxy, undefined);
      const opts = mockCreateGrpcWebTransport.mock.calls[0]![0]!;
      expect(opts.interceptors).toHaveLength(0);
    });

    it("does not add interceptor when token is empty string", () => {
      createTransportWithAuth(mockGrpcProxy, "");
      const opts = mockCreateGrpcWebTransport.mock.calls[0]![0]!;
      expect(opts.interceptors).toHaveLength(0);
    });
  });
});
