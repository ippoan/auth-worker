/**
 * Mock/Live 統一テストヘルパー
 *
 * stubOrReal() で fetch の挙動を切り替え、同じ it() が
 * mock (CI 高速) と live (実 API) の両方で動く。
 *
 * mock: ALC_API_URL 未設定 (デフォルト)
 * live:  ALC_API_URL=http://localhost:18081 npx vitest run
 */
import { vi, beforeAll } from "vitest";
import { isLive, ALC_API_URL, waitForApi, makeJwt } from "./live-env";
import { createMockEnv } from "./mock-env";
import type { Env } from "../../src/index";

const originalFetch = globalThis.fetch;

/** mock: fetch を stub / live: 何もしない (real fetch) */
export function stubOrReal(mockResponse: Response): void {
  if (!isLive) {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(mockResponse));
  }
}

/** mock/live で Env を切り替え */
export function testEnv(): Env {
  return createMockEnv(isLive ? { ALC_API_ORIGIN: ALC_API_URL } : {});
}

/** Bearer token 付きリクエスト */
export function authRequest(path: string, init: RequestInit = {}): Request {
  return new Request(`https://auth.test.example${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${makeJwt()}`,
      "Content-Type": "application/json",
      ...init.headers,
    },
  });
}

/** JSON body 付き認証リクエスト */
export function authJsonRequest(
  path: string,
  body: unknown,
  method = "POST",
): Request {
  return authRequest(path, { method, body: JSON.stringify(body) });
}

/** 認証なしリクエスト */
export function noAuthRequest(path: string, method = "POST"): Request {
  return new Request(`https://auth.test.example${path}`, { method });
}

/** 認証なし JSON リクエスト */
export function noAuthJsonRequest(path: string, body: unknown): Request {
  return new Request(`https://auth.test.example${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** fetch stub をリストア */
export function restoreFetch(): void {
  vi.stubGlobal("fetch", originalFetch);
}

/** live 時のみ API 起動待ち (beforeAll で使用) */
export function waitIfLive(): void {
  if (isLive) {
    beforeAll(() => waitForApi());
  }
}

/** mock 専用アサーション。live 時はスキップ */
export function assertMock(fn: () => void): void {
  if (!isLive) fn();
}

export { isLive };
