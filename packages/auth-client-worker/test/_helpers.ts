/**
 * Lightweight in-memory KVNamespace mock for the package's own tests.
 *
 * We deliberately don't depend on `@cloudflare/vitest-pool-workers` here —
 * the package is published as a library so its tests should run in plain
 * Node (Vitest) without consumer-side test infra. The mock implements just
 * enough of the KVNamespace surface that the SDK actually uses (`get`,
 * `put`, `delete`, JSON typing on `get`).
 */

export class MemoryKV {
  private store = new Map<string, string>();

  async get(
    key: string,
    type?: "text" | "json",
  ): Promise<string | unknown | null> {
    const raw = this.store.get(key);
    if (raw === undefined) return null;
    if (type === "json") return JSON.parse(raw);
    return raw;
  }

  async put(
    key: string,
    value: string,
    _opts?: { expirationTtl?: number },
  ): Promise<void> {
    // TTL not enforced in tests — KV is in-memory only and we don't
    // exercise expiry. The opts argument is accepted for API compat.
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

export function makeKv(): KVNamespace {
  return new MemoryKV() as unknown as KVNamespace;
}

export function fakeSecretsStoreSecret(value: string): SecretsStoreSecret {
  return { get: async () => value } as unknown as SecretsStoreSecret;
}
