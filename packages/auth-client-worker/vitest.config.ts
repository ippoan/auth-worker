import { defineConfig } from "vitest/config";

// Plain Vitest config — no cloudflare:test pool — so the package can be
// tested in pure Node. KV is mocked via `MemoryKV` in test/_helpers.ts.
export default defineConfig({
  test: {
    globals: true,
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      reportsDirectory: "./coverage",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts"],
    },
  },
});
