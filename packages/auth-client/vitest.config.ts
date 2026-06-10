import { defineConfig } from "vitest/config";

// Plain Vitest (pure Node) — covers framework-agnostic modules
// (createAuthFetch / jwt). Nuxt 依存の useAuth.ts / .vue は消費側 (vue-tsc)
// で型チェックされるためここでは対象外。
export default defineConfig({
  test: {
    globals: true,
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      reportsDirectory: "./coverage",
      include: ["src/createAuthFetch.ts", "src/jwt.ts"],
    },
  },
});
