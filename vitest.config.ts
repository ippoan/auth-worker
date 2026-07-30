import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // packages/auth-client の test は外部依存が vitest だけなので root の
    // node_modules で動く。CI (frontend-ci の test_command) は root で
    // `vitest run` を 1 回叩くだけなので、ここに含めないと lib 側のテストが
    // まるごと走らない (Refs ippoan/nuxt-trouble#236)。
    include: ["test/**/*.test.ts", "packages/auth-client/test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      reportsDirectory: "./coverage",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts", "src/types/**"],
    },
  },
});
