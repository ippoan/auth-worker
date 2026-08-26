import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      // Refs #483: `src/internal-entrypoint.ts` が継承する workerd built-in。
      // この repo の vitest は node で走る (pool-workers 未使用) ので解決できず、
      // 放置すると `src/index.ts` を import している既存テストが全部落ちる。
      // 実行時の形だけを再現した stub に差し替える (型は
      // worker-configuration.d.ts の本物の宣言がそのまま効く)。
      "cloudflare:workers": fileURLToPath(
        new URL("./test/helpers/cloudflare-workers-stub.ts", import.meta.url),
      ),
    },
  },
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
