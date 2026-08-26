/**
 * `cloudflare:workers` の最小 stub (vitest 用、Refs #483)。
 *
 * この repo の vitest は **node で走る** (`@cloudflare/vitest-pool-workers` は
 * 未使用) ので、workerd built-in module の `cloudflare:workers` は解決できない
 * (`Cannot find package 'cloudflare:workers'`)。`src/internal-entrypoint.ts` が
 * `WorkerEntrypoint` を継承する以上、それを import する `src/index.ts` も
 * 芋づるで解決不能になり、**index.ts を import している既存テスト全部**が
 * 落ちてしまう。
 *
 * そこで `vitest.config.ts` の `resolve.alias` でこのファイルに差し替える。
 * 型は `worker-configuration.d.ts` の `declare module 'cloudflare:workers'`
 * (= 本物の宣言) がそのまま効くので、ここは**実行時の形だけ**を再現すれば良い
 * (`ctx` / `env` を持つ基底クラス)。
 *
 * 本番 bundle (wrangler/esbuild) はこの alias を通らず workerd の実物を使う。
 */

/** 本物の `WorkerEntrypoint` と同じ `constructor(ctx, env)` / `this.env` だけを持つ。 */
export class WorkerEntrypoint<Env = unknown> {
  protected ctx: unknown;
  protected env: Env;
  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}

/** 同 module の他の export を使い始めたらここに足す (今は WorkerEntrypoint だけ)。 */
export class DurableObject<Env = unknown> {
  protected ctx: unknown;
  protected env: Env;
  constructor(ctx: unknown, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
