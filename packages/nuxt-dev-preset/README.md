# @ippoan/nuxt-dev-preset

Nuxt module that reads `.ippoan-dev.yaml` and configures dev-time settings so that the frontend is reachable through `https://<name>-dev.ippoan.org` via the ippoan dev-proxy tunnel.

## Usage

```bash
npm i -D @ippoan/nuxt-dev-preset
```

`.ippoan-dev.yaml` (repo root):
```yaml
name: my-app
port: 3099
cmd: "PORT=$PORT HOST=0.0.0.0 npm run dev"
```

`nuxt.config.ts`:
```ts
export default defineNuxtConfig({
  modules: ['@ippoan/nuxt-dev-preset'],
})
```

The module is a no-op in production builds. In `nuxt dev` it:
- binds the dev server to `0.0.0.0:<port-from-yaml>` (unless `PORT` env is set)
- configures Vite HMR to advertise `<name>-dev.ippoan.org` over `wss` so HMR events propagate through the Cloudflare tunnel + Access
- logs the public host for confirmation

## Options

```ts
export default defineNuxtConfig({
  modules: ['@ippoan/nuxt-dev-preset'],
  ippoanDev: {
    // specPath?: string   // override .ippoan-dev.yaml path
    // hostPattern?: (name) => string
    // hmr?: boolean       // set false to leave vite.server.hmr untouched
  },
})
```
