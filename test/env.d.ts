declare module "cloudflare:test" {
  interface ProvidedEnv {
    GRPC_PROXY: Fetcher;
    GOOGLE_CLIENT_ID: string;
    GOOGLE_CLIENT_SECRET: string;
    OAUTH_STATE_SECRET: string;
    AUTH_WORKER_ORIGIN: string;
    ALC_API_ORIGIN: string;
    ALC_VEIN?: Fetcher;
    ALC_DTAKO?: Fetcher;
    ALC_LINEWORKS?: Fetcher;
    WORKER_ENV: string;
    AUTH_CONFIG: KVNamespace;
  }
}
