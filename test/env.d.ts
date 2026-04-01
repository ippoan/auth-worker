declare module "cloudflare:test" {
  interface ProvidedEnv {
    GRPC_PROXY: Fetcher;
    GOOGLE_CLIENT_ID: string;
    GOOGLE_CLIENT_SECRET: string;
    OAUTH_STATE_SECRET: string;
    AUTH_WORKER_ORIGIN: string;
    ALLOWED_REDIRECT_ORIGINS: string;
    ALC_API_ORIGIN: string;
  }
}
