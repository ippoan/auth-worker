// Auto-generated from rust-alc-api (ts-rs)
// Do not edit. Regenerate: scripts/export-ts-bindings.sh <output-dir>

// --- Backend API types (snake_case) ---

// --- Handler response types (camelCase, generated with #[ts(rename_all = "camelCase")]) ---
export type SsoConfigMapped = { provider: string, clientId: string, hasClientSecret: boolean, externalOrgId: string, enabled: boolean, woffId: string, createdAt: string, updatedAt: string, };
export type SsoConfigUpsertResponse = { provider: string, clientId: string, hasClientSecret: boolean, externalOrgId: string, woffId: string, enabled: boolean, };
export type BotConfigMapped = { id: string, provider: string, name: string, clientId: string, hasClientSecret: boolean, serviceAccount: string, botId: string, enabled: boolean, createdAt: string, updatedAt: string, };
export type BotConfigUpsertResponse = { id: string, provider: string, name: string, clientId: string, hasClientSecret: boolean, serviceAccount: string, botId: string, enabled: boolean, };

// Handler list response wrappers (camelCase)
export type SsoConfigListMapped = { configs: SsoConfigMapped[] };
export type BotConfigListMapped = { configs: BotConfigMapped[] };
