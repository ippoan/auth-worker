// Auto-generated from rust-alc-api (ts-rs)
// Do not edit. Regenerate: scripts/export-ts-bindings.sh <output-dir>

// --- Backend API types (snake_case) ---
export type SsoConfigRow = { provider: string, client_id: string, external_org_id: string, enabled: boolean, woff_id: string | null, created_at: string, updated_at: string, };
export type TenantAllowedEmail = { id: string, tenant_id: string, email: string, role: string, created_at: string, };
export type BotConfigResponse = { id: string, provider: string, name: string, client_id: string, service_account: string, bot_id: string, enabled: boolean, created_at: string, updated_at: string, };
export type UserResponse = { id: string, email: string, name: string, role: string, created_at: string, };

// --- Handler response types (camelCase, generated with #[ts(rename_all = "camelCase")]) ---
export type SsoConfigMapped = { provider: string, clientId: string, hasClientSecret: boolean, externalOrgId: string, enabled: boolean, woffId: string, createdAt: string, updatedAt: string, };
export type SsoConfigUpsertResponse = { provider: string, clientId: string, hasClientSecret: boolean, externalOrgId: string, woffId: string, enabled: boolean, };
export type BotConfigMapped = { id: string, provider: string, name: string, clientId: string, hasClientSecret: boolean, serviceAccount: string, hasPrivateKey: boolean, botId: string, enabled: boolean, createdAt: string, updatedAt: string, };
export type BotConfigUpsertResponse = { id: string, provider: string, name: string, clientId: string, hasClientSecret: boolean, serviceAccount: string, hasPrivateKey: boolean, botId: string, enabled: boolean, };

// List response wrappers
export type SsoConfigListResponse = { configs: SsoConfigRow[] };
export type BotConfigListResponse = { configs: BotConfigResponse[] };
export type UsersListResponse = { users: UserResponse[] };
export type InvitationsListResponse = { invitations: TenantAllowedEmail[] };

// Handler list response wrappers (camelCase)
export type SsoConfigListMapped = { configs: SsoConfigMapped[] };
export type BotConfigListMapped = { configs: BotConfigMapped[] };
