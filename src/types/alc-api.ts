// Auto-generated from rust-alc-api (ts-rs)
// Source SHA: 2c9459e53c46494f53020cfe4d5f1a19446176e4
// Do not edit. Regenerate: scripts/export-ts-bindings.sh /home/yhonda/js/auth-worker/src/types

export type SsoConfigRow = { provider: string, client_id: string, external_org_id: string, enabled: boolean, woff_id: string | null, created_at: string, updated_at: string, };
export type TenantAllowedEmail = { id: string, tenant_id: string, email: string, role: string, created_at: string, };
export type BotConfigResponse = { id: string, provider: string, name: string, client_id: string, service_account: string, bot_id: string, enabled: boolean, created_at: string, updated_at: string, };
export type UserResponse = { id: string, email: string, name: string, role: string, created_at: string, };

// List response wrappers
export type SsoConfigListResponse = { configs: SsoConfigRow[] };
export type BotConfigListResponse = { configs: BotConfigResponse[] };
export type UsersListResponse = { users: UserResponse[] };
export type InvitationsListResponse = { invitations: TenantAllowedEmail[] };
