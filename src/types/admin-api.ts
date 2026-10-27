// 会社の管理の口 (SSO 設定・Bot 設定・ユーザー・招待) の応答の形。
// rust-alc-api から alc-auth-worker (SSO・ユーザー・招待) と alc-lineworks-worker (Bot 設定) へ移り (W2c)、
// rust の型 (ts-rs) は消えたので、生成の alc-api.ts ではなくここに持つ (Refs ippoan/rust-alc-api#680)。
// 形は移行前の rust の型と同じ (snake_case)。

export type SsoConfigRow = { provider: string, client_id: string, external_org_id: string, enabled: boolean, woff_id: string | null, created_at: string, updated_at: string, };
export type TenantAllowedEmail = { id: string, tenant_id: string, email: string, role: string, created_at: string, };
export type BotConfigResponse = { id: string, provider: string, name: string, client_id: string, service_account: string, bot_id: string, enabled: boolean, created_at: string, updated_at: string, };
export type UserResponse = { id: string, email: string, name: string, role: string, created_at: string, };

// 一覧の応答の wrapper
export type SsoConfigListResponse = { configs: SsoConfigRow[] };
export type BotConfigListResponse = { configs: BotConfigResponse[] };
export type UsersListResponse = { users: UserResponse[] };
export type InvitationsListResponse = { invitations: TenantAllowedEmail[] };
