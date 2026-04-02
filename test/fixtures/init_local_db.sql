-- rust-alc-api ローカルテスト用 DB 初期化
-- 本番 Supabase と同等のスキーマ・ロール構成を再現

-- alc_api スキーマ
CREATE SCHEMA IF NOT EXISTS alc_api;

-- アプリケーションロール (NOBYPASSRLS = RLS が有効)
CREATE ROLE alc_api_app NOLOGIN NOBYPASSRLS;
GRANT USAGE ON SCHEMA alc_api TO alc_api_app;

-- search_path をデフォルトで alc_api に設定
-- (migration 001-025 の非修飾テーブル名が alc_api スキーマに作成されるように)
ALTER DATABASE postgres SET search_path TO alc_api, public;

-- Supabase 互換ロール
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN;
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT USAGE ON SCHEMA alc_api TO anon, authenticated, service_role;

-- resolve_sso_config: SSO 設定を RLS バイパスで検索 (認証前アクセス用)
-- 本番は Supabase Dashboard で手動作成。テスト用にここで定義。
CREATE OR REPLACE FUNCTION alc_api.resolve_sso_config(
    p_provider TEXT,
    p_lookup_key TEXT
) RETURNS TABLE (
    tenant_id UUID,
    client_id TEXT,
    client_secret_encrypted TEXT,
    external_org_id TEXT,
    woff_id TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT sso.tenant_id, sso.client_id, sso.client_secret_encrypted,
           sso.external_org_id, sso.woff_id
    FROM alc_api.sso_provider_configs sso
    WHERE sso.provider = p_provider
      AND sso.external_org_id = p_lookup_key
      AND sso.enabled = true
    LIMIT 1;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = alc_api;
