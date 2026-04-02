-- auth-worker integration test seed data
-- Runs AFTER migrations

SET search_path TO alc_api;

-- Test tenant
INSERT INTO tenants (id, name, slug) VALUES
  ('11111111-1111-1111-1111-111111111111', 'Test Tenant', 'test-tenant');

-- Test user (admin)
INSERT INTO users (id, tenant_id, google_sub, email, name, role) VALUES
  ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111',
   'google-sub-test', 'test@example.com', 'Test Admin', 'admin');

-- Allowed email (invitation)
INSERT INTO tenant_allowed_emails (id, tenant_id, email, role) VALUES
  ('aaaaaaaa-0001-0001-0001-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111',
   'invited@example.com', 'admin');

-- Disposable invitation for DELETE test
INSERT INTO tenant_allowed_emails (id, tenant_id, email, role) VALUES
  ('dddddddd-0001-0001-0001-dddddddddddd', '11111111-1111-1111-1111-111111111111',
   'delete-me@example.com', 'admin');

-- Disposable user for DELETE test
INSERT INTO users (id, tenant_id, google_sub, email, name, role) VALUES
  ('dddddddd-0002-0002-0002-dddddddddddd', '11111111-1111-1111-1111-111111111111',
   'google-sub-delete', 'delete-me@example.com', 'Delete Me', 'viewer');
