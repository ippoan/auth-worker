# Admin auth path (Option F) — staging smoke test

| Field        | Value                                                                                          |
|--------------|------------------------------------------------------------------------------------------------|
| Date         | 2026-05-18                                                                                     |
| Environment  | staging (`auth-staging.ippoan.org`, `mcp-staging.ippoan.org`)                                  |
| PRs covered  | ippoan/auth-worker#149, ippoan/github-mcp-server-rs#48                                         |
| Binary       | github-mcp-server-rs v0.0.14 (first release containing PR #48)                                 |
| Tester       | yhonda-ohishi                                                                                  |
| Result       | **PASS** (7/8 checks; 403 not_elevated path deferred — see "Deferred")                         |

## Architecture under test

```
binary (rust)  --MCP JWT-->  /mcp/admin/exec (auth-worker)
                                   |
                                   |--- 1. verify MCP JWT (HS256, MCP_JWT_SECRET)
                                   |--- 2. check KV elevate:{login}  (15min TTL flag)
                                   |--- 3. decrypt KV github_token:{sub}  (AES-256-GCM, SSO_ENCRYPTION_KEY)
                                   |--- 4. gate args.owner ∈ ALLOWED_ADMIN_ORGS (["ippoan"])
                                   '--- 5. forward to https://api.github.com with `Bearer <github_token>`
```

Browser-side elevation:

```
user --GET /mcp/elevate--> auth-worker
                              |-- 302 -> github.com/login/oauth/authorize (scope=read:user, prompt=consent)
user clicks Authorize on github.com
github.com --GET /mcp/elevate_callback?code&state--> auth-worker
                              '-- KV.put(elevate:{login}, {expires_at: now+15min}, ttl=15min)
```

## Results

| # | Check                                                                                          | Result | Observation                                                                                                              |
|---|------------------------------------------------------------------------------------------------|--------|--------------------------------------------------------------------------------------------------------------------------|
| 1 | staging deploy of both PRs                                                                     | ✓      | `GET /mcp/elevate` → 302 to `github.com/login/oauth/authorize?client_id=Ov23lib6Hu8C1V7FCvV0&scope=read:user&prompt=consent`. `POST /mcp/admin/exec` (no auth) → 401 `missing_authorization`. |
| 2 | binary v0.0.14 install                                                                         | ✓      | tarball asset became public at 07:55 UTC (~3 min after `Tag Release` dispatch); sha256 matched; `--version` reports `0.1.0 (v0.0.14)`. |
| 3 | device flow + token-staging.json                                                               | ✓      | `binary auth --env staging` printed `verification_uri_complete`, browser consent completed, `~/.config/github-mcp-server-rs/token-staging.json` saved with `scope=mcp.read mcp.write`. JWT claims: `sub=github:yhonda-ohishi`, `github_login=yhonda-ohishi`, `aud=github-mcp-server-rs`. |
| 4 | introspect + KV `github_token:{sub}` decrypt                                                   | ✓      | `POST /mcp/introspect` with end-user `Bearer <MCP_JWT>` returned `github_token=gho_KR...` (40 chars). GitHub `/user` 200 OK; `x-oauth-scopes: read:user, repo`; `x-oauth-client-id: Ov23lib6Hu8C1V7FCvV0`. |
| 5 | browser elevate → `elevate:yhonda-ohishi` 15min flag                                           | ✓      | User opened `https://auth-staging.ippoan.org/mcp/elevate` in browser, clicked Authorize. Subsequent `/mcp/admin/exec` call succeeded — the flag was readable from `MCP_OAUTH_KV`. |
| 6 | `/mcp/admin/exec get_branch_protection ippoan/cc-relay main`                                   | ✓      | HTTP 200. Body contains current protection: `enforce_admins=true`, `allow_force_pushes=false`, `allow_deletions=false`, `required_conversation_resolution=true`, `required_status_checks.strict=true` (contexts empty). |
| 7 | **PR #149 claim**: `repo` scope cannot delete repos (`delete_repo` is a separate OAuth scope) | ✓      | Created throwaway `ippoan/smoke-test-delete-1779091485` (HTTP 201) with the same `gho_KR...` token, then `DELETE /repos/ippoan/smoke-test-delete-1779091485` with the same token → **HTTP 403 "Must have admin rights to Repository."** and `x-accepted-oauth-scopes:` (empty — GitHub's signal that the required scope is absent). Structural narrowing of the token is verified. |
| 8 | 403 `not_elevated` failure path                                                                | —      | Deferred — see below.                                                                                                    |

## What `delete_repo` verification means

`POST /repos/ippoan/__nonexistent__` initially returned `x-accepted-oauth-scopes: repo`, which suggested the endpoint accepts `repo` scope. **That header is misleading on 404 responses** — GitHub only enforces the actual scope check when the resource exists. With an existing repo and the same token, the response was 403 with empty `x-accepted-oauth-scopes`, the documented signal that the calling token lacks `delete_repo`. The throwaway repo (`ippoan/smoke-test-delete-1779091485`) survives the smoke test exactly because the token couldn't delete it — which IS the deliverable of check #7.

Cleanup: the throwaway repo must be deleted manually (e.g. via the GitHub UI at `https://github.com/ippoan/smoke-test-delete-1779091485/settings#danger-zone`) using a token/session that DOES have `delete_repo` scope or admin org rights.

## What elevate actually protects

`delete_repo` being absent from `repo` scope is **GitHub's structural first wall**. `elevate` is the **second wall** around what `repo` scope CAN still do:

| Threat                                                  | Without elevate                                    | With elevate (this PR)                                                                                  |
|---------------------------------------------------------|----------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| Compromised binary (supply chain) silently calls admin  | `delete_branch_protection` callable any time       | Attacker must trick the user into opening `/mcp/elevate` in a browser AND clicking Authorize within 15min |
| MCP JWT leaked (token theft from binary process / log)  | JWT alone unlocks admin tools                      | JWT + a matching login that has browser-consented within 15min are both required                        |
| Shared CCoW container, second user invokes admin tool   | Anyone holding the JWT can call                    | Each user must perform the browser consent themselves                                                   |
| Operator slip (no intentionality wall)                  | `binary running` ≡ admin operations always armed   | Operator must explicitly open a browser and Authorize — visible intentionality + audit trail            |

Operations the second wall covers (the things `repo` scope CAN do that the first wall does NOT block):
- `delete_branch_protection` (in the binary's admin tool set) → strips main branch protection
- `set_branch_protection({enforce_admins: false})` → admins can bypass protection
- force-push to main (if protection is stripped)
- secrets/workflows/webhooks under the repo
- code/file/branch deletion, commit history rewrites, issues/PRs mutation

Audit trail bonus: every elevate triggers a fresh GitHub OAuth Apps consent grant on `github.com/login/oauth/authorize`, leaving a per-user `Authorize <App>` record on GitHub's side that can be cross-referenced against `/mcp/admin/exec` traffic in Workers logs.

## Deferred

- **Check #8 (403 `not_elevated`)**: PR #149 has no `DELETE /mcp/elevate` or `POST /mcp/elevate/revoke` endpoint, so the only ways to invalidate the flag are (a) wait 15min for natural TTL expiry, or (b) `wrangler kv key delete --remote --namespace-id 0498e6057b8c4d7fbca92e9de41524ee 'elevate:yhonda-ohishi'`. Both options were available at smoke-test time, but were skipped to keep the session short; the failure path is exercised structurally every time the flag expires in the wild.
- **Production `set_branch_protection`** against `ippoan/cc-relay main`: out of scope for this smoke test; only `get_branch_protection` (read-only) was run in production.

## Follow-up suggestions (not blockers)

1. **`GET /mcp/elevate/status`** that returns `{ elevated: bool, expires_at?: number }` for the JWT holder — would let the binary surface "Elevation active until 12:34Z" instead of failing on the first admin call.
2. **`DELETE /mcp/elevate`** authenticated by the MCP JWT — enables explicit revoke (useful for "I'm done with admin work, drop the flag") and makes future smoke tests of the 403 path trivial without a wrangler round-trip.
3. **Document the `x-accepted-oauth-scopes: repo` red herring** in the auth-worker README / handler header so the next reader doesn't repeat the 404-vs-existing-repo investigation.

## Reproduction recipe (for the next smoke test)

```bash
# 1. Install binary (released)
curl -sSfL "https://github.com/ippoan/github-mcp-server-rs/releases/download/v0.0.14/github-mcp-server-rs-v0.0.14-x86_64-unknown-linux-gnu.tar.gz" \
  | tar -xz -C /tmp && install -m 0755 /tmp/github-mcp-server-rs ~/.local/bin/

# 2. Device flow (prints verification_uri_complete; browser-confirm)
~/.local/bin/github-mcp-server-rs --env staging auth

# 3. Recover MCP JWT
JWT=$(python3 -c "import json; print(json.load(open('$HOME/.config/github-mcp-server-rs/token-staging.json'))['access_token'])")

# 4. Browser elevate (https://auth-staging.ippoan.org/mcp/elevate) -- click Authorize on github.com

# 5. Admin exec
curl -sS -X POST "https://auth-staging.ippoan.org/mcp/admin/exec" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  --data '{"tool":"get_branch_protection","args":{"owner":"ippoan","repo":"cc-relay","branch":"main"}}'
```
