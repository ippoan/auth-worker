/**
 * `/dashboard/branch-protection` HTML renderer (issue #159 Phase 1).
 *
 * Server-rendered shell + inline JS that fetches `GET /api/dashboard/repos`
 * and renders the table client-side. No SPA framework, no external assets —
 * auth-worker は Cloudflare Workers 上で動くため、生 HTML + inline script で
 * バンドルレス運用にしている (既存 `admin-*-html.ts` と同じ方針)。
 *
 * The page is **already gated** at the handler level by:
 *   1. `mcp_pair_session` cookie (= browser identity)
 *   2. `elevate:<login>` KV flag (= 15-minute admin window)
 * so the inline JS does not re-check auth — a 401 from the API endpoints will
 * trigger a hard reload to the elevate flow.
 */

import { PRESETS } from "./branch-protection-presets";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderBranchProtectionPage(opts: {
  github_login: string;
  elevate_url: string;
  csrf_token: string;
}): string {
  const presetMeta = Object.values(PRESETS).map((p) => ({
    id: p.id,
    label: p.label,
    description: p.description,
    required_checks: p.required_checks,
    project_type: p.project_type,
  }));
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Branch protection dashboard</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; color: #1f2937; }
  h1 { font-size: 1.5rem; margin-bottom: .25rem; }
  .meta { color: #6b7280; font-size: .9em; margin-bottom: 1.5rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { text-align: left; padding: .6rem .5rem; border-bottom: 1px solid #e5e7eb; font-size: .9em; vertical-align: top; }
  th { background: #f9fafb; font-weight: 600; }
  tr.unprotected { background: #fef2f2; }
  tr.unprotected td:first-child { border-left: 4px solid #dc2626; }
  .branch-warn {
    color: #b45309;
    font-family: ui-monospace, Menlo, monospace;
    font-size: .85em;
    padding: .1rem .35rem;
    border-radius: .25rem;
    background: #fef3c7;
    display: inline-block;
  }
  .branch-warn::before { content: "\\26A0\\FE0F  "; }
  .badge-ok { color: #15803d; font-weight: 600; }
  .badge-bad { color: #dc2626; font-weight: 600; }
  .badge-warn { color: #b45309; font-weight: 600; }
  button { font: inherit; padding: .35rem .7rem; border: 1px solid #d1d5db; border-radius: .35rem; background: #fff; cursor: pointer; }
  button:hover { background: #f3f4f6; }
  button.primary { background: #2563eb; color: #fff; border-color: #1d4ed8; }
  button.primary:hover { background: #1d4ed8; }
  button.danger { color: #dc2626; }
  button:disabled { opacity: .5; cursor: not-allowed; }
  .actions { display: flex; gap: .35rem; flex-wrap: wrap; }
  .checks { font-family: ui-monospace, Menlo, monospace; font-size: .8em; color: #4b5563; }
  .status { margin-top: 1rem; padding: .75rem; border-radius: .35rem; display: none; }
  .status.error { background: #fef2f2; color: #991b1b; display: block; }
  .status.success { background: #ecfdf5; color: #065f46; display: block; }
  .empty { color: #6b7280; font-style: italic; }
</style>
</head>
<body>
<h1>Branch protection dashboard</h1>
<p class="meta">
  Signed in as <code>${escapeHtml(opts.github_login)}</code>.
  Admin elevation expires in ~15 minutes.
  <a href="${escapeHtml(opts.elevate_url)}">Re-elevate</a>
</p>
<div id="status" class="status"></div>
<table id="repos">
  <thead>
    <tr>
      <th>Repo</th>
      <th>Default branch</th>
      <th>Protected</th>
      <th>Source</th>
      <th>Force push</th>
      <th>Deletion</th>
      <th>Required checks</th>
      <th>Repo settings</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
    <tr><td colspan="9" class="empty">Loading…</td></tr>
  </tbody>
</table>
<script id="presets" type="application/json">${JSON.stringify(presetMeta)}</script>
<script>
(function () {
  var CSRF = ${JSON.stringify(opts.csrf_token)};
  var presets = JSON.parse(document.getElementById("presets").textContent);
  var tbody = document.querySelector("#repos tbody");
  var statusEl = document.getElementById("status");

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function setStatus(msg, kind) {
    statusEl.className = "status " + (kind || "");
    statusEl.textContent = msg || "";
  }

  function handleAuthFailure() {
    setStatus("Admin elevation expired. Redirecting…", "error");
    window.location.href = ${JSON.stringify(opts.elevate_url)};
  }

  function loadRepos() {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">Loading…</td></tr>';
    fetch("/api/dashboard/repos", { credentials: "same-origin", headers: { "X-CSRF": CSRF } })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) { handleAuthFailure(); return null; }
        return r.json().then(function (b) { return { status: r.status, body: b }; });
      })
      .then(function (resp) {
        if (!resp) return;
        if (resp.status !== 200) {
          setStatus("Failed to load repos: " + (resp.body && resp.body.error || resp.status), "error");
          tbody.innerHTML = '<tr><td colspan="9" class="empty">Failed to load.</td></tr>';
          return;
        }
        renderRows(resp.body.repos || []);
      })
      .catch(function (e) {
        setStatus("Network error: " + e.message, "error");
      });
  }

  function renderRows(rows) {
    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="empty">No repos found.</td></tr>';
      return;
    }
    var html = "";
    rows.forEach(function (row) {
      var isProtected = row.protected === true;
      var rowClass = isProtected ? "" : "unprotected";
      var checksHtml = (row.required_checks || []).map(function (c) {
        return '<div>' + escapeHtml(c) + '</div>';
      }).join("") || '<span class="empty">none</span>';
      var source = row.protection_source || (isProtected ? "classic" : "none");
      var ruleTypes = row.ruleset_rule_types || [];
      var isEvaluateOnly = source === "none"
        && ruleTypes.length === 1
        && ruleTypes[0] === "evaluate-mode";
      var sourceLabel;
      if (isEvaluateOnly) {
        sourceLabel = '<span class="badge-warn">ruleset (evaluate)</span>'
          + ' <span class="checks">(dry-run, not enforced)</span>';
      } else if (source === "none") {
        sourceLabel = '<span class="empty">—</span>';
      } else if (source === "both") {
        sourceLabel = '<span class="badge-ok">classic + ruleset</span>';
      } else if (source === "ruleset") {
        var ruleHint = ruleTypes.join(", ");
        sourceLabel = '<span class="badge-ok">ruleset</span>'
          + (ruleHint ? ' <span class="checks">(' + escapeHtml(ruleHint) + ')</span>' : '');
      } else {
        sourceLabel = '<span class="badge-ok">classic</span>';
      }
      // Repo settings (allow_auto_merge + delete_branch_on_merge). CI's
      // branch-protection check requires both to be ON; either OFF blocks
      // gh pr merge --auto. Show inline badges + a one-click fix button.
      var settings = row.repo_settings;
      var settingsCell;
      if (!settings) {
        settingsCell = '<span class="empty">(unknown)</span>';
      } else {
        var amBadge = settings.allow_auto_merge
          ? '<span class="badge-ok">auto-merge</span>'
          : '<span class="branch-warn">auto-merge off</span>';
        var dbBadge = settings.delete_branch_on_merge
          ? '<span class="badge-ok">delete-on-merge</span>'
          : '<span class="branch-warn">delete-on-merge off</span>';
        settingsCell = amBadge + ' ' + dbBadge;
        if (!settings.allow_auto_merge || !settings.delete_branch_on_merge) {
          settingsCell += '<div style="margin-top:.35rem;"><button data-action="fix-settings"'
            + ' data-owner="' + escapeHtml(row.owner) + '"'
            + ' data-repo="' + escapeHtml(row.name) + '"'
            + ' title="Turn on Allow auto-merge + Delete branch on merge in repo Settings">'
            + 'Fix repo settings</button></div>';
        }
      }

      // Pick presets that match this repo's detected project_type. Unknown
      // → show everything so the operator is never locked out. Matching
      // preset rendered as primary; fallback (unknown) as plain so the
      // operator notices something's off. project_type === "any"
      // (= ippoan-base) is shown for every detected type because it ships
      // only safety knobs and no required_checks, so it can never
      // silent-block a CI.
      var rowType = row.project_type || "unknown";
      var matchedPresets = rowType === "unknown"
        ? presets
        : presets.filter(function (p) { return p.project_type === rowType || p.project_type === "any"; });
      var presetsToShow = matchedPresets.length > 0 ? matchedPresets : presets;
      var actions = presetsToShow.map(function (p) {
        var btnClass = rowType === "unknown" ? "" : "primary";
        return '<button class="' + btnClass + '" data-action="apply" data-owner="' + escapeHtml(row.owner)
          + '" data-repo="' + escapeHtml(row.name) + '" data-branch="' + escapeHtml(row.default_branch)
          + '" data-preset="' + escapeHtml(p.id) + '" title="' + escapeHtml(p.description) + '">'
          + escapeHtml(p.label) + '</button>';
      }).join("");
      if (isProtected) {
        actions += ' <button class="danger" data-action="remove" data-owner="' + escapeHtml(row.owner)
          + '" data-repo="' + escapeHtml(row.name) + '" data-branch="' + escapeHtml(row.default_branch)
          + '">Remove</button>';
      }
      // Project-type badge surfaces the auto-detection so the operator can
      // sanity-check why a particular preset is offered. The unknown state
      // is also exposed (amber) so a missing/odd ci.yml is visible rather
      // than silently degrading to "show everything".
      var typeBadge;
      if (rowType === "worker") {
        typeBadge = '<span class="badge-ok" title="Detected from .github/workflows/ci.yml (frontend-ci.yml)">worker</span>';
      } else if (rowType === "rust") {
        typeBadge = '<span class="badge-ok" title="Detected from .github/workflows/ci.yml (rust-ci.yml) or Cargo.toml">rust</span>';
      } else if (rowType === "go") {
        typeBadge = '<span class="badge-ok" title="Detected from .github/workflows/ci.yml (go-ci.yml) or go.mod">go</span>';
      } else if (rowType === "android") {
        typeBadge = '<span class="badge-ok" title="Detected from .github/workflows/ci.yml (android-ci.yml) or app/src/main/AndroidManifest.xml">android</span>';
      } else {
        typeBadge = '<span class="branch-warn" title="No ci.yml referencing ippoan/ci-workflows reusable; showing every preset as a fallback.">unknown type</span>';
      }
      actions = typeBadge + '<div style="margin-top:.25rem;">' + actions + '</div>';
      // Repos whose GitHub-declared default branch is anything other than
      // main/master are almost always misconfigured (typical cause: a
      // claude/ccoW session pushed the first commit to a feature branch
      // and GitHub adopted that as the default because main did not yet
      // exist). Surface a warning so the operator can fix it via repo
      // Settings → Branches before applying any protection preset.
      var STANDARD_DEFAULTS = ["main", "master"];
      var isSuspiciousDefault = STANDARD_DEFAULTS.indexOf(row.default_branch) === -1;
      var branchCell = isSuspiciousDefault
        ? '<span class="branch-warn" title="Unusual default branch — set Settings → Branches → Default to main on GitHub before applying a preset.">' + escapeHtml(row.default_branch) + '</span>'
        : '<code>' + escapeHtml(row.default_branch) + '</code>';
      html += '<tr class="' + rowClass + '">'
        + '<td>' + escapeHtml(row.owner) + '/' + escapeHtml(row.name) + '</td>'
        + '<td>' + branchCell + '</td>'
        + '<td>' + (isProtected ? '<span class="badge-ok">&#x2705;</span>' : '<span class="badge-bad">&#x274C; unprotected</span>') + '</td>'
        + '<td>' + sourceLabel + '</td>'
        + '<td>' + (!isProtected ? '<span class="badge-warn">allowed</span>' : (row.allow_force_pushes ? '<span class="badge-warn">allowed</span>' : '<span class="badge-ok">blocked</span>')) + '</td>'
        + '<td>' + (!isProtected ? '<span class="badge-warn">allowed</span>' : (row.allow_deletions ? '<span class="badge-warn">allowed</span>' : '<span class="badge-ok">blocked</span>')) + '</td>'
        + '<td class="checks">' + checksHtml + '</td>'
        + '<td>' + settingsCell + '</td>'
        + '<td><div class="actions">' + actions + '</div></td>'
        + '</tr>';
    });
    tbody.innerHTML = html;
  }

  tbody.addEventListener("click", function (ev) {
    var btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    var action = btn.getAttribute("data-action");
    var owner = btn.getAttribute("data-owner");
    var repo = btn.getAttribute("data-repo");
    var preset = btn.getAttribute("data-preset");
    if (action === "apply") {
      if (!confirm("Apply " + preset + " to " + owner + "/" + repo + "?")) return;
      btn.disabled = true;
      setStatus("Applying " + preset + " to " + owner + "/" + repo + "…", "");
      fetch("/api/dashboard/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/protection", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF": CSRF },
        body: JSON.stringify({ preset: preset }),
      })
        .then(function (r) {
          if (r.status === 401 || r.status === 403) { handleAuthFailure(); return null; }
          return r.json().then(function (b) { return { status: r.status, body: b }; });
        })
        .then(function (resp) {
          if (!resp) return;
          if (resp.status === 200 && resp.body.ok) {
            setStatus("Applied " + preset + " to " + owner + "/" + repo + ".", "success");
            loadRepos();
          } else {
            setStatus("Failed: " + JSON.stringify(resp.body), "error");
          }
        })
        .catch(function (e) { setStatus("Network error: " + e.message, "error"); })
        .then(function () { btn.disabled = false; });
    } else if (action === "fix-settings") {
      if (!confirm("Enable Allow auto-merge + Delete branch on merge on " + owner + "/" + repo + "?")) return;
      btn.disabled = true;
      setStatus("Fixing repo settings on " + owner + "/" + repo + "…", "");
      fetch("/api/dashboard/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/fix-settings", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-CSRF": CSRF },
        body: "{}",
      })
        .then(function (r) {
          if (r.status === 401 || r.status === 403) { handleAuthFailure(); return null; }
          return r.json().then(function (b) { return { status: r.status, body: b }; });
        })
        .then(function (resp) {
          if (!resp) return;
          if (resp.status === 200 && resp.body.ok) {
            setStatus("Repo settings fixed on " + owner + "/" + repo + ".", "success");
            loadRepos();
          } else {
            setStatus("Failed: " + JSON.stringify(resp.body), "error");
          }
        })
        .catch(function (e) { setStatus("Network error: " + e.message, "error"); })
        .then(function () { btn.disabled = false; });
    } else if (action === "remove") {
      if (!confirm("Remove branch protection from " + owner + "/" + repo + "?")) return;
      btn.disabled = true;
      setStatus("Removing protection on " + owner + "/" + repo + "…", "");
      fetch("/api/dashboard/repos/" + encodeURIComponent(owner) + "/" + encodeURIComponent(repo) + "/protection", {
        method: "DELETE",
        credentials: "same-origin",
        headers: { "X-CSRF": CSRF },
      })
        .then(function (r) {
          if (r.status === 401 || r.status === 403) { handleAuthFailure(); return null; }
          return r.json().then(function (b) { return { status: r.status, body: b }; });
        })
        .then(function (resp) {
          if (!resp) return;
          if (resp.status === 200 && resp.body.ok) {
            setStatus("Removed protection from " + owner + "/" + repo + ".", "success");
            loadRepos();
          } else {
            setStatus("Failed: " + JSON.stringify(resp.body), "error");
          }
        })
        .catch(function (e) { setStatus("Network error: " + e.message, "error"); })
        .then(function () { btn.disabled = false; });
    }
  });

  loadRepos();
})();
</script>
</body>
</html>`;
}
