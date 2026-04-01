/**
 * Rich Menu management page HTML template
 * Single-page app with inline JS for JWT auth + API calls
 */

export function renderAdminRichMenuPage(): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Rich Menu \u7ba1\u7406 - Logi Admin</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      padding: 1rem;
    }
    .container {
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      padding: 2rem;
      max-width: 700px;
      margin: 2rem auto;
    }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: #333; }
    .back-link {
      display: inline-flex; align-items: center; gap: 0.375rem; font-size: 1rem; color: #3b82f6;
      text-decoration: none; margin-bottom: 1rem; font-weight: 500;
      padding: 0.5rem 0.75rem; border: 1px solid #3b82f6; border-radius: 6px;
    }
    .back-link:hover { background: #3b82f6; color: white; }
    h2 { font-size: 1.1rem; margin-bottom: 1rem; color: #555; }
    .error {
      background: #fef2f2; border: 1px solid #fecaca; color: #dc2626;
      padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem;
    }
    .success {
      background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a;
      padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem;
    }
    .badge {
      display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px;
      font-size: 0.75rem; font-weight: 500;
    }
    .badge-green { background: #dcfce7; color: #166534; }
    .badge-yellow { background: #fef9c3; color: #854d0e; }
    .badge-red { background: #fef2f2; color: #dc2626; }
    .badge-blue { background: #dbeafe; color: #1e40af; }
    .btn {
      padding: 0.5rem 1rem; border: none; border-radius: 6px; font-size: 0.875rem;
      font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #3b82f6; color: white; }
    .btn-primary:hover:not(:disabled) { background: #2563eb; }
    .btn-gray { background: #f3f4f6; color: #374151; }
    .btn-gray:hover:not(:disabled) { background: #e5e7eb; }
    .btn-red { background: #fef2f2; color: #dc2626; }
    .btn-red:hover:not(:disabled) { background: #fecaca; }
    .btn-sm { padding: 0.375rem 0.75rem; font-size: 0.8rem; }
    .btn-green { background: #dcfce7; color: #166534; }
    .btn-green:hover:not(:disabled) { background: #bbf7d0; }
    label { display: block; font-size: 0.875rem; font-weight: 500; color: #555; margin-bottom: 0.25rem; }
    input, select {
      width: 100%; padding: 0.625rem 0.75rem; border: 1px solid #ddd;
      border-radius: 6px; font-size: 1rem; margin-bottom: 1rem; outline: none;
    }
    input:focus, select:focus { border-color: #3b82f6; }
    .divider { border-top: 1px solid #e5e7eb; margin: 1.5rem 0; }
    .form-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
    .empty { color: #9ca3af; font-size: 0.875rem; padding: 1rem 0; }
    .loading { text-align: center; padding: 2rem; color: #9ca3af; }
    .hidden { display: none !important; }
    .desc { font-size: 0.8rem; color: #6b7280; margin-bottom: 1.5rem; line-height: 1.5; }
    .field-desc { font-size: 0.75rem; color: #9ca3af; margin-top: -0.75rem; margin-bottom: 0.75rem; }
    .modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.5);
      display: flex; align-items: center; justify-content: center; z-index: 50;
    }
    .modal {
      background: white; border-radius: 8px; padding: 1.5rem;
      max-width: 400px; width: 90%;
    }
    .modal h3 { margin-bottom: 1rem; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem; }
    .menu-card {
      border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;
    }
    .menu-header {
      display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;
    }
    .menu-name { font-weight: 600; font-size: 1rem; }
    .menu-detail { font-size: 0.8rem; color: #6b7280; margin-bottom: 0.5rem; }
    .menu-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
    .area-row {
      display: flex; gap: 0.5rem; align-items: flex-start; margin-bottom: 0.75rem;
      padding: 0.75rem; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px;
      flex-wrap: wrap;
    }
    .area-row input, .area-row select {
      margin-bottom: 0.25rem; font-size: 0.875rem; padding: 0.375rem 0.5rem;
    }
    .area-bounds { display: flex; gap: 0.25rem; }
    .area-bounds input { width: 70px; }
    .area-action { flex: 1; min-width: 200px; }
    .area-action input, .area-action select { width: 100%; }
    .area-img-settings {
      display: flex; gap: 0.375rem; align-items: center; flex-wrap: wrap;
      margin-top: 0.25rem; padding-top: 0.375rem; border-top: 1px dashed #d1d5db;
      width: 100%;
    }
    .area-img-settings label {
      font-size: 0.7rem; color: #6b7280; margin-bottom: 0; white-space: nowrap;
    }
    .area-img-settings input[type="text"],
    .area-img-settings input[type="number"] {
      width: 80px; padding: 0.25rem 0.375rem; font-size: 0.8rem; margin-bottom: 0;
    }
    .area-img-settings input[type="color"] {
      width: 32px; height: 28px; padding: 0; border: 1px solid #d1d5db;
      border-radius: 4px; cursor: pointer; margin-bottom: 0;
    }
    .preset-btns { display: flex; gap: 0.25rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
    .preset-btn {
      padding: 0.25rem 0.5rem; border: 1px solid #d1d5db; border-radius: 4px;
      background: white; font-size: 0.7rem; cursor: pointer;
    }
    .preset-btn:hover { background: #f3f4f6; }
    .bot-select-row { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 1rem; }
    .bot-select-row select { flex: 1; margin-bottom: 0; }
    .file-input-wrapper { position: relative; overflow: hidden; display: inline-block; }
    .file-input-wrapper input[type="file"] {
      position: absolute; left: 0; top: 0; opacity: 0; width: 100%; height: 100%;
      cursor: pointer; margin: 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <a href="/admin/sso" class="back-link">\u2190 \u7ba1\u7406\u30c8\u30c3\u30d7</a>
    <h1>Rich Menu \u7ba1\u7406</h1>
    <p class="desc">
      LINE WORKS Bot \u306e\u30ea\u30c3\u30c1\u30e1\u30cb\u30e5\u30fc\u3092\u7ba1\u7406\u3057\u307e\u3059\u3002Bot \u3092\u9078\u629e\u3057\u3066\u304b\u3089\u64cd\u4f5c\u3057\u3066\u304f\u3060\u3055\u3044\u3002<br>
      \u753b\u50cf\u8981\u4ef6: JPEG/PNG, 2500x843 \u307e\u305f\u306f 2500x1686 px, 1MB\u4ee5\u4e0b
    </p>

    <div id="msg"></div>

    <!-- Bot selector -->
    <div class="bot-select-row">
      <label style="margin-bottom:0;white-space:nowrap;">Bot:</label>
      <select id="bot-select" onchange="onBotSelect()">
        <option value="">\u9078\u629e...</option>
      </select>
    </div>

    <!-- Menu list -->
    <div id="menu-list"></div>

    <div class="divider"></div>

    <!-- Create menu form -->
    <div id="create-section" class="hidden">
      <h2 id="form-title">\u65b0\u898f\u30e1\u30cb\u30e5\u30fc\u4f5c\u6210</h2>

      <label for="menu-name">\u30e1\u30cb\u30e5\u30fc\u540d</label>
      <input type="text" id="menu-name" placeholder="\u4f8b: \u30a2\u30d7\u30ea\u30e1\u30cb\u30e5\u30fc">

      <label for="menu-size">\u30b5\u30a4\u30ba</label>
      <select id="menu-size" onchange="onSizeChange()">
        <option value="843">2500 x 843\uff08\u901a\u5e38\uff09</option>
        <option value="1686">2500 x 1686\uff08\u5927\uff09</option>
      </select>

      <label>\u30a8\u30ea\u30a2</label>
      <div class="field-desc">\u30bf\u30c3\u30d7\u9818\u57df\u3092\u8a2d\u5b9a\u3057\u307e\u3059\uff081\u301c20\u500b\uff09</div>

      <div class="preset-btns">
        <button class="preset-btn" onclick="addPreset('left')">\u5de6\u534a\u5206</button>
        <button class="preset-btn" onclick="addPreset('right')">\u53f3\u534a\u5206</button>
        <button class="preset-btn" onclick="addPreset('full')">\u5168\u4f53</button>
        <button class="preset-btn" onclick="addPreset('left3')">\u5de6 1/3</button>
        <button class="preset-btn" onclick="addPreset('center3')">\u4e2d 1/3</button>
        <button class="preset-btn" onclick="addPreset('right3')">\u53f3 1/3</button>
      </div>

      <div id="areas-container"></div>

      <button class="btn btn-gray btn-sm" onclick="addArea()" style="margin-bottom:1rem;">+ \u30a8\u30ea\u30a2\u8ffd\u52a0</button>

      <!-- Preview canvas -->
      <div id="preview-section" class="hidden" style="margin-bottom:1rem;">
        <label>\u30d7\u30ec\u30d3\u30e5\u30fc</label>
        <div style="border:1px solid #d1d5db;border-radius:6px;overflow:hidden;display:inline-block;">
          <canvas id="preview-canvas" style="width:100%;max-width:500px;height:auto;display:block;"></canvas>
        </div>
        <div style="margin-top:0.5rem;display:flex;gap:0.5rem;">
          <button class="btn btn-primary btn-sm" onclick="previewAll()">\u5168\u30a8\u30ea\u30a2\u63cf\u753b</button>
          <button id="upload-img-btn" class="btn btn-green btn-sm hidden" onclick="uploadPreviewImage()">\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9</button>
        </div>
      </div>

      <div class="form-actions">
        <button id="cancel-edit-btn" class="btn btn-gray hidden" onclick="cancelEdit()">\u30ad\u30e3\u30f3\u30bb\u30eb</button>
        <button id="create-btn" class="btn btn-primary" onclick="handleCreateMenu()" disabled>\u4f5c\u6210</button>
      </div>
    </div>
  </div>

  <!-- Delete confirmation modal -->
  <div id="delete-modal" class="modal-overlay hidden">
    <div class="modal">
      <h3>\u30e1\u30cb\u30e5\u30fc\u524a\u9664\u78ba\u8a8d</h3>
      <p>\u30e1\u30cb\u30e5\u30fc\u300c<span id="delete-target"></span>\u300d\u3092\u524a\u9664\u3057\u307e\u3059\u304b\uff1f</p>
      <div class="modal-actions">
        <button class="btn btn-gray" onclick="closeDeleteModal()">\u30ad\u30e3\u30f3\u30bb\u30eb</button>
        <button class="btn btn-red" onclick="handleDeleteMenu()">\u524a\u9664</button>
      </div>
    </div>
  </div>

  <script>
    let token = null;
    let selectedBotId = '';
    let deleteMenuId = '';
    let areas = [];
    let editingMenuId = null; // non-null when editing existing menu
    let currentMenus = []; // cached menu list for image generation
    let imageStatus = {}; // richmenuId → boolean (has image)

    function initAuth() {
      const adminMatch = document.cookie.match(/sso_admin_token=([^;]+)/);
      const sharedMatch = document.cookie.match(/logi_auth_token=([^;]+)/);
      token = (adminMatch && adminMatch[1]) || (sharedMatch && sharedMatch[1]) || null;
      if (!token) {
        const callbackUri = window.location.origin + '/admin/rich-menu/callback';
        window.location.replace('/login?redirect_uri=' + encodeURIComponent(callbackUri));
      }
    }

    async function api(path, body) {
      const res = await fetch(path, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token,
        },
        body: body ? JSON.stringify(body) : '{}',
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || 'API error');
      }
      return data;
    }

    async function apiFormData(path, formData) {
      const res = await fetch(path, {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || 'API error');
      }
      return data;
    }

    function showMsg(text, type) {
      const el = document.getElementById('msg');
      el.className = type;
      el.textContent = text;
      if (type === 'success') {
        setTimeout(() => { el.className = ''; el.textContent = ''; }, 3000);
      }
    }

    function escapeHtml(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function escapeAttr(s) {
      return String(s).replace(/'/g,"\\\\'").replace(/"/g,'&quot;');
    }

    // ========== Bot selector ==========

    async function loadBots() {
      try {
        const data = await api('/api/bot-config/list');
        const configs = (data.configs || []).filter(c => c.enabled);
        const sel = document.getElementById('bot-select');
        sel.innerHTML = '<option value="">\u9078\u629e...</option>';
        configs.forEach(c => {
          const opt = document.createElement('option');
          opt.value = c.id;
          opt.textContent = c.name + ' (Bot ID: ' + c.botId + ')';
          sel.appendChild(opt);
        });

        // Auto-select from URL param
        const params = new URLSearchParams(window.location.search);
        const botParam = params.get('bot');
        if (botParam && configs.some(c => c.id === botParam)) {
          sel.value = botParam;
          onBotSelect();
        }
      } catch (e) {
        showMsg('Bot \u4e00\u89a7\u306e\u53d6\u5f97\u306b\u5931\u6557: ' + e.message, 'error');
      }
    }

    async function onBotSelect() {
      selectedBotId = document.getElementById('bot-select').value;
      if (!selectedBotId) {
        document.getElementById('menu-list').innerHTML = '';
        document.getElementById('create-section').classList.add('hidden');
        return;
      }
      document.getElementById('create-section').classList.remove('hidden');
      await loadMenus();
    }

    // ========== Menu list ==========

    async function loadMenus() {
      if (!selectedBotId) return;
      const el = document.getElementById('menu-list');
      el.innerHTML = '<div class="loading">\u8aad\u307f\u8fbc\u307f\u4e2d...</div>';

      try {
        const data = await api('/api/richmenu/list', { botConfigId: selectedBotId });
        imageStatus = data.imageStatus || {};
        renderMenus(data.richmenus || [], data.defaultRichmenuId);
      } catch (e) {
        el.innerHTML = '<div class="error">' + escapeHtml(e.message) + '</div>';
      }
    }

    function renderMenus(menus, defaultId) {
      currentMenus = menus;
      const el = document.getElementById('menu-list');
      if (menus.length === 0) {
        el.innerHTML = '<div class="empty">\u30e1\u30cb\u30e5\u30fc\u304c\u3042\u308a\u307e\u305b\u3093</div>';
        return;
      }
      el.innerHTML = menus.map(m => {
        const isDefault = m.richmenuId === defaultId;
        const hasImage = !!imageStatus[m.richmenuId];
        const areasSummary = (m.areas || []).map((a, i) =>
          '<div style="font-size:0.75rem;color:#6b7280;">' +
          '\u30a8\u30ea\u30a2' + (i+1) + ': ' + escapeHtml(a.action.type) +
          (a.action.uri ? ' \u2192 ' + escapeHtml(a.action.uri) : '') +
          (a.action.label ? ' (' + escapeHtml(a.action.label) + ')' : '') +
          ' [' + a.bounds.x + ',' + a.bounds.y + ' ' + a.bounds.width + 'x' + a.bounds.height + ']' +
          '</div>'
        ).join('');

        return \`
        <div class="menu-card">
          <div class="menu-header">
            <span class="menu-name">\${escapeHtml(m.richmenuName)}</span>
            <div style="display:flex;gap:0.25rem;align-items:center;">
              \${hasImage
                ? '<span class="badge badge-green">\u753b\u50cf\u3042\u308a</span>'
                : '<span class="badge badge-yellow">\u753b\u50cf\u306a\u3057</span>'}
              \${isDefault ? '<span class="badge badge-green">\u30c7\u30d5\u30a9\u30eb\u30c8</span>' : ''}
              <span class="badge badge-blue">\${m.size.width}x\${m.size.height}</span>
            </div>
          </div>
          <div class="menu-detail">\${areasSummary}</div>
          <div class="menu-actions">
            <button class="btn btn-primary btn-sm" onclick="generateAndUploadImage('\${m.richmenuId}')">\u753b\u50cf\u751f\u6210</button>
            <div class="file-input-wrapper">
              <button class="btn btn-gray btn-sm">\u753b\u50cf\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9</button>
              <input type="file" accept="image/png,image/jpeg" onchange="handleImageUpload('\${m.richmenuId}', this)">
            </div>
            \${isDefault
              ? '<button class="btn btn-gray btn-sm" onclick="handleDeleteDefault()">\u30c7\u30d5\u30a9\u30eb\u30c8\u89e3\u9664</button>'
              : '<button class="btn btn-green btn-sm" onclick="handleSetDefault(\\'' + m.richmenuId + '\\')">\u30c7\u30d5\u30a9\u30eb\u30c8\u8a2d\u5b9a</button>'
            }
            <button class="btn btn-gray btn-sm" onclick="startEdit('\${m.richmenuId}')">\u7de8\u96c6</button>
            <button class="btn btn-red btn-sm" onclick="confirmDeleteMenu('\${m.richmenuId}', '\${escapeAttr(m.richmenuName)}')">\u524a\u9664</button>
          </div>
        </div>
      \`}).join('');
    }

    // ========== Menu actions ==========

    const AREA_COLORS = [
      '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
      '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
    ];

    async function generateAndUploadImage(richmenuId) {
      const menu = currentMenus.find(m => m.richmenuId === richmenuId);
      if (!menu) { showMsg('\u30e1\u30cb\u30e5\u30fc\u304c\u898b\u3064\u304b\u308a\u307e\u305b\u3093', 'error'); return; }
      const imgAreas = (menu.areas || []).map((a, i) => ({
        bounds: a.bounds,
        action: a.action,
        img: { text: a.action.label || '', textColor: '#ffffff', fontSize: 80, bgColor: AREA_COLORS[i % AREA_COLORS.length] },
      }));

      showMsg('\u753b\u50cf\u751f\u6210\u4e2d...', 'success');
      try {
        const canvas = document.createElement('canvas');
        canvas.width = menu.size.width;
        canvas.height = menu.size.height;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#f0f0f0';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        imgAreas.forEach((a, i) => drawArea(ctx, a, i));

        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
        const formData = new FormData();
        formData.append('botConfigId', selectedBotId);
        formData.append('richmenuId', richmenuId);
        formData.append('image', blob, 'richmenu.png');
        await apiFormData('/api/richmenu/image', formData);
        imageStatus[richmenuId] = true;
        showMsg('\u753b\u50cf\u3092\u751f\u6210\u30fb\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9\u3057\u307e\u3057\u305f', 'success');
        await loadMenus();
      } catch (e) {
        showMsg(e.message, 'error');
      }
    }

    async function handleImageUpload(richmenuId, input) {
      const file = input.files[0];
      if (!file) return;
      if (file.size > 1024 * 1024) {
        showMsg('\u753b\u50cf\u306f1MB\u4ee5\u4e0b\u306b\u3057\u3066\u304f\u3060\u3055\u3044', 'error');
        input.value = '';
        return;
      }
      showMsg('\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9\u4e2d...', 'success');
      try {
        const formData = new FormData();
        formData.append('botConfigId', selectedBotId);
        formData.append('richmenuId', richmenuId);
        formData.append('image', file);
        await apiFormData('/api/richmenu/image', formData);
        imageStatus[richmenuId] = true;
        showMsg('\u753b\u50cf\u3092\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9\u3057\u307e\u3057\u305f', 'success');
        await loadMenus();
      } catch (e) {
        showMsg(e.message, 'error');
      }
      input.value = '';
    }

    async function handleSetDefault(richmenuId) {
      try {
        await api('/api/richmenu/default/set', { botConfigId: selectedBotId, richmenuId });
        showMsg('\u30c7\u30d5\u30a9\u30eb\u30c8\u306b\u8a2d\u5b9a\u3057\u307e\u3057\u305f', 'success');
        await loadMenus();
      } catch (e) {
        showMsg(e.message, 'error');
      }
    }

    async function handleDeleteDefault() {
      try {
        await api('/api/richmenu/default/delete', { botConfigId: selectedBotId });
        showMsg('\u30c7\u30d5\u30a9\u30eb\u30c8\u3092\u89e3\u9664\u3057\u307e\u3057\u305f', 'success');
        await loadMenus();
      } catch (e) {
        showMsg(e.message, 'error');
      }
    }

    function confirmDeleteMenu(richmenuId, name) {
      deleteMenuId = richmenuId;
      document.getElementById('delete-target').textContent = name;
      document.getElementById('delete-modal').classList.remove('hidden');
    }

    function closeDeleteModal() {
      document.getElementById('delete-modal').classList.add('hidden');
      deleteMenuId = '';
    }

    async function handleDeleteMenu() {
      try {
        await api('/api/richmenu/delete', { botConfigId: selectedBotId, richmenuId: deleteMenuId });
        showMsg('\u524a\u9664\u3057\u307e\u3057\u305f', 'success');
        closeDeleteModal();
        await loadMenus();
      } catch (e) {
        showMsg(e.message, 'error');
        closeDeleteModal();
      }
    }

    // ========== Edit menu ==========

    function startEdit(richmenuId) {
      // Find the menu from the rendered list
      api('/api/richmenu/list', { botConfigId: selectedBotId }).then(data => {
        const menu = (data.richmenus || []).find(m => m.richmenuId === richmenuId);
        if (!menu) { showMsg('\u30e1\u30cb\u30e5\u30fc\u304c\u898b\u3064\u304b\u308a\u307e\u305b\u3093', 'error'); return; }

        editingMenuId = richmenuId;
        document.getElementById('menu-name').value = menu.richmenuName;
        document.getElementById('menu-size').value = String(menu.size.height);
        areas = (menu.areas || []).map((a, i) => ({
          bounds: { ...a.bounds },
          action: { ...a.action },
          img: { text: a.action.label || '', textColor: '#ffffff', fontSize: 80, bgColor: AREA_COLORS[i % AREA_COLORS.length] },
        }));
        renderAreas();
        validateCreateForm();

        document.getElementById('form-title').textContent = '\u30e1\u30cb\u30e5\u30fc\u7de8\u96c6';
        document.getElementById('create-btn').textContent = '\u66f4\u65b0';
        document.getElementById('cancel-edit-btn').classList.remove('hidden');
        document.getElementById('preview-section').classList.remove('hidden');
        document.getElementById('upload-img-btn').classList.remove('hidden');
        initPreviewCanvas();

        document.getElementById('create-section').scrollIntoView({ behavior: 'smooth' });
      }).catch(e => showMsg(e.message, 'error'));
    }

    function cancelEdit() {
      editingMenuId = null;
      document.getElementById('menu-name').value = '';
      areas = [];
      renderAreas();
      validateCreateForm();
      document.getElementById('form-title').textContent = '\u65b0\u898f\u30e1\u30cb\u30e5\u30fc\u4f5c\u6210';
      document.getElementById('create-btn').textContent = '\u4f5c\u6210';
      document.getElementById('cancel-edit-btn').classList.add('hidden');
      document.getElementById('preview-section').classList.add('hidden');
      document.getElementById('upload-img-btn').classList.add('hidden');
    }

    // ========== Create menu ==========

    function getMenuHeight() {
      return parseInt(document.getElementById('menu-size').value) || 843;
    }

    function onSizeChange() {
      // Update area bounds hints when size changes
      validateCreateForm();
    }

    function addArea(preset) {
      const h = getMenuHeight();
      let bounds = { x: 0, y: 0, width: 2500, height: h };
      if (preset === 'left') bounds = { x: 0, y: 0, width: 1250, height: h };
      else if (preset === 'right') bounds = { x: 1250, y: 0, width: 1250, height: h };
      else if (preset === 'left3') bounds = { x: 0, y: 0, width: 833, height: h };
      else if (preset === 'center3') bounds = { x: 833, y: 0, width: 834, height: h };
      else if (preset === 'right3') bounds = { x: 1667, y: 0, width: 833, height: h };

      const area = {
        bounds,
        action: { type: 'uri', label: '', uri: '' },
        img: { text: '', textColor: '#ffffff', fontSize: 80, bgColor: AREA_COLORS[areas.length % AREA_COLORS.length] },
      };
      areas.push(area);
      renderAreas();
      validateCreateForm();
    }

    function addPreset(type) {
      addArea(type);
    }

    function removeArea(index) {
      areas.splice(index, 1);
      renderAreas();
      validateCreateForm();
    }

    function renderAreas() {
      const container = document.getElementById('areas-container');
      container.innerHTML = areas.map((a, i) => \`
        <div class="area-row">
          <div>
            <div style="font-size:0.75rem;color:#6b7280;margin-bottom:0.25rem;">\u30a8\u30ea\u30a2 \${i+1}</div>
            <div class="area-bounds">
              <input type="number" placeholder="x" value="\${a.bounds.x}" onchange="updateArea(\${i},'x',this.value)" title="X\u5ea7\u6a19">
              <input type="number" placeholder="y" value="\${a.bounds.y}" onchange="updateArea(\${i},'y',this.value)" title="Y\u5ea7\u6a19">
              <input type="number" placeholder="w" value="\${a.bounds.width}" onchange="updateArea(\${i},'w',this.value)" title="\u5e45">
              <input type="number" placeholder="h" value="\${a.bounds.height}" onchange="updateArea(\${i},'h',this.value)" title="\u9ad8\u3055">
            </div>
          </div>
          <div class="area-action">
            <select onchange="updateAreaType(\${i},this.value)">
              <option value="uri" \${a.action.type==='uri'?'selected':''}>URI</option>
              <option value="message" \${a.action.type==='message'?'selected':''}>\u30e1\u30c3\u30bb\u30fc\u30b8</option>
              <option value="postback" \${a.action.type==='postback'?'selected':''}>\u30dd\u30b9\u30c8\u30d0\u30c3\u30af</option>
            </select>
            <input type="text" placeholder="\u30e9\u30d9\u30eb\uff08PC\u8868\u793a\u7528\uff09" value="\${escapeHtml(a.action.label||'')}" oninput="updateAreaField(\${i},'label',this.value)">
            \${a.action.type === 'uri'
              ? '<input type="text" placeholder="https://..." value="' + escapeHtml(a.action.uri||'') + '" oninput="updateAreaField(' + i + ',\\'uri\\',this.value)">'
              : a.action.type === 'message'
              ? '<input type="text" placeholder="\u30e1\u30c3\u30bb\u30fc\u30b8\u30c6\u30ad\u30b9\u30c8" value="' + escapeHtml(a.action.text||'') + '" oninput="updateAreaField(' + i + ',\\'text\\',this.value)">'
              : '<input type="text" placeholder="postback data" value="' + escapeHtml(a.action.data||'') + '" oninput="updateAreaField(' + i + ',\\'data\\',this.value)">'}
          </div>
          <button class="btn btn-red btn-sm" onclick="removeArea(\${i})" style="align-self:flex-start;margin-top:1.25rem;">\u00d7</button>
          <div class="area-img-settings">
            <label>\u753b\u50cf:</label>
            <input type="text" placeholder="\u30c6\u30ad\u30b9\u30c8" value="\${escapeHtml(a.img?.text||'')}" oninput="updateImg(\${i},'text',this.value)" style="width:120px;" title="\u753b\u50cf\u30c6\u30ad\u30b9\u30c8">
            <label>\u8272</label>
            <input type="color" value="\${a.img?.textColor||'#ffffff'}" oninput="updateImg(\${i},'textColor',this.value)" title="\u30c6\u30ad\u30b9\u30c8\u8272">
            <label>px</label>
            <input type="number" value="\${a.img?.fontSize||80}" oninput="updateImg(\${i},'fontSize',parseInt(this.value)||80)" style="width:60px;" title="\u30d5\u30a9\u30f3\u30c8\u30b5\u30a4\u30ba">
            <label>\u80cc\u666f</label>
            <input type="color" value="\${a.img?.bgColor||'#3b82f6'}" oninput="updateImg(\${i},'bgColor',this.value)" title="\u80cc\u666f\u8272">
            <button class="btn btn-primary btn-sm" onclick="previewArea(\${i})" style="margin-left:auto;padding:0.2rem 0.5rem;font-size:0.7rem;">\u63cf\u753b</button>
          </div>
        </div>
      \`).join('');
    }

    function updateArea(index, field, value) {
      const v = parseInt(value) || 0;
      if (field === 'x') areas[index].bounds.x = v;
      else if (field === 'y') areas[index].bounds.y = v;
      else if (field === 'w') areas[index].bounds.width = v;
      else if (field === 'h') areas[index].bounds.height = v;
      validateCreateForm();
    }

    function updateAreaType(index, type) {
      areas[index].action = { type, label: areas[index].action.label || '' };
      renderAreas();
      validateCreateForm();
    }

    function updateAreaField(index, field, value) {
      areas[index].action[field] = value;
      validateCreateForm();
    }

    function updateImg(index, field, value) {
      if (!areas[index].img) areas[index].img = { text: '', textColor: '#ffffff', fontSize: 80, bgColor: '#3b82f6' };
      areas[index].img[field] = value;
    }

    // ========== Preview Canvas ==========

    function initPreviewCanvas() {
      const canvas = document.getElementById('preview-canvas');
      const menu = currentMenus.find(m => m.richmenuId === editingMenuId);
      const w = menu ? menu.size.width : 2500;
      const h = menu ? menu.size.height : getMenuHeight();
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#f0f0f0';
      ctx.fillRect(0, 0, w, h);
    }

    function drawArea(ctx, a, i) {
      const img = a.img || {};
      const bgColor = img.bgColor || AREA_COLORS[i % AREA_COLORS.length];
      const textColor = img.textColor || '#ffffff';
      const fontSize = img.fontSize || 80;
      const text = img.text || a.action.label || a.action.type || ('Area ' + (i + 1));
      const b = a.bounds;

      ctx.fillStyle = bgColor;
      ctx.fillRect(b.x, b.y, b.width, b.height);

      ctx.strokeStyle = 'rgba(0,0,0,0.2)';
      ctx.lineWidth = 4;
      ctx.strokeRect(b.x + 2, b.y + 2, b.width - 4, b.height - 4);

      ctx.fillStyle = textColor;
      ctx.font = 'bold ' + fontSize + 'px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(text, b.x + b.width / 2, b.y + b.height / 2);
    }

    function previewArea(index) {
      const canvas = document.getElementById('preview-canvas');
      if (!canvas.width || canvas.width === 300) initPreviewCanvas();
      const ctx = canvas.getContext('2d');
      const a = areas[index];
      // Clear this area first
      ctx.fillStyle = '#f0f0f0';
      ctx.fillRect(a.bounds.x, a.bounds.y, a.bounds.width, a.bounds.height);
      drawArea(ctx, a, index);
      document.getElementById('preview-section').classList.remove('hidden');
      document.getElementById('upload-img-btn').classList.remove('hidden');
    }

    function previewAll() {
      initPreviewCanvas();
      const canvas = document.getElementById('preview-canvas');
      const ctx = canvas.getContext('2d');
      areas.forEach((a, i) => drawArea(ctx, a, i));
    }

    async function uploadPreviewImage() {
      if (!editingMenuId) { showMsg('\u7de8\u96c6\u30e2\u30fc\u30c9\u3067\u306e\u307f\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9\u53ef\u80fd', 'error'); return; }
      const canvas = document.getElementById('preview-canvas');
      showMsg('\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9\u4e2d...', 'success');
      try {
        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
        const formData = new FormData();
        formData.append('botConfigId', selectedBotId);
        formData.append('richmenuId', editingMenuId);
        formData.append('image', blob, 'richmenu.png');
        await apiFormData('/api/richmenu/image', formData);
        imageStatus[editingMenuId] = true;
        showMsg('\u753b\u50cf\u3092\u30a2\u30c3\u30d7\u30ed\u30fc\u30c9\u3057\u307e\u3057\u305f', 'success');
        await loadMenus();
      } catch (e) {
        showMsg(e.message, 'error');
      }
    }

    function validateCreateForm() {
      const name = document.getElementById('menu-name').value.trim();
      const valid = name && areas.length > 0;
      document.getElementById('create-btn').disabled = !valid;
    }

    async function handleCreateMenu() {
      const btn = document.getElementById('create-btn');
      const isEdit = !!editingMenuId;
      btn.disabled = true;
      btn.textContent = isEdit ? '\u66f4\u65b0\u4e2d...' : '\u4f5c\u6210\u4e2d...';

      const h = getMenuHeight();
      const menuData = {
        botConfigId: selectedBotId,
        richmenuName: document.getElementById('menu-name').value.trim(),
        size: { width: 2500, height: h },
        areas: areas.map(a => ({
          bounds: a.bounds,
          action: a.action,
        })),
      };

      try {
        const result = await api('/api/richmenu/create', menuData);
        const newMenuId = result.richmenuId;

        if (isEdit) {
          // Generate and upload image to the NEW menu (edit = create new + delete old, so image must be re-uploaded)
          if (newMenuId && areas.length > 0) {
            try {
              const canvas = document.createElement('canvas');
              canvas.width = menuData.size.width;
              canvas.height = menuData.size.height;
              const ctx = canvas.getContext('2d');
              ctx.fillStyle = '#f0f0f0';
              ctx.fillRect(0, 0, canvas.width, canvas.height);
              areas.forEach((a, i) => drawArea(ctx, a, i));
              const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
              const formData = new FormData();
              formData.append('botConfigId', selectedBotId);
              formData.append('richmenuId', newMenuId);
              formData.append('image', blob, 'richmenu.png');
              await apiFormData('/api/richmenu/image', formData);
            } catch (imgErr) {
              console.error('Image re-upload to new menu failed:', imgErr);
            }
          }
          try {
            await api('/api/richmenu/delete', { botConfigId: selectedBotId, richmenuId: editingMenuId });
          } catch (delErr) {
            console.error('Old menu delete failed:', delErr);
          }
        }
        showMsg(isEdit ? '\u30e1\u30cb\u30e5\u30fc\u3092\u66f4\u65b0\u3057\u307e\u3057\u305f' : '\u30e1\u30cb\u30e5\u30fc\u3092\u4f5c\u6210\u3057\u307e\u3057\u305f', 'success');
        cancelEdit();
        await loadMenus();
      } catch (e) {
        showMsg(e.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = isEdit ? '\u66f4\u65b0' : '\u4f5c\u6210';
      }
    }

    // Init
    document.getElementById('menu-name').addEventListener('input', validateCreateForm);

    initAuth();
    loadBots();
  </script>
</body>
</html>`;
}
