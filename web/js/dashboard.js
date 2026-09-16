/* Admin dashboard logic. */

const $ = (id) => document.getElementById(id);
let currentUser = null; // for modal context

/* ---------------- tabs ---------------- */
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    ['users', 'cards', 'sessions', 'settings', 'cloud', 'logs'].forEach(name => {
      const el = $('tab-' + name);
      if (el) el.style.display = (btn.dataset.tab === name) ? '' : 'none';
    });
    loadTab(btn.dataset.tab);
  });
});

function loadTab(name) {
  if (name === 'users') loadUsers();
  else if (name === 'cards') loadCards();
  else if (name === 'sessions') loadSessions();
  else if (name === 'settings') loadSettings();
  else if (name === 'cloud') loadCloud();
  else if (name === 'logs') loadLogs();
}

/* ---------------- stats ---------------- */
async function loadStats() {
  const res = await api('admin/stats');
  if (!res.success) return;
  $('st-users').textContent = res.data.total_users;
  $('st-online').textContent = res.data.online_users;
  $('st-cards').textContent = res.data.unused_cards;
  $('st-banned').textContent = res.data.banned_users;
}

/* ---------------- users ---------------- */
async function loadUsers() {
  const q = $('user-search').value.trim();
  const res = await api('admin/users', { q });
  const body = $('users-body');
  if (!res.success) { body.innerHTML = '<tr><td colspan="8">加载失败</td></tr>'; return; }
  if (!res.data.users.length) {
    body.innerHTML = '<tr><td colspan="8" style="color:rgba(255,255,255,0.4)">暂无用户</td></tr>';
    return;
  }
  body.innerHTML = res.data.users.map(u => `
    <tr>
      <td>${u.uid}</td>
      <td><strong>${esc(u.username)}</strong>${u.suspected ? ' <span class="badge badge-warning">风控</span>' : ''}</td>
      <td>${esc(u.qq) || '—'}</td>
      <td>${fmtDate(u.expired_at)}</td>
      <td>${statusBadge(u.status)}</td>
      <td class="mono">${esc(u.hwid_host || '未绑定')}</td>
      <td>${fmtDate(u.last_login)}</td>
      <td><div class="actions">
        <button class="btn btn-outline btn-sm" onclick="openExpiry('${esc(u.username)}')">到期</button>
        <button class="btn btn-outline btn-sm" onclick="openPasswd('${esc(u.username)}')">改密</button>
        <button class="btn btn-outline btn-sm" onclick="resetHwid('${esc(u.username)}')">重置HWID</button>
        <button class="btn ${u.status === 'banned' ? 'btn-outline' : 'btn-danger'} btn-sm"
                onclick="toggleBan('${esc(u.username)}', ${u.status === 'banned'})">
                ${u.status === 'banned' ? '解封' : '封禁'}</button>
        <button class="btn btn-danger btn-sm" onclick="delUser('${esc(u.username)}')">删除</button>
      </div></td>
    </tr>`).join('');
}

$('user-search').addEventListener('input', () => {
  clearTimeout(window.__searchTimer);
  window.__searchTimer = setTimeout(loadUsers, 300);
});

function openExpiry(username) {
  currentUser = username;
  $('exp-user').textContent = username;
  $('exp-days').value = '';
  $('exp-date').value = '';
  openModal('modal-expiry');
}
$('exp-submit').addEventListener('click', async () => {
  const days = $('exp-days').value.trim();
  const date = $('exp-date').value.trim();
  if (!days && !date) return toast('请填写天数或日期', false);
  const body = { username: currentUser, expired_at: days || date };
  const res = await api('admin/user/set-expiry', body);
  toast(res.message, res.success);
  if (res.success) { closeModal('modal-expiry'); loadUsers(); loadStats(); }
});

function openPasswd(username) {
  currentUser = username;
  $('pw-user').textContent = username;
  $('pw-new').value = '';
  openModal('modal-passwd');
}
$('pw-submit').addEventListener('click', async () => {
  const pwd = $('pw-new').value;
  if (pwd.length < 6) return toast('密码至少 6 位', false);
  const res = await api('admin/user/reset-password', { username: currentUser, password: md5(pwd) });
  toast(res.message, res.success);
  if (res.success) closeModal('modal-passwd');
});

async function resetHwid(username) {
  if (!confirm(`重置 ${username} 的 HWID 绑定？该用户需要重新验证机器码。`)) return;
  const res = await api('admin/user/reset-hwid', { username });
  toast(res.message, res.success);
  loadUsers();
}

async function toggleBan(username, banned) {
  const res = await api('admin/user/ban', { username, banned });
  toast(res.message, res.success);
  loadUsers(); loadStats();
}

async function delUser(username) {
  if (!confirm(`确定删除用户 ${username}？此操作不可恢复。`)) return;
  const res = await api('admin/user/delete', { username });
  toast(res.message, res.success);
  loadUsers(); loadStats();
}

$('btn-create-user').addEventListener('click', () => {
  $('nu-username').value = ''; $('nu-password').value = '';
  $('nu-qq').value = ''; $('nu-days').value = '';
  openModal('modal-create');
});
$('nu-submit').addEventListener('click', async () => {
  const username = $('nu-username').value.trim();
  const password = $('nu-password').value;
  if (username.length < 3) return toast('用户名至少 3 位', false);
  if (password.length < 6) return toast('密码至少 6 位', false);
  const body = { username, password: md5(password), qq: $('nu-qq').value.trim() };
  const days = parseInt($('nu-days').value, 10);
  const res = await api('admin/user/create', body);
  if (!res.success) return toast(res.message, false);
  if (days > 0) {
    await api('admin/user/set-expiry', { username, expired_at: String(days) });
  }
  toast('用户已创建', true);
  closeModal('modal-create');
  loadUsers(); loadStats();
});

/* ---------------- cards ---------------- */
async function loadCards() {
  const res = await api('admin/cards');
  const body = $('cards-body');
  if (!res.success) { body.innerHTML = '<tr><td colspan="6">加载失败</td></tr>'; return; }
  if (!res.data.cards.length) {
    body.innerHTML = '<tr><td colspan="6" style="color:rgba(255,255,255,0.4)">暂无卡密</td></tr>';
    return;
  }
  body.innerHTML = res.data.cards.map(c => `
    <tr>
      <td class="mono">${esc(c.card_key)}</td>
      <td>${c.days} 天</td>
      <td>${c.used_by ? '<span class="badge badge-muted">已使用</span>' : '<span class="badge badge-success">未使用</span>'}</td>
      <td>${esc(c.used_by) || '—'}</td>
      <td>${fmtDate(c.created_at)}</td>
      <td>${c.used_by ? '' :
        `<button class="btn btn-danger btn-sm" onclick="delCard(${c.id})">删除</button>`}</td>
    </tr>`).join('');
}

async function delCard(id) {
  const res = await api('admin/cards/delete', { id });
  toast(res.message, res.success);
  loadCards();
}

$('btn-gen-card').addEventListener('click', () => openModal('modal-gencard'));
$('gc-submit').addEventListener('click', async () => {
  const res = await api('admin/cards/generate', {
    prefix: $('gc-prefix').value.trim() || 'PS',
    amount: parseInt($('gc-amount').value, 10) || 1,
    days: parseInt($('gc-days').value, 10) || 30
  });
  if (!res.success) return toast(res.message, false);
  closeModal('modal-gencard');
  toast(res.message, true);
  const keys = res.data.cards.join('\n');
  try { await navigator.clipboard.writeText(keys); toast('卡密已复制到剪贴板', true); } catch (e) {}
  loadCards(); loadStats();
});

/* ---------------- sessions ---------------- */
async function loadSessions() {
  const res = await api('admin/sessions');
  const body = $('sessions-body');
  if (!res.success) { body.innerHTML = '<tr><td colspan="6">加载失败</td></tr>'; return; }
  if (!res.data.sessions.length) {
    body.innerHTML = '<tr><td colspan="6" style="color:rgba(255,255,255,0.4)">当前没有在线会话</td></tr>';
    return;
  }
  body.innerHTML = res.data.sessions.map(s => `
    <tr>
      <td><strong>${esc(s.username)}</strong>${s.kicked ? ' <span class="badge badge-danger">已踢</span>' : ''}</td>
      <td class="mono">${esc(s.ip)}</td>
      <td>${esc(s.version) || '—'}</td>
      <td>${esc(s.qq) || '—'}</td>
      <td>${fmtDate(s.last_seen)}</td>
      <td>${s.kicked ? '' :
        `<button class="btn btn-danger btn-sm" onclick="kick('${esc(s.jwt)}')">踢下线</button>`}</td>
    </tr>`).join('');
}

async function kick(jwt) {
  if (!confirm('踢下线？客户端会在下次心跳（≤4 分钟）时退出。')) return;
  const res = await api('admin/sessions/kick', { jwt });
  toast(res.message, res.success);
  loadSessions();
}
$('btn-refresh-sessions').addEventListener('click', loadSessions);

/* ---------------- settings ---------------- */
async function loadSettings() {
  const res = await api('admin/settings');
  if (!res.success) return;
  $('set-maint').checked = res.data.maintenance;
  $('set-stopped').checked = res.data.service_stopped;
  $('set-minver').value = res.data.min_version;
  $('set-notice').value = res.data.announcement;
}
$('btn-save-settings').addEventListener('click', async () => {
  const res = await api('admin/settings/save', {
    maintenance: $('set-maint').checked,
    service_stopped: $('set-stopped').checked,
    min_version: $('set-minver').value.trim(),
    announcement: $('set-notice').value
  });
  toast(res.message, res.success);
});

/* ---------------- cloud constants ---------------- */
async function loadCloud() {
  const res = await api('admin/cloud');
  const body = $('cloud-body');
  if (!res.success) { body.innerHTML = '<tr><td colspan="4">加载失败</td></tr>'; return; }
  if (!res.data.constants.length) {
    body.innerHTML = '<tr><td colspan="4" style="color:rgba(255,255,255,0.4)">暂无云常量</td></tr>';
    return;
  }
  body.innerHTML = res.data.constants.map(c => `
    <tr>
      <td>${esc(c.source) || '—'}</td>
      <td class="mono">${esc(c.hash)}</td>
      <td>${c.strings.map(s => '<span class="badge badge-info">' + esc(s) + '</span>').join(' ')}</td>
      <td><button class="btn btn-danger btn-sm" onclick="delCloud(${c.id})">删除</button></td>
    </tr>`).join('');
}

async function delCloud(id) {
  const res = await api('admin/cloud/delete', { id });
  toast(res.message, res.success);
  loadCloud();
}

$('btn-cloud-add').addEventListener('click', () => {
  $('ca-source').value = ''; $('ca-strings').value = '';
  $('ca-hash-preview').textContent = 'hash: —';
  openModal('modal-cloudadd');
});
$('ca-source').addEventListener('input', () => {
  const v = $('ca-source').value;
  $('ca-hash-preview').textContent = 'hash: ' + (v ? javaHash(v) : '—');
});
$('ca-submit').addEventListener('click', async () => {
  const strings = $('ca-strings').value.split('\n').map(s => s.trim()).filter(Boolean);
  const res = await api('admin/cloud/add', { source: $('ca-source').value.trim(), strings });
  toast(res.message, res.success);
  if (res.success) { closeModal('modal-cloudadd'); loadCloud(); }
});

/* ---------------- logs ---------------- */
const LOG_COLORS = {
  login: 'badge-success', 'login-fail': 'badge-danger', risk: 'badge-warning',
  register: 'badge-info', card: 'badge-info', user: 'badge-muted',
  'web-login': 'badge-success', 'web-login-fail': 'badge-danger',
  'first-info': 'badge-info', 'hwid-bind': 'badge-info', admin: 'badge-muted', error: 'badge-danger'
};
async function loadLogs() {
  const res = await api('admin/logs');
  const body = $('logs-body');
  if (!res.success) { body.innerHTML = '<tr><td colspan="5">加载失败</td></tr>'; return; }
  if (!res.data.logs.length) {
    body.innerHTML = '<tr><td colspan="5" style="color:rgba(255,255,255,0.4)">暂无日志</td></tr>';
    return;
  }
  body.innerHTML = res.data.logs.map(l => `
    <tr>
      <td>${fmtDate(l.ts)}</td>
      <td><span class="badge ${LOG_COLORS[l.type] || 'badge-muted'}">${esc(l.type)}</span></td>
      <td>${esc(l.username) || '—'}</td>
      <td class="mono">${esc(l.ip) || '—'}</td>
      <td class="mono">${esc(l.detail)}</td>
    </tr>`).join('');
}
$('btn-refresh-logs').addEventListener('click', loadLogs);

/* ---------------- boot ---------------- */
$('logout-btn').addEventListener('click', async () => {
  await api('logout');
  window.location.href = '/';
});

(async function boot() {
  const me = await guardAdmin();
  if (!me) return;
  $('who').textContent = me.username;
  loadStats();
  loadUsers();
  setInterval(loadStats, 30000);
})();
