/* Shared helpers for all panel pages: API wrapper, toast, modals, escaping. */

async function api(action, body = {}, redirect401 = true) {
  const res = await fetch('/api/web/' + action, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body)
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty */ }
  if (!data.success && (res.status === 401) && redirect401) {
    window.location.href = '/';
    throw new Error('未登录');
  }
  return data;
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function toast(text, ok = true) {
  let host = document.getElementById('toast');
  if (!host) {
    host = document.createElement('div');
    host.id = 'toast';
    document.body.appendChild(host);
  }
  const item = document.createElement('div');
  item.className = 'toast-item ' + (ok ? 'ok' : 'err');
  item.textContent = text;
  host.appendChild(item);
  setTimeout(() => { item.style.opacity = '0'; item.style.transition = 'opacity .3s'; }, 3200);
  setTimeout(() => item.remove(), 3600);
}

function openModal(id) { document.getElementById(id).classList.add('show'); }

function closeModal(id) {
  const el = document.getElementById(id);
  el.classList.add('closing');
  setTimeout(() => { el.classList.remove('show', 'closing'); }, 200);
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'msg show ' + (ok ? 'success' : 'error');
  if (ok) setTimeout(() => el.classList.remove('show'), 2500);
}

function fmtDate(iso) {
  if (!iso) return '—';
  return iso.replace('T', ' ').slice(0, 19);
}

function statusBadge(status) {
  const map = {
    active: ['badge-success', '正常'],
    banned: ['badge-danger', '已封禁'],
    temp_banned: ['badge-warning', '暂封']
  };
  const m = map[status] || ['badge-muted', status];
  return '<span class="badge ' + m[0] + '">' + m[1] + '</span>';
}

/* Java String.hashCode, for cloud-constant keys */
function javaHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (31 * h + str.charCodeAt(i)) | 0;
  return h;
}

async function guardAdmin() {
  try {
    const me = await api('me');
    if (!me.success || !me.data || !me.data.is_admin) {
      window.location.href = '/panel';
      return null;
    }
    return me.data;
  } catch (e) { return null; }
}
