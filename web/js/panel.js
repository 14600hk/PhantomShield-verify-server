/* User self-service panel logic. */

const $ = (id) => document.getElementById(id);

async function loadInfo() {
  const res = await api('user/info');
  if (!res.success) return;
  const d = res.data;
  $('who').textContent = d.username;

  let expiredBadge;
  if (!d.expired_at) {
    expiredBadge = '<span class="badge badge-danger">无订阅</span>';
  } else if (new Date(d.expired_at.replace('T', ' ')) < new Date()) {
    expiredBadge = '<span class="badge badge-warning">已过期</span>';
  } else {
    expiredBadge = '<span class="badge badge-success">有效</span>';
  }

  $('info-body').innerHTML = `
    <tr><td style="width:140px;color:rgba(255,255,255,0.5)">用户名</td><td><strong>${esc(d.username)}</strong></td></tr>
    <tr><td style="color:rgba(255,255,255,0.5)">QQ</td><td>${esc(d.qq) || '—'}</td></tr>
    <tr><td style="color:rgba(255,255,255,0.5)">订阅状态</td><td>${expiredBadge} <span class="badge badge-info">${esc(d.role)}</span></td></tr>
    <tr><td style="color:rgba(255,255,255,0.5)">订阅到期</td><td>${fmtDate(d.expired_at)}</td></tr>
    <tr><td style="color:rgba(255,255,255,0.5)">机器码绑定</td><td>${d.hwid_bound ? '<span class="badge badge-success">已绑定 (' + esc(d.hwid_host) + ')</span>' : '<span class="badge badge-muted">首次登录时自动绑定</span>'}</td></tr>
    <tr><td style="color:rgba(255,255,255,0.5)">最后登录</td><td>${fmtDate(d.last_login)}</td></tr>`;

  $('notice').textContent = d.announcement ? '公告：' + d.announcement : '';
}

$('redeem-btn').addEventListener('click', async () => {
  const card = $('redeem-card').value.trim().toUpperCase();
  if (!card) return showMsg('redeem-msg', '请输入卡密', false);
  $('redeem-btn').disabled = true;
  try {
    const res = await api('user/redeem', { card });
    showMsg('redeem-msg', res.message, res.success);
    if (res.success) { $('redeem-card').value = ''; loadInfo(); }
  } finally { $('redeem-btn').disabled = false; }
});

$('pw-btn').addEventListener('click', async () => {
  const oldP = $('pw-old').value, newP = $('pw-new').value;
  if (newP.length < 6) return showMsg('pw-msg', '新密码至少 6 位', false);
  $('pw-btn').disabled = true;
  try {
    const res = await api('user/change-password', { old: md5(oldP), new: md5(newP) });
    showMsg('pw-msg', res.message, res.success);
    if (res.success) { $('pw-old').value = ''; $('pw-new').value = ''; }
  } finally { $('pw-btn').disabled = false; }
});

$('logout-btn').addEventListener('click', async () => {
  await api('logout');
  window.location.href = '/';
});

(async function boot() {
  try {
    const me = await api('me');
    if (!me.success || !me.data) { window.location.href = '/'; return; }
    if (me.data.is_admin) {
      // admins keep the shortcut; normal users just see the panel
    }
  } catch (e) { return; }
  loadInfo();
})();
