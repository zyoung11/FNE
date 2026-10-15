const LEVELS = [
  ['standard', '标准 128k'],
  ['higher', '较高 192k'],
  ['exhigh', '极高 320k'],
  ['lossless', '无损 FLAC'],
  ['hires', 'Hi-Res'],
  ['jyeffect', '高清环绕声'],
  ['sky', '沉浸环绕声'],
  ['dolby', '杜比全景声'],
  ['jymaster', '超清母带']
];
const LEVEL_NAME = Object.fromEntries(LEVELS);
const APP_MODE = document.body.dataset.mode || 'download';
let status = {};
let selected = new Map();
let songOrigin = new Map();
let selSeq = 0;
let navStack = [];
let listKind = 'song';
let loginTimer = null;
let jobTimer = null;

async function fetchJSON(url, options) {
  const resp = await fetch(url, options);
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
  return data;
}

function groupSelected() {
  const groups = new Map();
  selected.forEach((s) => {
    const o = songOrigin.get(s.id) || { kind: 'root', name: '', pos: 0 };
    const key = o.kind + '\u0000' + o.name;
    if (!groups.has(key)) groups.set(key, { kind: o.kind, name: o.name, rows: [] });
    groups.get(key).rows.push({ s, pos: o.pos });
  });
  groups.forEach((g) => g.rows.sort((a, b) => a.pos - b.pos));
  return Array.from(groups.values());
}

function sanitizePathName(name) {
  return String(name).replace(/[\\/:*?"<>|]/g, '_').trim();
}

function esc(text) {
  const d = document.createElement('div');
  d.textContent = text == null ? '' : text;
  return d.innerHTML;
}

function fmtDur(ms) {
  const s = Math.round((ms || 0) / 1000);
  return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
}

function showView(id) {
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  document.getElementById('hintbar').style.display = id === 'viewLogin' ? 'flex' : 'none';
  window.scrollTo(0, 0);
  if (id === 'viewSearch') {
    document.getElementById('keyword').focus();
  }
  scheduleSbUpdate();
}

async function refreshStatus() {
  try {
    status = await fetchJSON('/api/status');
    const cell = document.getElementById('authCell');
    if (status.loggedIn) {
      cell.textContent = status.nickname || '已登录';
      cell.classList.remove('accent');
    } else {
      cell.textContent = '未登录';
      cell.classList.add('accent');
    }
    if (status.defaultFolder) {
      document.getElementById('folderInput').value = status.defaultFolder;
      document.getElementById('folderInfo').textContent = status.defaultFolder;
    }
    document.getElementById('browseBtn').style.display = status.platform === 'windows' ? '' : 'none';
  } catch (e) {
    document.getElementById('authCell').textContent = '状态异常';
  }
}

async function startLogin() {
  try {
    const data = await fetchJSON('/api/login/qr', { method: 'POST' });
    document.getElementById('qrImage').src = '/api/qr.png?key=' + encodeURIComponent(data.key);
    setLoginState('等待扫码');
    if (loginTimer) clearInterval(loginTimer);
    loginTimer = setInterval(() => checkLogin(data.key), 2000);
  } catch (e) {
    if (loginTimer) { clearInterval(loginTimer); loginTimer = null; }
    setLoginState('连接已断开');
  }
}

const loginHint = '使用网易云音乐 APP 扫码登录 · r 刷新 · s 跳过';

function setLoginState(state) {
  if (!document.getElementById('viewLogin').classList.contains('active')) return;
  document.getElementById('hintText').textContent = state ? loginHint + ' · ' + state : loginHint;
}

document.addEventListener('keydown', (e) => {
  const modal = document.getElementById('logoutModal');
  if (modal && modal.style.display !== 'none') {
    if (e.key === 'Escape') { e.preventDefault(); closeLogoutModal(); }
    return;
  }
  const active = document.querySelector('.view.active').id;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (active === 'viewLogin') {
    if (e.key === 'r') { e.preventDefault(); startLogin(); }
    if (e.key === 's' && APP_MODE !== 'convert') { e.preventDefault(); skipLogin(); }
    return;
  }
  if (e.key === 'Enter') {
    if (active === 'viewQuality') { e.preventDefault(); goFolder(); }
    else if (active === 'viewFolder') { e.preventDefault(); startDownload(); }
    else if (active === 'viewPlaylistDetail') { e.preventDefault(); playlistMainAction(); }
  }
});

async function checkLogin(key) {
  try {
    const data = await fetchJSON('/api/login/check?key=' + encodeURIComponent(key));
    if (data.code === 803) {
      const saved = data.saved !== false;
      setLoginState(saved ? ('登录成功 · 已保存 ' + (status.cookiePath || '')) : '登录成功 · cookie 保存失败');
      clearInterval(loginTimer);
      loginTimer = null;
      await refreshStatus();
      if (APP_MODE === 'convert') loadPlaylists();
      else showView('viewSearch');
    } else if (data.code === 802) {
      setLoginState('已扫码 · 请在手机上确认');
    } else if (data.code === 800) {
      setLoginState('二维码已过期 · 按 r 刷新');
      clearInterval(loginTimer);
      loginTimer = null;
    }
  } catch (e) {
    clearInterval(loginTimer);
    loginTimer = null;
    setLoginState('连接已断开');
  }
}

function authClick() {
  if (status.loggedIn) {
    openLogoutModal();
  } else {
    showView('viewLogin');
  }
}

function openLogoutModal() {
  document.getElementById('logoutModal').style.display = 'flex';
}

function closeLogoutModal() {
  document.getElementById('logoutModal').style.display = 'none';
}

async function confirmLogout() {
  closeLogoutModal();
  try {
    await fetchJSON('/api/logout', { method: 'POST' });
  } catch (e) {
  }
  await refreshStatus();
  showView('viewLogin');
  startLogin();
}

function skipLogin() {
  if (loginTimer) { clearInterval(loginTimer); loginTimer = null; }
  showView('viewSearch');
}

function pushNav() {
  const active = document.querySelector('.view.active').id;
  if (active === 'viewCart') {
    navStack.push({ kind: 'cart' });
    return;
  }
  if (active === 'viewPlaylistDetail' && playlistCtx) {
    navStack.push({ kind: 'playlist', id: playlistCtx.id });
    return;
  }
  navStack.push({ kind: 'search', results: results, listKind: listKind });
}

function goBack() {
  const prev = navStack.pop();
  if (!prev) return;
  if (prev.kind === 'cart') {
    renderCart();
    showView('viewCart');
    return;
  }
  if (prev.kind === 'playlist') {
    loadPlaylistDetail(prev.id);
    return;
  }
  results = prev.results;
  listKind = prev.listKind;
  renderResults();
  updateSel();
  showView('viewSearch');
}

function updateSel() {
  const n = selected.size;
  const total = results.length ? results.length + ' 条 · ' : '';
  document.getElementById('selInfo').textContent = (n ? (total + '已选 ' + n + ' 首') : (total + '未选择')) + ' ›';
  document.getElementById('btnToQuality').disabled = n === 0;
  document.getElementById('btnMaxQuality').disabled = n === 0;
  const songs = results.filter((s) => !s.isAlbum && !s.isArtist);
  const all = songs.length > 0 && songs.every((s) => selected.has(s.id));
  const btnAll = document.getElementById('btnAll');
  btnAll.textContent = all ? '取消全选' : '全选';
  btnAll.style.display = songs.length ? '' : 'none';
}

function loadingHTML(text) {
  return '<div class="loading"><span class="spinner"></span>' + text + '</div>';
}

function setBusy(btn, busy) {
  if (!btn) return;
  if (busy) {
    btn.dataset.label = btn.textContent;
    btn.dataset.wasDisabled = btn.disabled ? '1' : '';
    btn.disabled = true;
    btn.classList.add('busy');
    btn.innerHTML = '<span class="spinner"></span>' + btn.dataset.label;
    return;
  }
  btn.classList.remove('busy');
  if (btn.dataset.label) btn.textContent = btn.dataset.label;
  btn.disabled = btn.dataset.wasDisabled === '1';
}

window.addEventListener('load', () => {
  refreshStatus().then(() => {
    if (APP_MODE === 'convert') {
      document.getElementById('plBackBtn').style.display = 'none';
      document.getElementById('jobBackBtn').textContent = '返回歌单';
      document.querySelectorAll('#hintActions .cell').forEach((btn) => {
        if (btn.textContent.trim() === '跳过') btn.style.display = 'none';
      });
    }
    if (status.loggedIn) {
      if (APP_MODE === 'convert') loadPlaylists();
      else showView('viewSearch');
    } else {
      showView('viewLogin');
      startLogin();
    }
  });
});

