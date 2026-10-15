let playlistCtx = null;
let plTracks = [];

function setConvertBusy(busy) {
  setBusy(document.getElementById('plMainBtn'), busy);
  setBusy(document.getElementById('cartActionBtn'), busy);
}
function openCart() {
  pushNav();
  renderCart();
  showView('viewCart');
}

function renderCart() {
  const box = document.getElementById('cartList');
  const items = Array.from(selected.values());
  document.getElementById('cartInfo').textContent = items.length ? ('共 ' + items.length + ' 首 · 点击行取消选择') : '购物车是空的';
  const btn = document.getElementById('cartActionBtn');
  btn.disabled = items.length === 0;
  btn.textContent = APP_MODE === 'convert' ? '开始转换' : '选择音质';
  if (!items.length) {
    box.innerHTML = '<div class="empty">还没有选择歌曲</div>';
    return;
  }
  box.innerHTML = groupSelected().map((g) => {
    const title = g.kind === 'root' ? '单曲' : (g.kind === 'album' ? g.name + ' · 专辑' : g.name + ' · 歌单');
    return `<div class="cart-group"><div class="cart-head">${esc(title)}</div>` +
      g.rows.map(({ s }) => `
      <div class="row selected" onclick="unpickSong(${s.id})">
        ${coverHTML(s)}
        <div class="main">
          <div class="name">${esc(s.name)}</div>
          <div class="sub">${songSub(s)}</div>
        </div>
        <div class="dur">${fmtDur(s.duration)}</div>
      </div>`).join('') + '</div>';
  }).join('');
}

function unpickSong(id) {
  selected.delete(id);
  renderCart();
}

function clearCart() {
  selected.clear();
  songOrigin.clear();
  renderCart();
}

async function loadPlaylists() {
  showView('viewPlaylists');
  const list = document.getElementById('playlistList');
  const empty = document.getElementById('playlistEmpty');
  empty.style.display = '';
  empty.innerHTML = loadingHTML('加载中');
  list.innerHTML = '';
  try {
    const data = await fetchJSON('/api/playlists');
    const playlists = data.playlists || [];
    if (!playlists.length) {
      empty.style.display = '';
      empty.textContent = '没有歌单';
    } else {
      empty.style.display = 'none';
    }
    list.innerHTML = playlists.map((p) => `
      <div class="row" onclick="loadPlaylistDetail(${p.id})">
        <img src="${esc(p.coverUrl || '')}" loading="lazy" alt="">
        <div class="main">
          <div class="name">${esc(p.name)}</div>
          <div class="sub">${p.trackCount} 首</div>
        </div>
        <div class="dur">${p.playCount ? p.playCount + ' 次' : ''}</div>
      </div>`).join('');
    document.getElementById('plInfo').textContent = playlists.length + ' 个歌单';
    scheduleSbUpdate();
  } catch (e) {
    empty.style.display = '';
    empty.textContent = '加载失败 ' + e.message;
  }
}

const plDetailCache = new Map();

async function loadPlaylistDetail(id) {
  showView('viewPlaylistDetail');
  const list = document.getElementById('plTracks');
  const empty = document.getElementById('plEmpty');
  empty.style.display = '';
  empty.innerHTML = loadingHTML('加载中');
  list.innerHTML = '';
  try {
    let data = plDetailCache.get(id);
    if (!data) {
      data = await fetchJSON('/api/playlist?id=' + id);
      plDetailCache.set(id, data);
    }
    playlistCtx = data.playlist;
    plTracks = data.songs || [];
    document.getElementById('plTitle').value = data.playlist.name;
    document.getElementById('plMainBtn').textContent = APP_MODE === 'convert' ? '开始转换' : '选择音质';
    if (!plTracks.length) {
      empty.style.display = '';
      empty.textContent = '歌单是空的';
    } else {
      empty.style.display = 'none';
    }
    renderPlaylistTracks();
    updatePlSel();
    scheduleSbUpdate();
  } catch (e) {
    empty.style.display = '';
    empty.textContent = '加载失败 ' + e.message;
  }
}

let plRendered = 0;
const PL_PAGE = 60;
const visiblePlRows = new Map();
const plRowObserver = new IntersectionObserver((entries) => {
  entries.forEach((en) => {
    const i = parseInt(en.target.id.slice(5), 10);
    if (en.isIntersecting) {
      const s = plTracks[i];
      if (s) en.target.classList.toggle('selected', selected.has(s.id));
      visiblePlRows.set(i, en.target);
    } else {
      visiblePlRows.delete(i);
    }
  });
}, { rootMargin: '200px 0px' });

function renderPlaylistTracks(reset) {
  if (reset !== false) {
    plRendered = 0;
    visiblePlRows.clear();
    document.getElementById('plTracks').innerHTML = '';
  }
  appendPlaylistTracks();
}

function appendPlaylistTracks() {
  const box = document.getElementById('plTracks');
  const end = Math.min(plRendered + PL_PAGE, plTracks.length);
  let html = '';
  for (let i = plRendered; i < end; i++) {
    const s = plTracks[i];
    if (s.ok === false) {
      html += `
    <div class="row disabled" id="plRow${i}">
      ${coverHTML(s)}
      <div class="main">
        <div class="name">${esc(s.name)}</div>
        <div class="sub">${songSub(s)}</div>
      </div>
      <div class="dur">不可下载</div>
    </div>`;
      continue;
    }
    html += `
    <div class="row ${selected.has(s.id) ? 'selected' : ''}" id="plRow${i}" onclick="togglePlTrack(${i})">
      ${coverHTML(s)}
      <div class="main">
        <div class="name">${esc(s.name)}</div>
        <div class="sub">${songSub(s)}</div>
      </div>
      <div class="dur">${fmtDur(s.duration)}</div>
    </div>`;
  }
  box.insertAdjacentHTML('beforeend', html);
  for (let i = plRendered; i < end; i++) {
    const el = document.getElementById('plRow' + i);
    if (el) plRowObserver.observe(el);
  }
  plRendered = end;
}

function maybeLoadMoreTracks() {
  if (!document.getElementById('viewPlaylistDetail').classList.contains('active')) return;
  if (plRendered >= plTracks.length) return;
  if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 700) {
    appendPlaylistTracks();
  }
}
window.addEventListener('scroll', maybeLoadMoreTracks, { passive: true });

function togglePlTrack(i) {
  const s = plTracks[i];
  if (selected.has(s.id)) {
    selected.delete(s.id);
    songOrigin.delete(s.id);
  } else {
    selected.set(s.id, s);
    songOrigin.set(s.id, { kind: 'playlist', name: playlistCtx ? playlistCtx.name : '', pos: i });
  }
  const row = document.getElementById('plRow' + i);
  if (row) row.classList.toggle('selected', selected.has(s.id));
  updatePlSel();
}

function toggleAllPlTracks() {
  const selectAll = !(selected.size === plTracks.length && plTracks.length > 0);
  if (selectAll) {
    plTracks.forEach((s, i) => {
      selected.set(s.id, s);
      songOrigin.set(s.id, { kind: 'playlist', name: playlistCtx ? playlistCtx.name : '', pos: i });
    });
  } else {
    plTracks.forEach((s) => songOrigin.delete(s.id));
    selected.clear();
  }
  visiblePlRows.forEach((row) => row.classList.toggle('selected', selectAll));
  updatePlSel();
}

function updatePlSel() {
  document.getElementById('plSelInfo').textContent = (selected.size ? ('已选 ' + selected.size + ' / ' + plTracks.length + ' 首') : ('未选择 · 共 ' + plTracks.length + ' 首')) + ' ›';
  const all = plTracks.length > 0 && selected.size === plTracks.length;
  document.getElementById('plBtnAll').textContent = all ? '取消全选' : '全选';
}

function playlistMainAction() {
  if (!selected.size) return;
  if (APP_MODE === 'convert') {
    startConvert();
    return;
  }
  goQuality();
}

async function startConvert() {
  const ids = plTracks.filter((s) => selected.has(s.id)).map((s) => s.id);
  if (!ids.length) return;
  setConvertBusy(true);
  try {
    await fetchJSON('/api/convert/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: playlistCtx.name, ids })
    });
    showView('viewProgress');
    if (jobTimer) clearInterval(jobTimer);
    jobTimer = setInterval(refreshJob, 800);
    refreshJob();
  } catch (e) {
    document.getElementById('plSelInfo').textContent = '启动失败 ' + e.message;
  }
  setConvertBusy(false);
}
