let folderReturn = 'viewSearch';
let qualityReturn = 'viewSearch';
let quality = new Map();
let songLevels = new Map();
async function fetchQuality() {
  const songs = Array.from(selected.values());
  const data = await fetchJSON('/api/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ songs })
  });
  songLevels.clear();
  const checkResults = data.results || [];
  for (const r of checkResults) {
    if (r.ok && r.levels) songLevels.set(r.id, r.levels);
  }
  return checkResults;
}

async function skipQuality() {
  if (!selected.size) return;
  folderReturn = 'viewSearch';
  try {
    await fetchQuality();
    quality.clear();
    songLevels.forEach((levels, id) => {
      quality.set(id, resolveLevel(levels, 'hires'));
    });
    goFolder();
  } catch (e) {
    searchMessage = '音质检测失败 ' + e.message;
    renderResults();
  }
}

async function goQuality() {
  if (!selected.size) return;
  qualityReturn = document.querySelector('.view.active').id;
  folderReturn = 'viewQuality';
  showView('viewQuality');
  const list = document.getElementById('qualityList');
  const empty = document.getElementById('qualityEmpty');
  empty.style.display = '';
  empty.textContent = '检测可用音质…';
  list.innerHTML = '';
  quality.clear();
  try {
    const checkResults = await fetchQuality();
    empty.style.display = 'none';
    const union = new Set();
    for (const r of checkResults) {
      if (r.ok && r.levels) r.levels.forEach((lv) => union.add(lv));
    }
    const unionLevels = LEVELS.map((l) => l[0]).filter((lv) => union.has(lv));
    const unified = document.getElementById('qUnified');
    unified.innerHTML = unionLevels.map((lv) => `<option value="${lv}">${LEVEL_NAME[lv] || lv}</option>`).join('');
    if (unionLevels.length) {
      const hiresIdx = LEVELS.findIndex((l) => l[0] === 'hires');
      unified.value = unionLevels.filter((lv) => LEVELS.findIndex((l) => l[0] === lv) <= hiresIdx).pop() || unionLevels[unionLevels.length - 1];
    }
    const songs = Array.from(selected.values());
    list.innerHTML = songs.map((s) => {
      const r = checkResults.find((x) => x.id === s.id) || {};
      if (!r.ok) {
        return `<div class="q-row"><div class="main"><div class="name">${esc(s.name)}</div>
          <div class="sub">${esc(s.artists)}</div></div><div class="label">不可下载</div></div>`;
      }
      return `<div class="q-row"><div class="main"><div class="name">${esc(s.name)}</div>
        <div class="sub">${esc(s.artists)} · 最高 ${LEVEL_NAME[r.top] || r.top} · ${r.type}</div></div>
        <div class="label" id="q${s.id}"></div></div>`;
    }).join('');
    applyUnified();
    scheduleSbUpdate();
    document.getElementById('qInfo').textContent = selected.size + ' 首 · 统一音质自动取各曲目最优可用档';
  } catch (e) {
    empty.style.display = '';
    empty.textContent = '音质检测失败 ' + e.message;
  }
}

function resolveLevel(levels, chosen) {
  const chosenIdx = LEVELS.findIndex((l) => l[0] === chosen);
  let resolved = levels[0];
  for (const lv of levels) {
    const idx = LEVELS.findIndex((l) => l[0] === lv);
    if (idx >= 0 && idx <= chosenIdx) resolved = lv;
  }
  return resolved;
}

function applyUnified() {
  const chosen = document.getElementById('qUnified').value;
  quality.clear();
  songLevels.forEach((levels, id) => {
    const resolved = resolveLevel(levels, chosen);
    quality.set(id, resolved);
    const cell = document.getElementById('q' + id);
    if (cell) cell.textContent = LEVEL_NAME[resolved] || resolved;
  });
}

function goFolder() {
  showView('viewFolder');
  const base = document.getElementById('folderInput').value || '未设置';
  const groups = new Set();
  selected.forEach((s) => {
    const o = songOrigin.get(s.id) || { kind: 'root', name: '' };
    groups.add(o.kind === 'root' ? '根目录' : o.name);
  });
  document.getElementById('folderInfo').textContent = base + '  ·  ' + Array.from(groups).join(' / ');
}

async function pickFolder() {
  const info = document.getElementById('folderInfo');
  info.textContent = '请在弹出的窗口中选择文件夹…';
  try {
    const data = await fetchJSON('/api/pick-folder', { method: 'POST' });
    document.getElementById('folderInput').value = data.folder;
    info.textContent = data.folder;
  } catch (e) {
    info.textContent = '选择失败 ' + e.message;
  }
}

async function startDownload() {
  const base = document.getElementById('folderInput').value.trim();
  if (!base) {
    document.getElementById('folderInfo').textContent = '请先填写保存路径';
    return;
  }
  const items = [];
  groupSelected().forEach((g) => {
    const folder = g.name ? (base.replace(/[\\/]+$/, '') + '/' + sanitizePathName(g.name)) : base;
    g.rows.forEach(({ s }) => {
      if (quality.has(s.id)) items.push({ song: s, level: quality.get(s.id), folder });
    });
  });
  if (!items.length) {
    document.getElementById('folderInfo').textContent = '没有可下载的歌曲';
    return;
  }
  try {
    await fetchJSON('/api/download', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ folder: base, items })
    });
    showView('viewProgress');
    if (jobTimer) clearInterval(jobTimer);
    jobTimer = setInterval(refreshJob, 800);
    refreshJob();
  } catch (e) {
    document.getElementById('folderInfo').textContent = '启动失败 ' + e.message;
  }
}

async function refreshJob() {
  try {
    const job = await fetchJSON('/api/job');
    if (job.state === 'idle') return;
    const total = job.items ? job.items.length : 0;
    const pct = total ? Math.round((job.done / total) * 100) : 0;
    document.getElementById('jobBar').style.width = pct + '%';
    document.getElementById('jobInfo').textContent = (job.state === 'finished' ? '完成' : '进行中 ' + pct + '%') + ' · ' + job.done + ' / ' + total + ' · ' + (job.folder || '');
    document.getElementById('jobList').innerHTML = (job.items || []).map((it) => {
      const cls = it.state === 'done' ? 'done' : (it.state === 'failed' ? 'failed' : '');
      const mark = it.state === 'done' ? '✓' : (it.state === 'failed' ? '✕' : '·');
      return `<div class="j-row ${cls}"><div class="st">${mark}</div>
        <div class="main">${esc(it.song.name)} — ${esc(it.song.artists)}</div>
        <div class="det">${esc(LEVEL_NAME[it.level] || it.level)}${it.detail ? ' · ' + esc(it.detail) : ''}</div></div>`;
    }).join('');
    if (job.state === 'finished') {
      clearInterval(jobTimer);
      jobTimer = null;
    }
    scheduleSbUpdate();
  } catch (e) {
  }
}

function backToSearch() {
  if (jobTimer) { clearInterval(jobTimer); jobTimer = null; }
  selected.clear();
  songOrigin.clear();
  quality.clear();
  playlistCtx = null;
  if (APP_MODE === 'convert') {
    loadPlaylists();
    return;
  }
  if (navStack.length) {
    const base = navStack[0];
    if (base.kind === 'search') {
      results = base.results;
      listKind = base.listKind;
    } else {
      results = [];
      listKind = 'song';
    }
    navStack = [];
  }
  updateSel();
  showView('viewSearch');
  renderResults();
  refreshStatus();
}
