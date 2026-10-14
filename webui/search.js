let searchType = 'song';
let results = [];
let albumTracks = [];
let albumCtx = '';
let searchMessage = '';
let suggestItems = [];
let suggestIndex = -1;
let suggestTimer = 0;

function showSuggest() {
  document.getElementById('suggestBox').style.display = '';
}

function hideSuggest() {
  document.getElementById('suggestBox').style.display = 'none';
  suggestIndex = -1;
}

function suggestVisible() {
  return document.getElementById('suggestBox').style.display !== 'none';
}

async function refreshSuggest(kw) {
  if (!kw) {
    hideSuggest();
    return;
  }
  try {
    const data = await fetchJSON('/api/suggest?kw=' + encodeURIComponent(kw));
    renderSuggest(data);
  } catch (e) {
    hideSuggest();
  }
}

function renderSuggest(data) {
  suggestItems = [];
  suggestIndex = -1;
  const groups = [];
  if (data.suggest && data.suggest.length) {
    groups.push(['KEYWORD', data.suggest.map((k) => ({ type: 'kw', text: k }))]);
  }
  if (data.songs && data.songs.length) {
    groups.push(['SONG', data.songs.map((s) => ({
      type: 'song', id: s.id, text: s.name,
      sub: (s.artists || []).map((a) => a.name).join(',')
    }))]);
  }
  if (data.artists && data.artists.length) {
    groups.push(['ARTIST', data.artists.map((a) => ({ type: 'artist', id: a.id, text: a.name }))]);
  }
  if (data.albums && data.albums.length) {
    groups.push(['ALBUM', data.albums.map((a) => ({
      type: 'album', id: a.id, text: a.name, sub: a.artist ? a.artist.name : ''
    }))]);
  }
  if (data.playlists && data.playlists.length) {
    groups.push(['PLAYLIST', data.playlists.map((p) => ({ type: 'playlist', id: p.id, text: p.name }))]);
  }
  let html = '';
  for (const [label, items] of groups) {
    html += '<div class="suggest-group"><div class="suggest-label">' + label + '</div>';
    for (const it of items) {
      suggestItems.push(it);
      const idx = suggestItems.length - 1;
      html += `<div class="suggest-item" id="sg${idx}" data-idx="${idx}">${esc(it.text)}` +
        (it.sub ? ` <span class="sub">${esc(it.sub)}</span>` : '') + '</div>';
    }
    html += '</div>';
  }
  if (!html) {
    hideSuggest();
    return;
  }
  document.getElementById('suggestPanel').innerHTML = html;
  showSuggest();
}

function pickSuggest(idx) {
  const it = suggestItems[idx];
  hideSuggest();
  if (!it) return;
  document.getElementById('keyword').value = it.text;
  if (it.type === 'artist') {
    switchTab('artist');
  } else if (it.type === 'album' || it.type === 'playlist') {
    switchTab('album');
  } else if (it.type === 'song') {
    switchTab('song');
  }
  doSearch();
}

function moveSuggest(delta) {
  selectSuggest(suggestIndex + delta);
}

function selectSuggest(index) {
  const items = Array.from(document.querySelectorAll('#suggestPanel .suggest-item'));
  if (items.length === 0) return;
  for (const item of items) item.classList.remove('active');
  suggestIndex = ((index % items.length) + items.length) % items.length;
  const item = items[suggestIndex];
  item.classList.add('active');
  item.scrollIntoView({ block: 'nearest' });
}

document.getElementById('keyword').addEventListener('keydown', (e) => {
  if (e.isComposing || e.keyCode === 229) return;
  const items = Array.from(document.querySelectorAll('#suggestPanel .suggest-item'));
  switch (e.key) {
    case 'ArrowDown':
      if (!items.length) return;
      e.preventDefault();
      selectSuggest(suggestIndex + 1);
      break;
    case 'ArrowUp':
      if (!items.length) return;
      e.preventDefault();
      selectSuggest(suggestIndex - 1);
      break;
    case 'Enter':
      if (suggestIndex >= 0 && items[suggestIndex]) {
        e.preventDefault();
        pickSuggest(parseInt(items[suggestIndex].dataset.idx, 10));
      } else {
        e.preventDefault();
        doSearch();
      }
      break;
    case 'Escape':
      hideSuggest();
      break;
  }
});

document.getElementById('keyword').addEventListener('input', () => {
  clearTimeout(suggestTimer);
  const kw = document.getElementById('keyword').value.trim();
  suggestTimer = setTimeout(() => refreshSuggest(kw), 200);
});
document.getElementById('suggestPanel').addEventListener('click', (e) => {
  const item = e.target.closest ? e.target.closest('.suggest-item') : null;
  if (!item) return;
  const idx = parseInt(item.dataset.idx, 10);
  if (!Number.isNaN(idx)) pickSuggest(idx);
});
document.addEventListener('click', (e) => {
  if (!e.target.closest('.topbar')) hideSuggest();
});

function switchTab(type) {
  searchType = type;
  document.getElementById('tabSong').classList.toggle('accent', type === 'song');
  document.getElementById('tabAlbum').classList.toggle('accent', type === 'album');
  document.getElementById('tabArtist').classList.toggle('accent', type === 'artist');
}

function parseInput(text) {
  const m = text.match(/music\.163\.com\/.*?(?:song|album|playlist|artist)\?id=(\d+)/);
  if (m) {
    const kind = text.includes('artist') ? 'artist' : (text.includes('album') ? 'album' : (text.includes('playlist') ? 'playlist' : 'song'));
    return { kind, id: m[1] };
  }
  if (/^\d+$/.test(text.trim())) return { kind: searchType, id: text.trim() };
  return null;
}

async function doSearch() {
  hideSuggest();
  clearTimeout(suggestTimer);
  const text = document.getElementById('keyword').value.trim();
  const direct = parseInput(text);
  playlistCtx = null;
  document.getElementById('results').innerHTML = '';
  searchMessage = '';
  results = [];
  navStack = [];
  listKind = searchType;
  updateSel();
  renderResults();
  if (!text) return;
  try {
    if (direct && direct.kind === 'album') {
      await loadAlbum(direct.id);
      return;
    }
    if (direct && direct.kind === 'artist') {
      await loadArtistAlbums(direct.id);
      return;
    }
    const kw = direct ? direct.id : encodeURIComponent(text);
    const data = await fetchJSON('/api/search?type=' + searchType + '&kw=' + kw + '&limit=30');
    if (data.type === 'album') {
      results = (data.albums || []).map((a) => ({
        id: a.id, name: a.name, artists: a.artist, album: '', coverUrl: a.coverUrl,
        duration: 0, trackNum: a.trackNum, isAlbum: true
      }));
      listKind = 'album';
    } else if (data.type === 'artist') {
      results = (data.artists || []).map((a) => ({
        id: a.id, name: a.name, artists: '', album: '', coverUrl: a.coverUrl,
        duration: 0, albumSize: a.albumSize, isArtist: true
      }));
      listKind = 'artist';
    } else {
      results = data.songs || [];
      listKind = 'song';
    }
    if (!results.length) {
      searchMessage = '没有结果 · 换个关键词，或直接粘贴歌曲链接';
    }
    renderResults();
  } catch (e) {
    searchMessage = '搜索失败 ' + e.message;
    renderResults();
  }
}

const musicIcon = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>';

function imgFallback(el) {
  const d = document.createElement('div');
  d.className = 'img-ph';
  d.innerHTML = musicIcon;
  el.replaceWith(d);
}

function coverHTML(s) {
  if (!s.coverUrl) return '<div class="img-ph">' + musicIcon + '</div>';
  return `<img src="${esc(s.coverUrl)}" loading="lazy" alt="" onerror="imgFallback(this)">`;
}

function artistLinks(s) {
  if (s.artistRefs && s.artistRefs.length) {
    return s.artistRefs.map((a) => a.id
      ? `<span class="lnk" onclick="event.stopPropagation();loadArtistAlbums(${a.id})">${esc(a.name)}</span>`
      : esc(a.name)).join(',');
  }
  return s.artistId
    ? `<span class="lnk" onclick="event.stopPropagation();loadArtistAlbums(${s.artistId})">${esc(s.artists)}</span>`
    : esc(s.artists);
}

function songSub(s) {
  const artist = artistLinks(s);
  if (!s.album) return artist;
  const album = s.albumId
    ? `<span class="lnk" onclick="event.stopPropagation();loadAlbum(${s.albumId})">${esc(s.album)}</span>`
    : esc(s.album);
  return `${artist} · ${album}`;
}

function renderResults() {
  const box = document.getElementById('results');
  if (!results.length) {
    box.innerHTML = searchMessage ? `<div class="empty-msg">${esc(searchMessage)}</div>` : '';
    document.getElementById('backBtn').style.display = navStack.length ? '' : 'none';
    scheduleSbUpdate();
    return;
  }
  box.innerHTML = results.map((s, i) => {
    if (s.isArtist) {
      return `
    <div class="row ${selected.has(s.id) ? 'selected' : ''}" onclick="toggleResult(${i})">
      ${coverHTML(s)}
      <div class="main">
        <div class="name">${esc(s.name)}</div>
        <div class="sub">歌手${s.albumSize ? ' · ' + s.albumSize + ' 张专辑' : ''}</div>
      </div>
      <div class="dur">ARTIST</div>
    </div>`;
    }
    const sub = s.isAlbum
      ? `${esc(s.artists)}${s.trackNum ? ' · ' + s.trackNum + ' 首' : ''}`
      : (listKind === 'song' ? songSub(s) : artistLinks(s));
    return `
    <div class="row ${selected.has(s.id) ? 'selected' : ''}" onclick="toggleResult(${i})">
      ${coverHTML(s)}
      <div class="main">
        <div class="name">${esc(s.name)}</div>
        <div class="sub">${sub}</div>
      </div>
      <div class="dur">${s.isAlbum ? 'ALBUM' : fmtDur(s.duration)}</div>
    </div>`;
  }).join('');
  document.getElementById('backBtn').style.display = navStack.length ? '' : 'none';
  scheduleSbUpdate();
}

async function toggleResult(i) {
  const s = results[i];
  if (s.isArtist) {
    await loadArtistAlbums(s.id);
    return;
  }
  if (s.isAlbum) {
    await loadAlbum(s.id);
    return;
  }
  if (selected.has(s.id)) {
    selected.delete(s.id);
    songOrigin.delete(s.id);
  } else {
    selected.set(s.id, s);
    markOrigin(s, i);
  }
  renderResults();
  updateSel();
}
function markOrigin(s, pos) {
  if (listKind === 'albumTracks' && albumCtx) {
    songOrigin.set(s.id, { kind: 'album', name: albumCtx, pos: pos });
  } else {
    songOrigin.set(s.id, { kind: 'root', name: '', pos: selSeq++ });
  }
}

async function loadAlbum(id) {
  showView('viewSearch');
  const data = await fetchJSON('/api/album?id=' + id);
  pushNav();
  playlistCtx = null;
  albumCtx = data.album ? data.album.name : '';
  albumTracks = data.songs || [];
  results = albumTracks;
  listKind = 'albumTracks';
  renderResults();
  updateSel();
}

function toggleAll() {
  const songs = results.filter((s) => !s.isAlbum && !s.isArtist);
  if (!songs.length) return;
  const all = songs.every((s) => selected.has(s.id));
  songs.forEach((s, idx) => {
    if (all) {
      selected.delete(s.id);
      songOrigin.delete(s.id);
    } else {
      selected.set(s.id, s);
      markOrigin(s, idx);
    }
  });
  renderResults();
  updateSel();
}

async function loadArtistAlbums(id) {
  showView('viewSearch');
  const data = await fetchJSON('/api/artist-albums?id=' + id);
  pushNav();
  results = (data.albums || []).map((a) => ({
    id: a.id, name: a.name, artists: a.artist, album: '', coverUrl: a.coverUrl,
    duration: 0, trackNum: a.trackNum, isAlbum: true
  }));
  listKind = 'artistAlbums';
  renderResults();
  updateSel();
}
