const sbUpdates = [];
let sbFrame = 0;

function scheduleSbUpdate() {
  if (sbFrame) return;
  sbFrame = requestAnimationFrame(() => {
    sbFrame = 0;
    for (const update of sbUpdates) update();
  });
}

function makeScrollbar(track, thumb, axis, measure, pin) {
  let dragging = false;
  let dragStart = 0;
  let scrollStart = 0;

  const update = () => {
    const state = measure();
    if (pin) pin();
    if (state.total <= state.visible + 1) {
      track.classList.add('hidden');
      return;
    }
    track.classList.remove('hidden');
    const trackLen = Math.round(axis === 'y' ? track.clientHeight : track.clientWidth);
    if (trackLen <= 0) return;
    const thumbLen = Math.max(28, Math.round(trackLen * (state.visible / state.total)));
    const maxOffset = trackLen - thumbLen;
    const range = Math.max(1, state.total - state.visible);
    const ratio = Math.min(1, Math.max(0, state.current / range));
    const edge = 2;
    let offset = Math.round(maxOffset * ratio);
    if (state.current <= 0 || offset <= edge) {
      offset = 0;
    } else if (state.current >= state.total - state.visible || offset >= maxOffset - edge) {
      offset = maxOffset;
    }
    if (axis === 'y') {
      thumb.style.height = thumbLen + 'px';
      thumb.style.top = offset + 'px';
    } else {
      thumb.style.width = thumbLen + 'px';
      thumb.style.left = offset + 'px';
    }
  };

  thumb.addEventListener('pointerdown', (event) => {
    dragging = true;
    dragStart = axis === 'y' ? event.clientY : event.clientX;
    scrollStart = measure().current;
    thumb.classList.add('dragging');
    thumb.setPointerCapture(event.pointerId);
    event.preventDefault();
  });
  thumb.addEventListener('pointermove', (event) => {
    if (!dragging) return;
    const state = measure();
    const trackLen = axis === 'y' ? track.clientHeight : track.clientWidth;
    const thumbLen = axis === 'y' ? thumb.offsetHeight : thumb.offsetWidth;
    const delta = (axis === 'y' ? event.clientY : event.clientX) - dragStart;
    const range = Math.max(1, trackLen - thumbLen);
    state.set(scrollStart + delta * ((state.total - state.visible) / range));
  });
  const stop = () => {
    dragging = false;
    thumb.classList.remove('dragging');
  };
  thumb.addEventListener('pointerup', stop);
  thumb.addEventListener('pointercancel', stop);
  sbUpdates.push(update);
  return update;
}

function addTrack(container, extraClass, axis) {
  const track = document.createElement('div');
  track.className = `sb ${axis === 'y' ? 'sb-v' : 'sb-h'} ${extraClass}`.trim();
  const thumb = document.createElement('div');
  thumb.className = 'sb-thumb';
  track.appendChild(thumb);
  container.appendChild(track);
  return { track, thumb };
}

const windowBar = addTrack(document.body, 'sb-window', 'y');
makeScrollbar(windowBar.track, windowBar.thumb, 'y', () => ({
  total: document.documentElement.scrollHeight,
  visible: window.innerHeight,
  current: window.scrollY,
  set: (value) => window.scrollTo(0, value),
}));
document.addEventListener('scroll', scheduleSbUpdate, { capture: true, passive: true });
window.addEventListener('load', scheduleSbUpdate);
let sbResizeTimer = 0;
window.addEventListener('resize', () => {
  clearTimeout(sbResizeTimer);
  sbResizeTimer = setTimeout(scheduleSbUpdate, 150);
});
scheduleSbUpdate();
