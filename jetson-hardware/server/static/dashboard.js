// Al-Ahsa Smart Bus dashboard client.
// - Status strip: per-bus cards with badges, derived from /api/buses
// - Live events: smart per-type rendering with filter tabs
// - Route map: Leaflet Simple CRS, draws all routes from /api/routes plus
//   bus markers
// - Historical charts: 4 mini Chart.js line charts (rx, cctv, loss, rtt)
// - Forensic archive: filtered table with pill-formatted attack types

(function () {
  'use strict';

  // ====================================================================
  // helpers
  // ====================================================================

  function fmtTs(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    return d.toISOString().slice(11, 19);
  }
  function fmtDate(ts) {
    if (!ts) return '';
    return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19);
  }
  function fmtBytes(n) {
    if (n == null) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(2) + ' MB';
  }
  function fmtBps(b) {
    if (b == null || !isFinite(b)) return '—';
    if (b < 1) return '0';
    if (b < 1000) return b.toFixed(0) + ' bps';
    if (b < 1e6) return (b / 1000).toFixed(1) + ' kbps';
    return (b / 1e6).toFixed(2) + ' Mbps';
  }
  function fmtPct(x) {
    if (x == null) return '—';
    return (x * 100).toFixed(1) + '%';
  }
  function fmtMs(x) {
    if (x == null) return '—';
    return x.toFixed(0) + ' ms';
  }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function shortId(s) {
    s = String(s || '');
    return s.length > 10 ? s.slice(0, 8) + '…' : s;
  }

  // ====================================================================
  // event categorisation
  // ====================================================================

  const ATTACK_TYPES = new Set(['ddos_detect', 'gps_spoof']);
  const SYSTEM_TYPES = new Set([
    'forensic_ddos', 'forensic_gps_spoof', 'forensic_uploaded',
  ]);

  function eventKind(type) {
    if (ATTACK_TYPES.has(type)) return 'attack';
    if (SYSTEM_TYPES.has(type) || (type || '').startsWith('forensic_')) return 'system';
    if (type === 'ticket') return 'ticket';
    return 'other';
  }

  function renderEventDetail(ev) {
    const t = ev.type || '';
    const d = (ev.detail && typeof ev.detail === 'object') ? ev.detail : {};
    const v1 = ev.value1;
    const v2 = ev.value2;

    if (t === 'ddos_detect') {
      // value1 = rate Mbps, value2 = loss %, detail string with rtt
      return (
        '<span class="key">rate</span> <span class="val bad">' + fmtFloat(v1, 2) + ' Mbps</span> · ' +
        '<span class="key">loss</span> <span class="val bad">' + fmtFloat(v2, 1) + '%</span>' +
        (d && typeof ev.detail === 'string'
          ? ' · <span class="val">' + esc(ev.detail) + '</span>'
          : '')
      );
    }
    if (t === 'gps_spoof') {
      return (
        '<span class="key">speed</span> <span class="val bad">' + fmtFloat(d.speed || v1, 1) + ' m/s</span> · ' +
        '<span class="key">corridor</span> <span class="val bad">' + fmtFloat(d.corridor_dist || v2, 0) + ' m</span> · ' +
        '<span class="key">src</span> <span class="val">' + esc(d.src_addr || d.src_ip || '?') + '</span>'
      );
    }
    if (t.startsWith('forensic_')) {
      const fid = d.forensic_id;
      const link = fid ? '<a href="/forensics/' + fid + '.pdf" target="_blank">#' + fid + '</a>' : '';
      return (
        '<span class="key">report</span> <span class="val">' + link + '</span> · ' +
        '<span class="key">size</span> <span class="val">' + fmtBytes(v1) + '</span>'
      );
    }
    if (t === 'ticket') {
      return (
        '<span class="key">txn</span> <span class="val">' + esc(shortId(d.txn_id)) + '</span> · ' +
        '<span class="key">size</span> <span class="val">' + (d.size_bytes || v1 || 0) + ' B</span>'
      );
    }
    // Fallback: show JSON or string detail
    if (typeof ev.detail === 'string') return esc(ev.detail);
    return esc(JSON.stringify(d));
  }

  function fmtFloat(x, digits) {
    const n = Number(x);
    return isFinite(n) ? n.toFixed(digits) : '—';
  }

  // ====================================================================
  // events panel
  // ====================================================================

  let currentFilter = 'important';

  function passesFilter(kind) {
    if (currentFilter === 'all') return true;
    if (currentFilter === 'attacks') return kind === 'attack';
    if (currentFilter === 'tickets') return kind === 'ticket';
    if (currentFilter === 'important') return kind !== 'ticket';
    return true;
  }

  function renderEvents(arr) {
    if (!Array.isArray(arr)) arr = [];
    const filtered = arr.filter((ev) => passesFilter(eventKind(ev.type)));
    if (!filtered.length) {
      const note = arr.length
        ? 'No events match this filter (' + arr.length + ' hidden).'
        : 'No events yet.';
      return '<div class="events-empty">' + esc(note) + '</div>';
    }
    return filtered.map((ev) => {
      const kind = eventKind(ev.type);
      return (
        '<div class="event-row kind-' + kind + '">' +
          '<span class="ev-ts">' + esc(fmtTs(ev.ts)) + '</span>' +
          '<span class="ev-bus">bus ' + esc(ev.bus_id) + '</span>' +
          '<span class="ev-type">' + esc(prettyType(ev.type)) + '</span>' +
          '<span class="ev-detail">' + renderEventDetail(ev) + '</span>' +
        '</div>'
      );
    }).join('');
  }

  function prettyType(t) {
    const map = {
      ddos_detect: 'DDoS',
      gps_spoof: 'GPS spoof',
      ticket: 'ticket',
      forensic_ddos: 'forensic',
      forensic_gps_spoof: 'forensic',
    };
    return map[t] || t || 'event';
  }

  // ====================================================================
  // status strip (bus cards)
  // ====================================================================

  function renderStatusStrip(buses) {
    const strip = document.getElementById('status-strip');
    if (!strip) return;
    strip.removeAttribute('data-loading');
    if (!buses || !buses.length) {
      strip.innerHTML = '<em style="color:var(--muted);font-style:italic;padding:0.5rem;">no buses reporting</em>';
      return;
    }
    const now = Date.now() / 1000;
    strip.innerHTML = buses.map((b) => {
      const last = b.last_metric_ts || (b.last_gps && b.last_gps.ts) || 0;
      const stale = last ? (now - last > 30) : true;
      const loss = b.heartbeat_loss == null ? 0 : b.heartbeat_loss;
      const rtt = b.rtt_ms;

      let cls = 'ok', label = 'OK';
      if (stale) { cls = 'alert'; label = 'OFFLINE'; }
      else if (loss > 0.05 || (rtt != null && rtt > 200)) { cls = 'warn'; label = 'DEGRADED'; }

      const cardCls = cls === 'alert' ? 'is-alert' : (cls === 'warn' ? 'is-warn' : '');
      const gps = b.last_gps
        ? '(' + Math.round(b.last_gps.pos_x) + ', ' + Math.round(b.last_gps.pos_y) + ')'
        : '—';
      return (
        '<div class="bus-card ' + cardCls + '">' +
          '<span class="bid">bus ' + esc(b.bus_id) + '</span>' +
          '<div class="metrics">' +
            '<span><span class="label">rx</span>' + fmtBps(b.rx_bps) + '</span>' +
            '<span><span class="label">cctv</span>' + fmtBps(b.cctv_bps) + '</span>' +
            '<span><span class="label">loss</span>' + fmtPct(b.heartbeat_loss) + '</span>' +
            '<span><span class="label">rtt</span>' + fmtMs(b.rtt_ms) + '</span>' +
            '<span><span class="label">gps</span>' + esc(gps) + '</span>' +
          '</div>' +
          '<span class="badge ' + cls + '">' + label + '</span>' +
        '</div>'
      );
    }).join('');
  }

  // ====================================================================
  // map
  // ====================================================================

  const MAP_STATE = { map: null, markers: {}, routesDrawn: false };
  // ns-3 grid is roughly 0..15000 m on X and 0..20000 m on Y.
  const GRID_BOUNDS = [[-20000, 0], [0, 15000]];   // [[south, west], [north, east]]
  // Leaflet Simple CRS uses (y, x); we negate y so north = up.
  function toLatLng(pos_x, pos_y) { return [-pos_y, pos_x]; }

  function ensureMap() {
    if (MAP_STATE.map || typeof L === 'undefined') return MAP_STATE.map;
    const el = document.getElementById('map');
    if (!el) return null;
    MAP_STATE.map = L.map(el, {
      crs: L.CRS.Simple, minZoom: -5, maxZoom: 3,
      attributionControl: false, zoomControl: true,
    });
    MAP_STATE.map.fitBounds(GRID_BOUNDS);
    L.rectangle(GRID_BOUNDS, { color: '#334155', weight: 1, fillOpacity: 0 })
      .addTo(MAP_STATE.map);
    return MAP_STATE.map;
  }

  async function drawRoutes() {
    const map = ensureMap();
    if (!map || MAP_STATE.routesDrawn) return;
    try {
      const resp = await fetch('/api/routes');
      if (!resp.ok) return;
      const data = await resp.json();
      (data.routes || []).forEach((route) => {
        if (!route || !route.length) return;
        const latlngs = route.map(([x, y]) => toLatLng(x, y));
        L.polyline(latlngs, { color: '#475569', weight: 1.5, opacity: 0.8 }).addTo(map);
      });
      MAP_STATE.routesDrawn = true;
    } catch (err) {
      console.warn('drawRoutes failed', err);
    }
  }

  function updateMap(buses) {
    const map = ensureMap();
    if (!map) return;
    drawRoutes();
    const seen = new Set();
    (buses || []).forEach((b) => {
      if (!b.last_gps) return;
      const { pos_x, pos_y } = b.last_gps;
      if (pos_x == null || pos_y == null) return;
      const ll = toLatLng(pos_x, pos_y);
      seen.add(b.bus_id);
      if (MAP_STATE.markers[b.bus_id]) {
        MAP_STATE.markers[b.bus_id].setLatLng(ll);
      } else {
        MAP_STATE.markers[b.bus_id] = L.circleMarker(ll, {
          radius: 6, color: '#60a5fa', fillColor: '#60a5fa',
          fillOpacity: 0.9, weight: 1,
        }).addTo(map).bindTooltip('bus ' + b.bus_id, { permanent: false });
      }
    });
    Object.keys(MAP_STATE.markers).forEach((id) => {
      if (!seen.has(parseInt(id, 10))) {
        MAP_STATE.markers[id].remove();
        delete MAP_STATE.markers[id];
      }
    });
  }

  // ====================================================================
  // bus-select dropdown population
  // ====================================================================

  function refreshBusSelect(buses) {
    const sel = document.getElementById('bus-select');
    if (!sel) return;
    const ids = new Set((buses || []).map((b) => String(b.bus_id)));
    const existing = new Set(
      Array.from(sel.options).map((o) => o.value).filter(Boolean)
    );
    if (ids.size === existing.size && [...ids].every((x) => existing.has(x))) return;
    const current = sel.value;
    sel.innerHTML = '<option value="">(all)</option>' +
      [...ids].sort((a, b) => +a - +b)
        .map((id) => '<option value="' + esc(id) + '">bus ' + esc(id) + '</option>')
        .join('');
    if (current && ids.has(current)) sel.value = current;
  }

  // ====================================================================
  // HTMX swap interception
  // ====================================================================

  document.body.addEventListener('htmx:beforeSwap', (e) => {
    const id = e.detail.target.id;
    if (id !== 'events-list') return;
    try {
      const data = JSON.parse(e.detail.xhr.responseText);
      e.detail.shouldSwap = false;
      const arr = Array.isArray(data) ? data : (data.events || []);
      lastEvents = arr;
      document.getElementById('events-list').innerHTML = renderEvents(arr);
    } catch (err) {
      console.error('events swap failed', err);
    }
  });

  // ====================================================================
  // /api/buses polling (status strip + map + bus-select)
  // ====================================================================

  let lastEvents = [];

  async function refreshBuses() {
    try {
      const resp = await fetch('/api/buses');
      if (!resp.ok) return;
      const data = await resp.json();
      const arr = Array.isArray(data) ? data : (data.buses || []);
      renderStatusStrip(arr);
      updateMap(arr);
      refreshBusSelect(arr);
    } catch (err) {
      console.warn('buses poll failed', err);
    }
  }

  // ====================================================================
  // historical charts
  // ====================================================================

  const CHARTS = {};
  const PALETTE = {
    rx:   '#60a5fa',
    cctv: '#34d399',
    loss: '#f87171',
    rtt:  '#fbbf24',
  };

  function mkChart(canvasId, color, yFmt) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === 'undefined') return null;
    return new Chart(canvas.getContext('2d'), {
      type: 'line',
      data: { datasets: [{
        data: [], borderColor: color, backgroundColor: color + '22',
        borderWidth: 1.4, pointRadius: 0, tension: 0.25, fill: true,
      }] },
      options: {
        animation: false, parsing: false, responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { type: 'linear',
               ticks: { callback: (v) => new Date(v * 1000).toISOString().slice(11, 16),
                        color: '#94a3b8', maxTicksLimit: 5, font: { size: 9 } },
               grid: { color: '#1f2530' } },
          y: { beginAtZero: true,
               ticks: { color: '#94a3b8', maxTicksLimit: 4, font: { size: 9 },
                        callback: yFmt },
               grid: { color: '#1f2530' } },
        },
        plugins: { legend: { display: false }, tooltip: { enabled: true } },
      },
    });
  }

  async function refreshCharts() {
    const rangeEl = document.getElementById('range-select');
    const busEl   = document.getElementById('bus-select');
    if (!rangeEl) return;
    const range = rangeEl.value || '1h';
    const busId = busEl && busEl.value;
    const url = '/api/metrics?range=' + encodeURIComponent(range) +
                (busId ? '&bus_id=' + encodeURIComponent(busId) : '');
    let payload;
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error('http ' + resp.status);
      payload = await resp.json();
    } catch (err) {
      console.warn('metrics fetch failed', err);
      return;
    }
    const series = payload.series || [];
    const rx   = []; const cctv = [];
    const loss = []; const rtt  = [];
    series.forEach((r) => {
      if (r.rx_bps         != null) rx.push({ x: r.ts, y: r.rx_bps });
      if (r.cctv_bps       != null) cctv.push({ x: r.ts, y: r.cctv_bps });
      if (r.heartbeat_loss != null) loss.push({ x: r.ts, y: r.heartbeat_loss * 100 });
      if (r.rtt_ms         != null) rtt.push({ x: r.ts, y: r.rtt_ms });
    });
    if (!CHARTS.rx)   CHARTS.rx   = mkChart('chart-rx',   PALETTE.rx,   (v) => (v / 1e6).toFixed(1) + 'M');
    if (!CHARTS.cctv) CHARTS.cctv = mkChart('chart-cctv', PALETTE.cctv, (v) => (v / 1e6).toFixed(1) + 'M');
    if (!CHARTS.loss) CHARTS.loss = mkChart('chart-loss', PALETTE.loss, (v) => v.toFixed(0) + '%');
    if (!CHARTS.rtt)  CHARTS.rtt  = mkChart('chart-rtt',  PALETTE.rtt,  (v) => v.toFixed(0) + 'ms');
    setData(CHARTS.rx, rx);
    setData(CHARTS.cctv, cctv);
    setData(CHARTS.loss, loss);
    setData(CHARTS.rtt, rtt);
  }
  function setData(chart, data) {
    if (!chart) return;
    chart.data.datasets[0].data = data;
    chart.update('none');
  }

  // ====================================================================
  // forensic archive
  // ====================================================================

  async function refreshForensics() {
    const busEl    = document.getElementById('fa-bus');
    const attackEl = document.getElementById('fa-attack');
    const sinceEl  = document.getElementById('fa-since');
    const untilEl  = document.getElementById('fa-until');
    const params = new URLSearchParams();
    if (busEl && busEl.value) params.set('bus_id', busEl.value);
    if (attackEl && attackEl.value) params.set('attack_type', attackEl.value);
    if (sinceEl && sinceEl.value) {
      const t = Date.parse(sinceEl.value) / 1000;
      if (!isNaN(t)) params.set('since', t);
    }
    if (untilEl && untilEl.value) {
      const t = (Date.parse(untilEl.value) / 1000) + 86400;
      if (!isNaN(t)) params.set('until', t);
    }
    params.set('limit', '200');

    const tbody = document.querySelector('#fa-table tbody');
    try {
      const resp = await fetch('/api/forensics?' + params.toString());
      if (!resp.ok) throw new Error('http ' + resp.status);
      const arr = await resp.json();
      const rows = Array.isArray(arr) ? arr : (arr.forensics || []);
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="fa-empty">no reports</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map((f) => {
        const at = (f.attack_type || 'unknown').toLowerCase();
        const safeCls = at.replace(/[^a-z0-9_]/g, '_');
        return '<tr>' +
          '<td>' + esc(fmtDate(f.ts)) + '</td>' +
          '<td>' + esc(f.bus_id) + '</td>' +
          '<td><span class="pill ' + esc(safeCls) + '">' + esc(prettyType(at) || at) + '</span></td>' +
          '<td>' + esc(fmtBytes(f.bytes)) + '</td>' +
          '<td><a href="' + esc(f.url) + '" target="_blank" rel="noopener">download</a></td>' +
        '</tr>';
      }).join('');
    } catch (err) {
      console.warn('forensics fetch failed', err);
      tbody.innerHTML = '<tr><td colspan="5" class="fa-empty">error loading archive</td></tr>';
    }
  }

  // ====================================================================
  // wire-up
  // ====================================================================

  document.addEventListener('DOMContentLoaded', () => {
    // Filter tabs
    document.querySelectorAll('.filter-tabs .tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-tabs .tab').forEach((b) => b.classList.remove('is-active'));
        btn.classList.add('is-active');
        currentFilter = btn.dataset.filter;
        document.getElementById('events-list').innerHTML = renderEvents(lastEvents);
      });
    });

    // Map (eager init so it sizes correctly)
    setTimeout(ensureMap, 50);

    // Initial polls
    refreshBuses();
    refreshCharts();
    refreshForensics();

    // Recurring polls
    setInterval(refreshBuses, 3000);
    setInterval(refreshCharts, 15000);
    setInterval(refreshForensics, 30000);

    // Chart controls
    const rangeSel = document.getElementById('range-select');
    const busSel   = document.getElementById('bus-select');
    const chartBtn = document.getElementById('chart-refresh');
    if (rangeSel) rangeSel.addEventListener('change', refreshCharts);
    if (busSel)   busSel.addEventListener('change', refreshCharts);
    if (chartBtn) chartBtn.addEventListener('click', refreshCharts);

    // Forensic controls
    const faBtn = document.getElementById('fa-refresh');
    ['fa-bus', 'fa-attack', 'fa-since', 'fa-until'].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('change', refreshForensics);
    });
    if (faBtn) faBtn.addEventListener('click', refreshForensics);
  });
})();
