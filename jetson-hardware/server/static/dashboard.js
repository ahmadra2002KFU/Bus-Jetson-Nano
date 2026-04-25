// Al-Ahsa Smart Bus dashboard client.
// - Intercepts HTMX polling swaps for /api/events and /api/buses and renders
//   JSON responses into HTML.
// - Drives Chart.js historical line charts from /api/metrics.
// - Shows per-bus GPS positions on a Leaflet map (ns-3 grid, Simple CRS).

(function () {
  'use strict';

  // -------------------- helpers --------------------

  function fmtTs(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    return d.toISOString().slice(11, 19);
  }

  function fmtBytes(n) {
    if (n == null) return '';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(2) + ' MB';
  }

  function fmtBps(b) {
    if (b == null || !isFinite(b)) return '';
    if (b < 1000) return b.toFixed(0) + ' bps';
    if (b < 1e6) return (b / 1000).toFixed(1) + ' kbps';
    return (b / 1e6).toFixed(2) + ' Mbps';
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function attackClass(type) {
    if (!type) return '';
    if (type === 'ddos' || type === 'gps_spoof' ||
        type === 'forensic_ddos' || type === 'forensic_gps_spoof') {
      return 'ev-attack';
    }
    return '';
  }

  // -------------------- events panel --------------------

  function renderEvents(arr) {
    if (!arr || !arr.length) return '<em>no events yet</em>';
    return arr.map((ev) => {
      const detail = ev.detail == null
        ? ''
        : (typeof ev.detail === 'string'
            ? ev.detail
            : JSON.stringify(ev.detail));
      return (
        '<div class="event-row ' + attackClass(ev.type) + '">' +
          '<span class="ev-ts">' + esc(fmtTs(ev.ts)) + '</span>' +
          '<span class="ev-bus">bus ' + esc(ev.bus_id) + '</span>' +
          '<span class="ev-type">' + esc(ev.type) + '</span>' +
          '<span class="ev-detail">' + esc(detail).slice(0, 200) + '</span>' +
        '</div>'
      );
    }).join('');
  }

  // -------------------- buses / telemetry panel --------------------

  const MAP_STATE = { map: null, markers: {} };

  function ensureMap() {
    if (MAP_STATE.map || typeof L === 'undefined') return MAP_STATE.map;
    const el = document.getElementById('map');
    if (!el) return null;
    MAP_STATE.map = L.map(el, {
      crs: L.CRS.Simple,
      minZoom: -4,
      maxZoom: 4,
      attributionControl: false,
    });
    // ns-3 grid is ~20 km x 20 km (0..20000 m). Leaflet Simple CRS uses
    // (y, x); we flip y so north is up.
    const bounds = [[-20000, 0], [0, 20000]];
    MAP_STATE.map.fitBounds(bounds);
    L.rectangle(bounds, { color: '#334155', weight: 1, fill: false })
      .addTo(MAP_STATE.map);
    return MAP_STATE.map;
  }

  function updateMap(buses) {
    const map = ensureMap();
    if (!map) return;
    const seen = new Set();
    (buses || []).forEach((b) => {
      if (!b.last_gps) return;
      const { pos_x, pos_y } = b.last_gps;
      if (pos_x == null || pos_y == null) return;
      const latlng = [-pos_y, pos_x];
      seen.add(b.bus_id);
      if (MAP_STATE.markers[b.bus_id]) {
        MAP_STATE.markers[b.bus_id].setLatLng(latlng);
      } else {
        MAP_STATE.markers[b.bus_id] = L.circleMarker(latlng, {
          radius: 6, color: '#60a5fa', fillColor: '#60a5fa', fillOpacity: 0.8,
        }).addTo(map).bindTooltip('bus ' + b.bus_id);
      }
    });
    Object.keys(MAP_STATE.markers).forEach((id) => {
      if (!seen.has(parseInt(id, 10))) {
        MAP_STATE.markers[id].remove();
        delete MAP_STATE.markers[id];
      }
    });
  }

  function renderBuses(arr) {
    if (!arr || !arr.length) return '<em>no buses seen yet</em>';
    return arr.map((b) => {
      const loss = b.heartbeat_loss == null
        ? '-' : (b.heartbeat_loss * 100).toFixed(1) + '%';
      const rtt = b.rtt_ms == null ? '-' : b.rtt_ms.toFixed(1) + ' ms';
      const rx = fmtBps(b.rx_bps) || '-';
      const cctv = fmtBps(b.cctv_bps) || '-';
      const gps = b.last_gps
        ? '(' + b.last_gps.pos_x.toFixed(0) + ', ' + b.last_gps.pos_y.toFixed(0) + ')'
        : '-';
      return (
        '<div class="bus-card">' +
          '<span class="bid">bus ' + esc(b.bus_id) + '</span>' +
          '<span class="metrics">' +
            'rx=' + esc(rx) + ' | cctv=' + esc(cctv) +
            ' | loss=' + esc(loss) + ' | rtt=' + esc(rtt) +
            ' | gps=' + esc(gps) +
          '</span>' +
        '</div>'
      );
    }).join('');
  }

  // -------------------- HTMX swap interception --------------------

  document.body.addEventListener('htmx:beforeSwap', (e) => {
    const id = e.detail.target.id;
    if (id !== 'events-list' && id !== 'buses-list') return;
    try {
      const data = JSON.parse(e.detail.xhr.responseText);
      e.detail.shouldSwap = false;
      const el = document.getElementById(id);
      if (id === 'events-list') {
        el.innerHTML = renderEvents(data);
      } else if (id === 'buses-list') {
        el.innerHTML = renderBuses(data);
        updateMap(data);
        refreshBusSelect(data);
      }
    } catch (err) {
      console.error('swap parse failed for', id, err);
    }
  });

  // -------------------- bus-select dropdown --------------------

  function refreshBusSelect(buses) {
    const sel = document.getElementById('bus-select');
    if (!sel) return;
    const ids = new Set((buses || []).map((b) => String(b.bus_id)));
    const existing = new Set(
      Array.from(sel.options).map((o) => o.value).filter(Boolean)
    );
    if (ids.size === existing.size && [...ids].every((x) => existing.has(x))) {
      return;
    }
    const current = sel.value;
    sel.innerHTML = '<option value="">(all)</option>' +
      [...ids].sort((a, b) => +a - +b)
        .map((id) => '<option value="' + esc(id) + '">bus ' + esc(id) + '</option>')
        .join('');
    if (current && ids.has(current)) sel.value = current;
  }

  // -------------------- historical charts --------------------

  const CHARTS = {};

  function mkChart(canvasId, label, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === 'undefined') return null;
    const ctx = canvas.getContext('2d');
    return new Chart(ctx, {
      type: 'line',
      data: { datasets: [{
        label, data: [], borderColor: color, backgroundColor: color,
        borderWidth: 1.2, pointRadius: 0, tension: 0.2,
      }] },
      options: {
        animation: false, parsing: false, responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { type: 'linear', ticks: {
              callback: (v) => new Date(v * 1000).toISOString().slice(11, 19),
              color: '#94a3b8',
            }, grid: { color: '#212838' } },
          y: { beginAtZero: true, ticks: { color: '#94a3b8' },
              grid: { color: '#212838' } },
        },
        plugins: { legend: { labels: { color: '#cbd5e1' } } },
      },
    });
  }

  async function refreshCharts() {
    const rangeEl = document.getElementById('range-select');
    const busEl = document.getElementById('bus-select');
    if (!rangeEl) return;
    const range = rangeEl.value || '1h';
    const busId = busEl && busEl.value;
    const url = '/api/metrics?range=' + encodeURIComponent(range) +
      (busId ? '&bus_id=' + encodeURIComponent(busId) : '');
    let payload;
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error('metrics http ' + resp.status);
      payload = await resp.json();
    } catch (err) {
      console.error('metrics fetch failed', err);
      return;
    }
    const series = payload.series || [];
    const rx = []; const cctv = []; const loss = [];
    series.forEach((r) => {
      if (r.rx_bps != null)         rx.push({ x: r.ts, y: r.rx_bps });
      if (r.cctv_bps != null)       cctv.push({ x: r.ts, y: r.cctv_bps });
      if (r.heartbeat_loss != null) loss.push({ x: r.ts, y: r.heartbeat_loss * 100 });
    });
    if (!CHARTS.rx)   CHARTS.rx   = mkChart('chart-rx',   'rx bps',           '#60a5fa');
    if (!CHARTS.cctv) CHARTS.cctv = mkChart('chart-cctv', 'cctv bps',         '#34d399');
    if (!CHARTS.loss) CHARTS.loss = mkChart('chart-loss', 'heartbeat loss %', '#f87171');
    if (CHARTS.rx)   { CHARTS.rx.data.datasets[0].data   = rx;   CHARTS.rx.update('none'); }
    if (CHARTS.cctv) { CHARTS.cctv.data.datasets[0].data = cctv; CHARTS.cctv.update('none'); }
    if (CHARTS.loss) { CHARTS.loss.data.datasets[0].data = loss; CHARTS.loss.update('none'); }
  }

  // -------------------- forensic archive --------------------

  async function refreshForensics() {
    const busEl = document.getElementById('fa-bus');
    const attackEl = document.getElementById('fa-attack');
    const sinceEl = document.getElementById('fa-since');
    const untilEl = document.getElementById('fa-until');
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
      if (!resp.ok) throw new Error('forensics http ' + resp.status);
      const arr = await resp.json();
      if (!arr.length) {
        tbody.innerHTML =
          '<tr><td colspan="5"><em>no forensic reports</em></td></tr>';
        return;
      }
      tbody.innerHTML = arr.map((f) => (
        '<tr>' +
          '<td>' + esc(new Date(f.ts * 1000).toISOString().replace('T', ' ').slice(0, 19)) + '</td>' +
          '<td>' + esc(f.bus_id) + '</td>' +
          '<td>' + esc(f.attack_type) + '</td>' +
          '<td>' + esc(fmtBytes(f.bytes)) + '</td>' +
          '<td><a href="' + esc(f.url) + '" target="_blank" rel="noopener">download</a></td>' +
        '</tr>'
      )).join('');
    } catch (err) {
      console.error('forensics fetch failed', err);
      tbody.innerHTML = '<tr><td colspan="5"><em>error loading archive</em></td></tr>';
    }
  }

  // -------------------- wire-up --------------------

  document.addEventListener('DOMContentLoaded', () => {
    ensureMap();
    refreshCharts();
    refreshForensics();

    const rangeSel = document.getElementById('range-select');
    const busSel = document.getElementById('bus-select');
    const chartBtn = document.getElementById('chart-refresh');
    if (rangeSel) rangeSel.addEventListener('change', refreshCharts);
    if (busSel)   busSel.addEventListener('change', refreshCharts);
    if (chartBtn) chartBtn.addEventListener('click', refreshCharts);

    const faBtn = document.getElementById('fa-refresh');
    const faBus = document.getElementById('fa-bus');
    const faAttack = document.getElementById('fa-attack');
    if (faBtn)    faBtn.addEventListener('click', refreshForensics);
    if (faBus)    faBus.addEventListener('change', refreshForensics);
    if (faAttack) faAttack.addEventListener('change', refreshForensics);

    setInterval(refreshCharts, 30_000);
    setInterval(refreshForensics, 30_000);
  });
})();
