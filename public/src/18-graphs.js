  // =================================================================
  // 18-graphs.js: Metric graphs.
  // =================================================================


  /**
   * One metric, at full size, over as long as it has been recorded.
   *
   * The sparkline on a card answers "is this moving"; this answers "when
   * did it start" and "is today unusual", which needs axes, a range and
   * the numbers spelled out.
   */
  const METRICS = {
    cpu: { label: 'CPU utilisation', unit: '%', colour: 'var(--green)', max: 100 },
    poeW: { label: 'PoE load', unit: 'W', colour: 'var(--blue)' },
    cpuPps: { label: 'CPU input rate', unit: 'pps', colour: 'var(--amber)' }
  };

  function initGraph(s) {
    s.graphOverlay = s.pane.querySelector('.f-graph-overlay');
    s.graphBody = s.pane.querySelector('.f-graph-body');
    s.graphTitle = s.pane.querySelector('.f-graph-title');
    s.graphStatus = s.pane.querySelector('.f-graph-status');
    s.graphRange = 24 * 60 * 60 * 1000;

    s.pane.querySelector('.f-graph-close').addEventListener('click', () => closeOverlays(s));
    for (const btn of s.pane.querySelectorAll('.graph-ranges .tr')) {
      btn.addEventListener('click', () => {
        for (const b of s.pane.querySelectorAll('.graph-ranges .tr')) b.classList.remove('active');
        btn.classList.add('active');
        s.graphRange = Number(btn.dataset.range);
        // The range decides how far back to *ask*, not only what to draw:
        // choosing "7 days" while holding one day would silently show a
        // day and label it a week.
        loadHistory(s, s.graphRange || 0).then(() => drawGraph(s));
      });
    }
    s.pane.querySelector('.f-graph-save').addEventListener('click', () => {
      const rows = graphSamples(s);
      const key = s.graphMetric;
      const csv = 'time,' + key + '\n' + rows
        .map((r) => new Date(r.t).toISOString() + ',' + (r[key] === undefined ? '' : r[key]))
        .join('\n');
      download(safeHost(s.host) + '-' + key + '-' + stamp() + '.csv', csv);
    });
  }

  function openGraph(s, key) {
    if (!METRICS[key]) return;
    s.graphMetric = key;
    s.graphTitle.textContent = METRICS[key].label + '  \u00b7  ' + (s.sysName || s.host);
    openOverlay(s, 'graphOverlay');
    // The card's own hour is in memory; everything older has to be asked
    // for, and the range decides how much. graphRange may legitimately be 0
    // ("All"), which must be passed through rather than replaced by a default.
    const win = Number.isFinite(s.graphRange) ? s.graphRange : 24 * 60 * 60 * 1000;
    loadHistory(s, win).then(() => drawGraph(s));
    drawGraph(s);
  }

  function graphSamples(s) {
    const key = s.graphMetric;
    const since = s.graphRange ? Date.now() - s.graphRange : 0;
    return (s.history || [])
      .filter((x) => x.t >= since && x[key] !== null && x[key] !== undefined &&
        Number.isFinite(x[key]));
  }

  function drawGraph(s) {
    const host = s.graphBody;
    if (!host) return;
    clear(host);
    const key = s.graphMetric;
    const meta = METRICS[key] || {};
    const pts = graphSamples(s);

    if (pts.length < 2) {
      host.appendChild(el('div', 'empty-state', pts.length
        ? 'Only one reading so far in this range \u2014 a line needs two.'
        : 'Nothing recorded in this range yet.'));
      s.graphStatus.textContent = '';
      return;
    }

    const values = pts.map((p) => p[key]);
    const min = Math.min.apply(null, values);
    const max = Math.max.apply(null, values);
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    const peak = pts[values.indexOf(max)];

    const stats = el('div', 'graph-stats');
    const stat = (label, value) => {
      const span = el('span', '', label);
      span.appendChild(el('b', '', value));
      stats.appendChild(span);
    };
    stat('Now', groupNum(values[values.length - 1]) + ' ' + (meta.unit || ''));
    stat('Peak', groupNum(max) + ' ' + (meta.unit || '') +
      '  at ' + new Date(peak.t).toLocaleString());
    stat('Average', groupNum(Math.round(avg * 10) / 10) + ' ' + (meta.unit || ''));
    stat('Lowest', groupNum(min) + ' ' + (meta.unit || ''));
    host.appendChild(stats);

    const W = 1000, H = 420, L = 62, R = 18, T = 16, B = 34;
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'none');

    const t0 = pts[0].t, t1 = pts[pts.length - 1].t;
    const tspan = (t1 - t0) || 1;
    // A y-axis that starts at zero tells the truth about proportion; one
    // that starts at the minimum shows detail. Utilisation gets zero,
    // because "40% versus 45%" should not look like a doubling.
    const top = meta.max ? meta.max : (max <= 0 ? 1 : max * 1.1);
    const bottom = 0;
    const x = (t) => L + ((t - t0) / tspan) * (W - L - R);
    const y = (v) => T + (1 - (v - bottom) / ((top - bottom) || 1)) * (H - T - B);

    const line = (x1, y1, x2, y2, cls) => {
      const el2 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      el2.setAttribute('x1', x1); el2.setAttribute('y1', y1);
      el2.setAttribute('x2', x2); el2.setAttribute('y2', y2);
      el2.setAttribute('class', cls);
      svg.appendChild(el2);
    };
    const text = (tx, ty, str, anchor) => {
      const el2 = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      el2.setAttribute('x', tx); el2.setAttribute('y', ty);
      el2.setAttribute('class', 'graph-tick');
      if (anchor) el2.setAttribute('text-anchor', anchor);
      el2.textContent = str;
      svg.appendChild(el2);
    };

    for (let i = 0; i <= 4; i++) {
      const v = bottom + ((top - bottom) * i) / 4;
      const yy = y(v);
      line(L, yy, W - R, yy, 'graph-grid');
      text(L - 8, yy + 3, groupNum(Math.round(v)), 'end');
    }
    line(L, T, L, H - B, 'graph-axis');
    line(L, H - B, W - R, H - B, 'graph-axis');

    // Time labels: a date when the range spans days, a clock when it does
    // not -- "14:05" on a week-long graph is meaningless.
    const spansDays = tspan > 36 * 60 * 60 * 1000;
    for (let i = 0; i <= 4; i++) {
      const t = t0 + (tspan * i) / 4;
      const d = new Date(t);
      text(x(t), H - B + 16,
        spansDays ? (d.getDate() + '/' + (d.getMonth() + 1))
          : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        i === 0 ? 'start' : (i === 4 ? 'end' : 'middle'));
    }

    const d = pts.map((p, i) => (i ? 'L' : 'M') + x(p.t).toFixed(1) + ' ' + y(p[key]).toFixed(1))
      .join(' ');
    const area = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    area.setAttribute('d', d + ' L' + x(t1).toFixed(1) + ' ' + y(bottom) +
      ' L' + x(t0).toFixed(1) + ' ' + y(bottom) + ' Z');
    area.setAttribute('class', 'graph-area');
    area.setAttribute('fill', meta.colour || 'var(--green)');
    svg.appendChild(area);

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    path.setAttribute('class', 'graph-line');
    path.setAttribute('stroke', meta.colour || 'var(--green)');
    svg.appendChild(path);

    /**
     * Every reading is a point. Above a few hundred they would merge into
     * a band and hide the line they belong to, so past that they are drawn
     * smaller and fainter -- still every reading, just not shouting. The
     * hover works on all of them either way.
     */
    const dense = pts.length > 400;
    const dots = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    for (const point of pts) {
      const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('cx', x(point.t).toFixed(1));
      c.setAttribute('cy', y(point[key]).toFixed(1));
      c.setAttribute('r', dense ? 1 : 2.4);
      c.setAttribute('fill', meta.colour || 'var(--green)');
      c.setAttribute('opacity', dense ? 0.45 : 0.9);
      dots.appendChild(c);
    }
    svg.appendChild(dots);

    // The reading under the pointer, spelled out. A crosshair rather than
    // a hit target per point: at one-pixel spacing you cannot aim at a
    // dot, but you can always aim at a moment in time.
    const marker = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    marker.setAttribute('visibility', 'hidden');
    const vline = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    vline.setAttribute('class', 'graph-grid');
    vline.setAttribute('y1', T); vline.setAttribute('y2', H - B);
    marker.appendChild(vline);
    const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    // Small enough to point at the reading rather than cover it.
    ring.setAttribute('r', 2.8);
    ring.setAttribute('fill', 'var(--bg)');
    ring.setAttribute('stroke', meta.colour || 'var(--green)');
    ring.setAttribute('stroke-width', 1.4);
    marker.appendChild(ring);
    svg.appendChild(marker);

    const readout = el('div', 'graph-readout');
    readout.style.visibility = 'hidden';
    host.appendChild(readout);

    const nearest = (time) => {
      // Binary search: at 25,000 points a linear scan on every mouse move
      // is enough to make the pointer feel sticky.
      let lo = 0, hi = pts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (pts[mid].t < time) lo = mid + 1; else hi = mid;
      }
      const before = pts[Math.max(0, lo - 1)];
      return Math.abs(before.t - time) < Math.abs(pts[lo].t - time) ? before : pts[lo];
    };

    svg.addEventListener('mousemove', (e) => {
      const box = svg.getBoundingClientRect();
      const px = ((e.clientX - box.left) / box.width) * W;
      if (px < L || px > W - R) { marker.setAttribute('visibility', 'hidden'); readout.style.visibility = 'hidden'; return; }
      const t = t0 + ((px - L) / (W - L - R)) * tspan;
      const point = nearest(t);
      const cx = x(point.t), cy = y(point[key]);
      vline.setAttribute('x1', cx); vline.setAttribute('x2', cx);
      ring.setAttribute('cx', cx); ring.setAttribute('cy', cy);
      marker.setAttribute('visibility', 'visible');
      readout.textContent = groupNum(point[key]) + ' ' + (meta.unit || '') + '   \u00b7   ' +
        new Date(point.t).toLocaleString();
      readout.style.visibility = 'visible';
      // Beside the cursor rather than parked at the bottom: a reading you
      // have to go and look for is a reading you read less often.
      const hostBox = host.getBoundingClientRect();
      let lx = e.clientX - hostBox.left + 14;
      let ly = e.clientY - hostBox.top + 16;
      if (lx + readout.offsetWidth > hostBox.width - 6) {
        lx = e.clientX - hostBox.left - readout.offsetWidth - 14;
      }
      if (ly + readout.offsetHeight > hostBox.height - 6) {
        ly = e.clientY - hostBox.top - readout.offsetHeight - 14;
      }
      readout.style.left = Math.max(0, lx) + 'px';
      readout.style.top = Math.max(0, ly) + 'px';
    });
    svg.addEventListener('mouseleave', () => {
      marker.setAttribute('visibility', 'hidden');
      readout.style.visibility = 'hidden';
    });

    host.appendChild(svg);
    s.graphStatus.textContent = pts.length.toLocaleString() + ' reading(s) \u00b7 ' +
      new Date(t0).toLocaleString() + ' to ' + new Date(t1).toLocaleString();
  }
