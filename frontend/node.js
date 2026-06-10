/* =============================================================
   ARGUS · node motion engine (shared)
   Reads window.ARGUS_NODE config set by each page.
   Handles: clock · hero decode · radar+target-lock · feed stream
            · number scramble · link spotlight · background motes
   ============================================================= */
(function () {
  const CFG = window.ARGUS_NODE || {};
  const RM = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#eba35a';
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

  /* i18n is handled per-tool (data-i18n + .lang-switch); ARGUS i18n omitted. */

  /* ---------------- UTC clock ---------------- */
  (function clock() {
    const el = $('#clock'); if (!el) return;
    const pad = (n) => String(n).padStart(2, '0');
    const tick = () => {
      const d = new Date();
      el.textContent = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    };
    tick(); setInterval(tick, 1000);
  })();

  /* ---------------- eyebrow rule draw-in ---------------- */
  requestAnimationFrame(() => {
    $$('.eyebrow .ln, .section-label .ln').forEach((ln) => { ln.style.transition = 'width .7s cubic-bezier(.22,1,.36,1)'; ln.style.width = '36px'; });
  });

  /* ---------------- hero decode ---------------- */
  (function decode() {
    const GLYPHS = '█▓▒░#%&@/\\<>=+*ABCDEF0123456789';
    $$('[data-decode]').forEach((el, idx) => {
      const final = el.textContent;
      if (RM) return;
      const chars = final.split('');
      el.textContent = '';
      const spans = chars.map((c) => {
        const s = document.createElement('span');
        s.className = 'ch';
        s.textContent = c === ' ' ? '\u00a0' : c;
        s.style.opacity = '0';
        el.appendChild(s);
        return { s, c };
      });
      const startDelay = 180 + idx * 120;
      spans.forEach(({ s, c }, i) => {
        if (c === ' ' || c === '-') { setTimeout(() => { s.style.opacity = '1'; }, startDelay + i * 45); return; }
        setTimeout(() => {
          s.style.opacity = '1';
          let n = 0; const rounds = 5 + (i % 4);
          const iv = setInterval(() => {
            if (n >= rounds) { clearInterval(iv); s.textContent = c; s.style.color = ''; return; }
            s.textContent = GLYPHS[(Math.random() * GLYPHS.length) | 0];
            s.style.color = accent;
            n++;
          }, 42);
        }, startDelay + i * 55);
      });
    });
  })();

  /* ---------------- number / text scramble ---------------- */
  (function scramble() {
    if (RM) return;
    $$('[data-scramble]').forEach((el, idx) => {
      const final = el.textContent; const chars = final.split('');
      const GL = '0123456789';
      setTimeout(() => {
        let frame = 0; const total = 26;
        const iv = setInterval(() => {
          el.textContent = chars.map((c, i) => {
            if (!/[0-9]/.test(c)) return c;
            if (frame > total - (chars.length - i) * 2) return c;
            return GL[(Math.random() * GL.length) | 0];
          }).join('');
          if (frame++ >= total) { clearInterval(iv); el.textContent = final; }
        }, 45);
      }, 600 + idx * 120);
    });
  })();

  /* ---------------- background motes ---------------- */
  (function motes() {
    const wrap = $('.bg-motes'); if (!wrap || RM) return;
    const N = 16;
    for (let i = 0; i < N; i++) {
      const m = document.createElement('span');
      m.className = 'mote';
      m.style.left = (Math.random() * 100) + '%';
      m.style.bottom = '-2vh';
      const dur = 10 + Math.random() * 14;
      m.style.animationDuration = dur + 's';
      m.style.animationDelay = (-Math.random() * dur) + 's';
      m.style.opacity = (0.2 + Math.random() * 0.4).toFixed(2);
      m.style.transform = `scale(${(0.6 + Math.random() * 1.2).toFixed(2)})`;
      wrap.appendChild(m);
    }
  })();

  /* ---------------- link spotlight ---------------- */
  $$('.links a').forEach((a) => {
    a.addEventListener('pointermove', (e) => {
      const r = a.getBoundingClientRect();
      a.style.setProperty('--mx', (e.clientX - r.left) + 'px');
      a.style.setProperty('--my', (e.clientY - r.top) + 'px');
    });
  });

  /* ---------------- build feed stream ---------------- */
  (function feed() {
    const items = $$('.feed li');
    items.forEach((li, i) => setTimeout(() => li.classList.add('in'), 260 + i * 160));
  })();

  /* ---------------- radar ---------------- */
  (function radar() {
    const svg = $('#radar-svg'); if (!svg) return;
    const NS = 'http://www.w3.org/2000/svg';
    const SIZE = 440, C = SIZE / 2;
    const mid = getComputedStyle(document.documentElement).getPropertyValue('--mid').trim();
    const dim = getComputedStyle(document.documentElement).getPropertyValue('--line').trim();
    const el = (t, a) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); return e; };
    svg.setAttribute('viewBox', `0 0 ${SIZE} ${SIZE}`);

    [0.97, 0.75, 0.53, 0.31].forEach((s, i) =>
      svg.appendChild(el('circle', { cx: C, cy: C, r: C * s, fill: 'none', stroke: i === 0 ? accent : dim, 'stroke-width': 1, 'stroke-dasharray': i === 0 ? '0' : '2 5', opacity: i === 0 ? 0.7 : 1 })));
    svg.appendChild(el('line', { x1: C, y1: 8, x2: C, y2: SIZE - 8, stroke: dim, 'stroke-dasharray': '2 7' }));
    svg.appendChild(el('line', { x1: 8, y1: C, x2: SIZE - 8, y2: C, stroke: dim, 'stroke-dasharray': '2 7' }));
    for (let i = 0; i < 72; i++) {
      const ang = i * 5 * Math.PI / 180;
      const r1 = C * 0.97, r2 = r1 - (i % 18 === 0 ? 12 : i % 6 === 0 ? 8 : 4);
      svg.appendChild(el('line', {
        x1: C + Math.cos(ang) * r1, y1: C + Math.sin(ang) * r1,
        x2: C + Math.cos(ang) * r2, y2: C + Math.sin(ang) * r2,
        stroke: i % 18 === 0 ? accent : mid, 'stroke-width': 1, opacity: i % 6 === 0 ? 0.8 : 0.4,
      }));
    }
    // bearing labels
    ['000', '090', '180', '270'].forEach((t, i) => {
      const ang = (i * 90 - 90) * Math.PI / 180;
      const tx = el('text', {
        x: C + Math.cos(ang) * C * 0.86, y: C + Math.sin(ang) * C * 0.86 + 3,
        'text-anchor': 'middle', 'font-family': 'IBM Plex Mono, monospace', 'font-size': 9,
        fill: mid, 'letter-spacing': 1,
      });
      tx.textContent = t; svg.appendChild(tx);
    });

    const blips = (CFG.radar && CFG.radar.blips) || [
      { a: 35, r: 0.36, lbl: '', speed: -1.0 },
      { a: 100, r: 0.62, lbl: '', speed: 0.8 },
      { a: 165, r: 0.46, lbl: '', speed: -1.3 },
      { a: 215, r: 0.78, lbl: '', speed: 0.6 },
      { a: 285, r: 0.40, lbl: '', speed: -0.9 },
      { a: 330, r: 0.70, lbl: '', speed: 1.1, live: true },
    ];
    const accent2 = getComputedStyle(document.documentElement).getPropertyValue('--accent-2').trim() || accent;
    const groups = blips.map((b) => {
      const g = el('g', {});
      const dot = el('circle', { cx: 0, cy: 0, r: b.live ? 5.5 : 3, fill: b.live ? accent : accent2, opacity: b.live ? 1 : 0.6 });
      if (b.live) dot.style.filter = `drop-shadow(0 0 6px ${accent})`;
      g.appendChild(dot);
      if (b.live) {
        const p = el('circle', { cx: 0, cy: 0, r: 7, fill: 'none', stroke: accent, 'stroke-width': 1, opacity: 0.6 });
        p.appendChild(el('animate', { attributeName: 'r', from: '7', to: '22', dur: '1.8s', repeatCount: 'indefinite' }));
        p.appendChild(el('animate', { attributeName: 'opacity', from: '0.6', to: '0', dur: '1.8s', repeatCount: 'indefinite' }));
        g.appendChild(p);
      }
      if (b.lbl) {
        const tx = el('text', { x: 11, y: 4, 'font-family': 'IBM Plex Mono, monospace', 'font-size': 10, fill: b.live ? accent : mid });
        tx.textContent = b.lbl; g.appendChild(tx);
      }
      svg.appendChild(g);
      return { g, cfg: b };
    });

    // center node
    svg.appendChild(el('circle', { cx: C, cy: C, r: 3.5, fill: accent }));
    const ring = el('circle', { cx: C, cy: C, r: 9, fill: 'none', stroke: accent, 'stroke-opacity': 0.5 });
    ring.appendChild(el('animate', { attributeName: 'r', from: '9', to: '28', dur: '2.2s', repeatCount: 'indefinite' }));
    ring.appendChild(el('animate', { attributeName: 'stroke-opacity', from: '0.5', to: '0', dur: '2.2s', repeatCount: 'indefinite' }));
    svg.appendChild(ring);

    // target-lock reticle
    const lock = el('g', { opacity: 0 });
    const span = 16;
    [[-1, -1, 1, 0], [-1, -1, 0, 1], [1, -1, -1, 0], [1, -1, 0, 1], [-1, 1, 1, 0], [-1, 1, 0, -1], [1, 1, -1, 0], [1, 1, 0, -1]]
      .forEach(([sx, sy, dx, dy]) => lock.appendChild(el('line', {
        x1: sx * span, y1: sy * span, x2: sx * span + dx * 7, y2: sy * span + dy * 7, stroke: accent, 'stroke-width': 1.4,
      })));
    const lockTxt = el('text', { x: span + 6, y: -span + 2, 'font-family': 'IBM Plex Mono, monospace', 'font-size': 9, fill: accent, 'letter-spacing': 1 });
    lock.appendChild(lockTxt);
    svg.appendChild(lock);

    let t0 = performance.now();
    let lockTarget = null, lockUntil = 0, nextLock = 1500;
    function frame(t) {
      const dt = (t - t0) / 1000;
      groups.forEach(({ g, cfg }) => {
        const a = (cfg.a + dt * cfg.speed * 6) * Math.PI / 180;
        cfg._x = C + Math.cos(a) * C * cfg.r; cfg._y = C + Math.sin(a) * C * cfg.r;
        g.setAttribute('transform', `translate(${cfg._x},${cfg._y})`);
      });
      const now = t;
      if (!lockTarget && now > nextLock) {
        lockTarget = groups[(Math.random() * groups.length) | 0].cfg;
        lockUntil = now + 1700;
        lockTxt.textContent = 'LOCK ' + String(((Math.random() * 900) | 0) + 100);
        lock.setAttribute('opacity', '0.95');
      }
      if (lockTarget) {
        lock.setAttribute('transform', `translate(${lockTarget._x},${lockTarget._y})`);
        if (now > lockUntil) { lockTarget = null; lock.setAttribute('opacity', '0'); nextLock = now + 1600 + Math.random() * 2200; }
      }
      raf = requestAnimationFrame(frame);
    }
    let raf;
    if (!RM) raf = requestAnimationFrame(frame);
    else groups.forEach(({ g, cfg }) => {
      const a = cfg.a * Math.PI / 180;
      g.setAttribute('transform', `translate(${C + Math.cos(a) * C * cfg.r},${C + Math.sin(a) * C * cfg.r})`);
    });
  })();
})();
