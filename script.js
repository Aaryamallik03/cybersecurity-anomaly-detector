const menuButton = document.querySelector('.menu-button');
const nav = document.querySelector('.nav');
menuButton?.addEventListener('click', () => {
  const open = nav.classList.toggle('open');
  menuButton.setAttribute('aria-expanded', String(open));
});
nav?.querySelectorAll('a').forEach(link => link.addEventListener('click', () => {
  nav.classList.remove('open');
  menuButton?.setAttribute('aria-expanded', 'false');
}));



// Lightweight animated plasma-like background: soft color fields, not a WebGL dependency.
const canvas = document.querySelector('#plasma');
const ctx = canvas?.getContext('2d');
let width = 0, height = 0, frame = 0, pointer = { x: 0.5, y: 0.5 };
function resizeCanvas() {
  if (!canvas || !ctx) return;
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  width = rect.width; height = rect.height;
  canvas.width = Math.max(1, Math.floor(width * dpr));
  canvas.height = Math.max(1, Math.floor(height * dpr));
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
canvas?.parentElement?.addEventListener('pointermove', e => {
  const r = canvas.getBoundingClientRect();
  pointer = { x: (e.clientX-r.left)/r.width, y: (e.clientY-r.top)/r.height };
});
canvas?.parentElement?.addEventListener('pointerleave', () => pointer = {x:.5,y:.5});
window.addEventListener('resize', resizeCanvas);
resizeCanvas();
function blob(x, y, radius, color, alpha = 0.75) {
  if (!ctx) return;
  const g = ctx.createRadialGradient(x, y, 0, x, y, radius);
  g.addColorStop(0, color.replace('ALPHA', String(alpha)));
  g.addColorStop(1, color.replace('ALPHA', '0'));
  ctx.fillStyle = g;
  ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.fill();
}
function animate() {
  if (!ctx || !canvas) return;
  frame += 0.006;
  ctx.clearRect(0, 0, width, height);
  blob(width*(.27 + Math.sin(frame)*.08), height*(.32 + Math.cos(frame*.8)*.1), width*.48, 'rgba(255,115,190,ALPHA)', .85);
  blob(width*(.74 + Math.cos(frame*.65)*.1), height*(.4 + Math.sin(frame*.9)*.13), width*.48, 'rgba(111,94,255,ALPHA)', .8);
  blob(width*(.48 + (pointer.x-.5)*.12 + Math.sin(frame*.7)*.05), height*(.78 + (pointer.y-.5)*.1), width*.48, 'rgba(65,220,224,ALPHA)', .75);
  blob(width*.5, height*.45, width*.3, 'rgba(255,220,138,ALPHA)', .38);
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) requestAnimationFrame(animate);
}
animate();

// ===== Event Lab: a working, in-browser simulation of the detection pipeline =====
(() => {
  const root = document.querySelector('#lab');
  if (!root) return;
  const $ = sel => root.querySelector(sel);
  const WINDOW = 60, FAIL_RULE = 3, ALERT_AT = 0.7;
  const fresh = () => ({ clock: 0, seq: 0, events: [], seen: new Set(), alerts: [], audit: [], dups: 0, last: null });
  let S = fresh(), view = 'alerts', selected = null, showAll = false;

  // Deterministic judging: same history + same event => same verdict.
  function evaluate(ev, history) {
    const fails = history.filter(h => h.src === ev.src && h.type === 'failed_login' && ev.t - h.t <= WINDOW).length;
    const rules = [];
    let score;
    if (ev.type === 'failed_login') {
      const n = fails + 1;
      score = Math.min(1, 0.15 + 0.2 * (n - 1));
      if (n >= FAIL_RULE) rules.push('failed-login burst (' + n + ' in ' + WINDOW + 's)');
    } else {
      score = 0.05;
      if (fails >= FAIL_RULE) { score = 0.85; rules.push('success after ' + fails + ' failures'); }
    }
    score = Math.round(score * 100) / 100;
    return { score, rules, alert: rules.length > 0 || score >= ALERT_AT };
  }

  function ingest(st, ev) {
    st.audit.push({ id: ev.id, kind: 'in', text: 'received ' + label(ev.type).toLowerCase() + ' from ' + ev.src });
    if (st.seen.has(ev.id)) {
      st.dups++;
      st.audit.push({ id: ev.id, kind: 'dup', text: 'duplicate ignored' });
      return;
    }
    st.seen.add(ev.id);
    const v = evaluate(ev, st.events);
    st.events.push(Object.assign({}, ev, v));
    st.audit.push({ id: ev.id, kind: 'in', text: 'stored with score ' + v.score.toFixed(2) });
    if (v.alert) {
      st.alerts.push({ id: ev.id, src: ev.src, score: v.score, rules: v.rules });
      st.audit.push({ id: ev.id, kind: 'alert', text: 'ALERT raised: ' + (v.rules.join(', ') || 'high score') });
    }
  }

  const label = t => t === 'failed_login' ? 'Failed login' : 'Successful login';
  const src = () => $('#lab-src').value;

  function send(type, source, dt) {
    S.clock += dt || 5;
    S.seq += 1;
    const ev = { id: 'evt-' + String(S.seq).padStart(3, '0'), t: S.clock, src: source || src(), type };
    S.last = ev;
    ingest(S, ev);
    selected = ev.id;
    render();
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function render() {
    $('#st-events').textContent = S.events.length;
    $('#st-dups').textContent = S.dups;
    $('#st-alerts').textContent = S.alerts.length;
    $('#ev-count').textContent = String(S.events.length).padStart(2, '0');

    const list = $('#ev-list');
    list.replaceChildren();
    if (!S.events.length) list.appendChild(el('div', 'empty', 'No events yet. Send one above ☝️'));
    S.events.slice().reverse().slice(0, 12).forEach(e => {
      const row = el('button', 'ev' + (e.alert ? ' is-alert' : '') + (e.id === selected ? ' sel' : ''));
      row.type = 'button';
      row.appendChild(el('span', 'feed-emoji ' + (e.alert ? 'feed-orange' : 'feed-green'), e.alert ? '!' : '✓'));
      const copy = el('span', 'feed-copy');
      copy.append(el('b', '', label(e.type)), el('small', '', e.src + ' · t+' + e.t + 's · ' + e.id));
      const meter = el('span', 'meter');
      const bar = document.createElement('i');
      bar.style.width = Math.round(e.score * 100) + '%';
      meter.appendChild(bar);
      row.append(copy, meter, el('span', 'feed-tag ' + (e.alert ? 'tag-orange' : 'tag-green'), e.alert ? 'ALERT' : 'OK'));
      row.addEventListener('click', () => { selected = e.id; view = 'audit'; showAll = false; render(); });
      list.appendChild(row);
    });

    root.querySelectorAll('.lab-tab').forEach(t => {
      const on = t.dataset.view === view;
      t.classList.toggle('active', on);
      t.setAttribute('aria-pressed', String(on));
    });
    const log = $('#log-list');
    const toggle = $('#audit-toggle');
    log.replaceChildren();
    toggle.hidden = view !== 'audit' || !selected;
    if (view === 'alerts') {
      if (!S.alerts.length) log.appendChild(el('div', 'empty', 'No alerts yet. Try the burst of 6 failures.'));
      S.alerts.slice().reverse().forEach(a => {
        const line = el('div', 'log-line alert');
        line.append(el('b', '', a.id + ' · score ' + a.score.toFixed(2)), document.createElement('br'), document.createTextNode(a.src + ' · ' + (a.rules.join(', ') || 'high score')));
        log.appendChild(line);
      });
    } else {
      const filtered = !showAll && selected;
      toggle.textContent = filtered ? 'Show all events' : 'Show only ' + selected;
      const items = (filtered ? S.audit.filter(a => a.id === selected) : S.audit).slice(-30);
      if (!items.length) log.appendChild(el('div', 'empty', 'The audit trail is empty. Send an event.'));
      items.slice().reverse().forEach(a => {
        const line = el('div', 'log-line' + (a.kind === 'alert' ? ' alert' : a.kind === 'dup' ? ' dup' : ''));
        line.append(el('b', '', a.id), document.createTextNode(' · ' + a.text));
        log.appendChild(line);
      });
    }
  }

  function replay() {
    const msg = $('#replay-msg');
    if (!S.events.length) { msg.textContent = 'Nothing to replay yet. Send a few events first.'; return; }
    const R = fresh();
    S.events.forEach(e => ingest(R, { id: e.id, t: e.t, src: e.src, type: e.type }));
    const key = st => st.alerts.map(a => a.id + ':' + a.score).join('|');
    msg.textContent = 'Replayed ' + R.events.length + ' events → ' + R.alerts.length + ' alerts. ' + (key(R) === key(S) ? 'Identical to the original run ✓' : 'Different from the original ✗');
  }

  const actions = {
    ok: () => send('login_success'),
    fail: () => send('failed_login'),
    burst: () => { const s = src(); for (let i = 0; i < 6; i++) send('failed_login', s, 2); },
    dup: () => { if (!S.last) { send('failed_login'); return; } ingest(S, S.last); selected = S.last.id; render(); },
    rand: () => send(Math.random() < 0.6 ? 'login_success' : 'failed_login', ['10.0.0.24', '10.0.0.18', '10.0.0.07'][Math.floor(Math.random() * 3)]),
    reset: () => { S = fresh(); selected = null; view = 'alerts'; showAll = false; $('#replay-msg').textContent = ''; render(); },
    replay
  };
  root.querySelectorAll('[data-act]').forEach(b => b.addEventListener('click', () => actions[b.dataset.act]()));
  root.querySelectorAll('.lab-tab').forEach(t => t.addEventListener('click', () => { view = t.dataset.view; render(); }));
  $('#audit-toggle').addEventListener('click', () => { showAll = !showAll; render(); });
  render();
})();
