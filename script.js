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
  const WINDOW = 60, FAIL_RULE = 3, SCAN_PORTS = 5, ALERT_AT = 0.7, LARGE = 20000000;
  const TYPES = ['login_success', 'failed_login', 'connection', 'data_transfer'];
  const NAMES = { login_success: 'Successful login', failed_login: 'Failed login', connection: 'Connection', data_transfer: 'Data transfer' };
  const SENSITIVE = { 22: 'SSH', 23: 'Telnet', 445: 'SMB', 1433: 'SQL Server', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL' };
  const fresh = () => ({ clock: 0, seq: 0, events: [], seen: new Set(), alerts: [], audit: [], dups: 0, last: null });
  let S = fresh(), view = 'alerts', selected = null, showAll = false;
  const label = t => NAMES[t] || t;
  const mb = b => (b / 1000000).toFixed(b >= 10000000 ? 0 : 1) + ' MB';

  // Deterministic judging: same history + same event => same verdict.
  function evaluate(ev, history) {
    const win = history.filter(h => h.src === ev.src && ev.t - h.t <= WINDOW);
    const fails = win.filter(h => h.type === 'failed_login').length;
    const rules = [], notes = [];
    let score = 0.05;
    if (ev.type === 'failed_login') {
      const n = fails + 1;
      score = Math.min(1, 0.15 + 0.2 * (n - 1));
      if (n >= FAIL_RULE) rules.push('failed-login burst (' + n + ' in ' + WINDOW + 's)');
      else notes.push('failed login #' + n + ' from this source');
    } else if (ev.type === 'login_success' && fails >= FAIL_RULE) {
      score = 0.85;
      rules.push('success after ' + fails + ' failures');
    }
    if (ev.port && SENSITIVE[ev.port]) { score += 0.3; notes.push('sensitive port ' + ev.port + ' (' + SENSITIVE[ev.port] + ')'); }
    if (ev.bytes > LARGE) { score += Math.min(0.5, 0.3 + Math.log10(ev.bytes / LARGE) * 0.25); notes.push('unusually large transfer (' + mb(ev.bytes) + ')'); }
    if (ev.hour !== undefined && ev.hour < 6) { score += 0.25; notes.push('activity at ' + String(ev.hour).padStart(2, '0') + ':00, outside normal hours'); }
    if (ev.type === 'connection' && ev.port) {
      const ports = new Set(win.filter(h => h.type === 'connection' && h.port).map(h => h.port));
      ports.add(ev.port);
      if (ports.size >= SCAN_PORTS) { score += 0.4; rules.push('port scan (' + ports.size + ' ports in ' + WINDOW + 's)'); }
    }
    score = Math.round(Math.min(1, score) * 100) / 100;
    const reasons = rules.concat(notes);
    return { score, rules, alert: rules.length > 0 || score >= ALERT_AT, reasons: reasons.length ? reasons : ['no risk factors found'] };
  }

  function ingest(st, ev) {
    const where = ev.src + (ev.port ? ':' + ev.port : '');
    st.audit.push({ id: ev.id, kind: 'in', text: 'received ' + label(ev.type).toLowerCase() + ' from ' + where });
    if (st.seen.has(ev.id)) {
      st.dups++;
      st.audit.push({ id: ev.id, kind: 'dup', text: 'duplicate ignored' });
      return { id: ev.id, status: 'duplicate', message: 'this event id was already processed, so it was ignored' };
    }
    st.seen.add(ev.id);
    const v = evaluate(ev, st.events);
    st.events.push(Object.assign({}, ev, v, { raw: ev }));
    st.audit.push({ id: ev.id, kind: 'in', text: 'stored with score ' + v.score.toFixed(2) });
    if (v.alert) {
      st.alerts.push({ id: ev.id, src: ev.src, score: v.score, reasons: v.reasons });
      st.audit.push({ id: ev.id, kind: 'alert', text: 'ALERT raised: ' + v.reasons.join(', ') });
    }
    return { id: ev.id, status: 'accepted', score: v.score, alert: v.alert, reasons: v.reasons };
  }

  // Schema check, like the API's validation: bad events are rejected, not stored.
  function validate(o) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) return 'the event must be a JSON object';
    const ip = typeof o.src === 'string' ? o.src.trim().split('.') : [];
    if (ip.length !== 4 || ip.some(p => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return '"src" must be an IPv4 address like 10.0.0.24';
    if (!TYPES.includes(o.type)) return '"type" must be one of: ' + TYPES.join(', ');
    if (o.port !== undefined && !(Number.isInteger(o.port) && o.port >= 1 && o.port <= 65535)) return '"port" must be a whole number from 1 to 65535';
    if (o.bytes !== undefined && !(typeof o.bytes === 'number' && o.bytes >= 0)) return '"bytes" must be a number, 0 or more';
    if (o.hour !== undefined && !(Number.isInteger(o.hour) && o.hour >= 0 && o.hour <= 23)) return '"hour" must be a whole number from 0 to 23';
    if (o.id !== undefined && !/^[\w-]{1,40}$/.test(String(o.id))) return '"id" may only use letters, numbers, - and _';
    return null;
  }

  const src = () => $('#lab-src').value;
  const nextId = () => { S.seq += 1; return 'evt-' + String(S.seq).padStart(3, '0'); };

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function showResult(res) {
    const box = $('#my-result');
    box.replaceChildren();
    let cls, text;
    if (res.status === 'rejected') { cls = 'res-rej'; text = '⛔ Rejected: ' + res.error; }
    else if (res.status === 'duplicate') { cls = 'res-dup'; text = '🔁 Duplicate ignored. That event id was already processed.'; }
    else if (res.alert) { cls = 'res-alert'; text = '🚨 ALERT · score ' + res.score.toFixed(2); }
    else if (res.score >= 0.4) { cls = 'res-watch'; text = '👀 Worth watching · score ' + res.score.toFixed(2) + ' (below the 0.70 alert line)'; }
    else { cls = 'res-ok'; text = '✅ Looks normal · score ' + res.score.toFixed(2); }
    box.append(el('div', 'res-verdict ' + cls, text), el('pre', 'res-json', JSON.stringify(res, null, 2)));
  }

  function send(type, source, dt, extra) {
    S.clock += dt || 5;
    const ev = Object.assign({ id: nextId(), t: S.clock, src: source || src(), type }, extra || {});
    S.last = ev;
    const res = ingest(S, ev);
    selected = ev.id;
    render();
    showResult(res);
  }

  function sendCustom() {
    stopGuide();
    let obj;
    try { obj = JSON.parse($('#f-json').value); }
    catch (e) { showResult({ status: 'rejected', error: 'that is not valid JSON (' + e.message + ')' }); return; }
    const err = validate(obj);
    if (err) {
      S.audit.push({ id: 'n/a', kind: 'dup', text: 'event rejected: ' + err });
      showResult({ status: 'rejected', error: err });
      render();
      return;
    }
    const ev = { id: obj.id !== undefined ? String(obj.id) : nextId(), src: obj.src.trim(), type: obj.type };
    if (typeof obj.t === 'number') { ev.t = obj.t; S.clock = Math.max(S.clock, obj.t); } else { S.clock += 5; ev.t = S.clock; }
    ['port', 'bytes', 'hour'].forEach(k => { if (obj[k] !== undefined) ev[k] = obj[k]; });
    S.last = ev;
    const res = ingest(S, ev);
    selected = ev.id;
    render();
    showResult(res);
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
      copy.append(el('b', '', label(e.type)), el('small', '', e.src + (e.port ? ':' + e.port : '') + ' · t+' + e.t + 's · ' + e.id));
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
        line.append(el('b', '', a.id + ' · score ' + a.score.toFixed(2)), document.createElement('br'), document.createTextNode(a.src + ' · ' + a.reasons.join(' · ')));
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
    S.events.forEach(e => ingest(R, e.raw));
    const key = st => st.alerts.map(a => a.id + ':' + a.score).join('|');
    msg.textContent = 'Replayed ' + R.events.length + ' events → ' + R.alerts.length + ' alerts. ' + (key(R) === key(S) ? 'Identical to the original run ✓' : 'Different from the original ✗');
  }

  const actions = {
    ok: () => send('login_success'),
    fail: () => send('failed_login'),
    burst: () => { const s = src(); for (let i = 0; i < 6; i++) send('failed_login', s, 2); },
    scan: () => { const s = src(); [21, 22, 23, 80, 443, 3389].forEach(p => send('connection', s, 1, { port: p })); },
    dup: () => {
      if (!S.last) { send('failed_login'); return; }
      const res = ingest(S, S.last);
      selected = S.last.id;
      render();
      showResult(res);
    },
    rand: () => send(Math.random() < 0.6 ? 'login_success' : 'failed_login', ['10.0.0.24', '10.0.0.18', '10.0.0.07'][Math.floor(Math.random() * 3)]),
    reset: () => { S = fresh(); selected = null; view = 'alerts'; showAll = false; $('#replay-msg').textContent = ''; $('#my-result').replaceChildren(el('div', 'empty', 'Your result will appear here.')); render(); },
    replay
  };

  // Guided demo: plays a pretend attack with a caption for each step.
  let timers = [], running = false;
  const guideBtn = $('#guide-run'), caption = $('#guide-caption'), IDLE = '▶ Watch a 20-second guided demo';
  function stopGuide(msg) {
    timers.forEach(clearTimeout);
    timers = [];
    running = false;
    guideBtn.textContent = IDLE;
    if (msg) caption.textContent = msg;
  }
  function guide() {
    if (running) { stopGuide('Guided demo stopped. Now try it yourself below 👇'); return; }
    actions.reset();
    running = true;
    guideBtn.textContent = '■ Stop the demo';
    const A = '10.0.0.24';
    const steps = [
      ['A normal login arrives from 10.0.0.07. Nothing odd here.', () => send('login_success', '10.0.0.07')],
      ['Now someone fails to log in on 10.0.0.24…', () => send('failed_login', A)],
      ['…and fails again. The score creeps up.', () => send('failed_login', A)],
      ['A third failure within 60 seconds. The failed-login rule fires and an alert is raised.', () => send('failed_login', A)],
      ['The same event is sent twice. Duplicate protection ignores the repeat.', () => actions.dup()],
      ['They finally get in. A success right after failures is suspicious, so another alert.', () => send('login_success', A)],
      ['Last step: replay every event. A deterministic system gives identical alerts.', () => { view = 'alerts'; render(); replay(); }]
    ];
    steps.forEach((st, i) => timers.push(setTimeout(() => {
      caption.textContent = 'Step ' + (i + 1) + ' of ' + steps.length + ' · ' + st[0];
      st[1]();
      if (i === steps.length - 1) {
        running = false;
        guideBtn.textContent = '↺ Watch it again';
        timers.push(setTimeout(() => { caption.textContent = 'That’s the whole idea. Now send your own event below 👇'; }, 2600));
      }
    }, i * 2800)));
  }
  guideBtn.addEventListener('click', guide);

  // "Send your own event" form: the fields write the JSON, and the JSON is what gets sent.
  const FIELDS = ['f-src', 'f-type', 'f-port', 'f-mb', 'f-hour'];
  const F = id => $('#' + id);
  function syncJson() {
    const o = { src: F('f-src').value.trim(), type: F('f-type').value };
    if (F('f-port').value !== '') o.port = Number(F('f-port').value);
    if (F('f-mb').value !== '') o.bytes = Math.round(Number(F('f-mb').value) * 1000000);
    if (F('f-hour').value !== '') o.hour = Number(F('f-hour').value);
    F('f-json').value = JSON.stringify(o, null, 2);
  }
  FIELDS.forEach(id => ['input', 'change'].forEach(ev => F(id).addEventListener(ev, syncJson)));
  const EXAMPLES = {
    normal: ['10.0.0.52', 'data_transfer', '443', '2', '11'],
    rdp: ['10.0.0.77', 'failed_login', '3389', '', '2'],
    big: ['10.0.0.88', 'data_transfer', '443', '150', '3']
  };
  root.querySelectorAll('[data-ex]').forEach(b => b.addEventListener('click', () => {
    EXAMPLES[b.dataset.ex].forEach((v, i) => { F(FIELDS[i]).value = v; });
    syncJson();
  }));
  F('f-send').addEventListener('click', sendCustom);

  root.querySelectorAll('[data-act]').forEach(b => b.addEventListener('click', () => { stopGuide(); actions[b.dataset.act](); }));
  root.querySelectorAll('.lab-tab').forEach(t => t.addEventListener('click', () => { view = t.dataset.view; render(); }));
  $('#audit-toggle').addEventListener('click', () => { showAll = !showAll; render(); });
  syncJson();
  render();
  $('#lab-status').textContent = 'LIVE · SIMULATED EVENTS';
})();
