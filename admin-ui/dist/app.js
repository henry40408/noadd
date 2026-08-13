// ============================================================
// Legacy hash routes
// ============================================================
// Routing moved to the server, so `#settings` became `/settings`. A bookmark or
// a link from before that still carries the hash, and left alone it would land
// on the dashboard with no sign anything was missed. Rewritten here, before
// anything renders, so the redirect is invisible rather than a visible flash of
// the wrong page.
const LEGACY_HASH_ROUTES = {
  '#dashboard': '/',
  '#stats': '/stats',
  '#logs': '/logs',
  '#filters': '/filters',
  '#settings': '/settings',
  '#account': '/account',
};
if (LEGACY_HASH_ROUTES[location.hash]) {
  location.replace(LEGACY_HASH_ROUTES[location.hash]);
}

// ============================================================
// API Client
// ============================================================
// Endpoints where a 401 means "that credential was wrong", not "your session
// is gone". Everywhere else a 401 is the signal to bounce back to the login
// screen; on these it would throw an operator out of a live session for
// mistyping a password, and discard the response body the form needs to
// explain what happened.
const CREDENTIAL_ENDPOINTS = new Set(['/api/auth/login', '/api/auth/reauth']);

const api = {
  async request(method, path, body) {
    const opts = { method, headers: {}, credentials: 'same-origin' };
    if (body) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    if (res.status === 401 && !CREDENTIAL_ENDPOINTS.has(path)) {
      window.dispatchEvent(new CustomEvent('auth-required'));
      throw new Error('Unauthorized');
    }
    if (!res.ok) {
      // Some 4xx responses carry `{"error": "..."}` explaining what the caller
      // has to change — a rejected password is the case that matters, where
      // the status code alone leaves the operator guessing. Surfaced as
      // `.detail` so a caller can prefer it over its own fallback copy;
      // responses without one are unchanged.
      const err = new Error(`${res.status} ${res.statusText}`);
      err.status = res.status;
      try {
        const parsed = await res.json();
        if (parsed && typeof parsed.error === 'string') err.detail = parsed.error;
        // `code` distinguishes the two 403s the re-authentication guard emits
        // from the CSRF guard's bare one; see withReauth.
        if (parsed && typeof parsed.code === 'string') err.code = parsed.code;
      } catch (e) { /* no body, or not JSON — the status line stands alone */ }
      throw err;
    }
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return null;
  },
  get: (p) => api.request('GET', p),
  post: (p, b) => api.request('POST', p, b),
  put: (p, b) => api.request('PUT', p, b),
  del: (p) => api.request('DELETE', p),
};

// ============================================================
// Component base
// ============================================================
// A custom element discards its own DOM when it is removed, but not what it
// attached elsewhere: interval timers, EventSource connections, and listeners
// on window/document. Those outlive the element, and each stranded closure also
// keeps the element's whole discarded subtree reachable through `this`.
//
// Anything registered through these helpers is released on disconnect, so a
// component cannot leak by forgetting to write a teardown. Subclasses that need
// their own disconnectedCallback must call super.
//
// Ownership that is start/stop-able (a poll timer behind a live toggle, say)
// stays hand-managed — registering it per start would pile up one dead entry
// per cycle — so those register a single track() that calls their own stopper.
//
// The other half of the problem is timing, which no registry can fix: an async
// connectedCallback resumes after its awaits, by which point the element may
// already be gone, and disconnectedCallback has run *before* it acquires
// anything. Guard resumption with `this.isConnected` — see DashboardPage.
class LiveElement extends HTMLElement {
  // Register an arbitrary teardown to run on disconnect.
  track(fn) {
    if (!this._cleanups) this._cleanups = [];
    this._cleanups.push(fn);
    return fn;
  }

  interval(fn, ms) {
    const id = setInterval(fn, ms);
    this.track(() => clearInterval(id));
    return id;
  }

  // Listen on a target that outlives this element (window, document, ...).
  // Returns the handler so callers can invoke it once for an initial paint.
  listen(target, type, fn) {
    target.addEventListener(type, fn);
    this.track(() => target.removeEventListener(type, fn));
    return fn;
  }

  disconnectedCallback() {
    const cleanups = this._cleanups;
    this._cleanups = null;
    if (!cleanups) return;
    // Reverse order, mirroring acquisition. One failure must not strand the
    // rest, so each runs independently.
    for (let i = cleanups.length - 1; i >= 0; i--) {
      try { cleanups[i](); } catch (e) { /* nothing useful to do here */ }
    }
  }
}

// ============================================================
// Utility
// ============================================================
const fullNumberFormatter = new Intl.NumberFormat();
const compactDecimalFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
function formatNum(n) {
  if (n == null || Number.isNaN(n)) return '—';
  if (n >= 1_000_000) return compactDecimalFormatter.format(n / 1_000_000) + 'M';
  if (n >= 1_000) return compactDecimalFormatter.format(n / 1_000) + 'K';
  return fullNumberFormatter.format(n);
}
function formatFull(n) {
  if (n == null || Number.isNaN(n)) return '—';
  return fullNumberFormatter.format(n);
}
function formatNumAdaptive(n, threshold = 1_000_000) {
  if (n == null || Number.isNaN(n)) return '—';
  return n < threshold ? fullNumberFormatter.format(n) : formatNum(n);
}
function formatPct(n, total) {
  if (!total || total <= 0 || n == null || Number.isNaN(n)) return '';
  return `${(n / total * 100).toFixed(1)}%`;
}
// Returns Markup so callers can interpolate it into html`` without it being
// escaped as text.
function sharePctSpan(count, sum) {
  const pct = formatPct(count, sum);
  return pct ? html` <span style="color:var(--text-dim);font-size:0.75em">(${pct})</span>` : '';
}

// Accepts either Unix seconds or milliseconds and returns milliseconds.
//
// This is NOT a licence to leave new fields' units unspecified — it exists for
// one remaining asymmetry: query-log rows carry `timestamp` straight from the
// `query_logs` column, which is milliseconds, while every other timestamp the
// API serves (timeline buckets, session created_at/last_seen, filter-list
// last_updated, rebuild started_at) is seconds. The two timeline types used to
// disagree with each other too, and this helper is exactly what hid it: a
// consumer that skipped it was silently off by 1000x. They now agree on
// seconds; keep it that way.
function normalizeTs(ts) {
  return ts > 1e12 ? ts : ts * 1000;
}

const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' });
function timeAgoText(ts) {
  if (!ts) return relativeTimeFormatter.format(0, 'second');
  const diff = Math.floor((Date.now() - normalizeTs(ts)) / 1000);
  if (Math.abs(diff) < 60) return relativeTimeFormatter.format(-diff, 'second');
  if (Math.abs(diff) < 3600) return relativeTimeFormatter.format(-Math.round(diff / 60), 'minute');
  if (Math.abs(diff) < 86400) return relativeTimeFormatter.format(-Math.round(diff / 3600), 'hour');
  return relativeTimeFormatter.format(-Math.round(diff / 86400), 'day');
}

function absTime(ts) {
  if (!ts) return '';
  return new Date(normalizeTs(ts)).toLocaleString([], { hour12: false });
}

// Returns Markup, not text: callers interpolate it into html`` and the span has
// to survive as an element.
function timeAgo(ts) {
  if (!ts) return 'never';
  // data-ts lets a periodic ticker recompute the relative text in place
  // (see LogsPage._refreshTimes) without re-rendering the whole row.
  return html`<span class="timeago" data-ts="${ts}" title="${absTime(ts)}">${timeAgoText(ts)}</span>`;
}

function formatTime(ts) {
  return new Date(normalizeTs(ts)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
}

// Browser's east-positive UTC offset in minutes (e.g. 480 for UTC+8), for the
// stats endpoints that align buckets to the viewer's local calendar rather than
// UTC-epoch boundaries. getTimezoneOffset() is UTC-minus-local, hence the sign flip.
function tzOffsetMinutes() {
  return -new Date().getTimezoneOffset();
}

// Tooltip label for the statistics Nd timeline / rate charts. Date for day
// buckets; date + HH:mm for sub-day buckets (7d→1h, 30d→6h) so hourly points
// sharing a date are distinguishable. tsSeconds is epoch seconds (charts 2/3);
// no timeZone option ⇒ browser-local, same as the rest of the chart formatting.
function fmtBucketLabel(tsSeconds, withTime) {
  const d = new Date(tsSeconds * 1000);
  const date = d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  return withTime ? `${date} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })}` : date;
}

// Escapes a value for interpolation into markup, in text *and* attribute
// position. Quotes are the reason this cannot go through textContent/innerHTML:
// that round-trip escapes &, < and > but leaves " alone, while most callers here
// interpolate into a double-quoted attribute. A raw " then closes the value
// early and everything after it is parsed as further attributes — including
// event handlers. A filter-list name of `x" onmouseover="alert(1)` was enough to
// get a live handler onto its table row.
const ESC_CHARS = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ESC_CHARS[c]);
}

// Escaping keeps a value inside its attribute; it does not make the value safe
// to navigate to. Registry entries are fetched from a third-party URL at
// runtime, so a javascript: homepage would run on click no matter how well the
// string was escaped. Anything that is not http(s) yields '' and renders no link.
function safeUrl(u) {
  if (!u) return '';
  try {
    const parsed = new URL(u, window.location.origin);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') ? parsed.href : '';
  } catch (e) {
    return '';
  }
}

// Markup that is already safe to emit as-is. Carrying it as a distinct type is
// what lets html`` tell "this is a value to escape" apart from "this is markup I
// built myself" without a flag at every interpolation. toString() means an
// innerHTML assignment serialises it for free.
class Markup {
  constructor(value) { this.value = value; }
  toString() { return this.value; }
}

// Wrap a string of markup you vouch for — a hand-written fragment, an inline
// SVG. Every use is a place where escaping is deliberately skipped, so it should
// only ever wrap a literal, never interpolated data.
function raw(value) {
  return new Markup(String(value));
}

// Tagged template for building markup: interpolations are escaped by default,
// which is the whole point — forgetting to call esc() is no longer possible,
// because not doing anything special is the safe path.
//
// Passed through untouched: Markup (so nested html`` and raw() compose) and
// arrays of it (so `${rows.map(r => html`…`)}` needs no join). null and
// undefined render as nothing rather than the strings "null"/"undefined".
// Everything else is escaped and stringified, booleans included — attributes
// like data-blocked="${l.blocked}" must still read "false", not empty.
function html(strings, ...values) {
  let out = '';
  strings.forEach((chunk, i) => {
    out += chunk;
    if (i < values.length) out += flatten(values[i]);
  });
  return new Markup(out);
}

function flatten(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof Markup) return value.value;
  if (Array.isArray(value)) return value.map(flatten).join('');
  return esc(value);
}

function showFormError(el, msg) {
  el.textContent = msg;
  el.style.display = 'block';
}

// There is no password dialog here any more. The three actions that need a
// password proof — add an operator, delete one, mint an API key — carry a
// "your password" field in their own form, and post it with the action. That
// removed the retry-after-403 dance along with the dialog, and made the path
// identical with and without JavaScript. `POST /api/auth/reauth` still exists
// for API callers; the UI is simply not one of them any more.

// Put a confirmation in front of the form `button` submits, cancelling the
// submit if it is declined. Attached to the form rather than the button so it
// also covers Enter from inside the form, and only where there is JavaScript to
// run it — without one the submit simply goes through, which is the behaviour
// every other destructive form on the server-rendered pages already has.
function confirmBeforeSubmit(button, message) {
  const form = button && button.closest('form');
  if (!form) return;
  form.onsubmit = (e) => { if (!confirm(message)) e.preventDefault(); };
}

// Password length band, mirroring MIN_PASSWORD_LENGTH / MAX_PASSWORD_LENGTH in
// src/admin/api.rs. Duplicated rather than fetched: this is only a courtesy
// check so the operator sees the problem before a round trip — the server
// enforces the real policy and stays authoritative if the two ever drift.
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

// The message for a password outside the band, or null when it fits. Counts
// code points rather than UTF-16 units so an emoji or a CJK passphrase is
// measured the same way `chars().count()` measures it server-side; `.length`
// would count a single astral character twice and reject a password the
// server would have accepted.
function passwordLengthError(pw) {
  const len = [...(pw || '')].length;
  if (len < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  if (len > MAX_PASSWORD_LENGTH) return `Password must be at most ${MAX_PASSWORD_LENGTH} characters`;
  return null;
}

// ============================================================
// Icons (inline SVG)
// ============================================================
const icons = {
  dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
  logs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
  filter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>',
  rules: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  stats: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="12" width="4" height="9" rx="1"/><rect x="10" y="7" width="4" height="14" rx="1"/><rect x="17" y="3" width="4" height="18" rx="1"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>',
  search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  external: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
};

// Marked once, here, rather than at each of the ~30 interpolation sites: these
// are hand-written SVG literals, and html`` must emit them rather than escape
// them. Doing it centrally also means no template needs raw() for an icon.
for (const key of Object.keys(icons)) icons[key] = raw(icons[key]);

// ============================================================
// Notice banners (in-flow, dismissible; replaces alert())
// ============================================================
const NOTICE_ICONS = {
  error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="7" x2="12" y2="13"/><circle cx="12" cy="16.75" r="1.15" fill="currentColor" stroke="none"/></svg>',
  success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="8 12.5 11 15.5 16 9"/></svg>',
  info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="11" x2="12" y2="16.5"/><circle cx="12" cy="7.75" r="1.15" fill="currentColor" stroke="none"/></svg>',
};
for (const key of Object.keys(NOTICE_ICONS)) NOTICE_ICONS[key] = raw(NOTICE_ICONS[key]);

// Show an in-flow banner at the top of the page content. type: 'error' |
// 'success' | 'info'. Persistent (no auto-dismiss) with a manual close
// button; error banners announce assertively, others politely. Duplicate
// message+type banners are collapsed. Returns the banner element, or null
// when the app shell (and its #notice-host) isn't mounted.
function showBanner(msg, type = 'info') {
  const host = document.getElementById('notice-host');
  if (!host) return null;
  const kind = NOTICE_ICONS[type] ? type : 'info';
  // Collapse an identical banner rather than stacking a second copy.
  const dupe = [...host.children].find(c => c.dataset.key === `${kind}:${msg}`);
  if (dupe) { host.appendChild(dupe); return dupe; }
  const el = document.createElement('div');
  el.className = `notice-banner ${kind}`;
  el.dataset.key = `${kind}:${msg}`;
  // role="alert" is assertive (errors interrupt); status is polite otherwise.
  el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  el.innerHTML = html`<span class="icon">${NOTICE_ICONS[kind]}</span>`
    + html`<span class="msg">${msg}</span>`
    + html`<button class="close" type="button" aria-label="Dismiss">${icons.close}</button>`;
  el.querySelector('.close').onclick = () => el.remove();
  host.appendChild(el);
  return el;
}

// ============================================================
// Web Components
// ============================================================

// --- App Shell ---
// --- Account Page ---
class AccountPage extends HTMLElement {
  // The page arrives server-rendered: the three tables, every form, and every
  // row action are real markup that works on its own. Nothing is fetched here
  // and nothing is re-drawn — a change redirects, and the page that comes back
  // is already correct.
  //
  // What is left is the one thing markup cannot do (copy to the clipboard) and
  // a confirmation in front of the destructive submits. Deleting an operator
  // needs neither: it expands into a named confirmation with a password field,
  // which is a better prompt than `confirm()` and is there without scripting.
  connectedCallback() {
    this.querySelectorAll('.js-only[hidden]').forEach(el => el.removeAttribute('hidden'));

    const copyBtn = this.querySelector('#api-key-copy');
    if (copyBtn) {
      const input = this.querySelector('#api-key-token');
      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(input.value);
        } catch (e) {
          input.select();
          document.execCommand('copy');
        }
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
      };
    }

    confirmBeforeSubmit(
      this.querySelector('#logout-others'),
      'Log out all other sessions? Your current session stays signed in.');

    this.querySelectorAll('.rev-sess').forEach(btn => confirmBeforeSubmit(btn,
      btn.dataset.current === 'true'
        ? 'Revoke this session? It is this device — you will be signed out.'
        : 'Revoke this session?'));

    this.querySelectorAll('.del-api-key').forEach(btn => confirmBeforeSubmit(btn,
      'Revoke this API key? Any client using it will lose access immediately.'));
  }
}
customElements.define('account-page', AccountPage);

// --- Rebuild Banner ---
// Polls /api/filter/rebuild-status every 2s and surfaces a slim strip while
// the filter engine is rebuilding, plus a brief success flash on completion.
class RebuildBanner extends LiveElement {
  connectedCallback() {
    this.prev = null;         // last observed rebuilding flag
    this.doneTimer = null;    // timer handle for the post-rebuild flash
    this.render('', '');
    this.interval(() => this.tick(), 2000);
    // doneTimer is re-armed on every completed rebuild, so it is cleared by
    // reading whatever handle is current at teardown rather than registering
    // one entry per arming.
    this.track(() => { if (this.doneTimer) clearTimeout(this.doneTimer); });
    this.tick();
  }
  async tick() {
    let body;
    try {
      body = await api.get('/api/filter/rebuild-status');
    } catch (e) {
      return;
    }
    const rebuilding = !!body.rebuilding;
    if (rebuilding) {
      if (this.doneTimer) { clearTimeout(this.doneTimer); this.doneTimer = null; }
      const elapsed = body.started_at ? Math.max(0, Math.floor(Date.now()/1000) - body.started_at) : 0;
      this.render('active', 'Rebuilding filter engine', `${elapsed}s elapsed`);
    } else if (this.prev === true) {
      const meta = body.last_duration_ms
        ? `Completed in ${(body.last_duration_ms / 1000).toFixed(1)}s`
        : 'Completed';
      this.render('done', 'Filter engine updated', meta);
      if (this.doneTimer) clearTimeout(this.doneTimer);
      this.doneTimer = setTimeout(() => {
        this.doneTimer = null;
        this.render('', '', '');
      }, 3000);
    } else {
      // Steady idle — hide unless we're still showing the success flash.
      if (!this.doneTimer) this.render('', '', '');
    }
    this.prev = rebuilding;
  }
  render(state, label, meta) {
    if (!state) {
      this.innerHTML = '';
      return;
    }
    const indicator = state === 'active'
      ? raw('<span class="spin"></span>')
      : html`<span class="check">${icons.check}</span>`;
    const metaHtml = meta ? html`<span class="meta">${meta}</span>` : '';
    this.innerHTML = html`
      <div class="rebuild-banner show ${state}" role="status" aria-live="polite">
        <span class="icon">${indicator}</span>
        <span class="text">
          <span class="label">${label}</span>
          ${metaHtml}
        </span>
      </div>`;
  }
}
customElements.define('rebuild-banner', RebuildBanner);

// --- Next-Step Onboarding Banner ---
// On a fresh install, tells the admin how to point a device's DNS at noadd
// and shows the server's DNS address. Auto-hides once a real DNS query has
// been served (polls /api/stats/summary every 3s). Can be dismissed; the
// dismissal persists server-side via PUT /api/settings.
class NextStepBanner extends LiveElement {
  connectedCallback() {
    this.timer = null;
    this.dnsAddr = '';
    this.innerHTML = '';   // render nothing until init decides
    this.init();
  }
  async init() {
    // 1) Respect a prior dismissal — if dismissed, never show or poll.
    let settings;
    try {
      settings = await api.get('/api/settings');
    } catch (e) {
      return;
    }
    if (settings && settings.onboarding_banner_dismissed === 'true') {
      return;
    }
    // 2) Resolve the DNS address to display: location.hostname + the port
    //    parsed from server-info's dns_addr (e.g. "0.0.0.0:53" -> "53").
    try {
      const info = await api.get('/api/server-info');
      const raw = (info && info.dns_addr) || '';
      const port = raw.includes(':') ? raw.slice(raw.lastIndexOf(':') + 1) : raw;
      this.dnsAddr = `${window.location.hostname}:${port}`;
    } catch (e) {
      return;
    }
    // 3) If a query was already served, stay hidden; otherwise show + poll.
    if (await this.hasQueries()) {
      return;
    }
    // Three awaits back; the banner may have been swapped out in the meantime,
    // and a timer started now would never be torn down.
    if (!this.isConnected) return;
    this.show();
    this.timer = this.interval(() => this.poll(), 3000);
  }
  async hasQueries() {
    try {
      const s = await api.get('/api/stats/summary');
      return ((s.total_today || 0) + (s.total_7d || 0) + (s.total_30d || 0)) > 0;
    } catch (e) {
      return false;
    }
  }
  async poll() {
    if (await this.hasQueries()) {
      if (this.timer) { clearInterval(this.timer); this.timer = null; }
      this.innerHTML = '';
    }
  }
  show() {
    this.innerHTML = html`
      <div class="rebuild-banner show" role="status" aria-live="polite" data-testid="next-step-banner">
        <span class="icon">${icons.dashboard}</span>
        <span class="text">
          <span class="label">Point a device's DNS at noadd to start blocking — set its DNS server to <strong data-testid="next-step-banner-addr">${this.dnsAddr}</strong>.</span>
        </span>
        <button class="btn" data-testid="next-step-banner-dismiss" title="Dismiss" style="margin-left:auto">${icons.close}</button>
      </div>`;
    const dismiss = this.querySelector('[data-testid="next-step-banner-dismiss"]');
    dismiss.onclick = () => this.dismiss();
  }
  async dismiss() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.innerHTML = '';
    try {
      await api.put('/api/settings', { onboarding_banner_dismissed: 'true' });
    } catch (e) {
      // best-effort; UI already hidden for this session
    }
  }
}
customElements.define('next-step-banner', NextStepBanner);

// --- Registry Modal ---
// Browse AdGuard HostlistsRegistry and batch-add selected filter lists.
class RegistryModal extends LiveElement {
  constructor() {
    super();
    this.data = null;            // cached { filters, groups }
    this.existingUrls = null;    // Set of URLs already in user's lists
    this.selected = new Set();   // filterId values currently checked
    this.adding = false;
  }

  async open() {
    this.innerHTML = '';
    const overlay = document.createElement('div');
    overlay.className = 'registry-overlay';
    overlay.innerHTML = `
      <div class="registry-dialog" role="dialog" aria-labelledby="registry-title" aria-modal="true">
        <div class="registry-head">
          <h3 id="registry-title">Browse Filter Registry</h3>
          <button class="close-btn" id="reg-close" aria-label="Close">${icons.close}</button>
        </div>
        <div class="registry-toolbar" style="display:none" id="reg-toolbar">
          <input type="text" id="reg-search" placeholder="Search name or description">
          <select id="reg-group">
            <option value="">All groups</option>
          </select>
          <label class="check"><input type="checkbox" id="reg-deprecated"> Show deprecated</label>
        </div>
        <div class="registry-body" id="reg-body">
          <div class="registry-loading"><div class="spin"></div>Loading registry…</div>
        </div>
        <div class="registry-summary" id="reg-summary" style="display:none"></div>
        <div class="registry-foot" style="display:none" id="reg-foot">
          <div class="count" id="reg-count">0 selected</div>
          <button class="btn btn-sm" id="reg-cancel">Cancel</button>
          <button class="btn btn-primary btn-sm" id="reg-add" disabled>${icons.plus} Add Selected</button>
        </div>
      </div>`;
    this.appendChild(overlay);

    // Close on backdrop click + Escape + close button
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay && !this.adding) this.close();
    });
    this.listen(document, 'keydown', (e) => {
      if (e.key === 'Escape' && !this.adding) this.close();
    });
    this.querySelector('#reg-close').onclick = () => { if (!this.adding) this.close(); };
    this.querySelector('#reg-cancel').onclick = () => { if (!this.adding) this.close(); };

    await this.load();
  }

  // Teardown rides on removal rather than on this method, so the document-level
  // Escape listener is released however the modal goes away.
  close() {
    this.remove();
  }

  async load() {
    const body = this.querySelector('#reg-body');
    try {
      const [data, lists] = await Promise.all([
        api.get('/api/registry/filters'),
        api.get('/api/lists'),
      ]);
      this.data = data;
      this.existingUrls = new Set(lists.map(l => l.url));
      this.populateGroups();
      this.wireControls();
      this.querySelector('#reg-toolbar').style.display = '';
      this.querySelector('#reg-foot').style.display = '';
      this.render();
    } catch (e) {
      body.innerHTML = `
        <div class="registry-error">
          Failed to load registry.<br>
          <button class="btn btn-sm" style="margin-top:14px" id="reg-retry">${icons.refresh} Retry</button>
        </div>`;
      this.querySelector('#reg-retry').onclick = () => { body.innerHTML = '<div class="registry-loading"><div class="spin"></div>Loading registry…</div>'; this.load(); };
    }
  }

  populateGroups() {
    const sel = this.querySelector('#reg-group');
    for (const g of this.data.groups) {
      const opt = document.createElement('option');
      opt.value = String(g.groupId);
      opt.textContent = g.groupName;
      sel.appendChild(opt);
    }
  }

  wireControls() {
    this.querySelector('#reg-search').oninput = () => this.render();
    this.querySelector('#reg-group').onchange = () => this.render();
    this.querySelector('#reg-deprecated').onchange = () => this.render();
    this.querySelector('#reg-add').onclick = () => this.submit();
  }

  filteredFilters() {
    const q = this.querySelector('#reg-search').value.trim().toLowerCase();
    const groupVal = this.querySelector('#reg-group').value;
    const showDep = this.querySelector('#reg-deprecated').checked;
    return this.data.filters.filter(f => {
      if (!showDep && f.deprecated) return false;
      if (groupVal && String(f.groupId) !== groupVal) return false;
      if (q) {
        const hay = (f.name + ' ' + f.description).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }

  groupClassFor(groupId) {
    const g = this.data.groups.find(x => x.groupId === groupId);
    if (!g) return '';
    const name = g.groupName.toLowerCase();
    if (name.includes('security')) return 'security';
    if (name.includes('regional')) return 'regional';
    if (name.includes('general')) return 'general';
    return '';
  }

  render() {
    const body = this.querySelector('#reg-body');
    const filtered = this.filteredFilters();
    if (!filtered.length) {
      body.innerHTML = '<div class="registry-empty">No filters match your search.</div>';
      this.updateCount();
      return;
    }
    const groupsById = new Map(this.data.groups.map(g => [g.groupId, g]));
    body.innerHTML = filtered.map(f => {
      const already = this.existingUrls.has(f.downloadUrl);
      const checked = this.selected.has(f.filterId);
      const groupName = groupsById.get(f.groupId)?.groupName || '';
      const groupCls = this.groupClassFor(f.groupId);
      const homeUrl = safeUrl(f.homepage);
      const home = homeUrl ? html`<a class="home" href="${homeUrl}" target="_blank" rel="noopener noreferrer">${icons.external}<span>Homepage</span></a>` : '';
      return html`
        <label class="registry-row">
          <input type="checkbox" data-id="${f.filterId}" ${checked ? raw('checked') : ''} ${already ? raw('disabled') : ''}>
          <div class="info">
            <div class="name-row">
              <span class="name">${f.name}</span>
              ${groupName ? html`<span class="group-pill ${groupCls}">${groupName}</span>` : ''}
              ${already ? raw('<span class="added-pill">Added</span>') : ''}
              ${f.deprecated ? raw('<span class="dep-pill">Deprecated</span>') : ''}
            </div>
            <div class="desc">${f.description || ''}</div>
            ${home}
          </div>
        </label>`;
    }).join('');
    body.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.onchange = () => {
        const id = parseInt(cb.dataset.id, 10);
        if (cb.checked) this.selected.add(id); else this.selected.delete(id);
        this.updateCount();
      };
    });
    this.updateCount();
  }

  updateCount() {
    const n = this.selected.size;
    this.querySelector('#reg-count').textContent = n === 1 ? '1 selected' : `${n} selected`;
    this.querySelector('#reg-add').disabled = n === 0 || this.adding;
  }

  async submit() {
    if (!this.selected.size) return;
    this.adding = true;
    const items = this.data.filters
      .filter(f => this.selected.has(f.filterId))
      .map(f => ({ name: f.name, url: f.downloadUrl }));
    const addBtn = this.querySelector('#reg-add');
    const cancelBtn = this.querySelector('#reg-cancel');
    const closeBtn = this.querySelector('#reg-close');
    addBtn.disabled = true;
    addBtn.innerHTML = '<div class="spin" style="width:12px;height:12px;display:inline-block;vertical-align:-2px"></div> Adding…';
    cancelBtn.disabled = true;
    closeBtn.disabled = true;
    try {
      const resp = await api.post('/api/lists/batch', { items });
      this.dispatchEvent(new CustomEvent('batch-added', { bubbles: true }));
      if (!resp.failed || resp.failed.length === 0) {
        this.close();
        return;
      }
      const summary = this.querySelector('#reg-summary');
      summary.style.display = '';
      summary.classList.add('error');
      // Plain text, escaped once where it lands in markup rather than per part.
      const failedList = resp.failed.map(f => `${f.name} (${f.error})`).join('; ');
      summary.innerHTML = html`Added ${resp.added.length}, failed ${resp.failed.length}: ${failedList}`;
      this.selected.clear();
      this.existingUrls = new Set(
        [...this.existingUrls, ...resp.added.map(a => a.url)]
      );
      // Swap Cancel → Close since work is done
      cancelBtn.textContent = 'Close';
      cancelBtn.disabled = false;
      closeBtn.disabled = false;
      this.adding = false;
      addBtn.innerHTML = `${icons.plus} Add Selected`;
      this.render();
    } catch (e) {
      const summary = this.querySelector('#reg-summary');
      summary.style.display = '';
      summary.classList.add('error');
      summary.textContent = 'Batch add failed. See browser console.';
      console.error(e);
      cancelBtn.disabled = false;
      closeBtn.disabled = false;
      addBtn.disabled = false;
      addBtn.innerHTML = `${icons.plus} Add Selected`;
      this.adding = false;
    }
  }
}
customElements.define('registry-modal', RegistryModal);

// --- Shared touch support for charts ---
// Pointer events fire for touch too, but a single tap doesn't reliably produce a
// `pointermove`, and `pointerleave` fires the instant the finger lifts — so on
// mobile the hover-driven tooltip never shows. addChartTouch() adds tap-to-show
// and drag-to-scrub for touch/pen while leaving mouse hover untouched. A single
// document-level "tap outside dismisses" listener (registered once, keyed by the
// persistent chart host so it never accumulates across re-renders) clears the
// tooltip — touch keeps it visible until then, matching native mobile tooltips.
const _chartTouchDismissers = new Map(); // persistent host element -> dismiss fn
document.addEventListener('pointerdown', (e) => {
  for (const [host, dismiss] of [..._chartTouchDismissers]) {
    if (!host.contains(e.target)) dismiss();
  }
}, true);

// svg    — the chart's <svg> (has touch-action:none so scrubbing won't scroll)
// host   — persistent container that survives re-renders (for outside-tap dismiss)
// onMove — chart's existing hover handler (positions cursor/tooltip from evt.clientX)
// onLeave— chart's existing handler that clears cursor/tooltip
function addChartTouch(svg, host, onMove, onLeave) {
  // Set while a touch/pen tooltip is up. After a tap, the browser synthesizes a
  // compatibility mouse sequence, and its `pointerleave` (pointerType 'mouse',
  // since the virtual cursor was never over the chart) would otherwise dismiss
  // the tooltip within ~20ms of the finger lifting — the tooltip appeared and
  // vanished, which on a phone reads as the tap not registering at all.
  let touchHeld = false;
  const dismiss = () => { _chartTouchDismissers.delete(host); touchHeld = false; onLeave(); };
  svg.addEventListener('pointerdown', (evt) => {
    if (evt.pointerType === 'mouse') return; // mouse keeps pure hover behavior
    try { svg.setPointerCapture(evt.pointerId); } catch (_) {}
    touchHeld = true;
    _chartTouchDismissers.set(host, dismiss);
    onMove(evt);
  });
  svg.addEventListener('pointermove', onMove);
  // Mouse dismisses on leave; touch/pen keep the tooltip until a tap outside.
  // The `touchHeld` guard is what distinguishes a real cursor leaving the chart
  // from the synthetic leave that follows a tap.
  svg.addEventListener('pointerleave', (evt) => {
    if (evt.pointerType === 'mouse' && !touchHeld) onLeave();
  });
  svg.addEventListener('pointercancel', dismiss);
}

// Aggregate adjacent timeline buckets so a bar chart never draws more bars than
// it can show legibly. Numeric fields are summed; each group keeps its first
// bucket's timestamp as the x-axis / tooltip anchor (rates are recomputed from
// the summed counts downstream). Returns `data` untouched when it already fits
// within `maxBars`.
function downsampleBuckets(data, maxBars) {
  if (!data || data.length <= maxBars) return data;
  const groupSize = Math.ceil(data.length / maxBars);
  const out = [];
  for (let i = 0; i < data.length; i += groupSize) {
    const agg = {};
    for (let j = i; j < Math.min(i + groupSize, data.length); j++) {
      const row = data[j];
      for (const k in row) {
        const v = row[k];
        if (typeof v !== 'number') continue;
        // timestamp anchors on the first bucket; counts accumulate.
        agg[k] = k === 'timestamp' ? (agg[k] ?? v) : (agg[k] || 0) + v;
      }
    }
    out.push(agg);
  }
  return out;
}

// Bar-count ceilings: a stacked bar needs ~7px, a grouped pair ~16px, and
// mobile gets fewer so each bar stays wide enough to read.
const MAX_BARS_STACKED = () => (window.innerWidth <= 480 ? 24 : 56);
const MAX_BARS_GROUPED = () => (window.innerWidth <= 480 ? 14 : 30);

// --- Shared SVG stacked-bar chart for query-volume timelines ---
// Used by Dashboard "Queries (24h)" and Statistics "Queries (last Nd)".
// One stacked bar per bucket: the sub-series stack from the bottom and the
// remainder (total − subs) is painted on top in series[0]'s colour, so the bar
// height always equals `total`. Hover dims the other bars and shows a tooltip.
// el      — a .chart-container (position:relative, 200px tall)
// data    — raw API rows; series[0].key must be 'total': it sets the y-scale
//           and colours the top "remainder" segment.
// series  — [{ key, color, label }]; series[0] is the total, the rest are
//           sub-categories (e.g. blocked, cached) stacked at the bottom.
//           `label` is the legend caption (shown in the .tl-legend row below).
// fmtX    — (row) => x-axis label as plain text; escaped here
// fmtTooltip — (row) => tooltip Markup, i.e. built with html`` (it carries markup
//           of its own, so it cannot be escaped as text)
function renderTimelineChart(el, data, series, fmtX, fmtTooltip) {
  data = downsampleBuckets(data, MAX_BARS_STACKED());
  const len = data.length;
  const w = 600, h = 180, padX = 8, padY = 12;
  const innerW = w - padX * 2, innerH = h - padY * 2;
  const totalKey = series[0].key;
  const max = Math.max(...data.map(d => d[totalKey] || 0), 1);
  const baseline = padY + innerH;
  const hOf = (v) => (v / max) * innerH; // value → bar height in viewBox units
  const slot = innerW / len;
  const bw = Math.min(slot * 0.7, 40);
  // Stack order, bottom→top: the sub-series in reverse of how they're passed,
  // then the remainder (total − subs) painted on top in series[0]'s colour.
  // So [total, cached, blocked] stacks blocked, cached, then resolved on top.
  const subs = series.slice(1).reverse();
  const bars = [];
  let rects = '';
  for (let i = 0; i < len; i++) {
    const d = data[i];
    const cx = padX + (i + 0.5) * slot;
    const x = cx - bw / 2;
    let cursor = baseline, subSum = 0;
    for (const s of subs) {
      const v = d[s.key] || 0; subSum += v;
      const hgt = hOf(v);
      if (hgt > 0.3) rects += `<rect class="tlbar" data-i="${i}" x="${x.toFixed(1)}" y="${(cursor - hgt).toFixed(1)}" width="${bw.toFixed(1)}" height="${hgt.toFixed(1)}" fill="${s.color}" fill-opacity="0.88"/>`;
      cursor -= hgt;
    }
    const remainder = Math.max(0, (d[totalKey] || 0) - subSum);
    const rh = hOf(remainder);
    if (rh > 0.3) rects += `<rect class="tlbar" data-i="${i}" x="${x.toFixed(1)}" y="${(cursor - rh).toFixed(1)}" width="${bw.toFixed(1)}" height="${rh.toFixed(1)}" fill="${series[0].color}" fill-opacity="0.58"/>`;
    bars.push({ i, cx, topY: baseline - hOf(d[totalKey] || 0), d });
  }
  // Gridlines stay inside the stretched SVG; numeric labels are real HTML in a
  // .tl-yticks overlay so preserveAspectRatio="none" never distorts the digits.
  const ticks = [0.25, 0.5, 0.75].map(p => {
    const y = (baseline - p * innerH).toFixed(1);
    return `<line x1="${padX}" y1="${y}" x2="${padX + innerW}" y2="${y}" stroke="var(--border)" stroke-dasharray="2 4" stroke-width="0.5"/>`;
  }).join('');
  const yTicks = '<div class="tl-yticks" aria-hidden="true">' +
    [0.25, 0.5, 0.75].map(p =>
      `<span class="tl-ytick" style="top:${(((baseline - p * innerH) / h) * 100).toFixed(2)}%">${formatNum(Math.round(max * p))}</span>`
    ).join('') +
    '</div>';

  // Fewer x-labels on narrow widths so single-line labels never collide.
  const targetLabels = window.innerWidth <= 480 ? 4 : 6;
  const labelEvery = Math.max(1, Math.round(len / targetLabels));
  let labels = '<div class="chart-labels">';
  for (let i = 0; i < len; i += labelEvery) labels += html`<div class="chart-label">${fmtX(data[i])}</div>`;
  labels += '</div>';

  const legend = '<div class="rate-legend tl-legend">' +
    series.map(s => `<span><i style="background:${s.color}"></i>${s.label}</span>`).join('') +
    '</div>';

  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" class="tl-svg">
      ${ticks}
      ${rects}
    </svg>
    ${yTicks}
    <div class="rate-tooltip"></div>
    ${labels}${legend}`;

  const svg = el.querySelector('.tl-svg');
  const tooltip = el.querySelector('.rate-tooltip');
  let hlIdx = -1;
  const highlight = (i) => {
    if (i === hlIdx) return;
    if (hlIdx !== -1) svg.querySelectorAll(`.tlbar[data-i="${hlIdx}"]`).forEach(r => r.classList.remove('hl'));
    if (i !== -1) svg.querySelectorAll(`.tlbar[data-i="${i}"]`).forEach(r => r.classList.add('hl'));
    hlIdx = i;
  };
  const onMove = (evt) => {
    const rect = svg.getBoundingClientRect();
    if (rect.width === 0) return;
    const svgX = ((evt.clientX - rect.left) / rect.width) * w;
    let best = bars[0];
    for (const b of bars) if (Math.abs(b.cx - svgX) < Math.abs(best.cx - svgX)) best = b;
    svg.classList.add('cursoring');
    highlight(best.i);
    tooltip.innerHTML = fmtTooltip(best.d);
    tooltip.classList.add('active'); // display:block first so offsetWidth is measurable
    const containerRect = el.getBoundingClientRect();
    const pxX = (best.cx / w) * rect.width;
    const pxY = (rect.top - containerRect.top) + (best.topY / h) * rect.height;
    // Tooltip is centered on `left` via translate(-50%); clamp so it never
    // spills past the container (the .card has overflow:hidden and clips it).
    const half = tooltip.offsetWidth / 2;
    tooltip.style.left = `${Math.max(half, Math.min(pxX, el.clientWidth - half))}px`;
    tooltip.style.top = `${pxY}px`;
  };
  const onLeave = () => { svg.classList.remove('cursoring'); highlight(-1); tooltip.classList.remove('active'); };
  addChartTouch(svg, el, onMove, onLeave);
}

// --- Dashboard Page ---
class DashboardPage extends LiveElement {
  constructor() {
    super();
    this._pollTimer = null;
    this._live = true;
    this._prevStats = null;
    this._prevChart = null;
    this._prevDomains = null;
    this._prevClients = null;
    this._prevUpstreams = null;
    this._dnsAddr = '';
  }

  // The body arrives server-rendered, with the real numbers already in it. What
  // is added here is what makes it a *dashboard* rather than a snapshot: the
  // chart, the ten-second poll, and the flash on whatever changed.
  //
  // The first poll re-draws cards that already hold the same values. That is
  // deliberate — the alternative is teaching the client to trust markup it did
  // not write, and every `_prev*` starts empty so nothing flashes on it.
  async connectedCallback() {
    this.querySelectorAll('.js-only[hidden]').forEach(el => el.removeAttribute('hidden'));

    this.querySelector('#live-btn').onclick = () => {
      this._live = !this._live;
      const btn = this.querySelector('#live-btn');
      btn.classList.toggle('paused', !this._live);
      btn.innerHTML = this._live
        ? '<span class="live-dot"></span> LIVE'
        : '<span class="live-dot"></span> PAUSED';
      if (this._live) this._startPolling();
      else this._stopPolling();
    };

    // The poll timer is start/stop-able from the live toggle, so it registers a
    // single teardown that defers to its own stopper.
    this.track(() => this._stopPolling());

    // The address to point a device at was rendered into the onboarding notice
    // already; take it from there rather than asking for it again. Every
    // appliance that has ever answered a query has no notice and needs none,
    // which is why this is not fetched up front any more.
    this._dnsAddr = this.querySelector('#onboard-empty code')?.textContent?.trim() || '';

    await this._fetchAll();
    // `_fetchAll` awaits, so the page may already have been swapped out —
    // disconnectedCallback would have run back when there was still no timer to
    // stop, leaving anything started now to poll forever.
    if (!this.isConnected) return;
    this._startPolling();
  }

  // Only ever needed by the onboarding notice, and only when the server did not
  // already render one — an appliance that starts answering queries mid-session
  // is the one case the markup cannot have covered.
  async _resolveDnsAddr() {
    if (this._dnsAddr) return this._dnsAddr;
    try {
      const info = await api.get('/api/server-info');
      const raw = (info && info.dns_addr) || '';
      const port = raw.includes(':') ? raw.slice(raw.lastIndexOf(':') + 1) : '';
      this._dnsAddr = port ? `${window.location.hostname}:${port}` : window.location.hostname;
    } catch (e) { this._dnsAddr = window.location.hostname; }
    return this._dnsAddr;
  }

  _startPolling() {
    this._stopPolling();
    this._pollTimer = setInterval(() => this._fetchAll(), 10000);
  }

  _stopPolling() {
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
  }

  async _fetchAll() {
    try {
      const [summary, timeline, domains, clients, upstreams] = await Promise.all([
        api.get('/api/stats/summary'),
        api.get('/api/stats/timeline'),
        api.get('/api/stats/top-domains'),
        api.get('/api/stats/top-clients'),
        api.get('/api/stats/top-upstreams'),
      ]);
      this.renderStats(summary);
      this.renderChart(timeline);
      this.renderTopDomains(domains);
      this.renderTopClients(clients);
      this.renderTopUpstreams(upstreams);
    } catch (e) { console.error(e); }
  }

  _flashCard(target) {
    const card = typeof target === 'string' ? this.querySelector(target) : target;
    if (!card) return;
    // Add flash class (no transition) to snap to highlight
    card.classList.add('flash');
    // Next frame: remove flash class, letting the transition fade it out
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        card.classList.remove('flash');
      });
    });
  }

  _flashIfChanged(prevKey, sig, card) {
    if (this[prevKey] && sig !== this[prevKey]) this._flashCard(card);
    this[prevKey] = sig;
  }

  // head opens <table>...<tbody>; the matching '</tbody></table>' close is appended here.
  _renderTopTable(data, { target, card, prevKey, sigFn, limit, head, row }) {
    this._flashIfChanged(prevKey, data.map(sigFn).join(';'), card);
    if (!data.length) { this.querySelector(target).innerHTML = '<p class="text-dim">No data</p>'; return; }
    const visible = limit ? data.slice(0, limit) : data;
    const sumVal = visible.reduce((a, d) => a + d.count, 0);
    // `head` is a literal from the caller and each row() returns Markup, so both
    // pass through unescaped; only the values inside row() get escaped.
    let markup = head;
    for (const d of visible) markup += row(d, sumVal);
    this.querySelector(target).innerHTML = markup + '</tbody></table>';
  }

  renderStats(s) {
    const pct = (v) => ((v || 0) * 100).toFixed(1);
    const ms = (v) => (v || 0).toFixed(1);

    // Server-provided, like its 7d/30d siblings — recomputing it here from
    // blocked_today/total_today produced the same number by a second route,
    // so the two could drift apart on any change to how the server divides.
    const ratio = pct(s.block_ratio_today);
    const ratio7d = pct(s.block_ratio_7d);
    const ratio30d = pct(s.block_ratio_30d);
    const cacheRate = pct(s.cache_hit_rate_today);
    const cacheRate7d = pct(s.cache_hit_rate_7d);
    const cacheRate30d = pct(s.cache_hit_rate_30d);
    const avgMs = ms(s.avg_response_ms_today);
    const avgMs7d = ms(s.avg_response_ms_7d);
    const avgMs30d = ms(s.avg_response_ms_30d);
    const fmtQps = (v) => v >= 100 ? Math.round(v).toString() : v >= 10 ? v.toFixed(1) : v.toFixed(2);
    // Main value is the live rate from the server's 60-second window. The card
    // is labelled Throughput and flashes on change, both of which promise a
    // current reading — a 24h mean cannot move on a traffic spike, so it went
    // in the sub-line with the other averages.
    // Sub-line carries 24h and 7d only. Three entries ("24h / 7d / 30d") wrap
    // to a second line in the six-column desktop grid, which makes this card
    // taller than the five beside it; the 30d mean is the least useful of the
    // three for a rate anyway, since it is smoothed almost flat.
    const qpsNow = fmtQps((s.queries_1m || 0) / 60);
    const qpsToday = fmtQps((s.total_today || 0) / 86400);
    const qps7d = fmtQps((s.total_7d || 0) / (7 * 86400));

    const vals = [s.total_today, s.blocked_today, ratio, cacheRate, avgMs, qpsNow];
    const prevVals = this._prevStats;
    this._prevStats = vals;

    const statsEl = this.querySelector('#stats');
    statsEl.innerHTML = `
      <div class="stat-card" data-i="0"><div class="stat-label">Queries Today</div><div class="stat-value accent" title="${formatFull(s.total_today)}">${formatNumAdaptive(s.total_today)}</div><div class="stat-sub">7d: ${formatNum(s.total_7d)} / 30d: ${formatNum(s.total_30d)}</div></div>
      <div class="stat-card" data-i="1" data-testid="stat-blocked-today"><div class="stat-label">Blocked Today</div><div class="stat-value red" title="${formatFull(s.blocked_today)}">${formatNumAdaptive(s.blocked_today)}</div><div class="stat-sub">7d: ${formatNum(s.blocked_7d)} / 30d: ${formatNum(s.blocked_30d)}</div></div>
      <div class="stat-card" data-i="2" data-testid="stat-block-rate"><div class="stat-label">Block Rate</div><div class="stat-value red">${ratio}%</div><div class="stat-sub">7d: ${ratio7d}% / 30d: ${ratio30d}%</div></div>
      <div class="stat-card" data-i="3"><div class="stat-label">Cache Hit Rate</div><div class="stat-value text-orange">${cacheRate}%</div><div class="stat-sub">7d: ${cacheRate7d}% / 30d: ${cacheRate30d}%</div></div>
      <div class="stat-card" data-i="4"><div class="stat-label">Avg Response</div><div class="stat-value text-orange">${avgMs}<span style="font-size:0.9rem;color:var(--text-dim)">ms</span></div><div class="stat-sub">7d: ${avgMs7d} ms / 30d: ${avgMs30d} ms</div></div>
      <div class="stat-card" data-i="5" data-testid="stat-throughput"><div class="stat-label">Throughput</div><div class="stat-value accent" data-testid="stat-throughput-value">${qpsNow}<span style="font-size:0.9rem;color:var(--text-dim)">q/s</span></div><div class="stat-sub">24h: ${qpsToday} / 7d: ${qps7d}</div></div>`;

    // Flash cards that changed (skip on first render)
    if (prevVals) {
      statsEl.querySelectorAll('.stat-card').forEach(card => {
        const i = parseInt(card.dataset.i);
        if (String(vals[i]) !== String(prevVals[i])) this._flashCard(card);
      });
    }

    this._renderOnboarding(s);
  }

  async _renderOnboarding(s) {
    const hasQueries = ((s.total_today || 0) + (s.total_7d || 0) + (s.total_30d || 0)) > 0;
    const box = this.querySelector('#onboard-empty');
    const chart = this.querySelector('#chart-card');
    if (!box) return;
    if (hasQueries) {
      box.style.display = 'none';
      if (chart) chart.style.display = '';
      return;
    }
    await this._resolveDnsAddr();
    box.innerHTML = html`
      <div class="card-title">Point a device at noadd to get started</div>
      <p style="color:var(--text-secondary);font-size:0.9rem;margin:8px 0">
        noadd hasn't served any DNS queries yet. To start filtering, configure a device or
        router to use this server as its DNS resolver, then send some traffic.
      </p>
      <p style="color:var(--text-secondary);font-size:0.9rem;margin:8px 0">
        Set the device's DNS server to:
        <code class="mono text-primary">${this._dnsAddr}</code>
      </p>`;
    box.style.display = '';
    if (chart) chart.style.display = 'none';
  }

  renderChart(rawData) {
    if (!rawData || !rawData.length) { this.querySelector('#chart').innerHTML = '<p class="panel-empty">No data yet</p>'; this._prevChart = null; return; }
    this._flashIfChanged('_prevChart', rawData.map(d => d.total + ',' + d.blocked).join(';'), '#chart-card');
    renderTimelineChart(this.querySelector('#chart'), rawData, [
      { key: 'total', color: 'var(--accent)', label: 'total' },
      { key: 'blocked', color: 'var(--red)', label: 'blocked' },
    ],
    (d) => formatTime(d.timestamp),
    (d) => {
      const pct = d.total > 0 ? ((d.blocked / d.total) * 100).toFixed(0) : '0';
      return html`${formatTime(d.timestamp)}<br><span class="text-accent">${formatFull(d.total)} total</span> · <span class="text-red">${formatFull(d.blocked)} blocked</span> (${pct}%)`;
    });
  }

  renderTopDomains(data) {
    this._renderTopTable(data, {
      target: '#top-domains', card: '#domains-card', prevKey: '_prevDomains',
      sigFn: d => d.domain + d.count, limit: 10,
      head: '<table class="top-table"><colgroup><col><col style="width:140px"></colgroup><thead><tr><th>Domain</th><th style="text-align:right">Count</th></tr></thead><tbody>',
      row: (d, sum) => html`<tr><td><div class="truncate-cell" title="${d.domain}">${d.domain}</div></td><td class="mono" style="text-align:right;white-space:nowrap">${formatFull(d.count)}${sharePctSpan(d.count, sum)}</td></tr>`,
    });
  }

  renderTopClients(data) {
    this._renderTopTable(data, {
      target: '#top-clients', card: '#clients-card', prevKey: '_prevClients',
      sigFn: d => d.client_ip + (d.doh_token || '') + d.count, limit: 10,
      head: '<table class="top-table"><colgroup><col><col style="width:140px"></colgroup><thead><tr><th>Client</th><th style="text-align:right">Count</th></tr></thead><tbody>',
      row: (d, sum) => {
        const tokenLine = d.doh_token
          ? html`<div class="truncate-cell" title="${d.doh_token}" style="color:var(--accent);font-size:0.7rem">${d.doh_token}</div>`
          : '';
        return html`<tr><td><div class="truncate-cell mono" title="${d.client_ip}">${d.client_ip}</div>${tokenLine}</td><td class="mono" style="text-align:right;white-space:nowrap">${formatFull(d.count)}${sharePctSpan(d.count, sum)}</td></tr>`;
      },
    });
  }

  renderTopUpstreams(data) {
    this._renderTopTable(data, {
      target: '#top-upstreams', card: '#upstreams-card', prevKey: '_prevUpstreams',
      sigFn: d => d.upstream + d.count,
      head: '<table class="top-table"><thead><tr><th>Upstream</th><th style="text-align:right;width:140px">Queries</th><th class="hide-mobile" style="text-align:right;width:120px">Avg Latency</th></tr></thead><tbody>',
      row: (d, sum) => html`<tr><td><div class="truncate-cell mono" title="${d.upstream}">${d.upstream}</div></td><td class="mono" style="text-align:right;white-space:nowrap">${formatFull(d.count)}${sharePctSpan(d.count, sum)}</td><td class="mono hide-mobile" style="text-align:right;white-space:nowrap">${d.avg_ms.toFixed(1)}ms</td></tr>`,
    });
  }
}
customElements.define('dashboard-page', DashboardPage);

// --- Statistics Page ---
class StatsPage extends HTMLElement {
  constructor() {
    super();
    this._range = '7d';
  }

  connectedCallback() {
    this.innerHTML = `
      <div class="page-header fade-in" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
        <div><h2>Statistics</h2><p>Long-term traffic patterns</p></div>
        <div class="range-switcher" id="range-switcher">
          <button class="active" data-range="7d">7d</button>
          <button data-range="30d">30d</button>
          <button data-range="90d">90d</button>
        </div>
      </div>
      <div class="stat-grid fade-in" id="highlights-grid" style="animation-delay:0.03s"></div>
      <div class="stats-row-2col fade-in" style="animation-delay:0.05s">
        <div class="card" id="timeline-card">
          <div class="card-title" id="timeline-title">Queries (last 7d)</div>
          <div class="chart-container" id="timeline-chart"><p class="panel-empty">Loading…</p></div>
        </div>
        <div class="card" id="rate-trend-card">
          <div class="card-title" id="rate-trend-title">Block &amp; Cache rate (last 7d)</div>
          <div class="rate-chart-container" id="rate-trend-chart"><p class="panel-empty">Loading…</p></div>
        </div>
      </div>
      <div class="card fade-in" style="animation-delay:0.08s" id="heatmap-card">
        <div class="card-title">Activity by hour (last 30d)</div>
        <div id="heatmap-container"><p class="panel-empty">Loading…</p></div>
      </div>
      <div class="stats-row-2col fade-in" style="animation-delay:0.1s">
        <div class="card" id="qtypes-card">
          <div class="card-title">Query Types</div>
          <div id="qtypes-chart"><p class="text-dim">Loading…</p></div>
        </div>
        <div class="card" id="outcomes-card">
          <div class="card-title">Outcomes</div>
          <div id="outcomes-chart"><p class="text-dim">Loading…</p></div>
        </div>
      </div>
      <div class="stats-row-2col fade-in" style="animation-delay:0.15s">
        <div class="card" id="ranged-domains-card">
          <div class="card-title" id="ranged-domains-title">Top Domains (last 7d)</div>
          <div id="ranged-domains"><p class="text-dim">Loading…</p></div>
        </div>
        <div class="card" id="ranged-clients-card">
          <div class="card-title" id="ranged-clients-title">Top Sources (last 7d)</div>
          <div id="ranged-clients"><p class="text-dim">Loading…</p></div>
        </div>
      </div>
      <div class="card fade-in" style="animation-delay:0.2s" id="health-card" data-testid="db-health-card">
        <div class="card-title">Database Health</div>
        <div class="stat-grid" id="health-grid"></div>
      </div>`;

    this.querySelector('#range-switcher').addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-range]');
      if (!btn) return;
      this._range = btn.dataset.range;
      this.querySelectorAll('#range-switcher button').forEach(b => {
        b.classList.toggle('active', b === btn);
      });
      this._fetchRanged();
    });

    this._fetchAll();
  }

  async _fetchAll() {
    await Promise.all([
      this._fetchRanged(),
      this._fetchHeatmap(),
      this._fetchHealth(),
    ]);
  }

  _updateRangedTitles() {
    const r = this._range;
    this.querySelector('#timeline-title').textContent = `Queries (last ${r})`;
    this.querySelector('#rate-trend-title').innerHTML = `Block &amp; Cache rate (last ${r})`;
    this.querySelector('#ranged-domains-title').textContent = `Top Domains (last ${r})`;
    this.querySelector('#ranged-clients-title').textContent = `Top Sources (last ${r})`;
  }

  async _fetchRanged() {
    this._updateRangedTitles();
    try {
      // Pass the viewer's UTC offset so the server aligns timeline buckets to
      // their local calendar (local midnight / hour), not UTC-epoch boundaries.
      const tzOffset = tzOffsetMinutes();
      const [timeline, breakdown, highlights, topDomains, topClients] = await Promise.all([
        api.get(`/api/stats/v2/timeline?range=${this._range}&tz_offset=${tzOffset}`),
        api.get(`/api/stats/v2/breakdown?range=${this._range}`),
        api.get(`/api/stats/v2/highlights?range=${this._range}`),
        api.get(`/api/stats/v2/top-domains?range=${this._range}`),
        api.get(`/api/stats/v2/top-clients?range=${this._range}`),
      ]);
      this._renderTimeline(timeline);
      this._renderBreakdown(breakdown);
      this._renderRateTrend(timeline);
      this._renderHighlights(highlights);
      this._renderRangedTopDomains(topDomains);
      this._renderRangedTopClients(topClients);
    } catch (e) { console.error(e); }
  }

  async _fetchHeatmap() {
    try {
      // Same local-calendar alignment as the timeline: without it the
      // hour-of-day rows are shifted by the viewer's UTC offset.
      const data = await api.get(`/api/stats/v2/heatmap?tz_offset=${tzOffsetMinutes()}`);
      this._renderHeatmap(data);
    } catch (e) { console.error(e); }
  }

  async _fetchHealth() {
    try {
      const data = await api.get('/api/stats/v2/health');
      this._renderHealth(data);
    } catch (e) { console.error(e); }
  }

  _formatBytes(bytes) {
    if (bytes == null) return '—';
    if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
  }

  _renderTimeline(rawData) {
    const el = this.querySelector('#timeline-chart');
    if (!rawData || !rawData.length) {
      el.innerHTML = '<p class="panel-empty">No data yet</p>';
      return;
    }
    // x-axis labels stay date-only; tooltips add HH:mm on sub-day buckets.
    const subDay = this._range !== '90d';
    const fmtDay = (d) => new Date(d.timestamp * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
    renderTimelineChart(el, rawData, [
      { key: 'total', color: 'var(--accent)', label: 'total' },
      { key: 'cached', color: 'var(--orange)', label: 'cached' },
      { key: 'blocked', color: 'var(--red)', label: 'blocked' },
    ],
    fmtDay,
    (d) => {
      const blocked = d.blocked || 0;
      const cached = d.cached || 0;
      const blockedPct = formatPct(blocked, d.total);
      const cachedPct = formatPct(cached, d.total);
      const blockedStr = blockedPct ? `${formatFull(blocked)} blocked (${blockedPct})` : `${formatFull(blocked)} blocked`;
      const cachedStr = cachedPct ? `${formatFull(cached)} cached (${cachedPct})` : `${formatFull(cached)} cached`;
      return html`${fmtBucketLabel(d.timestamp, subDay)}<br><span class="text-accent">${formatFull(d.total)} total</span> · <span class="text-red">${blockedStr}</span> · <span class="text-orange">${cachedStr}</span>`;
    });
  }

  _renderHeatmap(rawData) {
    const el = this.querySelector('#heatmap-container');
    // Build a [weekday][hour] lookup. API: 0=Sun..6=Sat
    // Display order: Mon(1)..Sun(0) — reorder so Mon is row 0
    const displayOrder = [1, 2, 3, 4, 5, 6, 0]; // Mon..Sun
    const dayLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

    const grid = {};
    if (rawData && rawData.length) {
      for (const d of rawData) {
        if (!grid[d.weekday]) grid[d.weekday] = {};
        grid[d.weekday][d.hour] = d.count;
      }
    }

    const allCounts = rawData && rawData.length ? rawData.map(d => d.count) : [0];
    const maxCount = Math.max(...allCounts, 1);

    if (!rawData || !rawData.length) {
      el.innerHTML = '<p class="panel-empty">No data yet</p>';
      return;
    }

    // Column labels row. Named `markup` rather than `html` so it does not shadow
    // the tagged template of that name.
    let markup = '<div class="heatmap-wrap"><div class="heatmap-col-labels"><div></div>';
    for (let h = 0; h < 24; h++) {
      const label = (h === 0 || h === 6 || h === 12 || h === 18) ? String(h).padStart(2, '0') : '';
      markup += html`<div class="heatmap-col-label">${label}</div>`;
    }
    markup += '</div>';

    // Data rows
    markup += '<div class="heatmap-table">';
    for (let ri = 0; ri < 7; ri++) {
      const wd = displayOrder[ri];
      markup += html`<div class="heatmap-row-label">${dayLabels[ri]}</div>`;
      for (let h = 0; h < 24; h++) {
        const count = (grid[wd] && grid[wd][h]) ? grid[wd][h] : 0;
        const opacity = count > 0 ? Math.max(0.08, count / maxCount) : 0.04;
        const dayName = dayLabels[ri];
        const edgeCls = [];
        if (ri === 0) edgeCls.push('edge-top');
        if (h <= 2) edgeCls.push('edge-left');
        if (h >= 21) edgeCls.push('edge-right');
        markup += html`<div class="heatmap-cell${edgeCls.length ? ' ' + edgeCls.join(' ') : ''}" style="--cell-op:${opacity.toFixed(3)}" title="${formatFull(count)} queries · ${dayName} ${String(h).padStart(2,'0')}:00">
          <span class="heatmap-tooltip">${formatFull(count)} · ${dayName} ${String(h).padStart(2,'0')}:00</span>
        </div>`;
      }
    }
    markup += '</div></div>';
    el.innerHTML = markup;

    // Touch: CSS :hover never fires on mobile, so tap a cell to show its tooltip,
    // tap another to switch, tap outside to dismiss. The listener lives on the
    // freshly-built .heatmap-wrap (GC'd with the next re-render — no accumulation).
    const wrap = el.querySelector('.heatmap-wrap');
    const clearActive = () => { _chartTouchDismissers.delete(el); wrap.querySelectorAll('.heatmap-cell.touch-active').forEach(c => c.classList.remove('touch-active')); };
    wrap.addEventListener('pointerup', (evt) => {
      if (evt.pointerType === 'mouse') return; // mouse keeps pure hover behavior
      const cell = evt.target.closest('.heatmap-cell');
      if (!cell) return;
      const wasActive = cell.classList.contains('touch-active');
      clearActive();
      if (!wasActive) { cell.classList.add('touch-active'); _chartTouchDismissers.set(el, clearActive); }
    });
  }

  _renderBarChart(containerId, entries, color) {
    const el = this.querySelector(containerId);
    if (!entries || !entries.length) {
      el.innerHTML = '<p class="text-dim">No data yet</p>';
      return;
    }
    const sorted = [...entries].sort((a, b) => b[1] - a[1]);
    const maxVal = Math.max(...sorted.map(e => e[1]), 1);
    const sumVal = sorted.reduce((a, e) => a + e[1], 0);
    const barThreshold = window.innerWidth <= 768 ? 100_000 : 1_000_000;
    let markup = '<div class="bar-list">';
    for (const [label, count] of sorted) {
      const barPct = (count / maxVal * 100).toFixed(1);
      const sharePct = formatPct(count, sumVal);
      const titleText = sharePct ? `${formatFull(count)} (${sharePct})` : formatFull(count);
      const pctLine = sharePct ? html`<div class="bar-row-pct">${sharePct}</div>` : '';
      markup += html`<div class="bar-row">
        <div class="bar-row-label" title="${label}">${label}</div>
        <div class="bar-row-track"><div class="bar-row-fill" style="width:${barPct}%;background:${color}"></div></div>
        <div class="bar-row-count" title="${titleText}"><div>${formatNumAdaptive(count, barThreshold)}</div>${pctLine}</div>
      </div>`;
    }
    markup += '</div>';
    el.innerHTML = markup;
  }

  _renderBreakdown(data) {
    if (!data) return;
    this._renderBarChart('#qtypes-chart', data.query_types, 'var(--accent)');
    this._renderBarChart('#outcomes-chart', data.outcomes, 'var(--orange)');
  }

  _renderHealth(data) {
    const el = this.querySelector('#health-grid');
    if (!data) { el.innerHTML = '<p class="text-dim">No data</p>'; return; }
    const oldest = data.oldest_log_timestamp
      ? new Date(data.oldest_log_timestamp * 1000).toLocaleDateString()
      : '—';
    const retention = data.log_retention_days != null ? `${data.log_retention_days}d` : '—';
    const avgDay = data.avg_new_rows_per_day != null ? formatNum(Math.round(data.avg_new_rows_per_day)) : '—';
    const fragPct = data.fragmentation_ratio != null ? Math.round(data.fragmentation_ratio * 100) : 0;
    const bytesPerLog = data.bytes_per_log ? this._formatBytes(Math.round(data.bytes_per_log)) : '—';
    const growthPerDay = data.bytes_per_log && data.avg_new_rows_per_day
      ? this._formatBytes(Math.round(data.bytes_per_log * data.avg_new_rows_per_day))
      : '—';
    const cov = data.log_coverage_days || 0;
    const coverage = cov > 0 ? `${cov >= 10 ? Math.round(cov) : cov.toFixed(1)}d` : '—';
    const projected = data.projected_full_bytes ? this._formatBytes(data.projected_full_bytes) : '—';
    el.innerHTML = html`
      <div class="stat-card"><div class="stat-label">Database Size</div><div class="stat-value accent">${this._formatBytes(data.db_size_bytes)}</div></div>
      <div class="stat-card"><div class="stat-label">Total Logs</div><div class="stat-value accent" title="${formatFull(data.total_log_count)}">${formatNumAdaptive(data.total_log_count, 10_000_000)}</div></div>
      <div class="stat-card"><div class="stat-label">Bytes / Log</div><div class="stat-value accent">${bytesPerLog}</div></div>
      <div class="stat-card"><div class="stat-label">Reclaimable</div><div class="stat-value accent">${this._formatBytes(data.reclaimable_bytes || 0)}</div><div class="stat-sub">${fragPct}% of file</div></div>
      <div class="stat-card"><div class="stat-label">Oldest Log</div><div class="stat-value" style="font-size:1.1rem;color:var(--text-secondary)">${oldest}</div></div>
      <div class="stat-card"><div class="stat-label">Log Coverage</div><div class="stat-value accent">${coverage}</div></div>
      <div class="stat-card"><div class="stat-label">Retention</div><div class="stat-value accent">${retention}</div></div>
      <div class="stat-card"><div class="stat-label">Avg / Day</div><div class="stat-value accent">${avgDay}</div></div>
      <div class="stat-card"><div class="stat-label">Growth / Day</div><div class="stat-value accent">${growthPerDay}</div></div>
      <div class="stat-card"><div class="stat-label">Projected Full</div><div class="stat-value accent">${projected}</div><div class="stat-sub">at full retention</div></div>`;
  }

  _renderHighlights(data) {
    const el = this.querySelector('#highlights-grid');
    if (!data) { el.innerHTML = ''; return; }
    const lat = data.latency || {};
    const sample = lat.sample_count || 0;
    const hasLat = sample > 0;
    const fmtMs = (ms) => hasLat ? `${formatNum(ms)}<span style="font-size:0.9rem;color:var(--text-dim)">ms</span>` : '—';
    el.innerHTML = `
      <div class="stat-card"><div class="stat-label">Unique Domains</div><div class="stat-value accent" title="${formatFull(data.unique_domains)}">${formatNumAdaptive(data.unique_domains, 10_000_000)}</div></div>
      <div class="stat-card"><div class="stat-label">Latency p50</div><div class="stat-value text-green">${fmtMs(lat.p50_ms)}</div></div>
      <div class="stat-card"><div class="stat-label">Latency p95</div><div class="stat-value text-orange">${fmtMs(lat.p95_ms)}</div></div>
      <div class="stat-card"><div class="stat-label">Latency p99</div><div class="stat-value text-red">${fmtMs(lat.p99_ms)}</div></div>`;
  }

  _renderRangedTopDomains(rows) {
    this._renderBarChart('#ranged-domains', (rows || []).map(d => [d.domain, d.count]), 'var(--accent)');
  }

  _renderRangedTopClients(rows) {
    const entries = (rows || []).map(d => {
      const label = d.doh_token ? `${d.client_ip} · ${d.doh_token}` : d.client_ip;
      return [label, d.count];
    });
    this._renderBarChart('#ranged-clients', entries, 'var(--green)');
  }

  _renderRateTrend(rawData) {
    const el = this.querySelector('#rate-trend-chart');
    if (!rawData || !rawData.length) {
      el.innerHTML = '<p class="panel-empty">No data yet</p>';
      return;
    }
    rawData = downsampleBuckets(rawData, MAX_BARS_GROUPED());
    const len = rawData.length;
    const w = 600;
    const h = 140;
    const padX = 8;
    const padY = 12;
    const innerW = w - padX * 2;
    const innerH = h - padY * 2;
    const baseline = padY + innerH;
    const hOf = (pct) => (pct / 100) * innerH; // percentage → bar height
    const slot = innerW / len;
    // Two grouped bars per bucket (block %, cache %) sitting side by side.
    const group = Math.min(slot * 0.7, 44);
    const bw = group / 2;
    const cats = [
      { key: 'blocked', color: 'var(--red)' },
      { key: 'cached', color: 'var(--green)' },
    ];
    const bars = [];
    let rects = '';
    for (let i = 0; i < len; i++) {
      const d = rawData[i];
      const total = d.total || 0;
      const blockedPct = total > 0 ? ((d.blocked || 0) / total) * 100 : 0;
      const cachedPct = total > 0 ? ((d.cached || 0) / total) * 100 : 0;
      const pcts = { blocked: blockedPct, cached: cachedPct };
      const cx = padX + (i + 0.5) * slot;
      const left = cx - group / 2;
      cats.forEach((c, gi) => {
        const hgt = hOf(pcts[c.key]);
        if (hgt > 0.3) rects += `<rect class="ratebar" data-i="${i}" x="${(left + gi * bw).toFixed(1)}" y="${(baseline - hgt).toFixed(1)}" width="${(bw * 0.86).toFixed(1)}" height="${hgt.toFixed(1)}" fill="${c.color}" fill-opacity="0.85"/>`;
      });
      bars.push({ i, cx, topY: baseline - hOf(Math.max(blockedPct, cachedPct)), d, blockedPct, cachedPct });
    }
    // Gridlines stay inside the stretched SVG (geometry should stretch). The
    // numeric % labels are real HTML in a .rate-yticks overlay so they are
    // never distorted by preserveAspectRatio="none" (same fix as .tl-yticks).
    const ticks = [25, 50, 75].map(p => {
      const y = (baseline - hOf(p)).toFixed(1);
      return `<line x1="${padX}" y1="${y}" x2="${padX + innerW}" y2="${y}" stroke="var(--border)" stroke-dasharray="2 4" stroke-width="0.5"/>`;
    }).join('');
    const yTicks = '<div class="rate-yticks" aria-hidden="true">' +
      [25, 50, 75].map(p =>
        `<span class="tl-ytick" style="top:${(((baseline - hOf(p)) / h) * 100).toFixed(2)}%">${p}%</span>`
      ).join('') + '</div>';
    // x-axis labels stay date-only; tooltips add HH:mm on sub-day buckets.
    const subDay = this._range !== '90d';
    const fmtDay = (d) => new Date(d.timestamp * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
    const targetLabels = window.innerWidth <= 480 ? 4 : 6;
    const labelEvery = Math.max(1, Math.round(len / targetLabels));
    let labels = '<div class="chart-labels">';
    for (let i = 0; i < len; i += labelEvery) labels += html`<div class="chart-label">${fmtDay(rawData[i])}</div>`;
    labels += '</div>';
    el.innerHTML = `
      <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" class="rate-svg">
        ${ticks}
        ${rects}
      </svg>
      ${yTicks}
      <div class="rate-tooltip"></div>
      ${labels}
      <div class="rate-legend">
        <span><i style="background:var(--red)"></i>blocked %</span>
        <span><i style="background:var(--green)"></i>cached %</span>
      </div>`;

    const svg = el.querySelector('.rate-svg');
    const tooltip = el.querySelector('.rate-tooltip');
    let hlIdx = -1;
    const highlight = (i) => {
      if (i === hlIdx) return;
      if (hlIdx !== -1) svg.querySelectorAll(`.ratebar[data-i="${hlIdx}"]`).forEach(r => r.classList.remove('hl'));
      if (i !== -1) svg.querySelectorAll(`.ratebar[data-i="${i}"]`).forEach(r => r.classList.add('hl'));
      hlIdx = i;
    };
    const onMove = (evt) => {
      const rect = svg.getBoundingClientRect();
      if (rect.width === 0) return;
      const svgX = ((evt.clientX - rect.left) / rect.width) * w;
      let best = bars[0];
      for (const b of bars) if (Math.abs(b.cx - svgX) < Math.abs(best.cx - svgX)) best = b;
      svg.classList.add('cursoring');
      highlight(best.i);
      tooltip.innerHTML = html`${fmtBucketLabel(best.d.timestamp, subDay)}<br><span class="text-red">${best.blockedPct.toFixed(1)}% blocked</span> · <span class="text-green">${best.cachedPct.toFixed(1)}% cached</span><br><span class="text-dim">${formatFull(best.d.total || 0)} total</span>`;
      tooltip.classList.add('active'); // display:block first so offsetWidth is measurable
      const pxX = (best.cx / w) * rect.width;
      const containerRect = el.getBoundingClientRect();
      const pxY = (rect.top - containerRect.top) + (best.topY / h) * rect.height;
      // Tooltip is centered on `left` via translate(-50%); clamp so it never
      // spills past the container (the .card has overflow:hidden and clips it).
      const half = tooltip.offsetWidth / 2;
      tooltip.style.left = `${Math.max(half, Math.min(pxX, el.clientWidth - half))}px`;
      tooltip.style.top = `${pxY}px`;
    };
    const onLeave = () => { svg.classList.remove('cursoring'); highlight(-1); tooltip.classList.remove('active'); };
    addChartTouch(svg, el, onMove, onLeave);
  }
}
customElements.define('stats-page', StatsPage);

// --- Query Log Page ---
class LogsPage extends LiveElement {
  constructor() {
    super();
    this.offset = 0;
    this.limit = 50;
    this.search = '';
    this.actionFilter = '';
    this.tokenFilter = '';
    this.typeFilter = '';
    this._live = false;
    this._es = null;
    this._timeTimer = null;
  }

  connectedCallback() {
    this.innerHTML = `
      <div class="page-header fade-in" style="display:flex;align-items:center;justify-content:space-between">
        <div><h2>Query Log</h2><p>DNS query history</p></div>
        <button class="live-toggle paused" id="log-live-btn" data-testid="logs-live-toggle" title="Stream new queries live as they arrive. Click to toggle."><span class="live-dot"></span> LIVE</button>
      </div>
      <div class="filters-row fade-in">
        <input type="text" id="log-search" placeholder="Domain prefix, or *pattern*" title="Plain text matches the domain prefix (fast). Use * or % anywhere for a substring/wildcard match (slower).">
        <select id="log-action">
          <option value="">All</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
        </select>
        <select id="log-type">
          <option value="">All Types</option>
          <option value="A">A</option>
          <option value="AAAA">AAAA</option>
          <option value="CNAME">CNAME</option>
          <option value="MX">MX</option>
          <option value="TXT">TXT</option>
          <option value="NS">NS</option>
          <option value="SOA">SOA</option>
          <option value="PTR">PTR</option>
          <option value="SRV">SRV</option>
          <option value="CAA">CAA</option>
          <option value="HTTPS">HTTPS</option>
        </select>
        <select id="log-token">
          <option value="">All Tokens</option>
        </select>
        <button class="btn btn-danger btn-sm" id="clear-logs">${icons.trash} Clear All</button>
      </div>
      <div class="card fade-in" style="animation-delay:0.05s">
        <div class="table-wrap hide-mobile-block"><table><thead><tr>
          <th>Time</th><th>Status</th><th>Query</th><th>Type</th><th>Client</th><th></th><th>Source</th><th>ms</th>
        </tr></thead><tbody id="log-body"></tbody></table></div>
        <div id="log-cards" class="show-mobile"></div>
        <div class="pagination" id="log-pagination"></div>
      </div>`;

    let debounce;
    this.querySelector('#log-search').oninput = (e) => {
      clearTimeout(debounce);
      debounce = setTimeout(() => { this.search = e.target.value; this.offset = 0; this.load(); }, 300);
    };
    this.querySelector('#log-action').onchange = (e) => {
      this.actionFilter = e.target.value; this.offset = 0; this.load();
    };
    this.querySelector('#log-token').onchange = (e) => {
      this.tokenFilter = e.target.value; this.offset = 0; this.load();
    };
    this.querySelector('#log-type').onchange = (e) => {
      this.typeFilter = e.target.value; this.offset = 0; this.load();
    };
    this.loadTokens();
    this.querySelector('#clear-logs').onclick = async () => {
      if (confirm('Delete all query logs?')) {
        await api.del('/api/logs');
        this.load();
      }
    };
    this.querySelector('#log-live-btn').onclick = () => this._toggleLive();
    // Both the stream and the ticker are toggled on and off during the page's
    // life, so they register single teardowns that defer to their own stoppers.
    this.track(() => { this._stopLive(); this._stopTimeTicker(); });
    this.load();
    this._startTimeTicker();
  }

  // Relative times ("2 seconds ago") are baked in at render/insert time, so
  // rows already on screen would otherwise freeze — most visibly during a live
  // tail. Recompute the visible spans in place once a second.
  _startTimeTicker() {
    this._stopTimeTicker();
    this._timeTimer = setInterval(() => this._refreshTimes(), 1000);
  }

  _stopTimeTicker() {
    if (this._timeTimer) { clearInterval(this._timeTimer); this._timeTimer = null; }
  }

  _refreshTimes() {
    this.querySelectorAll('.timeago').forEach(el => {
      const ts = Number(el.dataset.ts);
      if (ts) el.textContent = timeAgoText(ts);
    });
  }

  _toggleLive() {
    this._live = !this._live;
    const btn = this.querySelector('#log-live-btn');
    btn.classList.toggle('paused', !this._live);
    if (this._live) {
      // Live tail only makes sense on the newest page with default ordering.
      this.offset = 0;
      // Start streaming only after the baseline render completes, so incoming
      // events aren't wiped by renderLogs resetting body.innerHTML. Also hide
      // pagination — the live tail always shows the newest page.
      this.load().then(() => { if (this._live && this.isConnected) this._startLive(); });
      this._togglePagination(false);
    } else {
      this._stopLive();
      this._togglePagination(true);
    }
  }

  _startLive() {
    this._stopLive();
    this._es = new EventSource('/api/logs/stream');
    this._es.onmessage = (e) => {
      try { this._prependRow(JSON.parse(e.data)); } catch (_) {}
    };
    // EventSource auto-reconnects on error; nothing to do here.
  }

  _stopLive() {
    if (this._es) { this._es.close(); this._es = null; }
  }

  _togglePagination(show) {
    const pag = this.querySelector('#log-pagination');
    if (pag) pag.style.display = show ? '' : 'none';
  }

  _matchesFilters(l) {
    if (this.actionFilter === 'blocked' && !l.blocked) return false;
    if (this.actionFilter === 'allowed' && l.blocked) return false;
    if (this.typeFilter && l.query_type !== this.typeFilter) return false;
    if (this.tokenFilter && l.doh_token !== this.tokenFilter) return false;
    if (this.search) {
      // mirror server: plain text = domain prefix; *x* / %x% = substring
      const s = this.search.toLowerCase();
      const d = (l.domain || '').toLowerCase();
      const wild = s.includes('*') || s.includes('%');
      const needle = s.replace(/[*%]/g, '');
      if (wild ? !d.includes(needle) : !d.startsWith(needle)) return false;
    }
    return true;
  }

  _prependRow(l) {
    if (!this._live) return;
    if (this.offset !== 0) return;            // only tail the first page
    if (!this._matchesFilters(l)) return;
    const body = this.querySelector('#log-body');
    const cards = this.querySelector('#log-cards');
    if (body) {
      // Clear an empty-state placeholder row if present.
      if (body.querySelector('[data-testid="logs-empty-state"]') || (body.children.length === 1 && body.textContent.includes('No logs'))) body.innerHTML = '';
      const tr = document.createElement('tr');
      tr.className = 'log-row-new';
      tr.innerHTML = this._rowHtml(l);
      body.insertBefore(tr, body.firstChild);
      this._bindRowActions(tr);
      while (body.children.length > 200) body.removeChild(body.lastChild);
    }
    if (cards) {
      // Clear a mobile empty-state guide (no .log-card present yet) before inserting.
      if (!cards.querySelector('.log-card')) cards.innerHTML = '';
      const wrap = document.createElement('div');
      wrap.innerHTML = this._cardHtml(l);
      const card = wrap.firstElementChild;
      if (card) {
        card.classList.add('log-row-new');
        cards.insertBefore(card, cards.firstChild);
        this._bindRowActions(card);
        while (cards.children.length > 200) cards.removeChild(cards.lastChild);
      }
    }
  }

  _bindRowActions(scope) {
    (scope || this).querySelectorAll('.log-action').forEach(btn => {
      if (btn._bound) return; btn._bound = true;
      btn.onclick = async () => {
        const domain = btn.dataset.domain;
        const rule = btn.dataset.blocked === 'true' ? `@@||${domain}^` : `||${domain}^`;
        await api.post('/api/rules', { rule });
        btn.textContent = 'Done';
        btn.disabled = true;
      };
    });
  }

  async load() {
    try {
      let url = `/api/logs?limit=${this.limit}&offset=${this.offset}`;
      if (this.search) url += `&search=${encodeURIComponent(this.search)}`;
      if (this.actionFilter) url += `&blocked=${this.actionFilter === 'blocked'}`;
      if (this.tokenFilter) url += `&token=${encodeURIComponent(this.tokenFilter)}`;
      if (this.typeFilter) url += `&query_type=${encodeURIComponent(this.typeFilter)}`;
      const data = await api.get(url);
      this.total = data.total || 0;
      this.renderLogs(data.logs || []);
    } catch (e) { console.error(e); }
  }

  renderLogs(logs) {
    const noFilters = !this.search && !this.actionFilter && !this.tokenFilter && !this.typeFilter;
    const emptyGuide = `<div style="text-align:center;color:var(--text-secondary);padding:24px 12px">
        <div style="color:var(--text-primary);font-weight:600;margin-bottom:6px">No DNS queries logged yet</div>
        <div style="font-size:0.9rem">Once a device uses noadd as its DNS resolver, its queries will appear here.</div>
      </div>`;
    const emptyGuideDesktop = `<div data-testid="logs-empty-state" style="text-align:center;color:var(--text-secondary);padding:24px 12px">
        <div style="color:var(--text-primary);font-weight:600;margin-bottom:6px">No DNS queries logged yet</div>
        <div style="font-size:0.9rem">Once a device uses noadd as its DNS resolver, its queries will appear here.</div>
      </div>`;
    // Desktop table
    const body = this.querySelector('#log-body');
    if (!logs.length) {
      body.innerHTML = noFilters
        ? html`<tr><td colspan="8" style="padding:0">${raw(emptyGuideDesktop)}</td></tr>`
        : '<tr><td colspan="8" style="text-align:center;color:var(--text-dim)">No logs found</td></tr>';
    } else {
      body.innerHTML = logs.map(l => html`<tr>${this._rowHtml(l)}</tr>`).join('');
    }

    // Mobile card list
    const cards = this.querySelector('#log-cards');
    if (!logs.length) {
      cards.innerHTML = noFilters
        ? emptyGuide
        : '<p style="color:var(--text-dim);text-align:center;padding:16px">No logs found</p>';
    } else {
      cards.innerHTML = logs.map(l => this._cardHtml(l)).join('');
    }

    // Bind action buttons (both table and cards)
    this._bindRowActions(this);

    const pag = this.querySelector('#log-pagination');
    const currentPage = Math.floor(this.offset / this.limit) + 1;
    const totalPages = Math.max(1, Math.ceil(this.total / this.limit));
    const hasPrev = this.offset > 0;
    const hasNext = currentPage < totalPages;
    pag.innerHTML = html`
      <button class="btn btn-sm" ${hasPrev ? '' : raw('disabled')} id="pg-prev">Prev</button>
      <span>Page ${currentPage} / ${totalPages}</span>
      <button class="btn btn-sm" ${hasNext ? '' : raw('disabled')} id="pg-next">Next</button>`;
    pag.querySelector('#pg-prev').onclick = () => { this.offset = Math.max(0, this.offset - this.limit); this.load(); };
    pag.querySelector('#pg-next').onclick = () => { this.offset += this.limit; this.load(); };
  }

  _rowHtml(l) {
    return html`
        <td>${timeAgo(l.timestamp)}</td>
        <td style="text-align:center"><span class="st ${l.blocked ? 'st-block' : 'st-ok'}" title="${l.blocked ? 'blocked' : 'allowed'}">${l.blocked ? '✖' : '✔'}</span></td>
        <td><div style="display:flex;align-items:center;gap:6px;max-width:300px"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;color:var(--text-primary)" title="${l.domain}">${l.domain}</span>${l.authenticated_data ? html`<span class="badge badge-dnssec" style="flex:0 0 auto">dnssec</span>` : ''}</div>${l.result ? html`<div class="mono" style="font-size:0.85rem;color:var(--text-dim);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${l.result}">→ ${l.result}</div>` : ''}</td>
        <td class="mono">${l.query_type}</td>
        <td class="mono">${l.client_ip}${l.doh_token ? html`<br><span style="color:var(--accent);font-size:0.85rem">${l.doh_token}</span>` : ''}</td>
        <td><button class="btn btn-sm log-action ${l.blocked ? 'btn-allow' : 'btn-danger'}" data-domain="${l.domain}" data-blocked="${l.blocked}">${l.blocked ? 'Allow' : 'Block'}</button></td>
        <td>${l.cached ? html`<span class="badge badge-cached">cached</span>` : l.upstream ? html`<span class="mono" style="font-size:0.9rem">${l.upstream}</span>` : html`<span class="text-dim">-</span>`}</td>
        <td class="mono">${l.response_ms}</td>`;
  }

  _cardHtml(l) {
    return html`<div class="log-card">
        <div class="log-card-row1">
          <span class="st ${l.blocked ? 'st-block' : 'st-ok'}" title="${l.blocked ? 'blocked' : 'allowed'}" style="flex:0 0 auto">${l.blocked ? '✖' : '✔'}</span>
          <span class="log-card-domain" title="${l.domain}">${l.domain}</span>
          ${l.authenticated_data ? html`<span class="badge badge-dnssec" style="flex:0 0 auto">dnssec</span>` : ''}
          <button class="btn btn-sm log-action ${l.blocked ? 'btn-allow' : 'btn-danger'}" data-domain="${l.domain}" data-blocked="${l.blocked}" style="flex-shrink:0">${l.blocked ? 'Allow' : 'Block'}</button>
        </div>
        ${l.result ? html`<div class="mono" style="font-size:0.85rem;color:var(--text-dim);margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${l.result}">→ ${l.result}</div>` : ''}
        <div class="log-card-row2">
          <span class="lc-time">${timeAgo(l.timestamp)}</span>
          <span class="lc-type">${l.query_type}</span>
          <span class="lc-client text-secondary">${l.client_ip}</span>
          ${l.cached ? html`<span class="lc-cached">cached</span>` : l.upstream ? html`<span class="lc-up">${l.upstream}</span>` : ''}
          ${l.doh_token ? html`<span class="lc-token">${l.doh_token}</span>` : ''}
          <span class="lc-ms">${l.response_ms}ms</span>
        </div>
      </div>`;
  }

  async loadTokens() {
    try {
      const tokens = await api.get('/api/doh-tokens');
      const sel = this.querySelector('#log-token');
      for (const t of tokens) {
        const opt = document.createElement('option');
        opt.value = t.token;
        opt.textContent = t.token;
        sel.appendChild(opt);
      }
    } catch (e) { console.error(e); }
  }
}
customElements.define('logs-page', LogsPage);

// --- Filters Page (merged Lists + Rules + Domain Test) ---
class FiltersPage extends HTMLElement {
  // The body arrives server-rendered: every control here is a real form that
  // works on its own. What follows takes those forms over — same ids, same
  // buttons — so with JavaScript the page updates in place instead of
  // navigating, which is the behaviour it has always had.
  //
  // Nothing is loaded on connect. The lists and rules in the markup came from
  // the same storage a fetch would ask, and re-fetching them would only replace
  // what is already correct.
  connectedCallback() {
    // The no-JS submits are removed rather than hidden: a button that is there
    // but does nothing is worse than one that was never shipped. The reverse
    // for `js-only`, which the server ships hidden.
    this.querySelectorAll('.nojs-only').forEach(el => el.remove());
    this.querySelectorAll('.js-only[hidden]').forEach(el => el.removeAttribute('hidden'));

    // --- Domain Test ---
    // A GET form the server can answer on its own; here the verdict is fetched
    // and written into the same element, without the navigation.
    this.querySelector('#domain-test-form').onsubmit = (e) => {
      e.preventDefault();
      this.testDomain();
    };

    // --- Filter Lists ---
    this.querySelector('#update-all').closest('form').onsubmit = async (e) => {
      e.preventDefault();
      const btn = this.querySelector('#update-all');
      btn.disabled = true;
      btn.innerHTML = icons.refresh + ' Updating...';
      try { await api.post('/api/lists/update'); } catch (err) { console.error(err); }
      btn.disabled = false;
      btn.innerHTML = icons.refresh + ' Update All';
      this.loadLists();
    };

    this.querySelector('#add-list-form').onsubmit = async (e) => {
      e.preventDefault();
      const name = this.querySelector('#list-name').value.trim();
      const url = this.querySelector('#list-url').value.trim();
      if (!name || !url) return;
      try {
        await api.post('/api/lists', { name, url });
      } catch (err) {
        showBanner('Could not add that list — check the name and URL', 'error');
        return;
      }
      this.querySelector('#list-name').value = '';
      this.querySelector('#list-url').value = '';
      this.loadLists();
    };

    this.querySelector('#browse-registry').onclick = () => {
      const modal = document.createElement('registry-modal');
      modal.addEventListener('batch-added', () => this.loadLists());
      document.body.appendChild(modal);
      modal.open();
    };

    this.querySelector('#enable-recommended').closest('form').onsubmit = (e) => {
      e.preventDefault();
      this.enableRecommended();
    };

    // --- Custom Rules ---
    this.querySelector('#add-rule-form').onsubmit = async (e) => {
      e.preventDefault();
      const v = this.querySelector('#add-rule-input').value.trim();
      if (!v) return;
      try {
        await api.post('/api/rules', { rule: v });
        this.querySelector('#add-rule-input').value = '';
        this.loadRules();
      } catch (err) {
        showBanner('Invalid rule syntax', 'error');
      }
    };

    this.bindLists();
    this.bindRules();
  }

  async testDomain() {
    const domain = this.querySelector('#test-domain').value.trim();
    if (!domain) return;
    const el = this.querySelector('#test-result');
    try {
      const res = await api.post('/api/filter/check', { domain });
      if (res.action === 'blocked') {
        el.innerHTML = html`<span class="badge badge-blocked">Blocked</span>
          <span style="color:var(--text-secondary);font-size:0.85rem;margin-left:8px">
            Rule: <code class="text-primary">${res.rule}</code>
            &middot; List: <code class="text-primary">${res.list}</code>
          </span>`;
      } else {
        let detail = res.rule
          ? html` <span style="color:var(--text-secondary);font-size:0.85rem;margin-left:8px">Rule: <code class="text-primary">${res.rule}</code></span>`
          : '';
        el.innerHTML = '<span class="badge badge-allowed">Allowed</span>' + detail;
      }
    } catch (e) {
      el.innerHTML = '<span class="text-red">Error checking domain</span>';
    }
  }

  // Re-draw both the table and the cards after a change. The markup mirrors
  // `templates/filters.html` — forms and all — so a redrawn row is the same row
  // the server would have sent, and the bindings below apply to either.
  async loadLists() {
    try {
      const lists = await api.get('/api/lists');

      const body = this.querySelector('#lists-body');
      body.innerHTML = lists.map(l => html`<tr data-testid="filter-list-row" data-name="${l.name}">
        <td>
          <form method="post" action="/filters/lists/${l.id}/toggle" class="list-toggle-form">
            <label class="toggle">
              <input type="checkbox" name="enabled" data-testid="filter-list-toggle" ${l.enabled ? raw('checked') : ''} data-id="${l.id}">
              <div class="toggle-track"></div>
              <div class="toggle-thumb"></div>
            </label>
          </form>
        </td>
        <td class="text-primary">${l.name}</td>
        <td>${formatFull(l.rule_count)}</td>
        <td>${l.last_updated ? timeAgo(l.last_updated) : 'never'}</td>
        <td style="white-space:nowrap">
          <a href="/filters?edit=${l.id}" class="btn btn-sm edit-list" data-id="${l.id}" data-name="${l.name}" data-url="${l.url}">Edit</a>
          <form method="post" action="/filters/lists/${l.id}/delete" class="inline-form">
            <button type="submit" class="btn btn-danger btn-sm del-list" data-id="${l.id}">${icons.trash}</button>
          </form>
        </td>
      </tr>`).join('');

      const cards = this.querySelector('#lists-cards');
      cards.innerHTML = lists.map(l => html`<div class="log-card">
        <div class="log-card-row1">
          <form method="post" action="/filters/lists/${l.id}/toggle" class="list-toggle-form">
            <label class="toggle">
              <input type="checkbox" name="enabled" ${l.enabled ? raw('checked') : ''} data-id="${l.id}">
              <div class="toggle-track"></div>
              <div class="toggle-thumb"></div>
            </label>
          </form>
          <span style="flex:1;color:var(--text-primary);font-size:0.85rem">${l.name}</span>
          <a href="/filters?edit=${l.id}" class="btn btn-sm edit-list" data-id="${l.id}" data-name="${l.name}" data-url="${l.url}" style="flex-shrink:0">Edit</a>
          <form method="post" action="/filters/lists/${l.id}/delete" class="inline-form" style="flex-shrink:0">
            <button type="submit" class="btn btn-danger btn-sm del-list" data-id="${l.id}">${icons.trash}</button>
          </form>
        </div>
        <div class="log-card-row2">
          <span>${formatNum(l.rule_count)} rules</span>
          <span>${l.last_updated ? timeAgo(l.last_updated) : 'never updated'}</span>
        </div>
      </div>`).join('');

      this.bindLists();
    } catch (e) { console.error(e); }
  }

  // Applied to whatever rows are in the document — the ones the server rendered
  // on first load, and the ones `loadLists` drew afterwards.
  bindLists() {
    this.querySelectorAll('#lists-body input[type=checkbox], #lists-cards input[type=checkbox]').forEach(cb => {
      cb.onchange = async () => {
        try {
          await api.put(`/api/lists/${cb.dataset.id}`, { enabled: cb.checked });
        } catch (e) {
          // Put the toggle back where it was: leaving it showing a state the
          // server never accepted is the one outcome worse than failing.
          cb.checked = !cb.checked;
          showBanner('Could not change that list', 'error');
        }
        this._refreshAllDisabledWarning();
      };
    });

    this.querySelectorAll('.del-list').forEach(btn => {
      btn.closest('form').onsubmit = async (e) => {
        e.preventDefault();
        if (!confirm('Delete this list?')) return;
        await api.del(`/api/lists/${btn.dataset.id}`);
        this.loadLists();
      };
    });

    // A link without JavaScript, which expands the row on the server. Here the
    // navigation is cancelled and the dialog opens over the page instead.
    this.querySelectorAll('.edit-list').forEach(link => {
      link.onclick = (e) => {
        e.preventDefault();
        this.showEditDialog(link.dataset.id, link.dataset.name, link.dataset.url);
      };
    });

    this._refreshAllDisabledWarning();
  }

  // Read off the checkboxes rather than a cached list: they are the state the
  // operator is looking at, and after a toggle they are correct before any
  // reload would be.
  _refreshAllDisabledWarning() {
    const warn = this.querySelector('[data-testid="filters-all-disabled-warning"]');
    if (!warn) return;
    const boxes = [...this.querySelectorAll('#lists-body input[type=checkbox]')];
    const allDisabled = boxes.length > 0 && boxes.every(b => !b.checked);
    warn.style.display = allDisabled ? '' : 'none';
  }

  async enableRecommended() {
    const rows = [...this.querySelectorAll('#lists-body [data-testid="filter-list-row"]')];
    const pick = rows.find(r => r.dataset.name === 'AdGuard DNS filter') || rows[0];
    const box = pick && pick.querySelector('input[type=checkbox]');
    if (!box) return;
    try {
      await api.put(`/api/lists/${box.dataset.id}`, { enabled: true });
      await this.loadLists();
    } catch (e) { console.error(e); }
  }

  showEditDialog(id, name, url) {
    // Remove existing dialog if any
    const existing = document.querySelector('.dialog-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.innerHTML = html`
      <div class="dialog">
        <div class="dialog-title">Edit Filter List</div>
        <label for="edit-name">Name</label>
        <input type="text" id="edit-name" value="${name}">
        <label for="edit-url">URL</label>
        <input type="url" id="edit-url" value="${url}">
        <div class="dialog-health" id="edit-health"></div>
        <div class="dialog-actions">
          <button class="btn btn-sm" id="edit-check">${icons.refresh} Check URL</button>
          <span style="flex:1"></span>
          <button class="btn btn-sm" id="edit-cancel">Cancel</button>
          <button class="btn btn-primary btn-sm" id="edit-save">Save</button>
        </div>
      </div>`;

    document.body.appendChild(overlay);

    overlay.querySelector('#edit-cancel').onclick = () => overlay.remove();
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

    overlay.querySelector('#edit-check').onclick = async () => {
      const checkUrl = overlay.querySelector('#edit-url').value.trim();
      const healthEl = overlay.querySelector('#edit-health');
      const btn = overlay.querySelector('#edit-check');
      btn.disabled = true;
      btn.innerHTML = icons.refresh + ' Checking...';
      try {
        const res = await api.post(`/api/lists/${id}/check`, { url: checkUrl || undefined });
        if (res.ok) {
          const size = res.content_length > 1024 ? (res.content_length / 1024).toFixed(0) + ' KB' : res.content_length + ' B';
          healthEl.innerHTML = html`<span class="badge badge-allowed">OK</span> <span class="text-secondary">HTTP ${res.status} &middot; ${size}</span>`;
        } else {
          healthEl.innerHTML = html`<span class="badge badge-blocked">FAIL</span> <span class="text-secondary">${res.error || 'HTTP ' + res.status}</span>`;
        }
      } catch (e) {
        healthEl.innerHTML = '<span class="badge badge-blocked">Error</span>';
      }
      btn.disabled = false;
      btn.innerHTML = icons.refresh + ' Check URL';
    };

    overlay.querySelector('#edit-save').onclick = async () => {
      const newName = overlay.querySelector('#edit-name').value.trim();
      const newUrl = overlay.querySelector('#edit-url').value.trim();
      if (!newName || !newUrl) return;
      await api.put(`/api/lists/${id}`, { name: newName, url: newUrl });
      overlay.remove();
      this.loadLists();
    };
  }

  async loadRules() {
    try {
      const rules = await api.get('/api/rules');
      const el = this.querySelector('#rules-list');
      if (!rules.length) { el.innerHTML = '<p style="color:var(--text-dim);font-size:0.85rem">No rules</p>'; return; }
      let markup = '<table><tbody>';
      for (const r of rules) {
        const badge = r.rule_type === 'allow'
          ? raw('<span class="badge badge-allowed">allow</span>')
          : raw('<span class="badge badge-blocked">block</span>');
        markup += html`<tr data-testid="rule-row" data-rule="${r.rule}" data-type="${r.rule_type}">
          <td style="width:70px">${badge}</td>
          <td class="mono" style="color:var(--text-primary);font-size:0.85rem">${r.rule}</td>
          <td style="width:40px">
            <form method="post" action="/filters/rules/${r.id}/delete" class="inline-form">
              <button type="submit" class="btn btn-danger btn-sm del-rule" data-testid="rule-delete" data-id="${r.id}">${icons.trash}</button>
            </form>
          </td>
        </tr>`;
      }
      markup += '</tbody></table>';
      el.innerHTML = markup;
      this.bindRules();
    } catch (e) { console.error(e); }
  }

  bindRules() {
    this.querySelectorAll('.del-rule').forEach(btn => {
      btn.closest('form').onsubmit = async (e) => {
        e.preventDefault();
        await api.del(`/api/rules/${btn.dataset.id}`);
        this.loadRules();
      };
    });
  }
}
customElements.define('filters-page', FiltersPage);

// --- Settings Page ---
class SettingsPage extends HTMLElement {
  connectedCallback() {
    // The server ships a submit button so the page works without JavaScript.
    // With it, each field saves as it is changed — the button would be a second
    // way to do the same thing, and one that discards the per-field messages
    // the autosave path shows.
    const saveRow = this.querySelector('#settings-save-row');
    if (saveRow) saveRow.remove();

    this.load();

    this.renderUpstreams = async () => {
      const el = this.querySelector('#upstream-health');
      try {
        const rows = await api.get('/api/upstream/health');
        const transport = s => s.startsWith('tls://') ? ['dot','var(--accent)'] : s.startsWith('https://') ? ['doh','var(--accent)'] : ['plain','var(--orange)'];
        el.innerHTML = html`<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px"><span class="card-title" style="margin-bottom:0">Active upstreams</span><button class="btn btn-sm" id="refresh-upstream">${icons.refresh} Recheck</button></div>
          <div class="table-wrap"><table><thead><tr><th>Server</th><th>Transport</th><th>Health</th><th>Latency</th></tr></thead><tbody>` +
          rows.map(r => { const [t,c] = transport(r.server); return html`<tr>
            <td class="mono">${r.server}</td>
            <td><span class="badge" style="color:${c}">${t}</span></td>
            <td><span class="st ${r.ok ? 'st-ok' : 'st-block'}">${r.ok ? '✔' : '✖'}</span></td>
            <td class="mono">${r.ok ? r.latency_ms + 'ms' : '—'}</td></tr>`; }).join('') +
          `</tbody></table></div>`;
        const rb = el.querySelector('#refresh-upstream');
        if (rb) rb.onclick = () => this.renderUpstreams();
      } catch (e) { el.innerHTML = '<p class="text-red">Failed to load upstreams</p>'; }
    };

    this.querySelector('#apply-upstream').onclick = async (event) => {
      // It is a submit button so the page works without JavaScript. Here there
      // is JavaScript, so take over: PUT just this field and refresh the health
      // table, rather than submitting the whole form and navigating away.
      event.preventDefault();
      const msg = this.querySelector('#upstream-apply-msg');
      try {
        const res = await fetch('/api/settings', { method:'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify({ upstream_servers: this.querySelector('#s-upstream').value }) });
        if (!res.ok) { msg.style.color = 'var(--red)'; msg.textContent = res.status === 400 ? 'Invalid upstream entry — not applied' : 'Failed to apply'; return; }
        msg.style.color = 'var(--accent)'; msg.textContent = '✔ applied';
        await this.renderUpstreams();
        setTimeout(() => { msg.textContent = ''; }, 2500);
      } catch (e) { msg.style.color = 'var(--red)'; msg.textContent = 'Failed to apply'; }
    };

    // --- Unified auto-save: every control saves on change/blur and reports its
    // own result inline, right next to that field. Invalid values never PUT.
    const setMsg = (id, ok, msg) => {
      const el = this.querySelector(id);
      if (!el) return;
      el.style.color = ok ? 'var(--accent)' : 'var(--red)';
      el.textContent = msg ? (ok ? '✔ ' : '✗ ') + msg : '';
      if (el._t) clearTimeout(el._t);
      if (ok && msg) el._t = setTimeout(() => { el.textContent = ''; }, 2000);
    };
    const putField = async (id, payload, okMsg) => {
      try {
        await api.put('/api/settings', payload);
        setMsg(id, true, okMsg);
      } catch (e) {
        setMsg(id, false, 'Save failed');
      }
    };
    const isIpv4 = (s) =>
      /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s);
    const isIpv6 = (s) => { try { new URL('http://[' + s + ']/'); return true; } catch (e) { return false; } };

    this.querySelector('#s-doh-policy').onchange = (e) =>
      putField('#msg-doh-policy', { doh_access_policy: e.target.value }, 'Saved');

    this.querySelector('#s-strategy').onchange = (e) => {
      putField('#msg-strategy', { upstream_strategy: e.target.value }, 'Saved');
      this.loadEma();
    };

    this.querySelector('#s-dnssec').onchange = (e) =>
      putField('#msg-dnssec', { dnssec_disabled: e.target.value === 'off' ? 'true' : 'false' }, 'Saved');

    this.querySelector('#s-retention').onchange = (e) => {
      const v = e.target.value.trim();
      // Blank clears the setting → the server falls back to its default retention.
      if (v !== '' && (!/^\d+$/.test(v) || parseInt(v, 10) < 1)) { setMsg('#msg-retention', false, 'Must be a positive integer'); return; }
      putField('#msg-retention', { log_retention_days: v }, v === '' ? 'Using default' : 'Saved');
    };

    this.querySelector('#s-public-url').onchange = (e) => {
      const v = e.target.value.trim();
      if (v !== '') {
        let ok = /^https:\/\//i.test(v);
        if (ok) { try { new URL(v); } catch (err) { ok = false; } }
        if (!ok) { setMsg('#msg-public-url', false, 'Must be a valid https:// URL'); return; }
      }
      putField('#msg-public-url', { public_url: v }, 'Saved');
    };

    const syncBlockCustom = () => {
      this.querySelector('#s-block-custom').style.display =
        this.querySelector('#s-block-mode').value === 'custom_ip' ? 'block' : 'none';
    };
    // Validate the custom IPs (errors shown next to the offending field) and
    // save; report success at `msgId` (the control the user just touched).
    // Non-custom modes ignore the IP fields: send mode only so a stale/partial
    // value in a hidden field can never trigger a backend 400.
    const saveBlock = (msgId) => {
      const mode = this.querySelector('#s-block-mode').value;
      if (mode !== 'custom_ip') { putField(msgId, { block_mode: mode }, 'Saved'); return; }
      const v4 = this.querySelector('#s-block-ipv4').value.trim();
      const v6 = this.querySelector('#s-block-ipv6').value.trim();
      if (v4 !== '' && !isIpv4(v4)) { setMsg('#msg-block-ipv4', false, 'Invalid IPv4'); return; }
      if (v6 !== '' && !isIpv6(v6)) { setMsg('#msg-block-ipv6', false, 'Invalid IPv6'); return; }
      setMsg('#msg-block-ipv4', true, ''); setMsg('#msg-block-ipv6', true, '');
      putField(msgId, { block_mode: mode, block_custom_ipv4: v4, block_custom_ipv6: v6 }, 'Saved');
    };
    this.querySelector('#s-block-mode').onchange = () => { syncBlockCustom(); saveBlock('#msg-block-mode'); };
    this.querySelector('#s-block-ipv4').onchange = () => saveBlock('#msg-block-ipv4');
    this.querySelector('#s-block-ipv6').onchange = () => saveBlock('#msg-block-ipv6');

    this.querySelector('#add-token').onclick = async () => {
      const token = this.querySelector('#token-value').value.trim();
      if (!token) return;
      if (token.includes('/')) { showBanner('Token cannot contain /', 'error'); return; }
      await api.post('/api/doh-tokens', { token });
      this.querySelector('#token-value').value = '';
      this.loadTokens();
    };
    this.querySelector('#token-value').onkeydown = (e) => { if (e.key === 'Enter') this.querySelector('#add-token').click(); };
  }

  async load() {
    try {
      // Only what the form does not already hold. Every field on this page was
      // rendered with its current value by the server, so re-fetching settings
      // to fill them in would be asking a question already answered — and worse
      // than redundant: this used to overwrite whatever the operator had typed
      // in the window between the markup appearing and the response landing,
      // silently reverting the change they had just made.
      const info = await api.get('/api/server-info');
      this.renderUpstreams();
      this.loadEma();
      if (info) {
        const tls = info.tls_enabled
          ? raw('<span class="badge badge-allowed">TLS</span>')
          : raw('<span class="badge badge-off">Plain</span>');
        this.querySelector('#server-info').innerHTML = html`
          <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 16px">
            <span class="text-dim">DNS</span><span class="mono">${info.dns_addr}</span>
            <span class="text-dim">HTTP</span><span><span class="mono">${info.http_addr}</span> ${tls}</span>
          </div>`;
      }
    } catch (e) { console.error(e); }
    this.loadTokens();
  }

  async loadTokens() {
    try {
      const tokens = await api.get('/api/doh-tokens');
      const el = this.querySelector('#doh-tokens-list');
      if (!tokens || !tokens.length) {
        el.innerHTML = '<p style="color:var(--text-dim);font-size:0.85rem">No tokens configured</p>';
        return;
      }
      let markup = '<div class="table-wrap"><table><thead><tr><th>Token</th><th>DoH URL</th><th></th></tr></thead><tbody>';
      for (const t of tokens) {
        markup += html`<tr>
          <td class="mono text-primary">${t.token}</td>
          <td><code class="mono" style="color:var(--text-dim);font-size:0.75rem">/dns-query/${t.token}</code></td>
          <td style="white-space:nowrap"><a class="btn btn-sm" href="/api/mobileconfig/${t.token}" download style="text-decoration:none;margin-right:4px">Apple Profile</a><button class="btn btn-danger btn-sm del-token" data-id="${t.id}">${icons.trash} Delete</button></td>
        </tr>`;
      }
      markup += '</tbody></table></div>';
      el.innerHTML = markup;
      el.querySelectorAll('.del-token').forEach(btn => {
        btn.onclick = async () => {
          if (confirm('Delete this token? Clients using it will lose DoH access.')) {
            await api.del(`/api/doh-tokens/${btn.dataset.id}`);
            this.loadTokens();
          }
        };
      });
    } catch (e) { console.error(e); }
  }

  async loadEma() {
    const el = this.querySelector('#ema-latency');
    const strategy = this.querySelector('#s-strategy').value;
    if (strategy !== 'lowest-latency') {
      el.innerHTML = '';
      return;
    }
    try {
      const data = await api.get('/api/upstream/latency');
      if (!data || !data.length) {
        el.innerHTML = '<p style="color:var(--text-dim);font-size:0.85rem">No latency data yet. Data will appear after queries are processed.</p>';
        return;
      }
      let markup = '<div class="table-wrap"><table><thead><tr><th>Server</th><th>EMA Latency</th><th></th></tr></thead><tbody>';
      for (const d of data) {
        const badge = d.preferred ? raw(' <span class="badge badge-allowed">preferred</span>') : '';
        markup += html`<tr><td class="mono">${d.server}</td><td class="mono">${d.ema_ms.toFixed(1)}ms</td><td>${badge}</td></tr>`;
      }
      markup += '</tbody></table></div>';
      el.innerHTML = markup;
    } catch (e) {
      el.innerHTML = '';
    }
  }
}
customElements.define('settings-page', SettingsPage);

// ============================================================
// App Bootstrap
// ============================================================
// Reaching this file at all means the server already resolved the session and
// decided this is a page for a signed-in operator — an unauthenticated request
// was redirected before any HTML was written. Two round trips (`/api/health`,
// then `/api/settings`) and the repaint they forced are gone with that; what is
// left for the client is picking the page component out of the path.
const PAGES = {
  '/': 'dashboard-page',
  '/stats': 'stats-page',
  '/logs': 'logs-page',
  '/filters': 'filters-page',
  '/settings': 'settings-page',
  '/account': 'account-page',
};

// The shell is in the document already — the server rendered it, topbar and
// navigation and status bar and all — so there is no shell component here to
// wrap it in. Nothing below re-derives what the template settled: the active
// navigation item is a class it set from the path it was answering, and working
// that out again from `location.pathname` would be a second source for one
// fact.
//
// An unrecognised path mounts the dashboard rather than nothing. Only the six
// paths above route to this shell, so arriving with anything else means a stale
// link that somehow reached it.
// Only when the server left it empty. A page whose body is server-rendered
// ships its own component element in the markup, which upgrades in place — the
// enhancement attaches to the rendered form instead of replacing it. Mounting a
// second one here would leave two.
const pageContent = document.getElementById('page-content');
if (!pageContent.firstElementChild) {
  pageContent.appendChild(
    document.createElement(PAGES[location.pathname] || 'dashboard-page'));
}

// Dismiss is attached only where there is JavaScript to make it work, rather
// than shipped in the markup as a button that does nothing without it. The
// strip is one-shot either way: the flash cookie behind it was cleared by the
// very response that rendered it, so a navigation is enough to be rid of it.
const welcome = document.querySelector('[data-testid="setup-welcome"]');
if (welcome) {
  const dismiss = document.createElement('button');
  dismiss.className = 'btn';
  dismiss.dataset.testid = 'setup-welcome-dismiss';
  dismiss.style.marginLeft = 'auto';
  dismiss.setAttribute('aria-label', 'Dismiss');
  dismiss.textContent = 'Dismiss';
  dismiss.onclick = () => welcome.remove();
  welcome.appendChild(dismiss);
}

// A 401 from any later API call means the session ended underneath us — it
// expired, or another device revoked it. Navigate rather than swap in a login
// component: the sign-in form is a server-rendered page now, and `next` is what
// brings the operator back to the page they were on.
window.addEventListener('auth-required', () => {
  const here = location.pathname + location.search;
  window.location.assign(here === '/' ? '/login' : `/login?next=${encodeURIComponent(here)}`);
});
