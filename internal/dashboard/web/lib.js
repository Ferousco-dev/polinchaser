// Tiny DOM + API helpers. Everything is built with createElement/textContent:
// no innerHTML anywhere, so data from the server can never become markup.
const SVG_NS = "http://www.w3.org/2000/svg";

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, kids);
  return el;
}

export function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

export function svg(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
  append(el, kids);
  return el;
}

const ICONS = {
  dashboard: [["rect", { x: 3, y: 3, width: 7, height: 9, rx: 1.5 }], ["rect", { x: 14, y: 3, width: 7, height: 5, rx: 1.5 }], ["rect", { x: 14, y: 12, width: 7, height: 9, rx: 1.5 }], ["rect", { x: 3, y: 16, width: 7, height: 5, rx: 1.5 }]],
  repos: [["path", { d: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" }]],
  scans: [["path", { d: "M3 12h4l3-8 4 16 3-8h4" }]],
  findings: [["path", { d: "M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z" }], ["path", { d: "M12 8v5" }], ["path", { d: "M12 16h.01" }]],
  chart: [["path", { d: "M3 3v18h18" }], ["path", { d: "M7 15l4-4 3 3 5-6" }]],
  layers: [["path", { d: "M12 3l9 5-9 5-9-5z" }], ["path", { d: "M3 13l9 5 9-5" }]],
  server: [["rect", { x: 3, y: 4, width: 18, height: 7, rx: 2 }], ["rect", { x: 3, y: 13, width: 18, height: 7, rx: 2 }], ["path", { d: "M7 7.5h.01M7 16.5h.01" }]],
  list: [["path", { d: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" }]],
  settings: [["path", { d: "M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1" }], ["circle", { cx: 15, cy: 6, r: 2 }], ["circle", { cx: 9, cy: 12, r: 2 }], ["circle", { cx: 17, cy: 18, r: 2 }]],
  logout: [["path", { d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" }], ["path", { d: "M16 17l5-5-5-5" }], ["path", { d: "M21 12H9" }]],
  panelClose: [["rect", { x: 3, y: 3, width: 18, height: 18, rx: 3 }], ["path", { d: "M9 3v18" }], ["path", { d: "M16 15l-3-3 3-3" }]],
  panelOpen: [["rect", { x: 3, y: 3, width: 18, height: 18, rx: 3 }], ["path", { d: "M9 3v18" }], ["path", { d: "M14 9l3 3-3 3" }]],
  menu: [["path", { d: "M4 6h16M4 12h16M4 18h16" }]],
  fingerprint: [["path", { d: "M6 10a6 6 0 0 1 12 0" }], ["path", { d: "M9 21c0-3 .5-4.5.5-7a2.5 2.5 0 0 1 5 0c0 3-.5 5-1.5 8" }], ["path", { d: "M5 14c0-2 .3-3 .3-4" }], ["path", { d: "M19 10c0 5-.5 8-2 10" }], ["path", { d: "M12 14c0 3-.5 5.5-1.5 7.5" }]],
  shield: [["path", { d: "M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z" }], ["path", { d: "M9 12l2 2 4-4" }]],
  copy: [["rect", { x: 9, y: 9, width: 12, height: 12, rx: 2 }], ["path", { d: "M5 15V5a2 2 0 0 1 2-2h10" }]],
  plus: [["path", { d: "M12 5v14M5 12h14" }]],
  search: [["circle", { cx: 11, cy: 11, r: 6.5 }], ["path", { d: "M16 16l4.5 4.5" }]],
  chevron: [["path", { d: "M6 9l6 6 6-6" }]],
  check: [["path", { d: "M5 12.5l4.5 4.5L19 7.5" }]],
  trash: [["path", { d: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" }]],
};

export function icon(name, size) {
  const s = svg("svg", { class: "i", viewBox: "0 0 24 24", "aria-hidden": "true" });
  if (size) { s.setAttribute("width", size); s.setAttribute("height", size); }
  for (const [t, a] of ICONS[name] || []) s.append(svg(t, a));
  return s;
}

export class AuthError extends Error {}

// Short-lived in-memory GET cache: back/forward and repeat visits feel instant, hovering a
// nav link warms the next page, and duplicate in-flight requests share one round trip.
// Any write clears it, and nothing is persisted to disk (responses stay private).
const CACHE_TTL = 20000;
const cache = new Map();
const inflight = new Map();
export function clearApiCache() { cache.clear(); inflight.clear(); }
export function prefetch(path) { if (path && path.startsWith("/api/")) api(path).catch(() => {}); }
const clone = (v) => (v == null ? v : typeof structuredClone === "function" ? structuredClone(v) : JSON.parse(JSON.stringify(v)));

export async function api(path, { method = "GET", body, raw } = {}) {
  const cacheable = method === "GET" && !path.startsWith("/api/auth/");
  if (method !== "GET") clearApiCache();
  if (cacheable) {
    const hit = cache.get(path);
    if (hit && Date.now() - hit.t < CACHE_TTL) return clone(hit.data);
    if (inflight.has(path)) return clone(await inflight.get(path));
  }
  const run = request(path, { method, body, raw });
  if (!cacheable) return run;
  inflight.set(path, run);
  try {
    const data = await run;
    cache.set(path, { t: Date.now(), data });
    return clone(data);
  } catch (e) {
    if (e instanceof AuthError) clearApiCache();
    throw e;
  } finally { inflight.delete(path); }
}

async function request(path, { method, body, raw }) {
  const res = await fetch(path, {
    method, credentials: "same-origin", cache: "no-store",
    headers: body !== undefined && !raw ? { "Content-Type": "application/json" } : undefined,
    body: raw ? raw : body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && !path.startsWith("/api/auth/login") && !path.startsWith("/api/auth/status")) throw new AuthError("unauthenticated");
  if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
  return data;
}

export function toast(msg) {
  const t = h("div", { class: "toast", role: "status" }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 3500);
}

export const fmt = {
  num: (n) => (n == null ? "–" : Number(n).toLocaleString()),
  sha: (s) => (s ? s.slice(0, 7) : ""),
  date: (s) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "–"),
  rel(s) {
    if (!s) return "never";
    const d = (Date.now() - new Date(s).getTime()) / 1000;
    if (d < 60) return "just now";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  },
  label: (s) => String(s || "").replaceAll("_", " "),
};

export const chip = (value, text) => h("span", { class: "chip " + String(value).replace(/[^a-z_]/g, "") }, text ?? fmt.label(value));

// --- WebAuthn (base64url <-> ArrayBuffer) ---
const b64u = {
  dec(s) { s = s.replaceAll("-", "+").replaceAll("_", "/"); s += "=".repeat((4 - (s.length % 4)) % 4); return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer; },
  enc(buf) { let s = ""; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""); },
};

export async function createPasskey(options) {
  const pk = options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.user.id = b64u.dec(pk.user.id);
  for (const c of pk.excludeCredentials || []) c.id = b64u.dec(c.id);
  const cred = await navigator.credentials.create({ publicKey: pk });
  if (!cred) throw new Error("Passkey creation was cancelled");
  return JSON.stringify({
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64u.enc(cred.response.clientDataJSON), attestationObject: b64u.enc(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [] },
  });
}

export async function getPasskey(options) {
  const pk = options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  for (const c of pk.allowCredentials || []) c.id = b64u.dec(c.id);
  const cred = await navigator.credentials.get({ publicKey: pk });
  if (!cred) throw new Error("Sign-in was cancelled");
  const r = cred.response;
  return JSON.stringify({
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64u.enc(r.clientDataJSON), authenticatorData: b64u.enc(r.authenticatorData), signature: b64u.enc(r.signature),
      userHandle: r.userHandle ? b64u.enc(r.userHandle) : null },
  });
}

/**
 * Custom dropdown (replaces native <select>). options: [{value,label}].
 * Exposes .value. Keyboard: Enter/Space/Arrows to open and move, Esc to close.
 */
export function dropdown({ options, value, label, onchange }) {
  let cur = options.some((o) => o.value === value) ? value : options[0].value;
  let list = null, hi = 0;
  const text = h("span", {});
  const btn = h("button", { type: "button", class: "dd-btn", "aria-haspopup": "listbox", "aria-expanded": "false", "aria-label": label }, text, icon("chevron"));
  const root = h("div", { class: "dd" }, btn);
  const show = () => { text.textContent = options.find((o) => o.value === cur).label; };
  const close = () => {
    if (!list) return;
    list.remove(); list = null; root.classList.remove("open"); btn.setAttribute("aria-expanded", "false");
    document.removeEventListener("mousedown", away, true); document.removeEventListener("scroll", close, true); removeEventListener("resize", close);
  };
  const away = (e) => { if (!root.contains(e.target) && !(list && list.contains(e.target))) close(); };
  const pick = (v) => { const changed = v !== cur; cur = v; show(); close(); btn.focus(); if (changed && onchange) onchange(v); };
  const paint = () => [...list.children].forEach((li, i) => { li.classList.toggle("hi", i === hi); if (i === hi) li.scrollIntoView({ block: "nearest" }); });
  const open = () => {
    if (list) return;
    hi = Math.max(0, options.findIndex((o) => o.value === cur));
    list = h("ul", { class: "dd-list", role: "listbox", "aria-label": label },
      options.map((o, i) => h("li", { class: "dd-opt", role: "option", "aria-selected": String(o.value === cur),
        onmousedown: (e) => { e.preventDefault(); pick(o.value); }, onmousemove: () => { hi = i; paint(); } },
        h("span", {}, o.label), o.value === cur ? icon("check") : null)));
    document.body.append(list);
    const r = btn.getBoundingClientRect();
    list.style.left = r.left + "px"; list.style.top = r.bottom + 4 + "px"; list.style.minWidth = r.width + "px";
    root.classList.add("open"); btn.setAttribute("aria-expanded", "true"); paint();
    document.addEventListener("mousedown", away, true); document.addEventListener("scroll", close, true); addEventListener("resize", close);
  };
  btn.addEventListener("click", () => (list ? close() : open()));
  btn.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { close(); return; }
    if (e.key === "Tab") { close(); return; }
    if (!["ArrowDown", "ArrowUp", "Enter", " ", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    if (!list) { open(); return; }
    if (e.key === "ArrowDown") hi = Math.min(options.length - 1, hi + 1);
    else if (e.key === "ArrowUp") hi = Math.max(0, hi - 1);
    else if (e.key === "Home") hi = 0;
    else if (e.key === "End") hi = options.length - 1;
    else { pick(options[hi].value); return; }
    paint();
  });
  Object.defineProperty(root, "value", { get: () => cur, set: (v) => { if (options.some((o) => o.value === v)) { cur = v; show(); } } });
  show();
  return root;
}
