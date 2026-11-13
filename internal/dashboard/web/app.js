import { h, icon, api, AuthError, toast, fmt, chip, createPasskey, getPasskey, dropdown } from "./lib.js";
import { stackedBars, lineChart, hbars } from "./charts.js";

const app = document.getElementById("app");
const keep = (k) => k.filter((x) => x != null && x !== false);
const add = (el, ...k) => el.append(...keep(k));
const rep = (el, ...k) => el.replaceChildren(...keep(k));
const SB_KEY = "pc_sidebar_collapsed";
const sbGet = () => { try { return localStorage.getItem(SB_KEY) === "1"; } catch { return false; } };
const sbSet = (v) => { try { localStorage.setItem(SB_KEY, v ? "1" : "0"); } catch { /* storage unavailable */ } };

// ---------- routing ----------
const NAV = [
  { to: "/", label: "Overview", icon: "dashboard" },
  { to: "/repositories", label: "Repositories", icon: "repos" },
  { to: "/scans", label: "Scans", icon: "scans" },
  { to: "/findings", label: "Findings", icon: "findings" },
  { sec: "Operations" },
  { to: "/observability", label: "Observability", icon: "chart" },
  { to: "/intelligence", label: "Detection rules", icon: "layers" },
  { to: "/system", label: "System health", icon: "server" },
  { to: "/audit", label: "Audit log", icon: "list" },
];

function go(path) { history.pushState(null, "", path); route(); }
function link(to, ...kids) { return h("a", { href: to, onclick: (e) => { if (e.metaKey || e.ctrlKey) return; e.preventDefault(); go(to); } }, ...kids); }

window.addEventListener("popstate", route);

let me = null;

async function route() {
  document.body.classList.remove("drawer-open");
  const path = location.pathname;
  if (path === "/enroll") return enrollScreen();
  try { me = await api("/api/auth/me"); } catch (e) {
    if (e instanceof AuthError) { me = null; return loginScreen(); }
    return fatal(e);
  }
  shell(path);
}

function fatal(e) { rep(app, h("div", { class: "gate" }, h("div", { class: "card gate-card" }, h("p", { class: "err" }, e.message)))); }

// ---------- auth screens ----------
function gate(...kids) {
  return h("div", { class: "gate" }, h("div", { class: "card gate-card" },
    h("div", { class: "gate-brand" }, h("span", { class: "mark" }, icon("shield", 18)), "Chaser"), ...kids));
}

async function loginFlow(errEl) {
  errEl.textContent = "";
  try {
    const b = await api("/api/auth/login/begin", { method: "POST" });
    const body = await getPasskey(b.options);
    await api("/api/auth/login/finish?cid=" + encodeURIComponent(b.challenge_id), { method: "POST", raw: body });
    go("/");
  } catch (e) { errEl.textContent = e.name === "NotAllowedError" ? "Sign-in was cancelled or timed out." : "Sign-in failed. " + (e.message || ""); }
}

async function loginScreen() {
  const err = h("p", { class: "err" });
  const st = await api("/api/auth/status").catch(() => ({}));
  const btn = h("button", { class: "btn primary block", onclick: async () => { btn.disabled = true; await loginFlow(err); btn.disabled = false; } }, icon("fingerprint"), "Sign in with passkey");
  const kids = [h("p", { class: "gate-sub" }, "Private dashboard. Passkey sign-in only."), btn, err];
  if (st.setup_available) {
    const form = h("div", { class: "stack", hidden: true });
    const token = h("input", { class: "field", type: "password", autocomplete: "off", placeholder: "Setup token", "aria-label": "Setup token" });
    const name = h("input", { class: "field", value: "This device", maxlength: 60, "aria-label": "Device name" });
    const e2 = h("p", { class: "err" });
    add(form, h("p", { class: "hint" }, "Paste the setup token from your server settings to register your first passkey."), token, name,
      h("button", { class: "btn primary block", onclick: async () => {
        e2.textContent = "";
        try {
          const b = await api("/api/auth/setup/begin", { method: "POST", body: { token: token.value } });
          const body = await createPasskey(b.options);
          await api(`/api/auth/setup/finish?name=${encodeURIComponent(name.value)}&cid=${encodeURIComponent(b.challenge_id)}`, { method: "POST", raw: body });
          await loginFlow(e2);
        } catch (e) { e2.textContent = e.message || "Setup failed"; }
      } }, "Register passkey"), e2);
    kids.push(h("button", { class: "linkish", onclick: () => { form.hidden = !form.hidden; } }, "First-time setup"), form);
  }
  rep(app, gate(...kids));
}

function enrollScreen() {
  const token = decodeURIComponent(location.hash.slice(1));
  history.replaceState(null, "", "/enroll"); // keep the one-time token out of history
  const err = h("p", { class: "err" });
  const name = h("input", { class: "field", value: "My phone", maxlength: 60, "aria-label": "Device name" });
  const go2 = h("button", { class: "btn primary block", onclick: async () => {
    err.textContent = "";
    try {
      const b = await api("/api/auth/enroll/begin", { method: "POST", body: { token } });
      const body = await createPasskey(b.options);
      await api(`/api/auth/enroll/finish?name=${encodeURIComponent(name.value)}&cid=${encodeURIComponent(b.challenge_id)}`, { method: "POST", raw: body });
      go2.disabled = true;
      await loginFlow(err);
    } catch (e) { err.textContent = e.message || "Could not register this device"; }
  } }, icon("fingerprint"), "Register passkey on this device");
  rep(app, gate(h("p", { class: "gate-sub" }, token ? "Add this device" : "This link is missing its token"),
    token ? h("div", { class: "stack" }, h("div", {}, h("label", { class: "lbl" }, "Device name"), name), go2, err) : err));
}

// ---------- shell ----------
function sideSearch(collapsed) {
  if (collapsed) return h("button", { class: "row side-search-icon", "aria-label": "Search findings", title: "Search", onclick: () => {
    document.body.classList.remove("collapsed"); sbSet(false); shell(location.pathname); setTimeout(() => document.getElementById("side-q")?.focus(), 0); } }, icon("search"));
  const input = h("input", { id: "side-q", type: "search", placeholder: "Search findings", "aria-label": "Search findings", autocomplete: "off", maxlength: 120,
    onkeydown: (e) => { if (e.key === "Enter" && input.value.trim()) { go("/findings?" + new URLSearchParams({ q: input.value.trim(), status: "" })); input.blur(); } if (e.key === "Escape") input.blur(); } });
  return h("div", { class: "side-search", role: "search" }, icon("search"), input, h("kbd", { "aria-hidden": "true" }, "/"));
}
addEventListener("keydown", (e) => {
  const t = e.target;
  if (e.key === "/" && !e.metaKey && !e.ctrlKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) && !t.isContentEditable) { const q = document.getElementById("side-q"); if (q) { e.preventDefault(); q.focus(); } }
});

function sidebar(path) {
  const collapsed = document.body.classList.contains("collapsed");
  const active = (to) => (to === "/" ? path === "/" : path === to || path.startsWith(to + "/"));
  const row = (n) => h("li", {}, h("a", { class: "row" + (active(n.to) ? " active" : ""), href: n.to, title: n.label,
    onclick: (e) => { if (e.metaKey || e.ctrlKey) return; e.preventDefault(); go(n.to); } }, icon(n.icon), h("span", {}, n.label)));
  return h("aside", { class: "side", "aria-label": "Sidebar" }, h("div", { class: "side-card" },
    h("div", { class: "side-head" },
      h("a", { class: "brand", href: "/", "aria-label": "Chaser overview", onclick: (e) => { e.preventDefault(); go("/"); } }, h("span", { class: "mark" }, icon("shield")), "Chaser"),
      h("button", { class: "icon-btn", "aria-label": collapsed ? "Expand sidebar" : "Collapse sidebar", onclick: () => {
        const c = document.body.classList.toggle("collapsed"); sbSet(c); shell(location.pathname); } }, icon(collapsed ? "panelOpen" : "panelClose"))),
    sideSearch(collapsed),
    h("nav", { class: "nav", "aria-label": "Primary" }, h("ul", {}, NAV.map((n) => n.sec ? h("li", { class: "nav-sec" }, n.sec) : row(n))))),
    h("div", { class: "side-foot" },
      h("a", { class: "row", href: "/settings", title: "Settings", onclick: (e) => { e.preventDefault(); go("/settings"); } }, icon("settings"), h("span", {}, "Settings")),
      h("button", { class: "icon-btn signout", "aria-label": "Sign out", title: "Sign out", onclick: async () => { await api("/api/auth/logout", { method: "POST" }).catch(() => {}); go("/"); } }, icon("logout"))));
}

function shell(path) {
  document.body.classList.toggle("collapsed", sbGet());
  const content = h("div", { class: "content" });
  rep(app, 
    sidebar(path), h("div", { class: "scrim", onclick: () => document.body.classList.remove("drawer-open") }),
    h("div", { class: "main" },
      h("header", { class: "topbar" }, h("button", { class: "icon-btn", "aria-label": "Open menu", onclick: () => document.body.classList.add("drawer-open") }, icon("menu")), h("strong", {}, "Chaser")),
      h("main", {}, content)));
  const m = path.match(/^\/(scans|findings)\/(\d+)$/);
  const pages = { "/": pOverview, "/repositories": pRepos, "/scans": pScans, "/findings": pFindings, "/observability": pObs, "/intelligence": pIntel, "/system": pSystem, "/audit": pAudit, "/settings": pSettings };
  const fn = m ? (m[1] === "scans" ? () => pScan(content, m[2]) : () => pFinding(content, m[2])) : pages[path] ? () => pages[path](content) : () => add(content, h("div", { class: "empty" }, "Page not found."));
  Promise.resolve(fn(content)).catch((e) => { if (e instanceof AuthError) return loginScreen(); add(content, h("p", { class: "err" }, e.message)); });
}

// ---------- helpers ----------
const head = (title, sub, ...actions) => h("div", { class: "page-h" }, h("div", {}, h("h1", {}, title), sub && h("p", {}, sub)), h("div", {}, actions));
const card = (title, body, right) => h("section", { class: "card" }, title && h("div", { class: "card-h" }, h("h2", {}, title), right), body);
const stat = (k, v, s) => h("div", { class: "card stat" }, h("div", { class: "k" }, k), h("div", { class: "v" }, fmt.num(v)), s && h("div", { class: "s" }, s));
const empty = (t) => h("div", { class: "empty" }, t);
const table = (cols, rows, onRow) => h("div", { class: "tbl-wrap" }, rows.length ? h("table", {}, h("thead", {}, h("tr", {}, cols.map((c) => h("th", {}, c)))),
  h("tbody", {}, rows.map((r) => { const tr = h("tr", { class: onRow ? "link" : "", tabindex: onRow ? 0 : null, onclick: onRow ? () => onRow(r) : null, onkeydown: onRow ? (e) => { if (e.key === "Enter") onRow(r); } : null }, r.cells.map((c) => h("td", {}, c))); return tr; })))
  : empty("Nothing here yet."));
const sevColor = { critical: "--crit", high: "--high", medium: "--med", low: "--low", info: "--low" };

// ---------- pages ----------
async function pOverview(el) {
  const d = await api("/api/overview"), s = d.stats;
  add(el, head("Overview", "What is happening across your connected GitHub accounts."),
    h("div", { class: "grid g4" },
      stat("Installations", s.installations), stat("Monitored repositories", s.repositories),
      stat("Scans", s.scans_total, `${fmt.num(s.scans_24h)} in the last 24h`), stat("Open findings", s.open_findings),
      stat("Critical findings", s.critical_findings), stat("Commits with high/critical findings", s.commits_with_blocking_findings),
      stat("Unverified scans (7d)", s.unverified_scans_7d, "failed, timed out or incomplete")),
    h("div", { class: "grid g2 mt" },
      card("Open findings by severity", d.severity.length ? hbars(["critical", "high", "medium", "low", "info"].map((k) => ({ label: k, value: Number((d.severity.find((x) => x.severity === k) || {}).count || 0), color: sevColor[k] }))) : empty("No open findings.")),
      card("Recent scans", table(["Repository", "Status", "When"], d.recent_scans.map((r) => ({ id: r.id, cells: [h("span", { class: "trunc" }, r.repository), chip(r.status), fmt.rel(r.created_at)] })), (r) => go("/scans/" + r.id)))));
}

async function pRepos(el) {
  const all = await api("/api/repositories");
  const body = h("div", {});
  const q = h("input", { class: "field", type: "search", placeholder: "Search repositories", "aria-label": "Search repositories", autocomplete: "off", maxlength: 120 });
  const draw = () => {
    const term = q.value.trim().toLowerCase();
    const rows = term ? all.filter((r) => (r.full_name + " " + r.installation).toLowerCase().includes(term)) : all;
    rep(body, rows.length === 0 ? h("p", { class: "hint" }, term ? "No repositories match your search." : "No repositories yet.") :
      table(["Repository", "Installation", "Last scan", "Open", "High / critical"], rows.map((r) => ({ id: r.id, r, cells: [
        h("div", {}, h("span", { class: "trunc" }, r.full_name), h("div", { class: "hint" }, r.default_branch + (r.private ? " · private" : ""))), r.installation,
        r.last_scan_status ? h("span", {}, chip(r.last_scan_status), " ", h("span", { class: "hint" }, fmt.rel(r.last_scan_at))) : h("span", { class: "hint" }, "not scanned"),
        fmt.num(r.open_findings), r.blocking_findings > 0 ? chip("critical", fmt.num(r.blocking_findings)) : "0"] })), (r) => go("/findings?repo_id=" + r.id)));
  };
  q.addEventListener("input", draw);
  add(el, head("Repositories", `${all.length} repositories granted to the GitHub App.`), card(null, h("div", {}, q, body)));
  draw();
}

function pager(state, rerender, count) {
  return h("div", { class: "pager" }, h("button", { class: "btn sm", disabled: state.offset === 0, onclick: () => { state.offset = Math.max(0, state.offset - state.limit); rerender(); } }, "Previous"),
    h("span", { class: "hint" }, `Showing ${state.offset + 1}–${state.offset + count}`),
    h("button", { class: "btn sm", disabled: count < state.limit, onclick: () => { state.offset += state.limit; rerender(); } }, "Next"));
}

async function pScans(el) {
  const state = { limit: 25, offset: 0, status: "" };
  const body = h("div", {});
  const sel = dropdown({ label: "Status", value: "", onchange: (v) => { state.status = v; state.offset = 0; load(); },
    options: [{ value: "", label: "All statuses" }, ...["clean", "findings_detected", "incomplete", "failed", "timed_out", "running", "queued"].map((v) => ({ value: v, label: fmt.label(v) }))] });
  async function load() {
    const q = new URLSearchParams({ limit: state.limit, offset: state.offset }); if (state.status) q.set("status", state.status);
    const rows = await api("/api/scans?" + q);
    rep(body, table(["Repository", "Trigger", "Commit", "Ref", "Status", "Findings", "When"], rows.map((r) => ({ id: r.id, cells: [
      h("span", { class: "trunc" }, r.repository), fmt.label(r.trigger), h("span", { class: "mono" }, fmt.sha(r.commit_sha)),
      r.pr_number ? "PR #" + r.pr_number : r.branch || "–", chip(r.status), fmt.num(r.findings), fmt.rel(r.created_at)] })), (r) => go("/scans/" + r.id)), pager(state, load, rows.length));
  }
  add(el, head("Scans", "Every scan, from pushes, pull requests, schedules and installs."), card(null, h("div", {}, h("div", { class: "filters" }, sel), body)));
  await load();
}

async function pScan(el, id) {
  const { scan: s, findings } = await api("/api/scans/" + id);
  add(el, h("div", { class: "crumb" }, link("/scans", "Scans"), " / #" + id),
    head(s.repository, `${fmt.label(s.trigger)} scan of ${fmt.sha(s.commit_sha)}`),
    s.status === "failed" || s.status === "timed_out" || s.status === "incomplete" ? h("div", { class: "note warn" }, "This scan did not finish, so this commit has not been checked." + (s.error ? " " + s.error : "")) : null,
    h("div", { class: "grid g2 mt" }, card("Details", h("div", { class: "card-b" }, h("dl", { class: "kv" },
      h("dt", {}, "Status"), h("dd", {}, chip(s.status)), h("dt", {}, "Commit"), h("dd", { class: "mono" }, s.commit_sha), h("dt", {}, "Branch / PR"), h("dd", {}, s.pr_number ? "PR #" + s.pr_number : s.branch || "–"),
      h("dt", {}, "Author (Git metadata)"), h("dd", {}, s.author || "–"), h("dt", {}, "Files scanned"), h("dd", {}, fmt.num(s.files_scanned)), h("dt", {}, "Rule version"), h("dd", {}, s.rule_version || "–"),
      h("dt", {}, "Started"), h("dd", {}, fmt.date(s.created_at)), h("dt", {}, "Finished"), h("dd", {}, fmt.date(s.finished_at)))))),
    h("div", { class: "mt" }), card(`Findings (${findings.length})`, table(["Severity", "Confidence", "Finding", "File"], findings.map((f) => ({ id: f.id, cells: [chip(f.severity), chip(f.confidence), f.title, h("span", { class: "mono trunc" }, f.path + (f.line_start ? ":" + f.line_start : ""))] })), (f) => go("/findings/" + f.id))));
}

async function pFindings(el) {
  const p = new URLSearchParams(location.search);
  const state = { limit: 25, offset: 0, severity: p.get("severity") || "", confidence: "", status: p.get("status") ?? "open", q: p.get("q") || "", repo_id: p.get("repo_id") || "" };
  const body = h("div", {});
  const mk = (key, label, vals) => dropdown({ label, value: state[key], onchange: (v) => { state[key] = v; state.offset = 0; load(); },
    options: [{ value: "", label }, ...vals.map((v) => ({ value: v, label: fmt.label(v) }))] });
  const search = h("input", { class: "field grow", type: "search", placeholder: "Search path, title or rule", "aria-label": "Search", value: state.q, oninput: () => { clearTimeout(search._t); search._t = setTimeout(() => { state.q = search.value; state.offset = 0; load(); }, 250); } });
  async function load() {
    const q = new URLSearchParams({ limit: state.limit, offset: state.offset }); for (const k of ["severity", "confidence", "status", "q", "repo_id"]) if (state[k]) q.set(k, state[k]);
    const rows = await api("/api/findings?" + q);
    rep(body, table(["Severity", "Confidence", "Finding", "Repository", "File", "Status", "Last seen"], rows.map((f) => ({ id: f.id, cells: [chip(f.severity), chip(f.confidence), h("span", { class: "trunc" }, f.title),
      h("span", { class: "trunc" }, f.repository), h("span", { class: "mono trunc" }, f.path), chip(f.status), fmt.rel(f.last_detected_at)] })), (f) => go("/findings/" + f.id)), pager(state, load, rows.length));
  }
  add(el, head("Findings", "Severity is how bad it would be. Confidence is how sure we are."),
    card(null, h("div", {}, h("div", { class: "filters" }, search, mk("severity", "All severities", ["critical", "high", "medium", "low", "info"]), mk("confidence", "All confidence", ["confirmed_signature", "high", "medium", "low"]), mk("status", "All statuses", ["open", "resolved", "false_positive", "accepted_risk"])), body)));
  await load();
}

async function pFinding(el, id) {
  const { finding: f, occurrences, related } = await api("/api/findings/" + id);
  const reason = h("textarea", { class: "field", placeholder: "Reason (at least 10 characters to suppress). Saved to the audit log.", maxlength: 500, "aria-label": "Reason" });
  const expiry = dropdown({ label: "Suppress for", value: "30", options: [{ value: "7", label: "7 days" }, { value: "30", label: "30 days" }, { value: "90", label: "90 days" }, { value: "180", label: "180 days" }, { value: "365", label: "1 year" }, { value: "0", label: "No expiry" }] });
  const set = (status) => async () => {
    try { await api("/api/findings/" + id, { method: "PATCH", body: { status, reason: reason.value, expires_in_days: Number(expiry.value) } }); toast("Finding updated"); el.replaceChildren(); await pFinding(el, id); } catch (e) { toast(e.message); }
  };
  add(el, h("div", { class: "crumb" }, link("/findings", "Findings"), " / #" + id), head(f.title, f.repository + " · " + f.rule_id + " v" + f.rule_version),
    h("div", { class: "grid g2" },
      card("Assessment", h("div", { class: "card-b" }, h("dl", { class: "kv" }, h("dt", {}, "Severity"), h("dd", {}, chip(f.severity)), h("dt", {}, "Confidence"), h("dd", {}, chip(f.confidence)),
        h("dt", {}, "Category"), h("dd", {}, fmt.label(f.category)), h("dt", {}, "Status"), h("dd", {}, chip(f.status)), h("dt", {}, "File"), h("dd", { class: "mono" }, f.path),
        h("dt", {}, "First detected"), h("dd", {}, fmt.date(f.first_detected_at)), h("dt", {}, "Last detected"), h("dd", {}, fmt.date(f.last_detected_at)),
        f.suppressed_until ? h("dt", {}, "Suppressed until") : null, f.suppressed_until ? h("dd", {}, fmt.date(f.suppressed_until)) : null,
        f.suppression_reason ? h("dt", {}, "Suppression reason") : null, f.suppression_reason ? h("dd", {}, f.suppression_reason) : null),
        f.confidence !== "confirmed_signature" ? h("p", { class: "note mt" }, "This is a heuristic match, not confirmed malware.") : h("p", { class: "note warn mt" }, "Matches an exact known-malware signature."))),
      card("Explanation", h("div", { class: "card-b stack" }, h("p", {}, f.explanation), h("div", {}, h("h3", { class: "lbl" }, "Recommended remediation"), h("p", {}, f.remediation))))),
    h("div", { class: "mt" }), card("Triage", h("div", { class: "card-b stack" }, reason, h("div", {}, h("label", { class: "lbl" }, "If suppressing, suppress for"), expiry),
      h("div", { style: null }, [["Mark false positive", "false_positive"], ["Accept risk", "accepted_risk"], ["Resolve", "resolved"], ["Reopen", "open"]].filter(([, s]) => s !== f.status).map(([l, s]) =>
        h("button", { class: "btn sm" + (s === "open" ? " primary" : ""), onclick: set(s) }, l)).flatMap((b) => [b, " "])),
      f.confidence === "confirmed_signature" ? h("p", { class: "hint" }, "Suppressions are logged. Risk acceptance and confirmed signature matches must expire; expired suppressions reopen the finding.") : null)),
    h("div", { class: "mt" }), card(`Occurrences (${occurrences.length})`, table(["Scan", "Commit", "Line", "Seen", "Evidence (masked)"], occurrences.map((o) => ({ id: o.scan_id, cells: [link("/scans/" + o.scan_id, "#" + o.scan_id), h("span", { class: "mono" }, fmt.sha(o.commit_sha)), o.line_start || "–", fmt.rel(o.created_at), h("span", { class: "hint trunc" }, o.evidence)] })), (o) => go("/scans/" + o.scan_id))),
    related.length ? h("div", { class: "mt" }, card("Related findings", table(["Severity", "Finding", "File"], related.map((r) => ({ id: r.id, cells: [chip(r.severity), r.title, h("span", { class: "mono" }, r.path)] })), (r) => go("/findings/" + r.id)))) : null);
}

async function pObs(el) {
  const state = { days: 14 };
  const body = h("div", {});
  const sel = dropdown({ label: "Range", value: 14, onchange: (v) => { state.days = Number(v); load(); }, options: [7, 14, 30, 90].map((d) => ({ value: d, label: `Last ${d} days` })) });
  async function load() {
    const d = await api("/api/observability?days=" + state.days);
    const any = d.scans.some((x) => x.clean + x.findings_detected + x.incomplete + x.failed > 0);
    rep(body, 
      !any ? h("div", { class: "note" }, "No scans recorded in this range yet. Charts fill in as scans run.") : null,
      h("div", { class: "grid g2" },
        card("Scans per day", stackedBars(d.scans, [{ key: "clean", label: "Clean", color: "--c0" }, { key: "findings_detected", label: "Findings", color: "--c3" }, { key: "incomplete", label: "Incomplete", color: "--c2" }, { key: "failed", label: "Failed / timed out", color: "--c1" }])),
        card("New findings per day", stackedBars(d.new_findings, [{ key: "critical", label: "Critical", color: "--crit" }, { key: "high", label: "High", color: "--high" }, { key: "medium", label: "Medium", color: "--med" }, { key: "low", label: "Low / info", color: "--low" }])),
        card("Scan duration (seconds)", lineChart(d.scan_duration_seconds, [{ key: "p50", label: "Median", color: "--c0" }, { key: "p95", label: "95th percentile", color: "--c2" }], "s")),
        card("Background jobs finished", stackedBars(d.jobs, [{ key: "succeeded", label: "Succeeded", color: "--c0" }, { key: "dead", label: "Dead-lettered", color: "--c3" }])),
        card("Alert emails sent", stackedBars(d.emails, [{ key: "sent", label: "Sent", color: "--c0" }])),
        card("Open findings by rule", d.open_by_rule.length ? hbars(d.open_by_rule.map((r) => ({ label: r.rule_id, value: Number(r.count) }))) : empty("No open findings."))));
  }
  add(el, head("Observability", "Built from your stored scans, findings, jobs and emails.", sel), body);
  await load();
}

async function pIntel(el) {
  const d = await api("/api/intel");
  add(el, head("Detection rules", `Active signature set: ${d.version}`), h("div", { class: "note" }, d.note),
    d.feeds.length ? h("div", { class: "mt" }, card("External feeds", table(["Feed", "Host", "License", "Signatures", "Last refresh", "Status"], d.feeds.map((f) => ({ cells: [f.name, h("span", { class: "mono" }, f.host), h("span", { class: "hint" }, f.license), fmt.num(f.signature_count),
      f.last_fetched_at ? fmt.rel(f.last_fetched_at) : "never", f.last_status === "error" ? h("span", {}, chip("failed", "error"), " ", h("span", { class: "hint" }, f.last_error)) : chip(f.last_status === "ok" || f.last_status === "not_modified" ? "ok" : "pending", fmt.label(f.last_status))] }))))) : null,
    h("div", { class: "mt" }), card("Built-in signatures", table(["Rule", "Family", "Type", "Severity", "Provenance"], d.signatures.map((s) => ({ cells: [h("span", { class: "mono" }, s.id), s.family, s.kind, chip(s.severity), h("span", { class: "hint" }, s.provenance)] })))),
    h("p", { class: "hint mt" }, "The other checks (hidden payloads, persistence, secrets, dependencies, CI workflows) are built in and always on. They can flag suspicious code but never call it confirmed malware."));
}

async function pSystem(el) {
  const d = await api("/api/system"), j = d.jobs;
  add(el, head("System health", "Current status of the database, queue and integrations."),
    h("div", { class: "grid g4" }, stat("Queued jobs", j.queued), stat("Running jobs", j.running), stat("Dead-lettered jobs", j.dead), stat("Succeeded (24h)", j.succeeded_24h)),
    h("div", { class: "grid g2 mt" },
      card("Services", h("div", { class: "card-b" }, h("dl", { class: "kv" }, h("dt", {}, "Database"), h("dd", {}, chip("ok", "Connected")),
        h("dt", {}, "GitHub App"), h("dd", {}, d.github_app_configured ? chip("ok", "Configured") : chip("pending", "Not configured")),
        h("dt", {}, "Resend email"), h("dd", {}, d.email_configured ? chip("ok", "Configured") : chip("pending", "Not configured")),
        h("dt", {}, "Last worker activity"), h("dd", {}, j.last_activity ? fmt.rel(j.last_activity) : "No jobs recorded yet"), h("dt", {}, "Environment"), h("dd", {}, d.environment)))),
      card("Email deliveries", h("div", { class: "card-b" }, h("dl", { class: "kv" }, h("dt", {}, "Sent"), h("dd", {}, fmt.num(d.notifications.sent)), h("dt", {}, "Failed"), h("dd", {}, fmt.num(d.notifications.failed)), h("dt", {}, "Pending retry"), h("dd", {}, fmt.num(d.notifications.pending)), h("dt", {}, "Bounced"), h("dd", {}, d.notifications.bounced > 0 ? chip("failed", fmt.num(d.notifications.bounced)) : "0"), h("dt", {}, "Spam complaints"), h("dd", {}, d.notifications.complained > 0 ? chip("failed", fmt.num(d.notifications.complained)) : "0"))))),
    h("div", { class: "mt" }), card("Dead-lettered jobs", d.dead_jobs.length ? table(["Job", "Kind", "Attempts", "Error", "When"], d.dead_jobs.map((x) => ({ cells: ["#" + x.id, x.kind, x.attempts, h("span", { class: "hint trunc" }, x.last_error || ""), fmt.rel(x.finished_at)] }))) : empty("No dead-lettered jobs.")));
}

async function pAudit(el) {
  const state = { limit: 25, offset: 0 }, body = h("div", {});
  async function load() {
    const rows = await api(`/api/audit?limit=${state.limit}&offset=${state.offset}`);
    rep(body, table(["When", "Actor", "Action", "Target", "Detail"], rows.map((r) => ({ cells: [fmt.date(r.created_at), h("span", { class: "mono" }, r.actor), r.action, r.target || "–", h("span", { class: "hint trunc" }, r.detail && Object.keys(r.detail).length ? JSON.stringify(r.detail) : "")] }))), pager(state, load, rows.length));
  }
  add(el, head("Audit log", "Sign-ins, passkey changes, suppressions and settings changes."), card(null, body));
  await load();
}

async function pSettings(el) {
  const passkeys = h("div", {}), linkBox = h("div", { class: "stack" }), inst = h("div", { class: "stack" });
  async function loadPk() {
    const rows = await api("/api/auth/passkeys");
    rep(passkeys, table(["Name", "Added", "Last used", ""], rows.map((p) => ({ cells: [p.name + (p.id === me.passkey_id ? " (this device)" : ""), fmt.date(p.created_at), fmt.rel(p.last_used_at),
      h("button", { class: "btn sm danger", disabled: rows.length < 2, title: rows.length < 2 ? "The last passkey cannot be removed" : "", onclick: async () => {
        if (!confirm("Remove this passkey? Sessions that used it will be signed out.")) return;
        try { await api("/api/auth/passkeys/" + p.id, { method: "DELETE" }); toast("Passkey removed"); if (p.id === me.passkey_id) return go("/"); loadPk(); } catch (e) { toast(e.message); } } }, "Remove")] }))));
  }
  const mkLink = h("button", { class: "btn primary", onclick: async () => {
    try {
      const r = await api("/api/auth/enroll-link", { method: "POST" });
      const input = h("input", { class: "field mono", readonly: true, value: r.url, "aria-label": "Enrollment link" });
      rep(linkBox, h("div", { class: "note warn" }, `This link works once and expires in ${r.ttl_minutes} minutes. Open it on your phone. Anyone who gets it can add a passkey, so keep it to yourself.`),
        input, h("button", { class: "btn", onclick: async () => { try { await navigator.clipboard.writeText(r.url); toast("Link copied"); } catch { input.select(); } } }, icon("copy"), "Copy link"));
    } catch (e) { toast(e.message); }
  } }, icon("plus"), "Add a device");
  async function loadInst() {
    const rows = await api("/api/installations");
    rep(inst, ...(rows.length ? rows.map((i) => {
      const en = h("input", { type: "checkbox", checked: i.notify_enabled ? true : null, id: "en" + i.id });
      const rec = h("textarea", { class: "field", placeholder: "one email address per line", "aria-label": "Recipients" }); rec.value = (i.notify_recipients || []).join("\n");
      const sev = dropdown({ label: "Minimum severity", value: i.notify_min_severity, options: ["critical", "high", "medium", "low", "info"].map((v) => ({ value: v, label: fmt.label(v) })) });
      return card(i.account_login, h("div", { class: "card-b stack" }, h("label", {}, en, " Send alert emails"), h("div", {}, h("label", { class: "lbl" }, "Recipients"), rec), h("div", {}, h("label", { class: "lbl" }, "Alert at or above"), sev),
        h("button", { class: "btn primary sm", onclick: async () => {
          try { await api(`/api/installations/${i.id}/notifications`, { method: "PUT", body: { enabled: en.checked, recipients: rec.value.split("\n").map((x) => x.trim()).filter(Boolean), min_severity: sev.value } }); toast("Saved"); } catch (e) { toast(e.message); } } }, "Save")), h("span", { class: "hint" }, i.repositories + " repositories"));
    }) : [empty("No installations yet. Install the GitHub App to configure alerts.")]));
  }
  add(el, head("Settings"), card("Passkeys", h("div", {}, passkeys, h("div", { class: "card-b stack" }, mkLink, linkBox))), h("div", { class: "mt" }), h("h2", { class: "lbl mt" }, "Alert emails"), inst);
  await Promise.all([loadPk(), loadInst()]);
}

route();
