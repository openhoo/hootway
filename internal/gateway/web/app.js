"use strict";

const $ = (s, el = document) => el.querySelector(s);
const state = { data: null, editingKey: null, editingUpstream: null, lastSeq: 0, events: [], timer: null, shown: "" };

// theme
const root = document.documentElement;
const isDark = () => (root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
function labelTheme() { const l = `Switch to ${isDark() ? "light" : "dark"} theme`; $("#theme").ariaLabel = l; $("#theme").title = l; }
root.dataset.theme = localStorage.getItem("hootway-theme") || "";
labelTheme();
$("#theme").addEventListener("click", () => {
  root.dataset.theme = isDark() ? "light" : "dark";
  localStorage.setItem("hootway-theme", root.dataset.theme);
  labelTheme();
});

// api
async function api(method, path, body) {
  const res = await fetch("/api" + path, {
    method,
    headers: { "Content-Type": "application/json", "X-Hootway-Console": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty */ }
  if (res.status === 401 && path !== "/session") { showLogin(); throw new Error("Signed out"); }
  if (!res.ok) throw new Error(data?.error?.message || `Request failed (${res.status})`);
  return data;
}

// Builds DOM nodes; text is always inserted as text, never parsed as HTML.
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  n.append(...children.flat().filter((c) => c != null && c !== false));
  return n;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.textContent = ""), 2600);
}

function setError(sel, msg) { const e = $(sel); e.textContent = msg || ""; e.hidden = !msg; }

async function busy(btn, fn) {
  if (btn.disabled) return;
  btn.disabled = true;
  try { return await fn(); } finally { btn.disabled = false; }
}

// session
function showLogin() {
  stopPolling();
  Object.assign(state, { data: null, lastSeq: 0, events: [], shown: "" });
  for (const d of document.querySelectorAll("dialog[open]")) d.close();
  $("#app").hidden = true; $("#login").hidden = false;
  $("#login-token").focus();
}
async function showApp() {
  $("#login").hidden = true; $("#app").hidden = false;
  route();
  await refresh();
}
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const token = $("#login-token").value.trim();
  if (!token) return setError("#login-error", "Enter the admin token.");
  await busy(e.submitter || $("#login-form button"), async () => {
    try {
      await api("POST", "/session", { token });
      $("#login-token").value = ""; setError("#login-error");
      await showApp();
    } catch (err) { setError("#login-error", err.message); $("#login-token").select(); }
  });
});
$("#logout").addEventListener("click", async () => { await api("DELETE", "/session").catch(() => {}); showLogin(); });

// routing
const tabs = ["keys", "upstreams", "activity", "check"];
function route() {
  const tab = tabs.includes(location.hash.slice(1)) ? location.hash.slice(1) : "keys";
  for (const t of tabs) {
    $("#tab-" + t).hidden = t !== tab;
    $(`nav a[data-tab="${t}"]`).ariaCurrent = t === tab ? "page" : null;
  }
  document.title = `${tab[0].toUpperCase() + tab.slice(1)} · Hootway`;
  if (tab === "activity") startPolling(); else stopPolling();
}
addEventListener("hashchange", () => { if ($("#app").hidden) return; route(); $("#main").focus({ preventScroll: true }); });

// data
const lists = () => [$("#keys"), $("#upstreams")];
async function refresh() {
  if (!state.data) for (const l of lists()) l.replaceChildren(el("div", { class: "skeleton" }), el("div", { class: "skeleton" }));
  for (const l of lists()) l.ariaBusy = "true";
  try {
    state.data = await api("GET", "/state");
    render();
  } catch (err) {
    if (err.message !== "Signed out" && !state.data) {
      for (const l of lists()) l.replaceChildren(empty("Could not load the gateway state", err.message, "Try again", refresh, "ghost"));
    } else if (err.message !== "Signed out") toast(err.message);
  } finally { for (const l of lists()) l.ariaBusy = "false"; }
}

// Re-rendering a list replaces its buttons (and disabling a busy button drops
// focus to <body>); put keyboard focus back on the same action.
let lastFocus = "";
document.addEventListener("focusin", (e) => { if (e.target.dataset.f) lastFocus = e.target.dataset.f; });
function restoreFocus() {
  const a = document.activeElement;
  if (a !== document.body && a.isConnected) return;
  const t = lastFocus && $(`[data-f="${CSS.escape(lastFocus)}"]`);
  if (t) t.focus(); else if (!$("#app").hidden) $("#main").focus({ preventScroll: true });
}

function render() {
  const d = state.data;
  const banner = [];
  if (!d.persistent) banner.push("Changes apply immediately but are not saved: the gateway was started without a writable config file.");
  const broken = d.upstreams.filter((u) => u.problem);
  if (broken.length) banner.push(`${broken.length} upstream${broken.length > 1 ? "s have" : " has"} no usable credential: ${broken.map((u) => u.name).join(", ")}.`);
  $("#banner").textContent = banner.join(" "); $("#banner").hidden = !banner.length;

  const active = d.keys.filter((k) => !k.disabled && !k.expired).length;
  $("#stats").replaceChildren(
    stat("Active keys", active),
    stat("Forwarded", d.totals.forwarded),
    stat("Denied", d.totals.denied),
  );
  renderKeys(); renderUpstreams(); renderCheckKeys(); restoreFocus();
}
function stat(label, value) { return el("div", {}, el("dt", {}, label), el("dd", {}, String(value))); }
const action = (label, f, fn, cls = "link") => el("button", { class: cls, type: "button", "data-f": f, onclick: fn }, label);
const empty = (title, text, label, fn, cls = "primary") =>
  el("div", { class: "empty" }, el("p", {}, title), el("p", {}, text), label && el("button", { class: cls, type: "button", onclick: fn }, label));

function fmtDate(s) {
  if (!s) return "";
  return new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
function ago(s) {
  if (!s) return "never used";
  const sec = Math.max(0, (Date.now() - new Date(s)) / 1000);
  if (sec < 60) return "used just now";
  if (sec < 3600) return `used ${Math.floor(sec / 60)} min ago`;
  if (sec < 86400) return `used ${Math.floor(sec / 3600)} h ago`;
  return `used ${fmtDate(s)}`;
}

function renderKeys() {
  const list = $("#keys");
  const d = state.data;
  if (!d.keys.length) {
    const can = d.upstreams.length > 0;
    list.replaceChildren(empty("No keys yet",
      can ? "Create a key and give it to an agent instead of a real API token." : "Pick a service such as Jira or GitLab; Hootway walks you through the token.",
      "New key", () => openWizard()));
    return;
  }
  list.replaceChildren(...d.keys.map((k) => {
    const status = k.disabled ? el("span", { class: "pill off" }, "disabled")
      : k.expired ? el("span", { class: "pill bad" }, "expired")
      : el("span", { class: "pill" }, "active");
    return el("article", { class: "card" },
      el("div", { class: "item-head" },
        el("h3", {}, k.id), status, el("span", { class: "spacer" }),
        action("Edit", "ke:" + k.id, () => openKey(k)),
        action(k.disabled ? "Enable" : "Disable", "kt:" + k.id, (e) => toggleKey(k, e.currentTarget)),
        action("Rotate", "kr:" + k.id, () => rotateKey(k)),
        action("Delete", "kd:" + k.id, () => deleteKey(k), "link danger")),
      k.description ? el("p", { class: "quiet small" }, k.description) : null,
      el("div", { class: "item-meta" },
        el("span", { class: "mono", title: "First characters of the key hash" }, "#" + k.fingerprint),
        el("span", {}, ago(k.stats.last_used)),
        el("span", {}, `${k.stats.forwarded} forwarded · ${k.stats.denied} denied`),
        k.expires_at ? el("span", {}, (k.expired ? "expired " : "expires ") + fmtDate(k.expires_at)) : null,
        k.requests_per_minute ? el("span", {}, `${k.requests_per_minute}/min`) : null),
      el("ul", { class: "rules", "aria-label": "Access rules" }, ...k.grants.flatMap((g) => g.paths.map((p) =>
        el("li", {}, el("span", { class: "m" }, g.methods.join(" ")), el("span", { class: "u" }, "/" + g.upstream), el("span", {}, p))))));
  }));
}

function renderUpstreams() {
  const list = $("#upstreams");
  const d = state.data;
  if (!d.upstreams.length) {
    list.replaceChildren(empty("No upstreams yet", "An upstream is an API such as Jira that the gateway calls with its own credential.",
      "New upstream", () => openUpstream()));
    return;
  }
  list.replaceChildren(...d.upstreams.map((u) => {
    const users = d.keys.filter((k) => k.grants.some((g) => g.upstream === u.name)).length;
    const src = u.auth.secret_env ? `env ${u.auth.secret_env}` : u.auth.secret_file ? `file ${u.auth.secret_file}` : "";
    return el("article", { class: "card" },
      el("div", { class: "item-head" },
        el("h3", {}, "/" + u.name),
        u.problem ? el("span", { class: "pill bad", title: u.problem }, "credential missing") : el("span", { class: "pill" }, "ready"),
        el("span", { class: "spacer" }),
        action("Edit", "ue:" + u.name, () => openUpstream(u))),
      u.description ? el("p", { class: "quiet small" }, u.description) : null,
      el("div", { class: "item-meta" },
        el("span", { class: "mono" }, u.base_url),
        el("span", {}, `${u.auth.type}${src ? " · " + src : ""}`),
        el("span", {}, `${users} key${users === 1 ? "" : "s"}`)),
      u.problem ? el("p", { class: "error" }, u.problem) : null);
  }));
}

function renderCheckKeys() {
  const sel = $("#check-key");
  const cur = sel.value;
  sel.replaceChildren(...state.data.keys.map((k) => el("option", { value: k.id }, k.id)));
  if (state.data.keys.some((k) => k.id === cur)) sel.value = cur;
}

// keys
function grantRow(g = { upstream: "", methods: ["GET"], paths: [] }) {
  const ups = state.data.upstreams.map((u) => u.name);
  const row = el("div", { class: "grant" },
    el("select", { "aria-label": "Upstream", class: "g-up" }, ...ups.map((n) => el("option", { value: n, selected: n === g.upstream }, n))),
    el("input", { "aria-label": "Methods", class: "g-methods", value: g.methods.join(" "), placeholder: "GET POST", spellcheck: "false" }),
    el("textarea", { "aria-label": "Paths, one per line", class: "g-paths", rows: Math.max(1, g.paths.length), placeholder: "/rest/api/3/issue/*", spellcheck: "false" }, g.paths.join("\n")),
    el("button", { class: "link", type: "button", "aria-label": "Remove rule", onclick: () => { row.remove(); $("#add-grant").focus(); } }, "✕"));
  return row;
}

function toLocalInput(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const off = d.getTimezoneOffset() * 60000;
  return new Date(d - off).toISOString().slice(0, 16);
}

function openKey(k) {
  if (!state.data.upstreams.length) return openUpstream();
  state.editingKey = k || null;
  $("#key-dialog-title").textContent = k ? `Edit ${k.id}` : "New key";
  $("#key-save").textContent = k ? "Save" : "Create key";
  $("#key-id").value = k ? k.id : ""; $("#key-id").disabled = !!k;
  $("#key-desc").value = k ? k.description || "" : "";
  $("#key-expires").value = k ? toLocalInput(k.expires_at) : "";
  $("#key-rpm").value = k ? k.requests_per_minute : 0;
  $("#key-disabled").checked = k ? k.disabled : false;
  $("#grant-rows").replaceChildren(...(k ? k.grants : [{ upstream: state.data.upstreams[0].name, methods: ["GET"], paths: [] }]).map(grantRow));
  setError("#key-error");
  $("#key-dialog").showModal();
  (k ? $("#key-desc") : $("#key-id")).focus();
}
$("#new-key").addEventListener("click", () => openWizard());
$("#add-grant").addEventListener("click", () => {
  const r = grantRow({ upstream: state.data.upstreams[0]?.name, methods: ["GET"], paths: [] });
  $("#grant-rows").append(r); $(".g-paths", r).focus();
});

function readKeyForm() {
  const id = $("#key-id").value.trim();
  if (!state.editingKey && !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(id)) throw new Error("Name: use lowercase letters, digits, - and _.");
  const grants = [...document.querySelectorAll("#grant-rows .grant")].map((r) => ({
    upstream: $(".g-up", r).value,
    methods: $(".g-methods", r).value.toUpperCase().split(/[\s,]+/).filter(Boolean),
    paths: $(".g-paths", r).value.split("\n").map((s) => s.trim()).filter(Boolean),
  })).filter((g) => g.paths.length || g.methods.length);
  if (!grants.length) throw new Error("Add at least one access rule.");
  for (const g of grants) {
    if (!g.methods.length) throw new Error("Each rule needs at least one method, for example GET.");
    if (!g.paths.length) throw new Error("Each rule needs at least one path.");
  }
  const exp = $("#key-expires").value;
  const rpm = parseInt($("#key-rpm").value || "0", 10);
  if (Number.isNaN(rpm) || rpm < 0) throw new Error("Requests per minute must be 0 or more.");
  return {
    id, description: $("#key-desc").value.trim(), disabled: $("#key-disabled").checked,
    expires_at: exp ? new Date(exp).toISOString() : null, requests_per_minute: rpm, grants,
  };
}

$("#key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  let body;
  try { body = readKeyForm(); } catch (err) { return setError("#key-error", err.message); }
  await busy($("#key-save"), async () => {
    try {
      if (state.editingKey) {
        await api("PUT", "/keys/" + encodeURIComponent(state.editingKey.id), body);
        $("#key-dialog").close(); toast("Key saved");
      } else {
        const res = await api("POST", "/keys", body);
        $("#key-dialog").close(); showSecret(res.key, body.grants[0]?.upstream);
      }
      await refresh();
    } catch (err) { setError("#key-error", err.message); }
  });
});

function showSecret(key, upstream, hint) {
  $("#secret-value").textContent = key;
  const base = state.data.gateway_url + "/" + (upstream || "jira");
  const p = hint?.env || "HOOTWAY";
  const curl = hint?.test ? `curl -H "Authorization: Bearer $${p}_TOKEN" "$${p}_URL${hint.test}"`
    : `curl -H "Authorization: Bearer $${p}_TOKEN" "$${p}_URL/…"`;
  $("#secret-snippet").textContent =
`export ${p}_URL=${base}
export ${p}_TOKEN=${key}
${curl}`;
  $("#secret-dialog").showModal();
  $("#copy-secret").focus();
}
$("#copy-secret").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#secret-value").textContent); toast("Copied"); }
  catch { getSelection().selectAllChildren($("#secret-value")); toast("Press ⌘C / Ctrl+C to copy"); }
});
$("#secret-dialog").addEventListener("close", () => { $("#secret-value").textContent = ""; $("#secret-snippet").textContent = ""; });

function keyBody(k, patch) {
  return { id: k.id, description: k.description || "", disabled: k.disabled, expires_at: k.expires_at || null,
    requests_per_minute: k.requests_per_minute, grants: k.grants, ...patch };
}
function toggleKey(k, btn) {
  return busy(btn, async () => {
    try { await api("PUT", "/keys/" + encodeURIComponent(k.id), keyBody(k, { disabled: !k.disabled })); toast(k.disabled ? "Key enabled" : "Key disabled"); await refresh(); }
    catch (err) { toast(err.message); }
  });
}
function rotateKey(k) {
  confirmAction(`Rotate ${k.id}?`, "The current key stops working immediately. You will get a new key to give to the agent.", "Rotate", async () => {
    const res = await api("POST", `/keys/${encodeURIComponent(k.id)}/rotate`);
    $("#confirm-dialog").close(); showSecret(res.key, k.grants[0]?.upstream); await refresh();
  });
}
function deleteKey(k) {
  confirmAction(`Delete ${k.id}?`, "Agents using this key lose access immediately. This cannot be undone.", "Delete", async () => {
    await api("DELETE", "/keys/" + encodeURIComponent(k.id)); toast("Key deleted"); await refresh();
  });
}

function confirmAction(title, text, label, fn) {
  $("#confirm-title").textContent = title; $("#confirm-text").textContent = text; $("#confirm-ok").textContent = label;
  const dlg = $("#confirm-dialog");
  $("#confirm-ok").onclick = () => busy($("#confirm-ok"), async () => {
    try { await fn(); dlg.close(); } catch (err) { dlg.close(); toast(err.message); }
  });
  dlg.showModal();
  dlg.querySelector("[data-close]").focus();
}

// upstreams
function syncAuthFields() {
  const t = $("#up-auth").value;
  for (const n of document.querySelectorAll("#up-dialog [data-auth]")) n.hidden = !n.dataset.auth.split(" ").includes(t);
}
$("#up-auth").addEventListener("change", syncAuthFields);

function openUpstream(u) {
  state.editingUpstream = u || null;
  $("#up-title").textContent = u ? `Edit /${u.name}` : "New upstream";
  $("#up-name").value = u ? u.name : ""; $("#up-name").disabled = !!u;
  $("#up-url").value = u ? u.base_url : "";
  $("#up-desc").value = u ? u.description || "" : "";
  $("#up-timeout").value = u ? u.timeout_seconds || 60 : 60;
  const a = u ? u.auth : { type: "basic" };
  $("#up-auth").value = a.type;
  $("#up-auth-name").value = a.name || ""; $("#up-auth-prefix").value = a.prefix || "";
  $("#up-user").value = a.username || ""; $("#up-user-env").value = a.username_env || "";
  $("#up-secret-env").value = a.secret_env || ""; $("#up-secret-file").value = a.secret_file || "";
  $("#up-secret").value = "";
  $("#up-secret").disabled = !state.data.secret_storage;
  $("#up-secret").placeholder = state.data.secret_storage ? "Paste a new token to store it on the gateway" : "Needs a writable config file";
  $("#up-headers").value = u && u.headers ? Object.entries(u.headers).map(([k, v]) => `${k}: ${v}`).join("\n") : "";
  $("#up-delete").hidden = !u;
  syncAuthFields(); setError("#up-error");
  $("#up-dialog").showModal();
  (u ? $("#up-url") : $("#up-name")).focus();
}
$("#new-upstream").addEventListener("click", () => openUpstream());

$("#up-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#up-name").value.trim();
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(name)) return setError("#up-error", "Name: use lowercase letters, digits, - and _.");
  const type = $("#up-auth").value;
  const auth = { type };
  const v = (s) => $(s).value.trim();
  if (type === "header" || type === "query") auth.name = v("#up-auth-name");
  if (type === "header" && $("#up-auth-prefix").value) auth.prefix = $("#up-auth-prefix").value;
  if (type === "basic") { if (v("#up-user")) auth.username = v("#up-user"); if (v("#up-user-env")) auth.username_env = v("#up-user-env"); }
  if (type !== "none") { if (v("#up-secret-env")) auth.secret_env = v("#up-secret-env"); if (v("#up-secret-file")) auth.secret_file = v("#up-secret-file"); }
  const secret = type !== "none" ? $("#up-secret").value.trim() : "";
  const headers = {};
  for (const line of $("#up-headers").value.split("\n")) {
    if (!line.trim()) continue;
    const i = line.indexOf(":");
    if (i < 1) return setError("#up-error", `Header line "${line}" must look like Name: value.`);
    headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  const body = { name, base_url: v("#up-url"), description: v("#up-desc"), auth, timeout_seconds: parseInt($("#up-timeout").value || "0", 10) || 0 };
  if (Object.keys(headers).length) body.headers = headers;
  if (secret) body.secret = secret;
  await busy($("#up-save"), async () => {
    try {
      await api("PUT", "/upstreams/" + encodeURIComponent(name), body);
      $("#up-secret").value = "";
      $("#up-dialog").close(); await refresh();
      const now = state.data.upstreams.find((u) => u.name === name);
      toast(now && now.problem ? "Saved — the credential is not available yet" : "Upstream saved");
    } catch (err) { setError("#up-error", err.message); }
  });
});
$("#up-delete").addEventListener("click", () => {
  const u = state.editingUpstream;
  $("#up-dialog").close();
  confirmAction(`Delete /${u.name}?`, "Keys cannot reach this API afterwards. Remove its access rules from keys first.", "Delete", async () => {
    await api("DELETE", "/upstreams/" + encodeURIComponent(u.name)); toast("Upstream deleted"); await refresh();
  });
});

// activity
// One request in flight at a time; paused while the tab is hidden.
function startPolling() { if (!state.timer) { state.timer = true; pollEvents(); } }
function stopPolling() { clearTimeout(state.timer); state.timer = null; }
async function pollEvents() {
  if (!document.hidden) {
    try {
      const { events } = await api("GET", "/events?after=" + state.lastSeq);
      if (events.length) {
        state.lastSeq = events[events.length - 1].seq;
        state.events = state.events.concat(events).slice(-300);
      }
      renderEvents();
    } catch { /* signed out or offline; retried below */ }
  }
  if (state.timer) state.timer = setTimeout(pollEvents, 3000);
}
$("#activity-filter").addEventListener("change", () => renderEvents());
const outcomeText = {
  forwarded: "forwarded", forbidden: "not allowed", invalid_key: "invalid key", missing_key: "no key",
  bad_path: "unsafe path", rate_limited: "rate limited", upstream_error: "upstream failed", upstream_unconfigured: "no credential",
};
function renderEvents() {
  const f = $("#activity-filter").value;
  if (state.shown === state.lastSeq + f) return;
  state.shown = state.lastSeq + f;
  const list = state.events.filter((e) => !f || (f === "forwarded") === (e.outcome === "forwarded")).slice().reverse();
  const log = $("#activity");
  if (!list.length) {
    log.replaceChildren(empty(f ? "Nothing matches this filter" : "Quiet so far", "Requests from agents appear here as they happen."));
    return;
  }
  log.replaceChildren(...list.slice(0, 200).map((e) => {
    const ok = e.outcome === "forwarded";
    return el("div", { class: "ev" + (ok ? "" : " denied") },
      el("span", { class: "t" }, new Date(e.time).toLocaleTimeString()),
      el("span", { class: "m" }, e.method),
      el("span", { class: "p" }, e.path, e.key ? el("span", { class: "k" }, e.key) : null),
      el("span", { class: "o" }, el("span", { class: "pill" + (ok ? "" : e.outcome === "upstream_error" ? " warn" : " bad") },
        `${e.status} ${outcomeText[e.outcome] || e.outcome}`)));
  }));
}

// check
$("#check-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const out = $("#check-result");
  const verdict = (ok, title, text) => { out.className = "verdict " + (ok ? "ok" : "no"); out.replaceChildren(el("strong", {}, title), text); out.hidden = false; };
  const path = $("#check-path").value.trim();
  if (!$("#check-key").value) return verdict(false, "No keys", "Create a key first.");
  if (!path) { $("#check-path").focus(); return verdict(false, "Missing path", "Enter a path such as /jira/rest/api/3/myself."); }
  return busy(e.submitter || $("#check-form button"), async () => {
    try {
      const r = await api("POST", "/explain", { key: $("#check-key").value, method: $("#check-method").value, path });
      verdict(r.allowed, r.allowed ? "Allowed" : "Denied", r.reason);
    } catch (err) { verdict(false, "Error", err.message); }
  });
});

// dialogs
for (const b of document.querySelectorAll("[data-close]")) b.addEventListener("click", () => b.closest("dialog").close());
for (const d of document.querySelectorAll("dialog")) {
  let down = null;
  d.addEventListener("pointerdown", (e) => (down = e.target));
  d.addEventListener("click", (e) => { if (e.target === d && down === d && d.id !== "secret-dialog" && d.id !== "wiz") d.close(); });
  d.addEventListener("close", () => setTimeout(restoreFocus));
}
document.addEventListener("visibilitychange", () => { if (!document.hidden && !$("#app").hidden) refresh(); });

// boot
api("GET", "/session").then((s) => (s.authenticated ? showApp() : showLogin())).catch(showLogin);

// new-key wizard: pick a service, say where it runs, create the real token
// on the service's own page, then create a scoped virtual key for it.
const wiz = { step: "pick", preset: null, variant: null, level: "read", values: {} };
const variantOf = () => wiz.preset.variants.find((v) => v.id === wiz.variant);
const pv = (k) => variantOf()[k] ?? wiz.preset[k];
const levelsOf = () => pv("levels");

function normalizeURL(raw) {
  let s = raw.trim();
  if (!s) return "";
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (!/^https?:$/.test(u.protocol) || !u.hostname || u.username || u.password) return null;
  return (u.origin + u.pathname).replace(/\/+$/, "");
}

function fieldValues() {
  const out = {};
  for (const f of variantOf().fields) {
    const raw = ($("#wf-" + f.id)?.value || "").trim();
    if (f.kind === "site") {
      let site = raw.replace(/^https?:\/\//i, "").toLowerCase();
      const cut = site.indexOf(f.suffix);
      if (cut >= 0) site = site.slice(0, cut);
      if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(site)) throw new Error(`${f.label}: enter the name before ${f.suffix}.`);
      out[f.id] = site;
    } else if (f.kind === "url") {
      const u = normalizeURL(raw);
      if (!u) throw new Error(`${f.label}: enter the address of your server, for example ${f.placeholder}.`);
      out[f.id] = u;
    } else if (f.kind === "email") {
      if (!/^[^\s@:]+@[^\s@:]+$/.test(raw)) throw new Error(`${f.label}: enter an e-mail address.`);
      out[f.id] = raw;
    }
  }
  return out;
}

// The upstream that the wizard would create for the current answers.
function draftUpstream(name) {
  const v = variantOf();
  const auth = { ...v.auth };
  if (auth.type === "basic") auth.username = v.username(wiz.values);
  const up = { name, base_url: v.base(wiz.values), description: `${wiz.preset.name} · ${v.label}`, auth, timeout_seconds: 60 };
  const headers = pv("headers");
  if (headers) up.headers = { ...headers };
  return up;
}

function sameUpstream(u, d) {
  return u.base_url.replace(/\/+$/, "") === d.base_url && u.auth.type === d.auth.type && (u.auth.username || "") === (d.auth.username || "");
}
function existingMatch() {
  let d;
  try { wiz.values = fieldValues(); d = draftUpstream("x"); } catch { return null; }
  return state.data.upstreams.find((u) => sameUpstream(u, d)) || null;
}
function freeName(base, taken) {
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
}

function wizSteps() {
  const s = ["pick"];
  if (!wiz.preset) return s;
  const needsWhere = wiz.preset.variants.length > 1 || variantOf().fields.length || Object.keys(levelsOf()).length > 1 || !!wiz.reuse;
  if (needsWhere) s.push("where");
  if (!wiz.reuse || !$("#wiz-reuse-box").checked) s.push("token");
  s.push("key");
  return s;
}

function openWizard() {
  Object.assign(wiz, { step: "pick", preset: null, variant: null, level: "read", values: {}, reuse: null, tested: null });
  $("#wiz-presets").replaceChildren(...PRESETS.map((p) => {
    const used = state.data.upstreams.some((u) => u.name === p.id || u.name.startsWith(p.id + "-"));
    return el("button", { class: "tile", type: "button", "data-preset": p.id, onclick: () => pickPreset(p) },
      logo(p),
      el("span", { class: "tile-text" }, el("strong", {}, p.name), el("span", { class: "quiet small" }, used ? "Connected · " + p.blurb : p.blurb)));
  }));
  $("#wiz-custom").hidden = false;
  $("#wiz-secret").value = ""; $("#wiz-env").value = "";
  showStep("pick");
  $("#wiz").showModal();
  $("#wiz-presets .tile").focus();
}

// CSP forbids inline style attributes; CSSOM property writes are allowed.
function logo(p) {
  const n = el("span", { class: "logo", "aria-hidden": "true" }, p.mark);
  n.style.setProperty("--c", p.color);
  return n;
}

function pickPreset(p) {
  wiz.preset = p; wiz.variant = p.variants[0].id; wiz.level = "read"; wiz.values = {}; wiz.tested = null;
  renderWhere();
  wiz.reuse = existingMatch();
  syncReuse();
  go(+1);
}

function renderWhere() {
  const p = wiz.preset;
  $("#wiz-variant-set").hidden = p.variants.length < 2;
  $("#wiz-variants").replaceChildren(...p.variants.map((v) =>
    el("label", {}, el("input", { type: "radio", name: "wiz-variant", value: v.id, checked: v.id === wiz.variant,
      onchange: () => { wiz.variant = v.id; renderFields(); onWhereInput(); } }), " ", v.label)));
  renderFields();
  const levels = levelsOf();
  if (!levels[wiz.level]) wiz.level = Object.keys(levels)[0];
  $("#wiz-level-set").hidden = false;
  $("#wiz-levels").replaceChildren(...Object.keys(levels).map((l) =>
    el("label", { class: "choice" }, el("input", { type: "radio", name: "wiz-level", value: l, checked: l === wiz.level,
      onchange: () => { wiz.level = l; } }),
    el("span", {}, el("strong", {}, l === "read" ? "Read only" : "Read and write"), el("span", { class: "quiet small" }, p.levelText[l])))));
}

function renderFields() {
  const prev = {};
  for (const i of document.querySelectorAll("#wiz-fields input")) prev[i.id] = i.value;
  $("#wiz-fields").replaceChildren(...variantOf().fields.map((f) => {
    const input = el("input", { id: "wf-" + f.id, placeholder: f.placeholder, spellcheck: "false", autocomplete: f.kind === "email" ? "email" : "off",
      type: f.kind === "email" ? "email" : f.kind === "url" ? "url" : "text", inputmode: f.kind === "url" ? "url" : null, oninput: onWhereInput });
    input.value = prev["wf-" + f.id] || "";
    const control = f.kind === "site" ? el("span", { class: "affix" }, el("span", { class: "quiet" }, f.prefix), input, el("span", { class: "quiet" }, f.suffix)) : input;
    return el("label", { class: "field" }, el("span", {}, f.label), control, f.hint ? el("small", { class: "quiet" }, f.hint) : null);
  }));
}

function onWhereInput() { wiz.reuse = existingMatch(); syncReuse(); }
function syncReuse() {
  const r = wiz.reuse;
  $("#wiz-reuse").hidden = !r;
  if (r) {
    $("#wiz-reuse span").textContent = r.problem ? `Use the existing /${r.name} connection (its credential is currently missing)` : `Use the existing /${r.name} connection — no new token needed`;
  }
  updateProgress();
}
$("#wiz-reuse-box").addEventListener("change", updateProgress);

function showStep(step) {
  wiz.step = step;
  for (const s of document.querySelectorAll("#wiz [data-step]")) s.hidden = s.dataset.step !== step;
  $("#wiz-back").hidden = step === "pick";
  $("#wiz-next").hidden = step === "pick";
  const p = wiz.preset;
  $("#wiz-title").textContent = step === "pick" ? "New key" : step === "where" ? `Connect ${p.name}`
    : step === "token" ? `${p.name} token` : "Agent key";
  $("#wiz-next").textContent = step === "key" ? "Create key" : "Continue";
  setError("#wiz-error");
  updateProgress();
  if (step === "token") enterToken();
  if (step === "key") enterKey();
}
function updateProgress() {
  const s = wizSteps();
  $("#wiz-progress").textContent = wiz.step === "pick" ? "" : `Step ${s.indexOf(wiz.step) + 1} of ${s.length}`;
}

function go(dir) {
  const s = wizSteps();
  const i = s.indexOf(wiz.step);
  const next = s[Math.min(s.length - 1, Math.max(0, i + dir))];
  showStep(next);
  const focus = {
    pick: "#wiz-presets .tile", where: "#wiz-fields input, #wiz-variants input:checked, #wiz-levels input:checked",
    token: "#wiz-token-link", key: "#wiz-key-id",
  }[next];
  $(focus)?.focus();
}
$("#wiz-back").addEventListener("click", () => go(-1));
$("#wiz-custom").addEventListener("click", () => { $("#wiz").close(); state.data.upstreams.length ? openKey() : openUpstream(); });

function tokenSource() { return document.querySelector('input[name="wiz-src"]:checked').value; }
function syncSource() {
  const src = tokenSource();
  for (const n of document.querySelectorAll("#wiz [data-src]")) n.hidden = n.dataset.src !== src;
  wiz.tested = null; $("#wiz-test-result").textContent = ""; $("#wiz-test-result").className = "test-result";
}
for (const r of document.querySelectorAll('input[name="wiz-src"]')) r.addEventListener("change", () => { syncSource(); $(tokenSource() === "paste" ? "#wiz-secret" : "#wiz-env").focus(); });
$("#wiz-secret").addEventListener("input", () => { wiz.tested = null; $("#wiz-test-result").textContent = ""; });

function enterToken() {
  const v = variantOf();
  const help = pv("tokenHelp");
  $("#wiz-token-help").textContent = help ? help(wiz.level) : "Create a personal access token for the account the agent should act as.";
  $("#wiz-token-link").href = v.token(wiz.values, wiz.level);
  const store = state.data.secret_storage;
  $("#wiz-nostore").hidden = store;
  document.querySelector('input[name="wiz-src"][value="paste"]').disabled = !store;
  if (!store) document.querySelector('input[name="wiz-src"][value="env"]').checked = true;
  if (!$("#wiz-env").value) $("#wiz-env").value = `${wiz.preset.env}_TOKEN`;
  $("#wiz-test").hidden = !pv("test");
  syncSource();
}

async function testToken(btn) {
  const out = $("#wiz-test-result");
  const body = { upstream: draftUpstream("draft"), path: pv("test") };
  if (tokenSource() === "paste") {
    const secret = $("#wiz-secret").value.trim();
    if (!secret) { out.className = "test-result bad"; out.textContent = "Paste the token first."; $("#wiz-secret").focus(); return; }
    body.secret = secret;
  } else {
    body.upstream.auth.secret_env = $("#wiz-env").value.trim();
  }
  out.className = "test-result"; out.textContent = "Testing…";
  await busy(btn, async () => {
    try {
      const r = await api("POST", "/probe", body);
      wiz.tested = r.ok;
      out.className = "test-result " + (r.ok ? "ok" : "bad");
      out.textContent = (r.ok ? "✓ " : "") + r.message[0].toUpperCase() + r.message.slice(1) + (r.status && !r.ok ? ` (${r.status})` : "");
    } catch (err) { out.className = "test-result bad"; out.textContent = err.message; }
  });
}
$("#wiz-test").addEventListener("click", (e) => testToken(e.currentTarget));

function enterKey() {
  const name = wiz.upstreamName();
  const ids = new Set(state.data.keys.map((k) => k.id));
  if (!$("#wiz-key-id").dataset.touched) $("#wiz-key-id").value = freeName(`${name}-agent`, ids);
  const grants = levelsOf()[wiz.level];
  $("#wiz-rules").replaceChildren(...grants.map((g) => el("div", { class: "grant fixed" },
    el("span", { class: "g-up mono" }, "/" + name),
    el("input", { "aria-label": "Methods", class: "g-methods", value: g.methods.join(" "), spellcheck: "false" }),
    el("textarea", { "aria-label": "Paths, one per line", class: "g-paths", rows: g.paths.length, spellcheck: "false" }, g.paths.join("\n")))));
  const note = pv("note");
  $("#wiz-note").textContent = note || ""; $("#wiz-note").hidden = !note;
}
$("#wiz-key-id").addEventListener("input", (e) => { e.target.dataset.touched = "1"; });

wiz.upstreamName = () => {
  if (wiz.reuse && $("#wiz-reuse-box").checked) return wiz.reuse.name;
  return freeName(wiz.preset.id, new Set(state.data.upstreams.map((u) => u.name)));
};

function validateStep() {
  if (wiz.step === "where") {
    wiz.values = fieldValues();
    wiz.reuse = existingMatch(); syncReuse();
  }
  if (wiz.step === "token") {
    if (tokenSource() === "paste" && !$("#wiz-secret").value.trim()) throw new Error("Paste the token you created, or choose Environment variable.");
    if (tokenSource() === "env" && !/^[A-Za-z_][A-Za-z0-9_]*$/.test($("#wiz-env").value.trim())) throw new Error("Enter a variable name such as " + wiz.preset.env + "_TOKEN.");
    if (wiz.tested === false && !$("#wiz-next").dataset.confirm) {
      $("#wiz-next").dataset.confirm = "1";
      throw new Error("The test failed. Fix the token or URL, or press Continue again to save it anyway.");
    }
  }
}

$("#wiz-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (wiz.step === "pick") return;
  try { validateStep(); } catch (err) { return setError("#wiz-error", err.message); }
  delete $("#wiz-next").dataset.confirm;
  if (wiz.step !== "key") return go(+1);
  await busy($("#wiz-next"), createFromWizard);
});

async function createFromWizard() {
  const id = $("#wiz-key-id").value.trim();
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(id)) return setError("#wiz-error", "Key name: use lowercase letters, digits, - and _.");
  const name = wiz.upstreamName();
  const grants = [...document.querySelectorAll("#wiz-rules .grant")].map((r) => ({
    upstream: name,
    methods: $(".g-methods", r).value.toUpperCase().split(/[\s,]+/).filter(Boolean),
    paths: $(".g-paths", r).value.split("\n").map((s) => s.trim()).filter(Boolean),
  })).filter((g) => g.methods.length && g.paths.length);
  if (!grants.length) return setError("#wiz-error", "Keep at least one access rule.");
  const rpm = parseInt($("#wiz-rpm").value || "0", 10);
  if (Number.isNaN(rpm) || rpm < 0) return setError("#wiz-error", "Per minute must be 0 or more.");
  const days = $("#wiz-expires").value;
  const expires = days ? new Date(Date.now() + days * 86400000).toISOString() : null;
  try {
    if (!(wiz.reuse && $("#wiz-reuse-box").checked)) {
      const up = draftUpstream(name);
      if (tokenSource() === "paste") up.secret = $("#wiz-secret").value.trim();
      else up.auth.secret_env = $("#wiz-env").value.trim();
      await api("PUT", "/upstreams/" + encodeURIComponent(name), up);
      $("#wiz-secret").value = "";
      // A retry after a failed key creation must not create a second upstream.
      await refresh();
      wiz.reuse = state.data.upstreams.find((u) => u.name === name); $("#wiz-reuse-box").checked = true;
    }
    const res = await api("POST", "/keys", { id, description: `${wiz.preset.name} · ${wiz.level === "read" ? "read only" : "read and write"}`,
      disabled: false, expires_at: expires, requests_per_minute: rpm, grants });
    $("#wiz").close();
    showSecret(res.key, name, { env: wiz.preset.env, test: pv("test") });
    delete $("#wiz-key-id").dataset.touched;
    await refresh();
  } catch (err) { setError("#wiz-error", err.message); }
}
$("#wiz").addEventListener("close", () => { $("#wiz-secret").value = ""; delete $("#wiz-key-id").dataset.touched; });
