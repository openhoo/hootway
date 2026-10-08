"use strict";

const $ = (s, el = document) => el.querySelector(s);
const state = { data: null, editingKey: null, editingUpstream: null, lastSeq: 0, events: [], timer: null };

// ---------- theme ----------
const root = document.documentElement;
const storedTheme = localStorage.getItem("hootway-theme");
if (storedTheme) root.dataset.theme = storedTheme;
$("#theme").addEventListener("click", () => {
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  localStorage.setItem("hootway-theme", root.dataset.theme);
});

// ---------- api ----------
async function api(method, path, body) {
  const res = await fetch("/api" + path, {
    method,
    headers: { "Content-Type": "application/json", "X-Hootway-Console": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty */ }
  if (res.status === 401 && path !== "/session") { showLogin(); throw new Error("Signed out"); }
  if (!res.ok) throw new Error((data && data.error && data.error.message) || `Request failed (${res.status})`);
  return data;
}

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) n.append(c);
  return n;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 2600);
}

function setError(sel, msg) { const e = $(sel); e.textContent = msg || ""; e.hidden = !msg; }

async function busy(btn, fn) {
  btn.disabled = true;
  try { return await fn(); } finally { btn.disabled = false; }
}

// ---------- session ----------
function showLogin() {
  stopPolling();
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

// ---------- routing ----------
const tabs = ["keys", "upstreams", "activity", "check"];
function route() {
  const tab = tabs.includes(location.hash.slice(1)) ? location.hash.slice(1) : "keys";
  for (const t of tabs) {
    $("#tab-" + t).hidden = t !== tab;
    const link = $(`nav a[data-tab="${t}"]`);
    if (t === tab) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  }
  document.title = `${tab[0].toUpperCase() + tab.slice(1)} · Hootway`;
  if (tab === "activity") startPolling(); else stopPolling();
}
addEventListener("hashchange", () => { route(); $("#main").focus({ preventScroll: true }); });

// ---------- data ----------
async function refresh() {
  if (!state.data) $("#keys").replaceChildren(el("div", { class: "skeleton" }), el("div", { class: "skeleton" }));
  try {
    state.data = await api("GET", "/state");
    render();
  } catch (err) {
    if (err.message !== "Signed out") {
      $("#keys").replaceChildren(el("div", { class: "empty" }, el("p", {}, "Could not load the gateway state."), el("p", {}, err.message),
        el("button", { class: "ghost", type: "button", onclick: refresh }, "Try again")));
    }
  }
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
  renderKeys(); renderUpstreams(); renderCheckKeys();
}
function stat(label, value) { return el("div", {}, el("dt", {}, label), el("dd", {}, String(value))); }

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
    list.replaceChildren(el("div", { class: "empty" },
      el("p", {}, "No keys yet"),
      el("p", {}, can ? "Create a key and give it to an agent instead of a real API token." : "Add an upstream first, then create a key for it."),
      el("button", { class: "primary", type: "button", onclick: () => (can ? openKey() : openUpstream()) }, can ? "New key" : "New upstream")));
    return;
  }
  list.replaceChildren(...d.keys.map((k) => {
    const status = k.disabled ? el("span", { class: "pill off" }, "disabled")
      : k.expired ? el("span", { class: "pill bad" }, "expired")
      : el("span", { class: "pill" }, "active");
    return el("article", { class: "card" },
      el("div", { class: "item-head" },
        el("h3", {}, k.id), status, el("span", { class: "spacer" }),
        el("button", { class: "link", type: "button", onclick: () => openKey(k) }, "Edit"),
        el("button", { class: "link", type: "button", onclick: () => toggleKey(k) }, k.disabled ? "Enable" : "Disable"),
        el("button", { class: "link", type: "button", onclick: () => rotateKey(k) }, "Rotate"),
        el("button", { class: "link danger ghost", type: "button", onclick: () => deleteKey(k) }, "Delete")),
      k.description ? el("p", { class: "quiet small", style: null }, k.description) : null,
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
    list.replaceChildren(el("div", { class: "empty" }, el("p", {}, "No upstreams yet"),
      el("p", {}, "An upstream is an API such as Jira that the gateway calls with its own credential."),
      el("button", { class: "primary", type: "button", onclick: () => openUpstream() }, "New upstream")));
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
        el("button", { class: "link", type: "button", onclick: () => openUpstream(u) }, "Edit")),
      u.description ? el("p", { class: "quiet small" }, u.description) : null,
      el("div", { class: "item-meta" },
        el("span", { class: "mono" }, u.base_url),
        el("span", {}, `${u.auth.type}${src ? " · " + src : ""}`),
        el("span", {}, `${users} key${users === 1 ? "" : "s"}`)),
      u.problem ? el("p", { class: "error", style: null }, u.problem) : null);
  }));
}

function renderCheckKeys() {
  const sel = $("#check-key");
  const cur = sel.value;
  sel.replaceChildren(...state.data.keys.map((k) => el("option", { value: k.id }, k.id)));
  if (cur) sel.value = cur;
}

// ---------- keys ----------
function grantRow(g = { upstream: "", methods: ["GET"], paths: [] }) {
  const ups = state.data.upstreams.map((u) => u.name);
  const row = el("div", { class: "grant" },
    el("select", { "aria-label": "Upstream", class: "g-up" }, ...ups.map((n) => el("option", { value: n, selected: n === g.upstream }, n))),
    el("input", { "aria-label": "Methods", class: "g-methods", value: g.methods.join(" "), placeholder: "GET POST", spellcheck: "false" }),
    el("textarea", { "aria-label": "Paths, one per line", class: "g-paths", rows: Math.max(1, g.paths.length), placeholder: "/rest/api/3/issue/*", spellcheck: "false" }, g.paths.join("\n")),
    el("button", { class: "link", type: "button", "aria-label": "Remove rule", onclick: () => row.remove() }, "✕"));
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
$("#new-key").addEventListener("click", () => openKey());
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

function showSecret(key, upstream) {
  $("#secret-value").textContent = key;
  const base = (state.data.gateway_url || location.origin.replace(/:\d+$/, ":8787")) + "/" + (upstream || "jira");
  $("#secret-snippet").textContent =
`export HOOTWAY_URL=${base}
export HOOTWAY_KEY=${key}
curl -H "Authorization: Bearer $HOOTWAY_KEY" "$HOOTWAY_URL/…"`;
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
async function toggleKey(k) {
  try { await api("PUT", "/keys/" + encodeURIComponent(k.id), keyBody(k, { disabled: !k.disabled })); toast(k.disabled ? "Key enabled" : "Key disabled"); await refresh(); }
  catch (err) { toast(err.message); }
}
function rotateKey(k) {
  confirmAction(`Rotate ${k.id}?`, "The current key stops working immediately. You will get a new key to give to the agent.", "Rotate", async () => {
    const res = await api("POST", `/keys/${encodeURIComponent(k.id)}/rotate`);
    showSecret(res.key, k.grants[0]?.upstream); await refresh();
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

// ---------- upstreams ----------
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
  const headers = {};
  for (const line of $("#up-headers").value.split("\n")) {
    if (!line.trim()) continue;
    const i = line.indexOf(":");
    if (i < 1) return setError("#up-error", `Header line "${line}" must look like Name: value.`);
    headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  const body = { name, base_url: v("#up-url"), description: v("#up-desc"), auth, timeout_seconds: parseInt($("#up-timeout").value || "0", 10) || 0 };
  if (Object.keys(headers).length) body.headers = headers;
  await busy($("#up-save"), async () => {
    try {
      await api("PUT", "/upstreams/" + encodeURIComponent(name), body);
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

// ---------- activity ----------
function startPolling() { if (!state.timer) { pollEvents(); state.timer = setInterval(pollEvents, 3000); } }
function stopPolling() { clearInterval(state.timer); state.timer = null; }
async function pollEvents() {
  try {
    const { events } = await api("GET", "/events?after=" + state.lastSeq);
    if (events.length) {
      state.lastSeq = events[events.length - 1].seq;
      state.events = state.events.concat(events).slice(-300);
    }
    renderEvents();
  } catch { /* shown on next refresh */ }
}
$("#activity-filter").addEventListener("change", renderEvents);
const outcomeText = {
  forwarded: "forwarded", forbidden: "not allowed", invalid_key: "invalid key", missing_key: "no key",
  bad_path: "unsafe path", rate_limited: "rate limited", upstream_error: "upstream failed", upstream_unconfigured: "no credential",
};
function renderEvents() {
  const f = $("#activity-filter").value;
  const list = state.events.filter((e) => !f || (f === "forwarded") === (e.outcome === "forwarded")).slice().reverse();
  const log = $("#activity");
  if (!list.length) {
    log.replaceChildren(el("div", { class: "empty", style: null }, el("p", {}, "Quiet so far"), el("p", {}, "Requests from agents appear here as they happen.")));
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

// ---------- check ----------
$("#check-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#check-result");
  if (!$("#check-key").value) { out.className = "verdict no"; out.replaceChildren(el("strong", {}, "No keys"), "Create a key first."); out.hidden = false; return; }
  try {
    const r = await api("POST", "/explain", { key: $("#check-key").value, method: $("#check-method").value, path: $("#check-path").value });
    out.className = "verdict " + (r.allowed ? "ok" : "no");
    out.replaceChildren(el("strong", {}, r.allowed ? "Allowed" : "Denied"), r.reason);
  } catch (err) { out.className = "verdict no"; out.replaceChildren(el("strong", {}, "Error"), err.message); }
  out.hidden = false;
});

// ---------- dialogs ----------
for (const b of document.querySelectorAll("[data-close]")) b.addEventListener("click", () => b.closest("dialog").close());
for (const d of document.querySelectorAll("dialog")) d.addEventListener("click", (e) => { if (e.target === d && d.id !== "secret-dialog") d.close(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden && !$("#app").hidden) refresh(); });

// ---------- boot ----------
api("GET", "/session").then((s) => (s.authenticated ? showApp() : showLogin())).catch(showLogin);
