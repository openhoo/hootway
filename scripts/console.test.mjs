// Console regression tests run with Node's standard library only.
import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFileSync } from "node:fs";

const appScript = new vm.Script(readFileSync(new URL("../internal/gateway/web/app.js", import.meta.url), "utf8"), { filename: "app.js" });
const presetsScript = new vm.Script(readFileSync(new URL("../internal/gateway/web/presets.js", import.meta.url), "utf8"), { filename: "presets.js" });
// The browser files keep these bindings lexical rather than exporting them.
// This fixed expression retrieves references; test values never become code.
const bindingsScript = new vm.Script("({ state, wiz, PRESETS })");

function consoleHarness() {
  const nodes = new Map(), groups = new Map();
  class Node {
    constructor() { this.value = ""; this.textContent = ""; this.dataset = {}; this.children = []; this.listeners = new Map(); this.hidden = false; this.disabled = false; this.isConnected = true; this.className = ""; this.fields = new Map(); }
    addEventListener(name, fn) { this.listeners.set(name, fn); }
    setAttribute(name, value) { if (name.startsWith("data-")) this.dataset[name.slice(5)] = value; else this[name] = value; }
    removeAttribute(name) { delete this[name]; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    querySelector(selector) { return this.fields.get(selector) || node(selector); }
    querySelectorAll() { return []; }
    closest() { return null; }
    focus() { document.activeElement = this; }
    select() { this.focus(); }
    showModal() { this.open = true; }
    close() { this.open = false; this.listeners.get("close")?.(); }
  }
  const node = (selector) => { if (!nodes.has(selector)) nodes.set(selector, new Node()); return nodes.get(selector); };
  const document = {
    documentElement: new Node(), body: new Node(), hidden: false,
    querySelector: node, querySelectorAll: (selector) => groups.get(selector) || [],
    createElement: () => new Node(), addEventListener() {}, activeElement: null,
  };
  document.activeElement = document.body;
  const context = vm.createContext({ document, URL, Date, CSS: { escape: (x) => x },
    matchMedia: () => ({ matches: false, addEventListener() {} }), localStorage: { getItem() {}, setItem() {} },
    location: { hash: "" }, addEventListener() {}, navigator: {}, getSelection() {},
    setTimeout: () => 1, clearTimeout() {}, AbortController,
    fetch: () => new Promise(() => {}), PRESETS: [],
  }, { codeGeneration: { strings: false, wasm: false } });
  presetsScript.runInContext(context);
  appScript.runInContext(context);
  const { state, wiz, PRESETS } = bindingsScript.runInContext(context);
  state.data = { upstreams: [], keys: [], totals: { forwarded: 0, denied: 0 }, persistent: true, secret_storage: true, gateway_url: "http://localhost:8787" };
  return { context, state, wiz, presets: PRESETS, node, groups, document, Node };
}
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
const response = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });

// These inputs used to be silently truncated to integers by parseInt.
test("quotas and timeouts reject fractions and exponent notation", () => {
  const h = consoleHarness();
  for (const raw of ["1.5", "1e3", "-1", "Infinity", "9007199254740992"]) {
    assert.throws(() => h.context.wholeNumber(raw, "Quota"));
  }
  assert.equal(h.context.wholeNumber("120", "Quota"), 120);
  assert.equal(h.context.wholeNumber("", "Quota"), 0);
});

test("URL answers reject queries, fragments and ambiguous paths", () => {
  const h = consoleHarness();
  assert.equal(h.context.normalizeURL("example.com/service/"), "https://example.com/service");
  for (const raw of ["https://example.com?token=x", "https://example.com/#view", "https://example.com/a/../b", "https://example.com/%2e%2e/b", "https://example.com/a//b", "https://example.com/a%2fb", "https://user:pass@example.com"]) {
    assert.equal(h.context.normalizeURL(raw), null, raw);
  }
});

test("shell values keep command substitution and quotes literal", () => {
  const h = consoleHarness();
  assert.equal(h.context.shellQuote("https://example.com/$(touch /tmp/nope)'"), "'https://example.com/$(touch /tmp/nope)'\"'\"''");
  h.state.data.upstreams = [{ name: "test", base_url: "https://example.com/$(whoami)" }];
  h.state.data.proxy = true;
  h.context.showSecret("hw_demo", "test");
  assert.match(h.node("#secret-snippet").textContent, /export HOOTWAY_URL='http:\/\/localhost:8787\/test'/);
  assert.match(h.node("#secret-snippet").textContent, /curl 'https:\/\/example.com\/\$\(whoami\)\/…'/);
});

test("upstream reuse includes credential and header semantics", () => {
  const h = consoleHarness();
  const up = { base_url: "https://example.com", auth: { type: "header", name: "Authorization", prefix: "" }, headers: { "Api-Version": "1" } };
  assert.equal(h.context.sameUpstream(up, up), true);
  assert.equal(h.context.sameUpstream(up, { ...up, auth: { ...up.auth, name: "X-API-Key" } }), false);
  assert.equal(h.context.sameUpstream(up, { ...up, auth: { ...up.auth, prefix: "Bearer " } }), false);
  assert.equal(h.context.sameUpstream(up, { ...up, headers: { "Api-Version": "2" } }), false);
});

test("sign out rejects late API results and clears all secret fields", async () => {
  const h = consoleHarness(); const d = deferred();
  h.context.fetch = () => d.promise;
  h.node("#up-secret").value = "fake upstream token";
  h.node("#wiz-secret").value = "fake wizard token";
  h.node("#secret-value").textContent = "hw_fake";
  const pending = h.context.api("GET", "/state");
  h.context.showLogin();
  d.resolve(response({ stale: true }));
  await assert.rejects(pending, /Signed out/);
  assert.equal(h.node("#up-secret").value, "");
  assert.equal(h.node("#wiz-secret").value, "");
  assert.equal(h.node("#secret-value").textContent, "");
});

test("an older state response cannot replace a later refresh", async () => {
  const h = consoleHarness(); const a = deferred(), b = deferred(); let calls = 0;
  h.context.fetch = () => (++calls === 1 ? a.promise : b.promise);
  const first = h.context.refresh(), second = h.context.refresh();
  const data = { upstreams: [], keys: [], persistent: true, totals: {forwarded: 0, denied: 0} };
  b.resolve(response({ ...data, marker: "new" })); await second;
  a.resolve(response({ ...data, marker: "old" })); await first;
  assert.equal(h.state.data.marker, "new");
});

test("stopping activity polling prevents late results from being rendered", async () => {
  const h = consoleHarness(); const d = deferred(); h.context.fetch = () => d.promise;
  const pending = h.context.startPolling();
  h.context.stopPolling();
  d.resolve(response({events:[{seq:1, time:new Date().toISOString(), outcome:"forwarded", method:"GET", path:"/x", status:200}]}));
  await pending; await new Promise((r) => setImmediate(r));
  assert.equal(h.state.events.length, 0);
});

test("a wizard retry reuses the connection persisted before key failure", async () => {
  const h = consoleHarness(); const requests = []; let failKey = true;
  h.node("#wiz-key-id").value = "agent"; h.node("#wiz-rpm").value = "120"; h.node("#wiz-secret").value = "fake";
  h.node('input[name="wiz-src"]:checked').value = "paste";
  const row = new h.Node(); row.fields.set(".g-methods", new h.Node()); row.fields.get(".g-methods").value = "GET";
  row.fields.set(".g-paths", new h.Node()); row.fields.get(".g-paths").value = "/user";
  h.groups.set("#wiz-rules .grant", [row]);
  Object.assign(h.wiz, { preset: h.presets.find((p) => p.id === "github"), variant: "cloud", level: "read", values: {}, reuse: null, step: "key" });
  h.context.fetch = async (url, options) => {
    requests.push([url, options.method]);
    if (url === "/api/state") return response({error:{message:"offline"}}, 503);
    if (url === "/api/keys" && failKey) { failKey = false; return response({error:{message:"key conflict"}}, 422); }
    return response(url === "/api/keys" ? {key:"hw_fake"} : {name:"github",base_url:"https://api.github.com",auth:{type:"bearer",secret_file:"/tmp/fake"}});
  };
  await h.context.createFromWizard();
  await h.context.createFromWizard();
  assert.equal(requests.filter(([url]) => url.startsWith("/api/upstreams/")).length, 1);
  assert.equal(requests.filter(([url]) => url === "/api/keys").length, 2);
});

test("suggested names stay within the schema limit even after a collision", () => {
  const h = consoleHarness();
  const base = "a".repeat(63);
  const suggestion = h.context.freeName(base + "-agent", new Set([base]));
  assert.equal(suggestion.length, 63);
  assert.equal(suggestion.slice(-2), "-2");
});

test("editing a key preserves the precise expiry when the date field is unchanged", () => {
  const h = consoleHarness();
  const expiry = "2027-01-01T12:34:56.789Z";
  h.state.editingKey = { id: "agent", expires_at: expiry };
  h.node("#key-id").value = "agent";
  h.node("#key-expires").value = h.context.toLocalInput(expiry);
  const row = new h.Node();
  for (const [selector, value] of [[".g-up", "jira"], [".g-methods", "GET"], [".g-paths", "/rest/api/3/myself"]]) {
    const n = new h.Node(); n.value = value; row.fields.set(selector, n);
  }
  h.groups.set("#grant-rows .grant", [row]);
  assert.equal(h.context.readKeyForm().expires_at, expiry);
});

test("changing Check inputs while awaiting a response cannot display an obsolete verdict", async () => {
  const h = consoleHarness(); const d = deferred(); h.context.fetch = () => d.promise;
  h.node("#check-key").value = "agent"; h.node("#check-method").value = "GET"; h.node("#check-path").value = "/jira/old";
  h.node("#check-result").hidden = true;
  const pending = h.node("#check-form").listeners.get("submit")({preventDefault() {}, submitter:new h.Node()});
  h.node("#check-path").value = "/jira/new";
  d.resolve(response({allowed:true,reason:"granted"})); await pending;
  assert.equal(h.node("#check-result").hidden, true);
});

test("an incomplete wizard rule is rejected before any upstream or key mutation", async () => {
  const h = consoleHarness(); let calls = 0; h.context.fetch = async () => { calls++; return response({}); };
  h.node("#wiz-key-id").value = "agent"; h.node("#wiz-rpm").value = "120";
  Object.assign(h.wiz, { preset: h.presets.find((p) => p.id === "github"), variant: "cloud", level: "read", values: {}, reuse: null });
  const row = new h.Node();
  row.fields.set(".g-methods", new h.Node()); row.fields.get(".g-methods").value = "GET";
  row.fields.set(".g-paths", new h.Node());
  h.groups.set("#wiz-rules .grant", [row]);
  await h.context.createFromWizard();
  assert.equal(calls, 0);
  assert.match(h.node("#wiz-error").textContent, /Each access rule/);
});

test("a probe result cannot approve a token after its inputs have changed", async () => {
  const h = consoleHarness(); const d = deferred(); h.context.fetch = () => d.promise;
  Object.assign(h.wiz, { preset: h.presets.find((p) => p.id === "github"), variant: "cloud", values: {}, probe: 0, step: "token" });
  h.node("#wiz").open = true; h.node("#wiz-secret").value = "first fake token";
  h.node('input[name="wiz-src"]:checked').value = "paste";
  const pending = h.context.testToken(h.node("#wiz-test"));
  h.node("#wiz-secret").value = "second fake token"; h.context.resetProbe();
  d.resolve(response({ok:true,message:"connection works",status:200})); await pending;
  assert.equal(h.wiz.tested, null);
  assert.equal(h.node("#wiz-test-result").textContent, "");
});

test("Bitbucket token instructions show current vendor scope names", () => {
  const h = consoleHarness();
  const help = h.presets.find((p) => p.id === "bitbucket").variants[0].tokenHelp("write");
  for (const scope of ["read:user:bitbucket", "read:repository:bitbucket", "read:pullrequest:bitbucket", "write:pullrequest:bitbucket"]) assert.match(help, new RegExp(scope));
});
