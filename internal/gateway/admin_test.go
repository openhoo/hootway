package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const adminToken = "hwa_test-admin"

type console struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
}

func (c *console) call(method, path string, body any, header bool) (int, map[string]any) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, r)
	if header {
		req.Header.Set("X-Hootway-Console", "1")
	}
	res, err := c.client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func newConsole(t *testing.T, upstream string) (*console, *Gateway, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hootway.json")
	raw := `{"upstreams":[{"name":"jira","base_url":"` + upstream + `","auth":{"type":"bearer","secret_env":"T"}}],"keys":[]}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(cfg, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Getenv: func(string) string { return "real" }})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewAdmin(gw, path, HashKey(adminToken), "http://gw"))
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &console{t: t, srv: srv, client: &http.Client{Jar: jar}}, gw, path
}

func TestConsoleLifecycle(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	c, gw, path := newConsole(t, up.URL)

	if code, _ := c.call("GET", "/api/state", nil, true); code != 401 {
		t.Fatalf("unauthenticated state: %d", code)
	}
	if code, _ := c.call("POST", "/api/session", map[string]string{"token": "nope"}, true); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	if code, _ := c.call("POST", "/api/session", map[string]string{"token": adminToken}, true); code != 200 {
		t.Fatalf("login: %d", code)
	}
	grant := []Grant{{Upstream: "jira", Methods: []string{"GET"}, Paths: []string{"/issue/*"}}}
	if code, _ := c.call("POST", "/api/keys", map[string]any{"id": "agent", "grants": grant}, false); code != 403 {
		t.Fatalf("missing csrf header: %d", code)
	}
	code, res := c.call("POST", "/api/keys", map[string]any{"id": "agent", "grants": grant}, true)
	if code != 200 {
		t.Fatalf("create key: %d %v", code, res)
	}
	key := res["key"].(string)

	// The new key works immediately and was persisted as a hash only.
	if rec := do(gw, "GET", "/jira/issue/A-1", key, nil); rec.Code != 200 {
		t.Fatalf("new key: %d", rec.Code)
	}
	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), key) || !strings.Contains(string(saved), HashKey(key)) {
		t.Fatal("config must contain the hash and not the key")
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("persisted config invalid: %v", err)
	}

	// Invalid changes are rejected and nothing changes.
	if code, _ := c.call("PUT", "/api/keys/agent", map[string]any{"grants": []Grant{{Upstream: "nope", Methods: []string{"GET"}, Paths: []string{"/**"}}}}, true); code != 422 {
		t.Fatalf("invalid grant: %d", code)
	}
	if rec := do(gw, "GET", "/jira/issue/A-1", key, nil); rec.Code != 200 {
		t.Fatal("rejected update must not change the active config")
	}

	// Explain.
	_, ex := c.call("POST", "/api/explain", map[string]string{"key": "agent", "method": "DELETE", "path": "/jira/issue/A-1"}, true)
	if ex["allowed"] != false || ex["outcome"] != "forbidden" {
		t.Fatalf("explain: %v", ex)
	}

	// State and events never expose the key.
	_, st := c.call("GET", "/api/state", nil, true)
	b, _ := json.Marshal(st)
	_, ev := c.call("GET", "/api/events", nil, true)
	eb, _ := json.Marshal(ev)
	if strings.Contains(string(b)+string(eb), key) || strings.Contains(string(b), HashKey(key)) || strings.Contains(string(b), "real") {
		t.Fatal("state leaked a key, hash or secret")
	}
	if !strings.Contains(string(eb), `"outcome":"forwarded"`) {
		t.Fatalf("events missing request: %s", eb)
	}

	// Rotate: old key stops working, new key works.
	_, rot := c.call("POST", "/api/keys/agent/rotate", nil, true)
	newKey := rot["key"].(string)
	if rec := do(gw, "GET", "/jira/issue/A-1", key, nil); rec.Code != 401 {
		t.Fatalf("old key after rotate: %d", rec.Code)
	}
	if rec := do(gw, "GET", "/jira/issue/A-1", newKey, nil); rec.Code != 200 {
		t.Fatalf("new key after rotate: %d", rec.Code)
	}

	// Upstream in use cannot be deleted; key deletion revokes access.
	if code, _ := c.call("DELETE", "/api/upstreams/jira", nil, true); code != 422 {
		t.Fatalf("delete used upstream: %d", code)
	}
	if code, _ := c.call("DELETE", "/api/keys/agent", nil, true); code != 200 {
		t.Fatalf("delete key: %d", code)
	}
	if rec := do(gw, "GET", "/jira/issue/A-1", newKey, nil); rec.Code != 401 {
		t.Fatalf("deleted key: %d", rec.Code)
	}

	// Logout ends the session.
	c.call("DELETE", "/api/session", nil, true)
	if code, _ := c.call("GET", "/api/state", nil, true); code != 401 {
		t.Fatalf("after logout: %d", code)
	}
}

func TestUpstreamWithMissingSecretIsReportedNotFatal(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	c, gw, _ := newConsole(t, up.URL)
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	code, res := c.call("PUT", "/api/upstreams/gh", map[string]any{"base_url": "https://api.github.com", "auth": map[string]string{"type": "bearer", "secret_env": "MISSING"}}, true)
	if code != 200 {
		t.Fatalf("save upstream: %d %v", code, res)
	}
	gw.getenv = func(string) string { return "" }
	gw.Apply(gw.Config())
	if gw.Problems()["gh"] == "" {
		t.Fatal("expected credential problem")
	}
}

func TestConsoleServesUIWithSecurityHeaders(t *testing.T) {
	c, _, _ := newConsole(t, "http://127.0.0.1:1")
	for _, p := range []string{"/", "/app.js", "/app.css", "/anything"} {
		res, err := c.client.Get(c.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("%s: %d %q", p, res.StatusCode, res.Header.Get("Content-Security-Policy"))
		}
	}
}

func TestConsoleAssetsCompressedAndRevalidated(t *testing.T) {
	c, _, _ := newConsole(t, "http://127.0.0.1:1")
	tr := &http.Transport{DisableCompression: true}
	get := func(path string, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest("GET", c.srv.URL+path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res
	}
	res := get("/app.js", map[string]string{"Accept-Encoding": "gzip, br"})
	if res.Header.Get("Content-Encoding") != "gzip" || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/javascript") || res.Header.Get("ETag") == "" {
		t.Fatalf("headers: %v", res.Header)
	}
	if res := get("/app.js", nil); res.Header.Get("Content-Encoding") != "" {
		t.Fatal("gzip without Accept-Encoding")
	}
	if res := get("/app.js", map[string]string{"If-None-Match": res.Header.Get("ETag")}); res.StatusCode != http.StatusNotModified {
		t.Fatalf("revalidate: %d", res.StatusCode)
	}
	if res := get("/keys", nil); res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("spa fallback: %d %v", res.StatusCode, res.Header)
	}
}

func TestEmbeddedConsoleAssetsMatchSources(t *testing.T) {
	sources, _ := filepath.Glob("web/*.*")
	n := 0
	for _, src := range sources {
		if strings.HasSuffix(src, ".gz") {
			continue
		}
		n++
		want, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		a := webAssets[filepath.Base(src)]
		if a == nil || !bytes.Equal(a.raw, want) {
			t.Errorf("%s: embedded asset is stale; run scripts/compress-web.sh", src)
		}
	}
	if n == 0 || n != len(webAssets) {
		t.Fatalf("%d sources, %d embedded assets", n, len(webAssets))
	}
}
