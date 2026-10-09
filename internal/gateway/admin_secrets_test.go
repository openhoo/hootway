package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleStoresPastedSecretWriteOnly(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	c, gw, path := newConsole(t, up.URL)
	gw.getenv = os.Getenv
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)

	const secret = "glpat-super-secret-value"
	code, res := c.call("PUT", "/api/upstreams/gitlab", map[string]any{
		"base_url": up.URL, "auth": map[string]string{"type": "bearer"}, "secret": secret}, true)
	if code != 200 {
		t.Fatalf("save upstream: %d %v", code, res)
	}
	file := gw.Config().Upstreams[1].Auth.SecretFile
	if filepath.Dir(file) != filepath.Join(filepath.Dir(path), "secrets") {
		t.Fatalf("secret file %q not in managed directory", file)
	}
	if st, err := os.Stat(file); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode: %v %v", st, err)
	}
	saved, _ := os.ReadFile(path)
	_, state := c.call("GET", "/api/state", nil, true)
	b, _ := json.Marshal(state)
	b2, _ := json.Marshal(res)
	if strings.Contains(string(saved)+string(b)+string(b2), secret) {
		t.Fatal("secret leaked into config, state or response")
	}
	if gw.Problems()["gitlab"] != "" {
		t.Fatalf("problem: %s", gw.Problems()["gitlab"])
	}

	// The stored secret is injected upstream.
	_, kres := c.call("POST", "/api/keys", map[string]any{"id": "a", "grants": []Grant{{Upstream: "gitlab", Methods: []string{"GET"}, Paths: []string{"/**"}}}}, true)
	if rec := do(gw, "GET", "/gitlab/user", kres["key"].(string), nil); rec.Code != 200 || got.authz != "Bearer "+secret {
		t.Fatalf("forward: %d %q", rec.Code, got.authz)
	}

	// Replacing the secret removes the old file; an invalid save keeps it.
	if code, _ := c.call("PUT", "/api/upstreams/gitlab", map[string]any{"base_url": "nope", "auth": map[string]string{"type": "bearer"}, "secret": "x2"}, true); code != 422 {
		t.Fatalf("invalid save: %d", code)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("failed save removed the active secret")
	}
	if n, _ := filepath.Glob(filepath.Join(filepath.Dir(file), "*")); len(n) != 1 {
		t.Fatalf("failed save left files: %v", n)
	}
	c.call("PUT", "/api/upstreams/gitlab", map[string]any{"base_url": up.URL, "auth": map[string]string{"type": "bearer"}, "secret": "second"}, true)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("old secret file not removed after replacement")
	}

	// Secrets with line breaks are refused.
	if code, _ := c.call("PUT", "/api/upstreams/gitlab", map[string]any{"base_url": up.URL, "auth": map[string]string{"type": "bearer"}, "secret": "a\nb"}, true); code != 422 {
		t.Fatalf("multiline secret: %d", code)
	}

	// Deleting the upstream removes its managed secret.
	c.call("DELETE", "/api/keys/a", nil, true)
	file = gw.Config().Upstreams[1].Auth.SecretFile
	if code, _ := c.call("DELETE", "/api/upstreams/gitlab", nil, true); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("secret file not removed with upstream")
	}
}

func TestConsoleSecretNeedsWritableConfig(t *testing.T) {
	cfg, _ := ParseConfig([]byte(`{"upstreams":[],"keys":[]}`))
	gw, _ := New(cfg, Options{})
	srv := httptest.NewServer(NewAdmin(gw, "", HashKey(adminToken), "http://gw"))
	defer srv.Close()
	req, _ := http.NewRequest("PUT", srv.URL+"/api/upstreams/x", strings.NewReader(`{"base_url":"https://example.com","auth":{"type":"bearer"},"secret":"s"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Hootway-Console", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 422 {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestConsoleProbe(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	c, _, _ := newConsole(t, up.URL)
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)

	// Draft with a pasted secret: only the status comes back.
	_, res := c.call("POST", "/api/probe", map[string]any{"upstream": map[string]any{"base_url": up.URL, "auth": map[string]string{"type": "basic", "username": "me@x"}},
		"secret": "tok", "path": "/rest/api/3/myself"}, true)
	if res["ok"] != true || got.path != "/rest/api/3/myself" || got.authz != "Basic bWVAeDp0b2s=" {
		t.Fatalf("probe: %v %+v", res, got)
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), "tok") {
		t.Fatal("probe echoed the secret")
	}
	// Active upstream by name.
	if _, res := c.call("POST", "/api/probe", map[string]any{"name": "jira", "path": "/x"}, true); res["ok"] != true || got.authz != "Bearer real" {
		t.Fatalf("named probe: %v %q", res, got.authz)
	}
	// Unsafe or query paths are refused before anything is sent.
	got = seen{}
	for _, p := range []string{"/a/../b", "/a?x=1", "a", "/a//b", "/%2e%2e/x"} {
		if code, _ := c.call("POST", "/api/probe", map[string]any{"name": "jira", "path": p}, true); code != 422 {
			t.Fatalf("%s: %d", p, code)
		}
	}
	if got.path != "" {
		t.Fatal("unsafe probe reached the upstream")
	}
	// Probes require the console header and a session.
	if code, _ := c.call("POST", "/api/probe", map[string]any{"name": "jira", "path": "/x"}, false); code != 403 {
		t.Fatalf("csrf: %d", code)
	}
}
