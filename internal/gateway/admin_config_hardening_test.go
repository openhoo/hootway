package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigRejectsAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{
		`null`, `{}]`, `{} }`, `{} true`, `{} {}`,
		`{"keys":[],"keys":[]}`, `{"keys":[],"KEYS":[]}`,
		`{"upstreams":[{"name":"x","base_url":"https://example.com","auth":{"type":"none","type":"bearer","secret_env":"S"}}]}`,
	} {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("ambiguous JSON accepted: %s", raw)
		}
	}
	if _, err := ParseConfig([]byte("{} \n\t")); err != nil {
		t.Fatalf("trailing whitespace: %v", err)
	}
}

func TestConfigRejectsUnsafeBaseURLs(t *testing.T) {
	for _, base := range []string{
		"https://:443", "https://example.com?", "https://example.com#",
		"https://example.com/a/../b", "https://example.com/a//b", "https://example.com/a%2Fb",
		"https://example.com/%2e/x", "https://example.com/a;param=1", "https://example.com/a%5cb",
	} {
		data, _ := json.Marshal(Config{Upstreams: []Upstream{{Name: "x", BaseURL: base, Auth: Auth{Type: "none"}}}})
		if _, err := ParseConfig(data); err == nil {
			t.Errorf("unsafe base URL accepted: %s", base)
		}
	}
	data, _ := json.Marshal(Config{Upstreams: []Upstream{{Name: "x", BaseURL: "https://example.com/api%20v1/", Auth: Auth{Type: "none"}}}})
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("safe encoded base path rejected: %v", err)
	}
	if got := cfg.Upstreams[0].base.EscapedPath(); got != "/api%20v1" {
		t.Fatalf("escaped base path: %q", got)
	}
}

func TestConfigRejectsInvalidMethodsAndTimeoutOverflow(t *testing.T) {
	for _, method := range []string{"", "GET POST", "GET\r\n", "GÉT", "get"} {
		cfg := &Config{Upstreams: []Upstream{{Name: "x", BaseURL: "https://example.com", Auth: Auth{Type: "none"}}}, Keys: []Key{{ID: "k", SHA256: HashKey("test"), Grants: []Grant{{Upstream: "x", Methods: []string{method}, Paths: []string{"/**"}}}}}}
		if err := cfg.validate(); err == nil {
			t.Errorf("invalid method accepted: %q", method)
		}
	}
	cfg := &Config{Upstreams: []Upstream{{Name: "x", BaseURL: "https://example.com", Auth: Auth{Type: "none"}, TimeoutSeconds: int((1<<63-1)/int64(time.Second)) + 1}}}
	if err := cfg.validate(); err == nil {
		t.Fatal("timeout duration overflow accepted")
	}
}

func TestAdminDecodeRejectsAmbiguousAndOversizedBodiesWithoutReflectingSecrets(t *testing.T) {
	const secret = "synthetic-secret-that-must-not-be-reflected"
	for _, tt := range []struct {
		name, body string
		want       int
	}{
		{"trailing value", `{"token":"` + adminToken + `"} {}`, 400},
		{"trailing delimiter", `{"token":"` + adminToken + `"}]`, 400},
		{"duplicate", `{"token":"wrong","token":"` + adminToken + `"}`, 400},
		{"case alias", `{"Token":"wrong","token":"` + adminToken + `"}`, 400},
		{"null", `null`, 400},
		{"unknown secret field", `{"` + secret + `":"x"}`, 400},
		{"oversized whitespace", `{"token":"` + adminToken + `"}` + strings.Repeat(" ", 1<<20), 413},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var dst struct{ Token string }
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/session", strings.NewReader(tt.body))
			if decode(rec, req, &dst) {
				t.Fatal("malformed body accepted")
			}
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatal("secret reflected in decoding error")
			}
		})
	}
}

func TestConsoleFailedPersistPreservesLiveStateAndCleansNewSecret(t *testing.T) {
	c, gw, path := newConsole(t, "https://example.com")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Renaming a regular file over a directory must fail, even as root.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.call("PUT", "/api/upstreams/new", map[string]any{"base_url": "https://example.com", "auth": map[string]string{"type": "bearer"}, "secret": "synthetic"}, true); code != 500 {
		t.Fatalf("failed persist status = %d", code)
	}
	if len(gw.Config().Upstreams) != 1 {
		t.Fatal("failed persistence applied a new upstream")
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "secrets", "*"))
	if len(files) != 0 {
		t.Fatalf("failed persistence orphaned secret files: %v", files)
	}
	temps, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".hootway-*"))
	if len(temps) != 0 {
		t.Fatalf("failed persistence orphaned temporary files: %v", temps)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleFingerprintDoesNotExposeStoredKeyHash(t *testing.T) {
	c, gw, _ := newConsole(t, "https://example.com")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	_, result := c.call("POST", "/api/keys", map[string]any{"id": "k", "grants": []Grant{{Upstream: "jira", Methods: []string{"GET"}, Paths: []string{"/**"}}}}, true)
	if result["key"] == nil {
		t.Fatalf("create key: %v", result)
	}
	_, state := c.call("GET", "/api/state", nil, true)
	key := state["keys"].([]any)[0].(map[string]any)
	fp := key["fingerprint"].(string)
	if fp == gw.Config().Keys[0].SHA256[:8] || len(fp) != 8 {
		t.Fatal("fingerprint exposes a stored key hash prefix")
	}
}

func TestConsoleProbePreservesEscapedBasePathAndDoesNotFollowRedirect(t *testing.T) {
	var requests []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.RequestURI)
		w.Header().Set("Location", "/redirected")
		w.Header().Set("Set-Cookie", "private=synthetic")
		w.WriteHeader(http.StatusFound)
		io.WriteString(w, "synthetic-private-body")
	}))
	defer up.Close()
	c, _, _ := newConsole(t, up.URL+"/api%23v1")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	code, result := c.call("POST", "/api/probe", map[string]string{"name": "jira", "path": "/x%20y"}, true)
	if code != 200 || result["status"] != float64(302) || len(requests) != 1 || requests[0] != "/api%23v1/x%20y" {
		t.Fatalf("probe path/redirect: code=%d result=%v requests=%v", code, result, requests)
	}
	body, _ := json.Marshal(result)
	if bytes.Contains(body, []byte("synthetic")) {
		t.Fatal("probe exposes private response content")
	}
}

func TestManagedSecretCleanupPreservesSharedAndUnmanagedFiles(t *testing.T) {
	for _, managed := range []bool{true, false} {
		t.Run(map[bool]string{true: "shared managed", false: "unmanaged"}[managed], func(t *testing.T) {
			c, gw, path := newConsole(t, "https://example.com")
			c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
			file := filepath.Join(filepath.Dir(path), "secrets", "hand-written-token")
			if managed {
				code, result := c.call("PUT", "/api/upstreams/one", map[string]any{"base_url": "https://example.com", "auth": map[string]string{"type": "bearer"}, "secret": "synthetic"}, true)
				if code != 200 {
					t.Fatalf("create managed secret: %v", result)
				}
				file = gw.Config().Upstreams[1].Auth.SecretFile
			} else {
				if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte("synthetic"), 0o600); err != nil {
					t.Fatal(err)
				}
				if code, result := c.call("PUT", "/api/upstreams/one", map[string]any{"base_url": "https://example.com", "auth": map[string]string{"type": "bearer", "secret_file": file}}, true); code != 200 {
					t.Fatalf("use unmanaged secret: %v", result)
				}
			}
			if managed {
				if code, result := c.call("PUT", "/api/upstreams/two", map[string]any{"base_url": "https://example.com", "auth": map[string]string{"type": "bearer", "secret_file": file}}, true); code != 200 {
					t.Fatalf("share managed secret: %v", result)
				}
			}
			if code, _ := c.call("DELETE", "/api/upstreams/one", nil, true); code != 200 {
				t.Fatalf("delete upstream: %d", code)
			}
			if _, err := os.Stat(file); err != nil {
				t.Fatal("cleanup removed a shared or unmanaged secret")
			}
			gw.Apply(gw.Config())
			if managed && gw.Problems()["two"] != "" {
				t.Fatalf("shared upstream broken after reload: %v", gw.Problems())
			}
			if managed {
				if code, _ := c.call("DELETE", "/api/upstreams/two", nil, true); code != 200 {
					t.Fatalf("delete last reference: %d", code)
				}
				if _, err := os.Stat(file); !os.IsNotExist(err) {
					t.Fatal("unreferenced managed secret was not removed")
				}
			}
		})
	}
}

func TestConsoleRejectsSymlinkSecretDirectory(t *testing.T) {
	c, _, path := newConsole(t, "https://example.com")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(filepath.Dir(path), "secrets")); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.call("PUT", "/api/upstreams/new", map[string]any{"base_url": "https://example.com", "auth": map[string]string{"type": "bearer"}, "secret": "synthetic"}, true); code != 422 {
		t.Fatalf("symlink secret directory accepted: %d", code)
	}
	files, _ := os.ReadDir(target)
	if len(files) != 0 {
		t.Fatal("secret was written outside the managed directory")
	}
}

func TestManagedSecretCleanupHonorsProxyAndAliasReferences(t *testing.T) {
	for _, kind := range []string{"top proxy", "upstream proxy", "symlink alias"} {
		t.Run(kind, func(t *testing.T) {
			c, gw, _ := newConsole(t, "https://example.com")
			c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
			code, result := c.call("PUT", "/api/upstreams/one", map[string]any{"base_url": "https://example.com", "auth": map[string]string{"type": "bearer"}, "secret": "synthetic"}, true)
			if code != 200 {
				t.Fatalf("create upstream: %v", result)
			}
			file := gw.Config().Upstreams[1].Auth.SecretFile
			if kind == "symlink alias" {
				alias := filepath.Join(t.TempDir(), "credential-link")
				if err := os.Symlink(file, alias); err != nil {
					t.Fatal(err)
				}
				if code, result := c.call("PUT", "/api/upstreams/two", map[string]any{"base_url": "https://example.com", "auth": map[string]string{"type": "bearer", "secret_file": alias}}, true); code != 200 {
					t.Fatalf("alias credential: %v", result)
				}
			} else {
				cfg, err := gw.Config().clone()
				if err != nil {
					t.Fatal(err)
				}
				op := &OutboundProxy{URL: "http://proxy.example:3128", Username: "test", SecretFile: file}
				if kind == "top proxy" {
					cfg.OutboundProxy = op
				} else {
					cfg.Upstreams[0].OutboundProxy = op
				}
				if err := cfg.validate(); err != nil {
					t.Fatal(err)
				}
				gw.Apply(cfg)
			}
			if code, _ := c.call("DELETE", "/api/upstreams/one", nil, true); code != 200 {
				t.Fatalf("delete original: %d", code)
			}
			if _, err := os.Stat(file); err != nil {
				t.Fatal("cleanup removed a credential used for proxy or alias auth")
			}
			gw.Apply(gw.Config())
			if len(gw.Problems()) != 0 {
				t.Fatalf("retained credential no longer resolves: %v", gw.Problems())
			}
			if kind == "symlink alias" {
				if code, _ := c.call("DELETE", "/api/upstreams/two", nil, true); code != 200 {
					t.Fatalf("delete alias reference: %d", code)
				}
				if _, err := os.Stat(file); !os.IsNotExist(err) {
					t.Fatal("last alias reference left its managed credential behind")
				}
			}
		})
	}
}

func TestConsoleContentNegotiationAndETagMatching(t *testing.T) {
	asset := webAssets["app.js"]
	for _, tt := range []struct {
		encoding string
		wantGzip bool
	}{
		{"gzip;q=0.0", false}, {"gzip;q=0.000", false}, {"gzip; q=0.5", true},
		{"gzip;q=bogus", false}, {"gzip;q=2", false}, {"*;q=0.5", true},
		{"*;q=1,gzip;q=0", false}, {"gzip;q=0,*;q=1", false},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/app.js", nil)
		req.Header.Set("Accept-Encoding", tt.encoding)
		asset.serve(rec, req)
		if got := rec.Header().Get("Content-Encoding") == "gzip"; got != tt.wantGzip {
			t.Errorf("Accept-Encoding %q gzip = %v, want %v", tt.encoding, got, tt.wantGzip)
		}
	}
	for _, tt := range []struct {
		tag  string
		want int
	}{
		{asset.etag, 304}, {"W/" + asset.etag, 304}, {`"other", ` + asset.etag, 304},
		{"*", 304}, {`"prefix` + asset.etag + `suffix"`, 200}, {`"unmatched"`, 200},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/app.js", nil)
		req.Header.Set("If-None-Match", tt.tag)
		asset.serve(rec, req)
		if rec.Code != tt.want {
			t.Errorf("If-None-Match %q status = %d, want %d", tt.tag, rec.Code, tt.want)
		}
	}
}

func TestConsoleRejectsAmbiguousProbeInputsBeforeSendingCredentials(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	c, _, _ := newConsole(t, up.URL)
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	for _, request := range []map[string]any{
		{"name": "jira", "upstream": map[string]any{"base_url": up.URL, "auth": map[string]string{"type": "none"}}, "path": "/x"},
		{"name": "jira", "secret": "new-pasted-secret", "path": "/x"},
		{"path": "/x"},
	} {
		if code, _ := c.call("POST", "/api/probe", request, true); code != 422 {
			t.Errorf("ambiguous probe status = %d, want 422", code)
		}
	}
	if got.method != "" {
		t.Fatal("ambiguous probe sent a credential upstream")
	}
}

func TestConsoleRejectsKeyUpdateIDMismatch(t *testing.T) {
	c, gw, _ := newConsole(t, "https://example.com")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	grants := []Grant{{Upstream: "jira", Methods: []string{"GET"}, Paths: []string{"/**"}}}
	if code, _ := c.call("POST", "/api/keys", map[string]any{"id": "k", "grants": grants}, true); code != 200 {
		t.Fatalf("create key: %d", code)
	}
	if code, _ := c.call("PUT", "/api/keys/k", map[string]any{"id": "other", "description": "mismatched update", "grants": grants}, true); code != 422 {
		t.Fatalf("mismatched key update: %d", code)
	}
	if gw.Config().Keys[0].Description != "" {
		t.Fatal("mismatched update changed the key")
	}
}
