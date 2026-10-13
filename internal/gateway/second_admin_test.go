package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecondAdminLoginReplacesOnlyCurrentBrowserSession(t *testing.T) {
	_, gw, path := newConsole(t, "https://example.com")
	a := NewAdmin(gw, path, HashKey(adminToken), "http://gw")
	login := func(previous *http.Cookie) *http.Cookie {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/session", strings.NewReader(`{"token":"`+adminToken+`"}`))
		req.Header.Set("X-Hootway-Console", "1")
		if previous != nil {
			req.AddCookie(previous)
		}
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("login status = %d", rec.Code)
		}
		return rec.Result().Cookies()[0]
	}
	first := login(nil)
	otherBrowser := login(nil)
	current := login(first)
	for _, tt := range []struct {
		cookie *http.Cookie
		want   bool
	}{{first, false}, {otherBrowser, true}, {current, true}} {
		req := httptest.NewRequest("GET", "/api/state", nil)
		req.AddCookie(tt.cookie)
		if got := a.authenticated(req); got != tt.want {
			t.Errorf("session authenticated = %v, want %v", got, tt.want)
		}
	}
}

func TestSecondAdminSessionsRemainBounded(t *testing.T) {
	_, gw, path := newConsole(t, "https://example.com")
	a := NewAdmin(gw, path, HashKey(adminToken), "http://gw")
	var first *http.Cookie
	for i := 0; i <= maxAdminSessions; i++ {
		req := httptest.NewRequest("POST", "/api/session", strings.NewReader(`{"token":"`+adminToken+`"}`))
		req.Header.Set("X-Hootway-Console", "1")
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("login = %d", rec.Code)
		}
		if i == 0 {
			first = rec.Result().Cookies()[0]
		}
	}
	if len(a.sessions) != maxAdminSessions {
		t.Fatalf("session count = %d, want %d", len(a.sessions), maxAdminSessions)
	}
	req := httptest.NewRequest("GET", "/api/state", nil)
	req.AddCookie(first)
	if a.authenticated(req) {
		t.Fatal("oldest browser session was not retired at the session limit")
	}
}

func TestSecondAdminProxySecretCleanupAfterReplaceAndDelete(t *testing.T) {
	for _, action := range []string{"replace", "delete", "failed replace"} {
		t.Run(action, func(t *testing.T) {
			c, gw, _ := newConsole(t, "https://example.com")
			c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
			if code, result := c.call("PUT", "/api/upstreams/source", map[string]any{"base_url": "https://example.com", "auth": Auth{Type: "bearer"}, "secret": "synthetic-proxy-password"}, true); code != 200 {
				t.Fatalf("create credential: %d %v", code, result)
			}
			file := gw.Config().Upstreams[1].Auth.SecretFile
			cfg, err := gw.Config().clone()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Upstreams[1].Auth = Auth{Type: "none"}
			cfg.Upstreams[1].OutboundProxy = &OutboundProxy{URL: "http://proxy.example:3128", Username: "operator", SecretFile: file}
			if err := cfg.validate(); err != nil {
				t.Fatal(err)
			}
			gw.Apply(cfg)
			var code int
			if action == "delete" {
				code, _ = c.call("DELETE", "/api/upstreams/source", nil, true)
			} else {
				base := "https://example.com"
				if action == "failed replace" {
					base = "not a URL"
				}
				code, _ = c.call("PUT", "/api/upstreams/source", map[string]any{"base_url": base, "auth": Auth{Type: "none"}}, true)
			}
			_, err = os.Stat(file)
			if action == "failed replace" {
				if code != 422 || err != nil {
					t.Fatalf("failed mutation removed active proxy password: status=%d err=%v", code, err)
				}
			} else if code != 200 || !os.IsNotExist(err) {
				t.Fatalf("unreferenced proxy password retained: status=%d err=%v", code, err)
			}
		})
	}
}

func TestSecondAdminDraftProbeKeepsUsernameEnvironmentSeparate(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	c, gw, _ := newConsole(t, up.URL)
	gw.getenv = func(name string) string {
		if name == "HOOTWAY_DRAFT_SECRET" {
			return "synthetic-user"
		}
		return "real"
	}
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	code, result := c.call("POST", "/api/probe", map[string]any{"upstream": Upstream{BaseURL: up.URL, Auth: Auth{Type: "basic", UsernameEnv: "HOOTWAY_DRAFT_SECRET"}}, "secret": "synthetic-password", "path": "/check"}, true)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("synthetic-user:synthetic-password"))
	if code != 200 || result["ok"] != true || got.authz != want {
		t.Fatal("draft probe did not use the independently resolved username and pasted password")
	}
}

func TestSecondAdminAssetValidatorsFollowSelectedEncoding(t *testing.T) {
	asset := webAssets["app.js"]
	serve := func(encoding, tag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/app.js", nil)
		if encoding != "" {
			req.Header.Set("Accept-Encoding", encoding)
		}
		if tag != "" {
			req.Header.Set("If-None-Match", tag)
		}
		rec := httptest.NewRecorder()
		asset.serve(rec, req)
		return rec
	}
	raw := serve("identity", "")
	gzip := serve("gzip", "")
	if !bytes.Equal(raw.Body.Bytes(), asset.raw) || !bytes.Equal(gzip.Body.Bytes(), asset.gz) {
		t.Fatal("asset encoding changed unexpectedly")
	}
	if raw.Header().Get("ETag") == gzip.Header().Get("ETag") {
		t.Fatal("different encoded bytes share one strong validator")
	}
	if rec := serve("identity", gzip.Header().Get("ETag")); rec.Code != 200 {
		t.Fatalf("gzip validator matched identity bytes: %d", rec.Code)
	}
	if rec := serve("gzip", gzip.Header().Get("ETag")); rec.Code != 304 || rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip revalidation metadata missing: %d %v", rec.Code, rec.Header())
	}
	if rec := serve("gzip;q=0,identity;q=0", ""); rec.Code != 406 {
		t.Fatalf("unacceptable asset representation served: %d", rec.Code)
	}
}

func TestSecondAdminEncodingRefusalsAndMultipleHeaderValues(t *testing.T) {
	for _, encoding := range []string{"gzip;q=1e0", "gzip;q=+1", "gzip;q=.5", "gzip;q=0.0000", "gzip;q=0;q=1", "gzip;q=0,gzip;q=1"} {
		if acceptsGzip(encoding) {
			t.Errorf("invalid or refused gzip encoding accepted: %q", encoding)
		}
	}
	req := httptest.NewRequest("GET", "/app.js", nil)
	req.Header.Add("Accept-Encoding", "br")
	req.Header.Add("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	webAssets["app.js"].serve(rec, req)
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("second encoding header was ignored")
	}
	req.Header.Add("If-None-Match", `"unrelated"`)
	req.Header.Add("If-None-Match", rec.Header().Get("ETag"))
	rec = httptest.NewRecorder()
	webAssets["app.js"].serve(rec, req)
	if rec.Code != 304 {
		t.Fatalf("second cache validator header was ignored: %d", rec.Code)
	}
}

func TestSecondAdminConfigRejectsHTTPHeaderControlValues(t *testing.T) {
	for _, bad := range []string{"synthetic\x01value", "synthetic\x1fvalue", "synthetic\x7fvalue"} {
		for _, prefix := range []bool{false, true} {
			up := Upstream{Name: "x", BaseURL: "https://example.com", Auth: Auth{Type: "none"}, Headers: map[string]string{"X-Test": bad}}
			if prefix {
				up.Headers = nil
				up.Auth = Auth{Type: "header", Name: "X-Token", SecretEnv: "SECRET", Prefix: bad}
			}
			data, _ := json.Marshal(Config{Upstreams: []Upstream{up}})
			if _, err := ParseConfig(data); err == nil {
				t.Errorf("invalid HTTP field value accepted, prefix=%v", prefix)
			}
		}
	}
	data, _ := json.Marshal(Config{Upstreams: []Upstream{{Name: "x", BaseURL: "https://example.com", Auth: Auth{Type: "none"}, Headers: map[string]string{"X-Test": "synthetic\tvalue"}}}})
	if _, err := ParseConfig(data); err != nil {
		t.Fatalf("legal tab in header value rejected: %v", err)
	}
}

func TestSecondAdminCleanupRetainsSharedProxySecret(t *testing.T) {
	c, gw, path := newConsole(t, "https://example.com")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	dir := filepath.Join(filepath.Dir(path), "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "shared-0123456789ab")
	if err := os.WriteFile(file, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := gw.Config().clone()
	if err != nil {
		t.Fatal(err)
	}
	cfg.OutboundProxy = &OutboundProxy{URL: "http://proxy.example:3128", Username: "operator", SecretFile: file}
	cfg.Upstreams = append(cfg.Upstreams, Upstream{Name: "source", BaseURL: "https://example.com", Auth: Auth{Type: "none"}, OutboundProxy: &OutboundProxy{URL: "http://other.proxy.example:3128", Username: "operator", SecretFile: file}})
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	gw.Apply(cfg)
	if code, _ := c.call("DELETE", "/api/upstreams/source", nil, true); code != 200 {
		t.Fatalf("delete upstream = %d", code)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("cleanup removed shared outbound proxy secret")
	}
}

func TestSecondAdminConcurrentCreateOnlyUpstreams(t *testing.T) {
	_, gw, path := newConsole(t, "https://example.com")
	a := NewAdmin(gw, path, HashKey(adminToken), "http://gw")
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	for _, secret := range []string{"synthetic-first", "synthetic-second"} {
		go func(secret string) {
			body, _ := json.Marshal(upstreamInput{Upstream: Upstream{BaseURL: "https://example.com", Auth: Auth{Type: "bearer"}}, Secret: secret})
			req := httptest.NewRequest("PUT", "/api/upstreams/new", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+adminToken)
			req.Header.Set("X-Hootway-Console", "1")
			req.Header.Set("If-None-Match", "*")
			rec := httptest.NewRecorder()
			<-start
			a.ServeHTTP(rec, req)
			results <- rec
		}(secret)
	}
	close(start)
	counts := map[int]int{}
	for i := 0; i < 2; i++ {
		rec := <-results
		counts[rec.Code]++
		if rec.Code == 412 && !strings.Contains(rec.Body.String(), `"code":"precondition_failed"`) {
			t.Fatalf("unexpected precondition response: %s", rec.Body.String())
		}
	}
	if counts[200] != 1 || counts[412] != 1 {
		t.Fatalf("concurrent create statuses = %v", counts)
	}
	if len(gw.Config().Upstreams) != 2 {
		t.Fatal("concurrent creation changed more than one upstream")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), "secrets", "*"))
	if err != nil || len(files) != 1 || files[0] != gw.Config().Upstreams[1].Auth.SecretFile {
		t.Fatalf("failed create retained staged credential: count=%d err=%v", len(files), err)
	}
	// Ordinary scripted PUT retains its established upsert semantics.
	req := httptest.NewRequest("PUT", "/api/upstreams/new", strings.NewReader(`{"base_url":"https://example.com","description":"updated","auth":{"type":"none"}}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Hootway-Console", "1")
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != 200 || gw.Config().Upstreams[1].Description != "updated" {
		t.Fatalf("ordinary PUT upsert failed: %d", rec.Code)
	}
}
