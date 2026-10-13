package gateway

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSecondRejectedPathsRedactCredentialsAcrossReload(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(up.Close)
	for _, tc := range []struct {
		name, path, key string
		status          int
		reload          bool
	}{
		{"unsafe path", "/jira/real-secret/%252e/admin", agentKey, http.StatusBadRequest, false},
		{"unknown route", "/unknown/real-secret", agentKey, http.StatusForbidden, false},
		{"unsafe auth failure", "/jira/real-secret/%252e/admin", "", http.StatusUnauthorized, false},
		{"auth failure while reloading", "/jira/real-secret", "", http.StatusUnauthorized, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := testGateway(t, up.URL, nil)
			var logs bytes.Buffer
			g.log = slog.New(slog.NewTextHandler(&logs, nil))
			rec := httptest.NewRecorder()
			var w http.ResponseWriter = rec
			if tc.reload {
				w = &secondHeaderHook{ResponseRecorder: rec, hook: func() {
					cfg, err := g.Config().clone()
					if err != nil {
						t.Fatal(err)
					}
					g.getenv = func(string) string { return "rotated-synthetic-secret" }
					g.Apply(cfg)
				}}
			}
			req := httptest.NewRequest("GET", tc.path, nil)
			if tc.key != "" {
				req.Header.Set("Authorization", "Bearer "+tc.key)
			}
			g.ServeHTTP(w, req)
			if rec.Code != tc.status || calls.Load() != 0 {
				t.Fatalf("status=%d upstream calls=%d", rec.Code, calls.Load())
			}
			events := g.events.since(0, 10)
			if len(events) != 1 || events[0].Path != "[redacted]" || strings.Contains(logs.String(), "real-secret") {
				t.Fatalf("rejected request retained credential in audit metadata: %+v", events)
			}
		})
	}
}

type secondHeaderHook struct {
	*httptest.ResponseRecorder
	hook func()
}

func (w *secondHeaderHook) WriteHeader(status int) {
	if w.hook != nil {
		hook := w.hook
		w.hook = nil
		hook()
	}
	w.ResponseRecorder.WriteHeader(status)
}

func TestSecondRedirectReferencesStayInsideGateway(t *testing.T) {
	var location string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, nil)
	cfg, err := g.Config().clone()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Upstreams[0].BaseURL = up.URL + "/api"
	cfg.Upstreams[0].Auth = Auth{Type: "query", Name: "api_key", SecretEnv: "JIRA_TOKEN"}
	cfg.Keys[0].RequestsPerMinute = 0
	cfg, err = cfg.clone()
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(cfg)
	u, _ := url.Parse(up.URL)
	for _, tc := range []struct{ name, location, want string }{
		{"absolute", up.URL + "/api/next?x=1#details", "/jira/next?x=1#details"},
		{"root relative", "/api/next?x=1#details", "/jira/next?x=1#details"},
		{"relative", "next?x=1#details", "/jira/next?x=1#details"},
		{"network path", "//" + u.Host + "/api/next?x=1#details", "/jira/next?x=1#details"},
		{"fragment inherits safe query", "#details", "/jira/redirect?existing=1#details"},
		{"credential-only query", "?api_key=real-secret", "/jira/redirect"},
		{"empty query", "?", "/jira/redirect?"},
		{"escaped relative path", "next%20item?x=1#details", "/jira/next%20item?x=1#details"},
		{"outside base", "/outside", "/outside"},
		{"external", "https://elsewhere.example/next", "https://elsewhere.example/next"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			location = tc.location
			rec := do(g, "GET", "/jira/redirect?existing=1", agentKey, nil)
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != tc.want {
				t.Fatalf("status=%d location=%q want=%q", rec.Code, rec.Header().Get("Location"), tc.want)
			}
			if strings.Contains(rec.Header().Get("Location"), "real-secret") {
				t.Fatal("redirect exposed the injected query credential")
			}
		})
	}
}

func TestSecondFollowingRelativeRedirectStillChecksGrant(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/api/redirect" {
			w.Header().Set("Location", "denied")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, nil)
	cfg, _ := g.Config().clone()
	cfg.Upstreams[0].BaseURL = up.URL + "/api"
	cfg, err := cfg.clone()
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(cfg)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest("GET", srv.URL+"/jira/redirect", nil)
	req.Header.Set("Authorization", "Bearer "+agentKey)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || calls.Load() != 1 || resp.Request.URL.Path != "/jira/denied" {
		t.Fatalf("status=%d calls=%d final path=%q", resp.StatusCode, calls.Load(), resp.Request.URL.Path)
	}
}

func TestSecondEncodedBaseAndCanonicalRedirectOrigins(t *testing.T) {
	g, _ := testGateway(t, "http://example.test", nil)
	cfg, _ := g.Config().clone()
	cfg.Upstreams[0].BaseURL = "http://Example.test:80/space%20base"
	cfg.Keys[0].RequestsPerMinute = 0
	cfg, err := cfg.clone()
	if err != nil {
		t.Fatal(err)
	}
	var location string
	g.transport = reviewRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.EscapedPath() != "/space%20base/redirect" {
			t.Fatalf("forwarded path changed: %q", req.URL.EscapedPath())
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {location}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	g.Apply(cfg)
	for _, tc := range []struct{ location, want string }{
		{"http://EXAMPLE.TEST/space%20base/next%20item#detail%20one", "/jira/next%20item#detail%20one"},
		{"//EXAMPLE.TEST:80/space%20base/next", "/jira/next"},
		{"/space%20base/next", "/jira/next"},
		{"next%20item", "/jira/next%20item"},
		{"http://synthetic-user@example.test/space%20base/next", "http://synthetic-user@example.test/space%20base/next"},
		{"http://example.test/space%20baseball/next", "http://example.test/space%20baseball/next"},
	} {
		location = tc.location
		rec := do(g, "GET", "/jira/redirect", agentKey, nil)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != tc.want {
			t.Errorf("location=%q: status=%d got=%q want=%q", tc.location, rec.Code, rec.Header().Get("Location"), tc.want)
		}
	}
}

func TestSecondExplainMatchesMalformedTargetDecisionOrder(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(up.Close)
	for _, enabled := range []bool{false, true} {
		g, _ := testGateway(t, up.URL, func(c *Config) {
			if enabled {
				c.Proxy = &ProxyMode{}
			}
		})
		for _, target := range []string{"/jira/rest/api/3/issue/%2e%2e?bad=%zz", up.URL + "/jira/rest/api/3/issue/%2e%2e?bad=%zz", up.URL + "/jira/rest/api/3/issue/A-1?bad=%zz", up.URL + "/unknown?bad=%zz"} {
			rec := do(g, "GET", target, agentKey, nil)
			decision := g.Explain("agent", "GET", target)
			if decision.Allowed || decision.Outcome != errorCode(t, rec) || calls.Load() != 0 {
				t.Errorf("proxy=%v target=%q: code=%s decision=%+v calls=%d", enabled, target, errorCode(t, rec), decision, calls.Load())
			}
		}
	}
}

func TestSecondMalformedQueriesAreRejectedWithoutForwarding(t *testing.T) {
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, func(c *Config) {
		c.Keys[0].RequestsPerMinute = 0
		c.Proxy = &ProxyMode{}
	})
	for _, query := range []string{"keep=1&discard=%zz", "keep=1&discard=two;values", "keep=1&discard=%", "keep=1&discard=%1"} {
		for _, target := range []string{"/jira/rest/api/3/issue/A-1?" + query, up.URL + "/jira/rest/api/3/issue/A-1?" + query} {
			rec := do(g, "GET", target, agentKey, nil)
			if rec.Code != http.StatusBadRequest || calls.Load() != 0 {
				t.Errorf("malformed query %q: status=%d upstream calls=%d", query, rec.Code, calls.Load())
			}
			if d := g.Explain("agent", "GET", target); d.Allowed || d.Outcome != "bad_query" {
				t.Errorf("Explain differs from malformed-query enforcement: %+v", d)
			}
		}
	}
}

func TestSecondValidEscapedQueriesArePreserved(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	query := "value=two%3Bvalues&literal=%25zz&duplicate=1&duplicate=2&plus=a+b&slash=%2f"
	rec := do(g, "GET", "/jira/rest/api/3/issue/A-1?"+query, agentKey, nil)
	if rec.Code != http.StatusOK || got.rawQuery != query {
		t.Fatalf("valid query changed: status=%d raw query=%q", rec.Code, got.rawQuery)
	}
}

func TestSecondResolvedHeaderCredentialsRejectHTTPControls(t *testing.T) {
	for _, auth := range []Auth{{Type: "bearer", SecretEnv: "S"}, {Type: "header", Name: "X-API-Key", SecretEnv: "S"}} {
		for _, secret := range []string{"synthetic\x01secret", "synthetic\x7fsecret"} {
			if _, err := resolveCredential(auth, func(string) string { return secret }); err == nil {
				t.Errorf("%s accepted an unusable HTTP header credential", auth.Type)
			}
		}
	}
	for _, auth := range []Auth{{Type: "basic", Username: "bot", SecretEnv: "S"}, {Type: "query", Name: "api_key", SecretEnv: "S"}} {
		cred, err := resolveCredential(auth, func(string) string { return "synthetic\x01secret" })
		if err != nil {
			t.Fatalf("%s encoding-safe credential rejected: %v", auth.Type, err)
		}
		req := httptest.NewRequest("GET", "http://example.test/", nil)
		cred.apply(req)
		if strings.Contains(req.Header.Get("Authorization"), "\x01") || strings.Contains(req.URL.RawQuery, "\x01") {
			t.Fatal("credential was not safely encoded")
		}
	}
}

func TestSecondKnownRoutesRedactOtherUpstreamCredentials(t *testing.T) {
	const otherSecret = "echo-only-synthetic-secret"
	for _, tc := range []struct {
		name, path string
		status     int
		calls      int32
	}{
		{"grant denial", "/jira/" + otherSecret, http.StatusForbidden, 0},
		{"forwarded request", "/jira/rest/api/3/issue/" + otherSecret, http.StatusNoContent, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(up.Close)
			g, _ := testGateway(t, up.URL, nil)
			cfg, err := g.Config().clone()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Upstreams = append(cfg.Upstreams, Upstream{Name: "echo", BaseURL: up.URL + "/echo", Auth: Auth{Type: "bearer", SecretEnv: "ECHO_TOKEN"}})
			cfg, err = cfg.clone()
			if err != nil {
				t.Fatal(err)
			}
			g.getenv = func(name string) string {
				return map[string]string{"JIRA_TOKEN": "real-secret", "ECHO_TOKEN": otherSecret}[name]
			}
			g.Apply(cfg)
			var logs bytes.Buffer
			g.log = slog.New(slog.NewTextHandler(&logs, nil))
			rec := do(g, "GET", tc.path, agentKey, nil)
			if rec.Code != tc.status || calls.Load() != tc.calls {
				t.Fatalf("status=%d upstream calls=%d", rec.Code, calls.Load())
			}
			events := g.events.since(0, 10)
			if len(events) != 1 || events[0].Path != "[redacted]" || strings.Contains(logs.String(), otherSecret) {
				t.Fatal("a known route retained a different upstream's credential in audit metadata")
			}
		})
	}
}
