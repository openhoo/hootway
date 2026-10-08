package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type seen struct {
	method, path, rawQuery, authz, cookie, hootwayHeader, custom string
}

func newUpstream(t *testing.T, got *seen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = seen{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Authorization"),
			r.Header.Get("Cookie"), r.Header.Get("X-Hootway-Key"), r.Header.Get("X-Atlassian-Token")}
		if r.URL.Path == "/jira/redirect" {
			w.Header().Set("Location", "http://"+r.Host+"/jira/rest/api/3/myself?x=1")
			w.WriteHeader(http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "upstream"})
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

const agentKey = "hw_test-agent-key"

func testGateway(t *testing.T, base string, mutate func(*Config)) (*Gateway, *time.Time) {
	t.Helper()
	raw := `{
	  "upstreams": [{
	    "name": "jira", "base_url": "` + base + `/jira",
	    "auth": {"type": "basic", "username": "bot@example.com", "secret_env": "JIRA_TOKEN"},
	    "headers": {"X-Atlassian-Token": "no-check"}
	  }],
	  "keys": [{
	    "id": "agent", "sha256": "` + HashKey(agentKey) + `", "requests_per_minute": 3,
	    "grants": [
	      {"upstream": "jira", "methods": ["GET"], "paths": ["/rest/api/3/issue/*", "/rest/api/3/search/**", "/redirect"]},
	      {"upstream": "jira", "methods": ["POST"], "paths": ["/rest/api/3/issue/*/comment"]}
	    ]
	  }]
	}`
	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(cfg)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	g, err := New(cfg, Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Getenv: func(k string) string { return map[string]string{"JIRA_TOKEN": "real-secret"}[k] },
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, &now
}

func do(g http.Handler, method, target, key string, extra map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(""))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct{ Error struct{ Code string } }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body.Error.Code
}

func TestForwardsWithInjectedCredential(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	rec := do(g, "GET", "/jira/rest/api/3/issue/ABC-1?fields=summary", agentKey,
		map[string]string{"Cookie": "agent=1", "X-Hootway-Key": ""})
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got.path != "/jira/rest/api/3/issue/ABC-1" || got.rawQuery != "fields=summary" {
		t.Fatalf("unexpected upstream request %+v", got)
	}
	if got.authz != "Basic Ym90QGV4YW1wbGUuY29tOnJlYWwtc2VjcmV0" {
		t.Fatalf("credential not injected: %q", got.authz)
	}
	if got.cookie != "" || got.custom != "no-check" {
		t.Fatalf("headers not sanitised: %+v", got)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("upstream cookie leaked to agent")
	}
	if strings.Contains(rec.Body.String(), "real-secret") {
		t.Fatal("secret leaked")
	}
}

func TestBasicAuthKeyAndHeaderKeyAreStripped(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	req := httptest.NewRequest("GET", "/jira/rest/api/3/search/jql", nil)
	req.SetBasicAuth("agent@example.com", agentKey)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("basic-auth key: %d", rec.Code)
	}
	rec = do(g, "GET", "/jira/rest/api/3/search", "", map[string]string{"X-Hootway-Key": agentKey})
	if rec.Code != 200 || got.hootwayHeader != "" {
		t.Fatalf("header key: %d, forwarded header %q", rec.Code, got.hootwayHeader)
	}
}

func TestRejections(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	cases := []struct {
		name, method, path, key string
		status                  int
		code                    string
	}{
		{"missing key", "GET", "/jira/rest/api/3/issue/A-1", "", 401, "missing_key"},
		{"wrong key", "GET", "/jira/rest/api/3/issue/A-1", "hw_wrong", 401, "invalid_key"},
		{"method not granted", "DELETE", "/jira/rest/api/3/issue/A-1", agentKey, 403, "forbidden"},
		{"path not granted", "GET", "/jira/rest/api/3/user", agentKey, 403, "forbidden"},
		{"single star depth", "GET", "/jira/rest/api/3/issue/A-1/worklog", agentKey, 403, "forbidden"},
		{"unknown upstream", "GET", "/github/user", agentKey, 403, "forbidden"},
		{"dot segment", "GET", "/jira/rest/api/3/issue/../../../admin", agentKey, 400, "bad_path"},
		{"encoded slash", "GET", "/jira/rest/api/3/issue/A%2F..%2Fadmin", agentKey, 400, "bad_path"},
		{"encoded dot", "GET", "/jira/rest/api/3/issue/%2e%2e/x", agentKey, 400, "bad_path"},
		{"double slash", "GET", "/jira/rest/api/3//issue/A-1", agentKey, 400, "bad_path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got = seen{}
			rec := do(g, tc.method, tc.path, tc.key, nil)
			if rec.Code != tc.status || errorCode(t, rec) != tc.code {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
			if got.method != "" {
				t.Fatal("rejected request reached upstream")
			}
		})
	}
}

func TestPostGrantWithWildcard(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	if rec := do(g, "POST", "/jira/rest/api/3/issue/ABC-7/comment", agentKey, nil); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if got.method != "POST" || got.path != "/jira/rest/api/3/issue/ABC-7/comment" {
		t.Fatalf("%+v", got)
	}
}

func TestExpiryDisableAndRateLimit(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, now := testGateway(t, up.URL, nil)
	for i := 0; i < 3; i++ {
		if rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 429 {
		t.Fatalf("expected rate limit, got %d", rec.Code)
	}
	*now = now.Add(time.Minute)
	if rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 200 {
		t.Fatalf("after window: %d", rec.Code)
	}

	expired := time.Date(2026, 10, 8, 11, 59, 59, 0, time.UTC)
	g2, _ := testGateway(t, up.URL, func(c *Config) { c.Keys[0].ExpiresAt = &expired })
	if rec := do(g2, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 401 {
		t.Fatalf("expired key: %d", rec.Code)
	}
	g3, _ := testGateway(t, up.URL, func(c *Config) { c.Keys[0].Disabled = true })
	if rec := do(g3, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 401 {
		t.Fatalf("disabled key: %d", rec.Code)
	}
}

func TestRedirectIsRewrittenThroughGateway(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	rec := do(g, "GET", "/jira/redirect", agentKey, nil)
	if rec.Code != 302 || rec.Header().Get("Location") != "/jira/rest/api/3/myself?x=1" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestQueryAndHeaderAuth(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	cfg, err := ParseConfig([]byte(`{
	  "upstreams": [
	    {"name": "q", "base_url": "` + up.URL + `", "auth": {"type": "query", "name": "api_key", "secret_env": "S"}},
	    {"name": "h", "base_url": "` + up.URL + `", "auth": {"type": "header", "name": "Authorization", "prefix": "token ", "secret_env": "S"}}
	  ],
	  "keys": [{"id": "k", "sha256": "` + HashKey(agentKey) + `",
	    "grants": [{"upstream": "q", "methods": ["*"], "paths": ["/**"]}, {"upstream": "h", "methods": ["GET"], "paths": ["/**"]}]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Getenv: func(string) string { return "s3cret" }})
	if err != nil {
		t.Fatal(err)
	}
	do(g, "GET", "/q/v1/items?api_key=agent-supplied&a=b", agentKey, nil)
	if got.rawQuery != "a=b&api_key=s3cret" || got.authz != "" {
		t.Fatalf("query auth: %+v", got)
	}
	do(g, "GET", "/h/user", agentKey, nil)
	if got.authz != "token s3cret" || got.path != "/user" {
		t.Fatalf("header auth: %+v", got)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []string{
		`{"upstreams":[{"name":"x","base_url":"ftp://a","auth":{"type":"none"}}],"keys":[]}`,
		`{"upstreams":[{"name":"x","base_url":"https://a","auth":{"type":"bearer"}}],"keys":[]}`,
		`{"upstreams":[{"name":"x","base_url":"https://a","auth":{"type":"basic","secret_env":"S"}}],"keys":[]}`,
		`{"upstreams":[{"name":"x","base_url":"https://a","auth":{"type":"none"},"headers":{"Cookie":"a"}}],"keys":[]}`,
		`{"upstreams":[{"name":"x","base_url":"https://a","auth":{"type":"none"}}],"keys":[{"id":"k","sha256":"abc","grants":[{"upstream":"x","methods":["GET"],"paths":["/**"]}]}]}`,
		`{"upstreams":[{"name":"x","base_url":"https://a","auth":{"type":"none"}}],"keys":[{"id":"k","sha256":"` + HashKey("a") + `","grants":[{"upstream":"y","methods":["GET"],"paths":["/**"]}]}]}`,
		`{"upstreams":[{"name":"x","base_url":"https://a","auth":{"type":"none"}}],"keys":[{"id":"k","sha256":"` + HashKey("a") + `","grants":[{"upstream":"x","methods":["get"],"paths":["/a/**/b"]}]}]}`,
		`{"upstreams":[],"keys":[],"unknown":true}`,
	}
	for i, raw := range bad {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("config %d unexpectedly valid", i)
		}
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/a/*", "/a/b", true},
		{"/a/*", "/a/b/", true},
		{"/a/*", "/a/", false},
		{"/a/*", "/a/b/c", false},
		{"/a/**", "/a", true},
		{"/a/**", "/a/b/c", true},
		{"/a/**", "/ab", false},
		{"/**", "/", true},
		{"/a", "/a", true},
		{"/a", "/a/b", false},
	}
	for _, c := range cases {
		if got := matchPath(c.pattern, c.path); got != c.want {
			t.Errorf("matchPath(%q,%q)=%v want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	k, h, err := GenerateKey()
	if err != nil || !strings.HasPrefix(k, KeyPrefix) || HashKey(k) != h || len(k) < 40 {
		t.Fatalf("%q %q %v", k, h, err)
	}
}
