package gateway

import (
	"encoding/json"
	"fmt"
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

// referenceSplitRoute and referenceMatchPath are the original, simple
// implementations. The optimised versions must agree with them exactly.
func referenceSplitRoute(escaped string) (name, rest string, err error) {
	lower := strings.ToLower(escaped)
	for _, bad := range []string{"%2f", "%5c", "%2e", "%3b", "%00", "\\", "//", ";"} {
		if strings.Contains(lower, bad) {
			return "", "", errUnsafePath
		}
	}
	if !strings.HasPrefix(escaped, "/") {
		return "", "", errUnsafePath
	}
	name, rest, _ = strings.Cut(strings.TrimPrefix(escaped, "/"), "/")
	rest = "/" + rest
	for _, seg := range strings.Split(rest, "/") {
		if seg == "." || seg == ".." {
			return "", "", errUnsafePath
		}
	}
	return name, rest, nil
}

func referenceMatchPath(pattern, path string) bool {
	ps := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	xs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(xs) > 1 && xs[len(xs)-1] == "" {
		xs = xs[:len(xs)-1]
	}
	for i, p := range ps {
		if p == "**" {
			return true
		}
		if i >= len(xs) || (p != "*" && p != xs[i]) || (p == "*" && xs[i] == "") {
			return false
		}
	}
	return len(xs) == len(ps)
}

var routeSamples = []string{
	"", "/", "//", "/a", "/a/", "/a//b", "/jira/rest/api/3/issue/A-1", "/jira/.", "/jira/..", "/jira/./x",
	"/jira/a/../b", "/jira/..a/b", "/jira/a..", "/jira/%2e%2e/x", "/jira/%2E/x", "/jira/%2F", "/jira/a%2fb",
	"/jira/%5C", "/jira/%5c", "/jira/%00", "/jira/%0", "/jira/%2", "/jira/%", "/jira/%%2f", "/jira/%20x",
	"/jira/a\\b", "/jira/..;/x", "/jira/a;b", "/jira/%3B", "jira/a", "/jira/%41", "/jira/%2g", "/jira/%3e", "/jira/%2d", "/jira/x/", "/.", "/..", "/a/.b",
}

func TestSplitRouteMatchesReference(t *testing.T) {
	for _, p := range routeSamples {
		n1, r1, e1 := splitRoute(p)
		n2, r2, e2 := referenceSplitRoute(p)
		if n1 != n2 || r1 != r2 || (e1 == nil) != (e2 == nil) {
			t.Errorf("splitRoute(%q) = %q %q %v, reference %q %q %v", p, n1, r1, e1, n2, r2, e2)
		}
	}
}

func FuzzSplitRoute(f *testing.F) {
	for _, p := range routeSamples {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		n1, r1, e1 := splitRoute(p)
		n2, r2, e2 := referenceSplitRoute(p)
		if n1 != n2 || r1 != r2 || (e1 == nil) != (e2 == nil) {
			t.Fatalf("splitRoute(%q) = %q %q %v, reference %q %q %v", p, n1, r1, e1, n2, r2, e2)
		}
	})
}

func TestMatchPathMatchesReference(t *testing.T) {
	patterns := []string{"/", "/**", "/*", "/a", "/a/*", "/a/**", "/a/*/b", "/a/*/**", "/*/*", "/a/b/c"}
	paths := []string{"/", "//", "/a", "/a/", "/a//", "/ab", "/a/b", "/a/b/", "/a/b/c", "/a/b/c/", "/a//b", "/x/b", "/a/x/b", "/a/x/b/c", ""}
	for _, pat := range patterns {
		for _, p := range paths {
			if got, want := matchPath(pat, p), referenceMatchPath(pat, p); got != want {
				t.Errorf("matchPath(%q,%q)=%v reference %v", pat, p, got, want)
			}
		}
	}
}

func FuzzMatchPath(f *testing.F) {
	f.Add("/a/*/**", "/a/b/c")
	f.Add("/a/*", "/a/b/")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		if validatePattern(pattern) != nil {
			return
		}
		if got, want := matchPath(pattern, path), referenceMatchPath(pattern, path); got != want {
			t.Fatalf("matchPath(%q,%q)=%v reference %v", pattern, path, got, want)
		}
	})
}

func TestErrorBodiesAreStable(t *testing.T) {
	g, _ := testGateway(t, "http://127.0.0.1:1", nil)
	rec := do(g, "GET", "/jira/rest/api/3/user", agentKey, nil)
	want := `{"error":{"code":"forbidden","message":"this key is not allowed to call this upstream method and path"}}` + "\n"
	if rec.Code != 403 || rec.Body.String() != want {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", rec.Header())
	}
}

func TestKeyLookupRejectsNearMisses(t *testing.T) {
	g, _ := testGateway(t, "http://127.0.0.1:1", nil)
	st := g.state.Load()
	if st.lookupKey(agentKey) == nil {
		t.Fatal("valid key not found")
	}
	for _, k := range []string{"", agentKey[:len(agentKey)-1], agentKey + "x", strings.ToUpper(agentKey), HashKey(agentKey)} {
		if st.lookupKey(k) != nil {
			t.Errorf("lookupKey(%q) matched", k)
		}
	}
}

func TestRateLimitSurvivesReloadAndRemovedKeysAreForgotten(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	for i := 0; i < 3; i++ {
		do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil)
	}
	cfg, err := g.Config().clone()
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(cfg)
	if rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 429 {
		t.Fatalf("window lost on reload: %d", rec.Code)
	}
	empty, _ := g.Config().clone()
	empty.Keys = nil
	g.Apply(empty)
	g.limMu.Lock()
	n := len(g.windows)
	g.limMu.Unlock()
	if n != 0 {
		t.Fatalf("%d stale rate limit windows", n)
	}
}

func TestTransportIsSharedAcrossReloads(t *testing.T) {
	g, _ := testGateway(t, "http://127.0.0.1:1", nil)
	before := g.state.Load().upstreams["jira"].proxy.Transport
	cfg, _ := g.Config().clone()
	g.Apply(cfg)
	after := g.state.Load().upstreams["jira"].proxy.Transport
	if before != after || before == nil {
		t.Fatal("transport recreated on reload")
	}
	cfg, _ = g.Config().clone()
	cfg.Upstreams[0].TimeoutSeconds = 5
	g.Apply(cfg)
	if g.state.Load().upstreams["jira"].proxy.Transport == before {
		t.Fatal("transport with a different timeout must not be shared")
	}
}

func TestExplainAgreesWithEnforcement(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, func(c *Config) { c.Keys[0].RequestsPerMinute = 0 })
	for _, c := range []struct{ method, path string }{
		{"GET", "/jira/rest/api/3/issue/A-1"}, {"GET", "/jira/rest/api/3/issue/A-1/"}, {"POST", "/jira/rest/api/3/issue/A-1/comment"},
		{"DELETE", "/jira/rest/api/3/issue/A-1"}, {"GET", "/jira/rest/api/3/search"}, {"GET", "/jira/rest/api/3/user"},
		{"GET", "/jira/a/../b"}, {"GET", "/nope/x"},
	} {
		d := g.Explain("agent", c.method, c.path)
		rec := do(g, c.method, c.path, agentKey, nil)
		if d.Allowed != (rec.Code == 200) {
			t.Errorf("%s %s: explain allowed=%v, served %d", c.method, c.path, d.Allowed, rec.Code)
		}
		if d.Allowed && d.Grant == nil {
			t.Errorf("%s %s: no grant reported", c.method, c.path)
		}
	}
	if d := g.Explain("agent", "POST", "/jira/rest/api/3/issue/A-1/comment"); d.Grant == nil || d.Grant.Methods[0] != "POST" {
		t.Fatalf("wrong grant reported: %+v", d.Grant)
	}
}

func TestEventLogRing(t *testing.T) {
	l := newEventLog(4)
	if ev := l.since(0, 10); ev == nil || len(ev) != 0 {
		t.Fatalf("empty log: %v", ev)
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 10; i++ {
		outcome := "forwarded"
		if i%2 == 0 {
			outcome = "forbidden"
		}
		key := "a"
		if i == 10 {
			key = ""
		}
		l.add(Event{Key: key, Outcome: outcome, Time: t0.Add(time.Duration(i) * time.Second)})
	}
	seqs := func(evs []Event) string { return fmt.Sprint(len(evs), evs[0].Seq, evs[len(evs)-1].Seq) }
	if got := seqs(l.since(0, 100)); got != "4 7 10" {
		t.Fatalf("since(0): %s", got)
	}
	if got := seqs(l.since(8, 100)); got != "2 9 10" {
		t.Fatalf("since(8): %s", got)
	}
	if got := seqs(l.since(0, 2)); got != "2 9 10" {
		t.Fatalf("limit: %s", got)
	}
	if len(l.since(10, 5)) != 0 || len(l.since(99, 5)) != 0 || len(l.since(0, 0)) != 0 {
		t.Fatal("expected no events")
	}
	stats, fwd, denied := l.snapshot()
	a := stats["a"]
	if fwd != 5 || denied != 5 || a.Forwarded != 5 || a.Denied != 4 || a.LastUsed == nil || !a.LastUsed.Equal(t0.Add(9*time.Second)) {
		t.Fatalf("stats %+v fwd %d denied %d", a, fwd, denied)
	}
	if _, ok := stats[""]; ok {
		t.Fatal("anonymous requests must not create key stats")
	}
}

func TestAbortedProxyRequestIsRecorded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "short")
		if hj, ok := w.(http.Hijacker); ok {
			c, _, _ := hj.Hijack()
			_ = c.Close()
		}
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, nil)
	func() {
		defer func() { _ = recover() }() // ReverseProxy aborts with http.ErrAbortHandler
		do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil)
	}()
	evs := g.events.since(0, 10)
	if len(evs) != 1 || evs[0].Outcome != "forwarded" || evs[0].Key != "agent" {
		t.Fatalf("events %+v", evs)
	}
}
