package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// proxyGateway starts a gateway in proxy mode in front of upstream base and
// returns its URL. transport, when set, is used for upstream connections.
func proxyGateway(t *testing.T, base string, ca bool, transport http.RoundTripper) (*Gateway, *httptest.Server, string) {
	t.Helper()
	g, _ := testGateway(t, base, func(c *Config) {
		c.Proxy = &ProxyMode{}
		if ca {
			dir := t.TempDir()
			c.Proxy.CACertFile, c.Proxy.CAKeyFile = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
			if err := GenerateProxyCA(c.Proxy.CACertFile, c.Proxy.CAKeyFile, 24*time.Hour); err != nil {
				t.Fatal(err)
			}
		}
	})
	if transport != nil {
		g.transport = transport
		g.Apply(g.Config())
	} else {
		g.Apply(g.Config()) // load the CA added by mutate
	}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	caFile := ""
	if ca {
		caFile = g.Config().Proxy.CACertFile
	}
	return g, srv, caFile
}

func proxyClient(t *testing.T, proxyURL, key, caFile string) *http.Client {
	t.Helper()
	pu, _ := url.Parse(proxyURL)
	if key != "" {
		pu.User = url.UserPassword("agent", key)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu)}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func get(t *testing.T, c *http.Client, method, target string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestHTTPForwardProxyEnforcesPolicy(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	_, gw, _ := proxyGateway(t, up.URL, false, nil)
	c := proxyClient(t, gw.URL, agentKey, "")

	code, _ := get(t, c, "GET", up.URL+"/jira/rest/api/3/issue/ABC-1?fields=x", map[string]string{"Cookie": "a=1"})
	if code != 200 || got.path != "/jira/rest/api/3/issue/ABC-1" || got.rawQuery != "fields=x" {
		t.Fatalf("allowed proxy request: %d %+v", code, got)
	}
	if got.authz != "Basic Ym90QGV4YW1wbGUuY29tOnJlYWwtc2VjcmV0" || got.cookie != "" || got.custom != "no-check" {
		t.Fatalf("credential not injected or headers not sanitised: %+v", got)
	}

	for _, tc := range []struct {
		name, method, target string
		status               int
	}{
		{"path not granted", "GET", up.URL + "/jira/rest/api/3/user", 403},
		{"method not granted", "DELETE", up.URL + "/jira/rest/api/3/issue/A-1", 403},
		{"outside base path", "GET", up.URL + "/other/rest/api/3/issue/A-1", 403},
		{"base path prefix trick", "GET", up.URL + "/jiraX/rest/api/3/issue/A-1", 403},
		{"not an upstream (no open proxy)", "GET", "http://example.invalid/jira/rest/api/3/issue/A-1", 403},
		{"dot segment", "GET", up.URL + "/jira/rest/api/3/issue/%2e%2e/x", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got = seen{}
			if code, body := get(t, c, tc.method, tc.target, nil); code != tc.status || got.path != "" {
				t.Fatalf("status %d (want %d), upstream saw %q: %s", code, tc.status, got.path, body)
			}
		})
	}

	got = seen{}
	anon := proxyClient(t, gw.URL, "", "")
	req, _ := http.NewRequest("GET", up.URL+"/jira/rest/api/3/issue/A-1", nil)
	res, err := anon.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 407 || res.Header.Get("Proxy-Authenticate") == "" || got.path != "" {
		t.Fatalf("missing key: %d %q", res.StatusCode, res.Header.Get("Proxy-Authenticate"))
	}
	if code, _ := get(t, proxyClient(t, gw.URL, "hw_wrong", ""), "GET", up.URL+"/jira/rest/api/3/issue/A-1", nil); code != 407 || got.path != "" {
		t.Fatalf("wrong key: %d", code)
	}
	// The key may also come as the client's normal API token.
	if code, _ := get(t, anon, "GET", up.URL+"/jira/rest/api/3/issue/A-2", map[string]string{"Authorization": "Bearer " + agentKey}); code != 200 || got.authz != "Basic Ym90QGV4YW1wbGUuY29tOnJlYWwtc2VjcmV0" {
		t.Fatalf("inline key: %d %+v", code, got)
	}
}

func TestRedirectsStayAbsoluteForProxyClients(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	_, gw, _ := proxyGateway(t, up.URL, false, nil)
	req, _ := http.NewRequest("GET", up.URL+"/jira/redirect", nil)
	res, err := proxyClient(t, gw.URL, agentKey, "").Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, up.URL+"/jira/") {
		t.Fatalf("proxy redirect rewritten: %q", loc)
	}
}

func TestProxyModeOffKeepsGatewayBehaviour(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	gw := httptest.NewServer(g)
	defer gw.Close()
	c := proxyClient(t, gw.URL, agentKey, "")
	if code, _ := get(t, c, "GET", up.URL+"/jira/rest/api/3/issue/A-1", nil); code != 401 || got.path != "" {
		t.Fatalf("absolute-form request without proxy mode: %d %q", code, got.path)
	}
	req, _ := http.NewRequest(http.MethodConnect, gw.URL, nil)
	req.Host = "example.com:443"
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("CONNECT without proxy mode: %d", res.StatusCode)
	}
}

func TestHTTPSProxyInterceptsAndEnforcesPolicy(t *testing.T) {
	var mu sync.Mutex
	var got seen
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = seen{method: r.Method, path: r.URL.EscapedPath(), authz: r.Header.Get("Authorization"), hootwayHeader: r.Header.Get("Proxy-Authorization")}
		mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	g, gw, caFile := proxyGateway(t, up.URL, true, up.Client().Transport)
	c := proxyClient(t, gw.URL, agentKey, caFile)
	upHost := strings.TrimPrefix(up.URL, "https://")

	if code, body := get(t, c, "GET", up.URL+"/jira/rest/api/3/issue/A-1", nil); code != 200 || body != `{"ok":true}` {
		t.Fatalf("https proxy request: %d %s", code, body)
	}
	mu.Lock()
	if got.authz != "Basic Ym90QGV4YW1wbGUuY29tOnJlYWwtc2VjcmV0" || got.hootwayHeader != "" {
		t.Fatalf("credential not injected or proxy auth leaked: %+v", got)
	}
	got = seen{}
	mu.Unlock()
	if code, _ := get(t, c, "GET", up.URL+"/jira/rest/api/3/user", nil); code != 403 {
		t.Fatalf("denied path through tunnel: %d", code)
	}
	mu.Lock()
	if got.path != "" {
		t.Fatal("denied tunnel request reached the upstream")
	}
	mu.Unlock()

	// A tunnel needs a valid key itself.
	for _, auth := range []string{"", "Basic " + base64.StdEncoding.EncodeToString([]byte("a:hw_wrong"))} {
		req, _ := http.NewRequest(http.MethodConnect, gw.URL, nil)
		req.Host = upHost
		if auth != "" {
			req.Header.Set("Proxy-Authorization", auth)
		}
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 407 {
			t.Fatalf("CONNECT with %q: %d", auth, res.StatusCode)
		}
	}

	// CONNECT to a host that is not an upstream is refused before any TLS.
	req, _ := http.NewRequest(http.MethodConnect, gw.URL, nil)
	req.Host = "example.com:443"
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a:"+agentKey)))
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("CONNECT to non-upstream: %d", res.StatusCode)
	}

	// Disabling the key applies to already open tunnels.
	cfg, _ := g.Config().clone()
	cfg.Keys[0].Disabled = true
	g.Apply(cfg)
	if code, _ := get(t, c, "GET", up.URL+"/jira/rest/api/3/issue/A-1", nil); code != 407 {
		t.Fatalf("disabled key in open tunnel: %d", code)
	}

	var tunnels int
	for _, e := range g.events.since(0, 1000) {
		if e.Outcome == "tunnel" && e.Path == upHost {
			tunnels++
		}
		if e.Outcome == "forwarded" && !strings.HasPrefix(e.Path, "https://") {
			t.Fatalf("proxied event without origin: %+v", e)
		}
	}
	if tunnels == 0 {
		t.Fatal("tunnel not recorded")
	}
}

func TestHTTPSProxyWithoutCAIsRefused(t *testing.T) {
	_, gw, _ := proxyGateway(t, "https://jira.example.com", false, nil)
	req, _ := http.NewRequest(http.MethodConnect, gw.URL, nil)
	req.Host = "jira.example.com:443"
	req.Header.Set("Proxy-Authorization", "Bearer "+agentKey)
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatalf("CONNECT without CA: %d", res.StatusCode)
	}
}

func TestExplainAcceptsRealUpstreamURLs(t *testing.T) {
	g, _ := testGateway(t, "https://jira.example.com", nil)
	if d := g.Explain("agent", "GET", "https://jira.example.com/jira/rest/api/3/issue/A-1"); !d.Allowed {
		t.Fatalf("allowed URL: %+v", d)
	}
	if d := g.Explain("agent", "GET", "https://jira.example.com/jira/rest/api/3/user"); d.Allowed || d.Outcome != "forbidden" {
		t.Fatalf("denied URL: %+v", d)
	}
	if d := g.Explain("agent", "GET", "https://evil.example.com/jira/rest/api/3/issue/A-1"); d.Allowed {
		t.Fatalf("foreign origin: %+v", d)
	}
}

// outboundProxy records requests that arrive in absolute form, like an HTTP
// proxy, and answers them itself.
func outboundProxy(t *testing.T) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var mu sync.Mutex
	var reqs []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.Clone(r.Context()))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"via":"proxy"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestOutboundProxy(t *testing.T) {
	px, reqs := outboundProxy(t)
	raw := `{
	  "outbound_proxy": {"url": "` + px.URL + `", "username": "gw", "secret_env": "PROXY_PASS"},
	  "upstreams": [
	    {"name": "jira", "base_url": "http://jira.internal.test/base", "auth": {"type": "bearer", "secret_env": "TOKEN"}},
	    {"name": "direct", "base_url": "http://127.0.0.1:1", "auth": {"type": "none"}, "outbound_proxy": {"direct": true}}
	  ],
	  "keys": [{"id": "agent", "sha256": "` + HashKey(agentKey) + `", "grants": [
	    {"upstream": "jira", "methods": ["GET"], "paths": ["/**"]},
	    {"upstream": "direct", "methods": ["GET"], "paths": ["/**"]}]}]
	}`
	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Getenv: func(k string) string { return map[string]string{"TOKEN": "real-secret", "PROXY_PASS": "proxy-pass"}[k] }})
	if err != nil {
		t.Fatal(err)
	}
	rec := do(g, "GET", "/jira/rest/api/3/myself", agentKey, nil)
	if rec.Code != 200 || len(*reqs) != 1 {
		t.Fatalf("via outbound proxy: %d %s (%d proxy requests)", rec.Code, rec.Body, len(*reqs))
	}
	r := (*reqs)[0]
	if r.RequestURI != "http://jira.internal.test/base/rest/api/3/myself" || r.Header.Get("Authorization") != "Bearer real-secret" {
		t.Fatalf("proxy saw %s with authz %q", r.RequestURI, r.Header.Get("Authorization"))
	}
	if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("gw:proxy-pass")) {
		t.Fatal("proxy credentials not sent")
	}
	// The per-upstream override connects directly (and fails: nothing listens).
	if rec := do(g, "GET", "/direct/x", agentKey, nil); rec.Code != 502 || len(*reqs) != 1 {
		t.Fatalf("direct override: %d, %d proxy requests", rec.Code, len(*reqs))
	}
	// Proxy credentials never appear in the console state.
	st, _ := json.Marshal(NewAdmin(g, "", HashKey("hwa_x"), "http://gw").state())
	if strings.Contains(string(st), "proxy-pass") {
		t.Fatal("proxy password leaked into state")
	}
}

func TestOutboundProxyMissingSecretIsAProblem(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"outbound_proxy": {"url": "http://proxy:3128", "username": "u", "secret_env": "MISSING"},
	  "upstreams": [{"name": "jira", "base_url": "https://x.example", "auth": {"type": "none"}}], "keys": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, Options{Getenv: func(string) string { return "" }}); err == nil || !strings.Contains(err.Error(), "outbound proxy") {
		t.Fatalf("strict start: %v", err)
	}
	g, err := New(cfg, Options{Lenient: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if g.Problems()["jira"] == "" {
		t.Fatal("missing proxy secret not reported")
	}
}

func TestProxyConfigValidation(t *testing.T) {
	base := `"upstreams": [{"name": "jira", "base_url": "https://x.example", "auth": {"type": "none"}}], "keys": []`
	for name, frag := range map[string]string{
		"userinfo in url":       `"outbound_proxy": {"url": "http://u:p@proxy:3128"}`,
		"bad scheme":            `"outbound_proxy": {"url": "ftp://proxy:21"}`,
		"no url":                `"outbound_proxy": {}`,
		"path in url":           `"outbound_proxy": {"url": "http://proxy:3128/x"}`,
		"direct with url":       `"outbound_proxy": {"direct": true, "url": "http://proxy:3128"}`,
		"password without user": `"outbound_proxy": {"url": "http://proxy:3128", "secret_env": "P"}`,
		"half a CA":             `"proxy": {"ca_cert_file": "ca.pem"}`,
		"unknown field":         `"proxy": {"open": true}`,
	} {
		if _, err := ParseConfig([]byte("{" + frag + ", " + base + "}")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, frag := range []string{
		`"outbound_proxy": {"url": "socks5h://proxy:1080"}`,
		`"outbound_proxy": {"direct": true}`,
		`"proxy": {}`,
	} {
		if _, err := ParseConfig([]byte("{" + frag + ", " + base + "}")); err != nil {
			t.Errorf("%s: %v", frag, err)
		}
	}
}

func TestTransportsAreSeparatedByEgress(t *testing.T) {
	g, _ := testGateway(t, "http://127.0.0.1:1", nil)
	before := g.state.Load().upstreams["jira"].proxy.Transport
	cfg, _ := g.Config().clone()
	cfg.OutboundProxy = &OutboundProxy{URL: "http://proxy.test:3128"}
	cfg, _ = cfg.clone()
	g.Apply(cfg)
	after := g.state.Load().upstreams["jira"].proxy.Transport
	if before == after {
		t.Fatal("an outbound proxy change must not reuse the previous transport")
	}
}
