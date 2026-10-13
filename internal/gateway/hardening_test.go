package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNestedEscapesAndEncodedControlsNeverReachUpstream(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, func(c *Config) { c.Keys[0].RequestsPerMinute = 0 })
	for _, path := range []string{
		"/jira/rest/api/3/search/%252e%252e/admin",
		"/jira/rest/api/3/issue/A%252fadmin",
		"/jira/rest/api/3/search/%25252e%25252e/admin",
		"/jira/rest/api/3/issue/A%0a", "/jira/rest/api/3/issue/A%1f", "/jira/rest/api/3/issue/A%7f",
	} {
		got = seen{}
		if rec := do(g, "GET", path, agentKey, nil); rec.Code != http.StatusBadRequest || got.method != "" {
			t.Errorf("path %q: status %d, upstream called=%v", path, rec.Code, got.method != "")
		}
	}
}

func TestCallerMethodAndPathOverridesAreStripped(t *testing.T) {
	var overrides http.Header
	var actualMethod, actualPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		overrides = r.Header.Clone()
		actualMethod, actualPath = r.Method, r.URL.EscapedPath()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, nil)
	hdr := map[string]string{
		"X-HTTP-Method-Override": "DELETE", "X-HTTP-Method": "DELETE", "X-Method-Override": "DELETE",
		"X-Original-Method": "DELETE", "X-Original-URL": "/admin", "X-Rewrite-URL": "/admin",
		"X-Forwarded-Prefix": "/admin", "X-Forwarded-Uri": "/admin", "Forwarded": "host=evil.example",
	}
	if rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, hdr); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	for h := range hdr {
		if overrides.Get(h) != "" {
			t.Errorf("caller override %s reached the upstream", h)
		}
	}
	if actualMethod != "GET" || actualPath != "/jira/rest/api/3/issue/A-1" {
		t.Fatalf("forwarded request changed: %s %s", actualMethod, actualPath)
	}
}

func TestEscapedBasePreservesEscapedRequestPath(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	cfg, _ := g.Config().clone()
	cfg.Upstreams[0].BaseURL = up.URL + "/space%20base"
	cfg, err := cfg.clone()
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(cfg)
	if rec := do(g, "GET", "/jira/rest/api/3/issue/%41-1", agentKey, nil); rec.Code != 200 || got.path != "/space%20base/rest/api/3/issue/%41-1" {
		t.Fatalf("escaped path changed: status %d, path %q", rec.Code, got.path)
	}
}

func TestResponseHeadersAndTrailersCannotExposeCredentials(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Authorization", r.Header.Get("Authorization"))
		w.Header().Set("X-Echo-Secret", "token=real-secret")
		w.Header().Set("Set-Cookie", "early=real-secret")
		w.Header().Set("X-Safe", "preserved")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Trailer", "Set-Cookie, X-Echo-Secret, X-Safe-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
		w.Header().Set("Set-Cookie", "session=real-secret")
		w.Header().Set("X-Echo-Secret", "token=real-secret")
		w.Header().Set("X-Safe-Trailer", "preserved")
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	var early http.Header
	req, _ := http.NewRequest("GET", srv.URL+"/jira/rest/api/3/issue/A-1", nil)
	req.Header.Set("Authorization", "Bearer "+agentKey)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(_ int, h textproto.MIMEHeader) error { early = http.Header(h).Clone(); return nil },
	}))
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	for label, hdr := range map[string]http.Header{"early": early, "final": res.Header, "trailer": res.Trailer} {
		for h, vs := range hdr {
			if strings.EqualFold(h, "Authorization") || strings.EqualFold(h, "Set-Cookie") {
				if len(vs) > 0 {
					t.Errorf("%s leaked %s", label, h)
				}
			}
			for _, v := range vs {
				if strings.Contains(v, "real-secret") {
					t.Errorf("%s leaked secret through %s", label, h)
				}
			}
		}
	}
	if res.Header.Get("X-Safe") != "preserved" || res.Trailer.Get("X-Safe-Trailer") != "preserved" {
		t.Fatal("safe headers or trailers were removed")
	}
}

type reviewRoundTripper func(*http.Request) (*http.Response, error)

func (f reviewRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRequestTrailersDoNotCrossCredentialBoundary(t *testing.T) {
	g, _ := testGateway(t, "http://unused.test", nil)
	var trailers http.Header
	g.transport = reviewRoundTripper(func(r *http.Request) (*http.Response, error) {
		trailers = r.Trailer.Clone()
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	})
	g.Apply(g.Config())
	r := httptest.NewRequest("POST", "/jira/rest/api/3/issue/A-1/comment", strings.NewReader("body"))
	r.Header.Set("Authorization", "Bearer "+agentKey)
	r.Trailer = http.Header{"Authorization": {agentKey}, "Cookie": {"caller=secret"}, "X-Original-Url": {"/admin"}}
	res := httptest.NewRecorder()
	g.ServeHTTP(res, r)
	if res.Code != 204 || len(trailers) != 0 {
		t.Fatalf("request trailers reached the upstream: status %d, names %v", res.Code, trailers)
	}
}

func TestTransportErrorsDoNotLogSecrets(t *testing.T) {
	g, _ := testGateway(t, "http://unused.test", nil)
	var logs bytes.Buffer
	g.log = slog.New(slog.NewJSONHandler(&logs, nil))
	g.transport = reviewRoundTripper(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("upstream echoed " + r.Header.Get("Authorization"))
	})
	g.Apply(g.Config())
	rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(logs.String(), "Ym90QGV4YW1wbGUuY29tOnJlYWwtc2VjcmV0") {
		t.Fatal("transport error logged the credential")
	}
}

func TestResponseRedactsUsableBasicTokensAndEncodedSecrets(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Encoded", "secret%2fvalue")
		w.Header().Set("X-Nested", "secret%252fvalue")
		w.Header().Set("X-Malformed", "junk%zz secret%2fvalue")
		w.Header().Set("X-Malformed-Nested", "junk%zz secret%252fvalue")
		w.Header().Set("X-Token", strings.TrimPrefix(r.Header.Get("Authorization"), "Basic "))
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, nil)
	g.getenv = func(string) string { return "secret/value" }
	g.Apply(g.Config())
	rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil)
	for _, h := range []string{"X-Encoded", "X-Nested", "X-Malformed", "X-Malformed-Nested", "X-Token"} {
		if rec.Header().Get(h) != "" {
			t.Errorf("usable credential escaped sanitising via %s", h)
		}
	}
	// Egress proxies must not be able to echo their own Basic token either.
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proxy-Token", strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic "))
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(px.Close)
	cfg, _ := g.Config().clone()
	cfg.OutboundProxy = &OutboundProxy{URL: px.URL, Username: "proxy-user", SecretEnv: "S"}
	cfg, err := cfg.clone()
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(cfg)
	if rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 200 || rec.Header().Get("X-Proxy-Token") != "" {
		t.Fatalf("egress credential echo: %d", rec.Code)
	}
}

func TestUnannouncedResponseTrailersCannotLeak(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
		w.(http.Flusher).Flush()
		w.Header().Set(http.TrailerPrefix+"Set-Cookie", "session=opaque")
		w.Header().Set(http.TrailerPrefix+"X-Echo-Secret", "real-secret")
		w.Header().Set(http.TrailerPrefix+"X-Safe-Trailer", "preserved")
	}))
	t.Cleanup(up.Close)
	g, _ := testGateway(t, up.URL, nil)
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest("GET", srv.URL+"/jira/rest/api/3/issue/A-1", nil)
	req.Header.Set("Authorization", "Bearer "+agentKey)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.Trailer.Get("Set-Cookie") != "" || res.Trailer.Get("X-Echo-Secret") != "" {
		t.Fatal("unannounced credential or cookie trailer leaked")
	}
	if res.Trailer.Get("X-Safe-Trailer") != "preserved" {
		t.Fatal("safe unannounced trailer was removed")
	}
}

func TestAuditPathsRedactKnownKeyAndCredentialValues(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	var logs bytes.Buffer
	g.log = slog.New(slog.NewJSONHandler(&logs, nil))
	for _, segment := range []string{agentKey, "%68w_test-agent-key", "real-secret", base64.StdEncoding.EncodeToString([]byte("bot@example.com:real-secret"))} {
		if rec := do(g, "GET", "/jira/rest/api/3/search/"+segment, agentKey, nil); rec.Code != 200 && rec.Code != 429 {
			t.Fatalf("status %d", rec.Code)
		}
	}
	for _, ev := range g.events.since(0, 10) {
		if ev.Path != "[redacted]" {
			t.Errorf("sensitive audit path survived: %q", ev.Path)
		}
	}
	for _, sensitive := range []string{agentKey, "real-secret", base64.StdEncoding.EncodeToString([]byte("bot@example.com:real-secret"))} {
		if strings.Contains(logs.String(), sensitive) {
			t.Fatal("audit logger exposed a credential")
		}
	}
}

func TestDeniedAuditAndMethodMetadataCannotExposeKnownSecrets(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, func(c *Config) {
		c.Keys[0].Grants[0].Methods = []string{"*"}
	})
	if rec := do(g, "GET", "/jira/rest/api/3/search/real-secret", "hw_invalid", nil); rec.Code != 401 || got.method != "" {
		t.Fatal("invalid key reached upstream")
	}
	if rec := do(g, agentKey, "/jira/rest/api/3/search/ok", agentKey, nil); rec.Code != 200 {
		t.Fatalf("custom method: status %d", rec.Code)
	}
	events := g.events.since(0, 10)
	if len(events) != 2 || events[0].Path != "[redacted]" || events[1].Method != "[redacted]" {
		t.Fatal("untrusted audit metadata exposed a known secret")
	}
}

func TestEventCursorDoesNotWrap(t *testing.T) {
	l := newEventLog(3)
	l.add(Event{Outcome: "forbidden"})
	if got := l.since(math.MaxUint64, 10); len(got) != 0 {
		t.Fatalf("future cursor returned %d events", len(got))
	}
}

func TestObsoleteTransportPoolsAreRetired(t *testing.T) {
	g, _ := testGateway(t, "http://127.0.0.1:1", nil)
	for i := 1; i <= 5; i++ {
		cfg, _ := g.Config().clone()
		cfg.Upstreams[0].TimeoutSeconds = i
		g.Apply(cfg)
	}
	g.trMu.Lock()
	defer g.trMu.Unlock()
	if len(g.transports) != 1 {
		t.Fatalf("retained %d transport pools for one active upstream", len(g.transports))
	}
}

func TestProxyCAGenerationRejectsNonpositiveValidity(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Hour} {
		dir := t.TempDir()
		if err := GenerateProxyCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "key.pem"), d); err == nil {
			t.Errorf("accepted validity %s", d)
		}
	}
}

func TestAbsoluteTargetsAreDeniedWhenProxyIsDisabled(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	target := up.URL + "/jira/rest/api/3/issue/A-1"
	if rec := do(g, "GET", target, agentKey, nil); rec.Code != http.StatusMethodNotAllowed || got.method != "" {
		t.Fatalf("absolute-form request: status %d, upstream called=%v", rec.Code, got.method != "")
	}
	if d := g.Explain("agent", "GET", target); d.Allowed || d.Outcome != "proxy_disabled" {
		t.Fatalf("explain disagrees: %+v", d)
	}
}

func TestExplainRejectsAmbiguousTargetsAndAcceptsEmptyQuery(t *testing.T) {
	g, _ := testGateway(t, "https://jira.example.com", func(c *Config) { c.Proxy = &ProxyMode{} })
	for _, target := range []string{
		"https://user:password@jira.example.com/jira/rest/api/3/issue/A-1",
		"https://jira.example.com/jira/rest/api/3/issue/A-1#fragment",
		"/jira/rest/api/3/issue/A-1#fragment", "http:opaque", "/jira/rest/api/3/issue/%xx", "//other.example/jira/rest/api/3/issue/A-1",
	} {
		if d := g.Explain("agent", "GET", target); d.Allowed || d.Outcome != "bad_path" {
			t.Errorf("ambiguous target %q: %+v", target, d)
		}
	}
	if d := g.Explain("agent", "GET", "/jira/rest/api/3/issue/A-1?"); !d.Allowed {
		t.Fatalf("empty query: %+v", d)
	}
}

func TestOpenTunnelIsDeniedAfterProxyDisable(t *testing.T) {
	var calls int
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(up.Close)
	g, srv, ca := proxyGateway(t, up.URL, true, up.Client().Transport)
	c := proxyClient(t, srv.URL, agentKey, ca)
	if status, _ := get(t, c, "GET", up.URL+"/jira/rest/api/3/issue/A-1", nil); status != 200 {
		t.Fatal(status)
	}
	cfg, _ := g.Config().clone()
	cfg.Proxy = nil
	g.Apply(cfg)
	if status, _ := get(t, c, "GET", up.URL+"/jira/rest/api/3/issue/A-1", map[string]string{"Authorization": "Bearer " + agentKey}); status != 405 || calls != 1 {
		t.Fatalf("disabled tunnel: status %d, upstream calls %d", status, calls)
	}
}

func TestTunnelShutdownDrainsActiveRequests(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "completed")
	}))
	t.Cleanup(up.Close)
	g, srv, ca := proxyGateway(t, up.URL, true, up.Client().Transport)
	t.Cleanup(g.Close)
	c := proxyClient(t, srv.URL, agentKey, ca)
	result := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", up.URL+"/jira/rest/api/3/issue/A-1", nil)
		res, err := c.Do(req)
		if err == nil {
			defer res.Body.Close()
			var b []byte
			b, err = io.ReadAll(res.Body)
			if err == nil && string(b) != "completed" {
				err = errors.New("active response was not completed")
			}
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("request did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- g.Shutdown(ctx) }()
	select {
	case err := <-drained:
		close(release)
		t.Fatalf("shutdown discarded an active request: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
	if rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil); rec.Code != 503 {
		t.Fatalf("new request after shutdown: %d", rec.Code)
	}
}

func TestTunnelShutdownDeadlineForcesClosure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "late")
	}))
	t.Cleanup(up.Close)
	g, srv, ca := proxyGateway(t, up.URL, true, up.Client().Transport)
	t.Cleanup(g.Close)
	c := proxyClient(t, srv.URL, agentKey, ca)
	result := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("GET", up.URL+"/jira/rest/api/3/issue/A-1", nil)
		res, err := c.Do(req)
		if res != nil {
			res.Body.Close()
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("request did not start")
	}
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := g.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown deadline: %v", err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("deadline did not close the active tunnel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel remained open after deadline")
	}
}

type reviewTunnelConn struct{ id int }

func (*reviewTunnelConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*reviewTunnelConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (*reviewTunnelConn) Close() error                     { return nil }
func (*reviewTunnelConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (*reviewTunnelConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (*reviewTunnelConn) SetDeadline(time.Time) error      { return nil }
func (*reviewTunnelConn) SetReadDeadline(time.Time) error  { return nil }
func (*reviewTunnelConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnectLimitRefusesWithoutCallingUpstream(t *testing.T) {
	var calls int
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	t.Cleanup(up.Close)
	g, srv, _ := proxyGateway(t, up.URL, true, up.Client().Transport)
	t.Cleanup(g.Close)
	g.connMu.Lock()
	g.tunnels = make(map[net.Conn]*http.Server)
	for i := 0; i < maxProxyTunnels; i++ {
		g.tunnels[&reviewTunnelConn{id: i}] = nil
	}
	g.connMu.Unlock()
	req, _ := http.NewRequest("CONNECT", srv.URL, nil)
	req.Host = strings.TrimPrefix(up.URL, "https://")
	req.Header.Set("Proxy-Authorization", "Bearer "+agentKey)
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 503 || res.Header.Get("Retry-After") != "1" || !bytes.Contains(body, []byte(`"proxy_busy"`)) || calls != 0 {
		t.Fatalf("tunnel limit: status %d, upstream calls %d", res.StatusCode, calls)
	}
}

func TestConnectRequiresGrantForThatOrigin(t *testing.T) {
	var calls int
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	t.Cleanup(up.Close)
	g, srv, _ := proxyGateway(t, up.URL, true, up.Client().Transport)
	t.Cleanup(g.Close)
	cfg, _ := g.Config().clone()
	cfg.Upstreams = append(cfg.Upstreams, Upstream{Name: "other", BaseURL: "https://127.0.0.1:1", Auth: Auth{Type: "none"}})
	cfg.Keys[0].Grants = []Grant{{Upstream: "other", Methods: []string{"GET"}, Paths: []string{"/**"}}}
	cfg, err := cfg.clone()
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(cfg)
	req, _ := http.NewRequest("CONNECT", srv.URL, nil)
	req.Host = strings.TrimPrefix(up.URL, "https://")
	req.Header.Set("Proxy-Authorization", "Bearer "+agentKey)
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 || calls != 0 {
		t.Fatalf("foreign grant: status %d, upstream calls %d", res.StatusCode, calls)
	}
}

func TestTunnelRejectsConflictingHTTPAuthority(t *testing.T) {
	var calls int
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	t.Cleanup(up.Close)
	g, srv, ca := proxyGateway(t, up.URL, true, up.Client().Transport)
	t.Cleanup(g.Close)
	c := proxyClient(t, srv.URL, agentKey, ca)
	req, _ := http.NewRequest("GET", up.URL+"/jira/rest/api/3/issue/A-1", nil)
	req.Host = "other.example"
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 400 || calls != 0 {
		t.Fatalf("conflicting authority: status %d, upstream calls %d", res.StatusCode, calls)
	}
}

func TestProxyRejectsExpiredCA(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "key.pem")
	// X.509 validity is encoded with second precision, so this certificate
	// is already expired by the time its files can be read back.
	if err := GenerateProxyCA(cert, key, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProxyCA(cert, key); err == nil || !strings.Contains(err.Error(), "not currently valid") {
		t.Fatalf("expired CA: %v", err)
	}
}

func TestEnvironmentEgressCredentialsAreCoveredByRedaction(t *testing.T) {
	pu, _ := url.Parse("http://proxy-user:proxy-secret@proxy.invalid")
	target, _ := url.Parse("https://upstream.invalid")
	eg := (egress{id: "env", proxy: func(*http.Request) (*url.URL, error) { return pu, nil }}).withSensitiveCredentials(target)
	if eg.secret != "proxy-secret" || eg.authorization != "Basic "+base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret")) {
		t.Fatal("environment-selected credentials were not resolved for sanitising")
	}
}
