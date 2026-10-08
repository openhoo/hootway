package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// benchGateway builds a gateway with nKeys keys, each holding several grants
// over nUp upstreams, plus the agent key used by the benchmarks. Logging uses
// the production JSON handler writing to io.Discard so formatting cost is
// included.
func benchGateway(b *testing.B, base string, nKeys int, rpm int) *Gateway {
	b.Helper()
	var sb strings.Builder
	sb.WriteString(`{"upstreams":[`)
	const nUp = 8
	for i := 0; i < nUp; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"name":"up%d","base_url":"%s/api%d","auth":{"type":"bearer","secret_env":"TOKEN"},"headers":{"X-Static":"v"}}`, i, base, i)
	}
	sb.WriteString(`,{"name":"jira","base_url":"` + base + `/jira","auth":{"type":"basic","username":"bot@example.com","secret_env":"TOKEN"}}`)
	sb.WriteString(`],"keys":[`)
	for i := 0; i < nKeys; i++ {
		fmt.Fprintf(&sb, `{"id":"k%d","sha256":"%s","grants":[`, i, HashKey(fmt.Sprintf("hw_key-%d", i)))
		for j := 0; j < nUp; j++ {
			if j > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"upstream":"up%d","methods":["GET","POST"],"paths":["/v1/items/*","/v1/users/*/repos","/v2/**"]}`, j)
		}
		sb.WriteString(`]},`)
	}
	// The agent key has many non-matching grants before the matching one so
	// grant evaluation is exercised realistically.
	fmt.Fprintf(&sb, `{"id":"agent","sha256":"%s","requests_per_minute":%d,"grants":[`, HashKey(agentKey), rpm)
	for j := 0; j < nUp; j++ {
		fmt.Fprintf(&sb, `{"upstream":"up%d","methods":["GET"],"paths":["/a/*","/b/*/c","/d/**"]},`, j)
	}
	sb.WriteString(`{"upstream":"jira","methods":["DELETE","PUT","GET"],"paths":["/rest/api/2/*","/rest/api/3/project/*","/rest/api/3/issue/*","/rest/api/3/search/**"]}]}]}`)
	cfg, err := ParseConfig([]byte(sb.String()))
	if err != nil {
		b.Fatal(err)
	}
	g, err := New(cfg, Options{
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Getenv: func(string) string { return "real-secret" },
	})
	if err != nil {
		b.Fatal(err)
	}
	return g
}

func benchUpstream(b *testing.B) *httptest.Server {
	b.Helper()
	body := []byte(`{"id":"ABC-1","fields":{"summary":"hello world"}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	b.Cleanup(srv.Close)
	return srv
}

// discardWriter is a minimal ResponseWriter so the benchmark measures the
// gateway rather than httptest.ResponseRecorder.
type discardWriter struct {
	h      http.Header
	status int
}

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *discardWriter) WriteHeader(code int)        { d.status = code }

func (d *discardWriter) reset() {
	clear(d.h)
	d.status = 0
}

func newBenchRequest(method, target, key string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "agent=1")
	return req
}

func serveBench(b *testing.B, g *Gateway, method, target, key string, want int) {
	b.Helper()
	req := newBenchRequest(method, target, key)
	w := &discardWriter{h: http.Header{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.reset()
		g.ServeHTTP(w, req)
		if w.status != 0 && w.status != want {
			b.Fatalf("status %d, want %d", w.status, want)
		}
	}
}

func BenchmarkServeForwarded(b *testing.B) {
	up := benchUpstream(b)
	g := benchGateway(b, up.URL, 100, 0)
	serveBench(b, g, "GET", "/jira/rest/api/3/issue/ABC-1?fields=summary", agentKey, http.StatusOK)
}

func BenchmarkServeForwardedParallel(b *testing.B) {
	up := benchUpstream(b)
	g := benchGateway(b, up.URL, 100, 0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := newBenchRequest("GET", "/jira/rest/api/3/issue/ABC-1?fields=summary", agentKey)
		w := &discardWriter{h: http.Header{}}
		for pb.Next() {
			w.reset()
			g.ServeHTTP(w, req)
			if w.status != 0 && w.status != http.StatusOK {
				b.Errorf("status %d", w.status)
				return
			}
		}
	})
}

func BenchmarkServeDenied(b *testing.B) {
	g := benchGateway(b, "http://127.0.0.1:1", 100, 0)
	b.Run("forbidden", func(b *testing.B) {
		serveBench(b, g, "GET", "/jira/rest/api/3/user/x", agentKey, http.StatusForbidden)
	})
	b.Run("invalid_key", func(b *testing.B) {
		serveBench(b, g, "GET", "/jira/rest/api/3/issue/ABC-1", "hw_not-a-real-key", http.StatusUnauthorized)
	})
	b.Run("missing_key", func(b *testing.B) {
		serveBench(b, g, "GET", "/jira/rest/api/3/issue/ABC-1", "", http.StatusUnauthorized)
	})
	b.Run("bad_path", func(b *testing.B) {
		serveBench(b, g, "GET", "/jira/rest/api/3/issue/%2e%2e/x", agentKey, http.StatusBadRequest)
	})
}

func BenchmarkServeDeniedParallel(b *testing.B) {
	g := benchGateway(b, "http://127.0.0.1:1", 100, 0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := newBenchRequest("GET", "/jira/rest/api/3/user/x", agentKey)
		w := &discardWriter{h: http.Header{}}
		for pb.Next() {
			w.reset()
			g.ServeHTTP(w, req)
		}
	})
}

func BenchmarkKeyLookup(b *testing.B) {
	g := benchGateway(b, "http://127.0.0.1:1", 1000, 0)
	st := g.state.Load()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if benchLookup(st, agentKey) == nil {
			b.Fatal("key not found")
		}
	}
}

func BenchmarkExtractKey(b *testing.B) {
	bearer := newBenchRequest("GET", "/jira/x", agentKey)
	basic := httptest.NewRequest("GET", "/jira/x", nil)
	basic.SetBasicAuth("agent@example.com", agentKey)
	for name, req := range map[string]*http.Request{"bearer": bearer, "basic": basic} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if extractKey(req) != agentKey {
					b.Fatal("key not extracted")
				}
			}
		})
	}
}

func BenchmarkGrantMatch(b *testing.B) {
	g := benchGateway(b, "http://127.0.0.1:1", 10, 0)
	st := g.state.Load()
	k := benchLookup(st, agentKey)
	cases := []struct {
		name, up, method, path string
		want                   bool
	}{
		{"allow_last_grant", "jira", "GET", "/rest/api/3/search/jql/deep/path", true},
		{"allow_star", "jira", "GET", "/rest/api/3/issue/ABC-1", true},
		{"deny_path", "jira", "GET", "/rest/api/3/user/x", false},
		{"deny_method", "jira", "POST", "/rest/api/3/issue/ABC-1", false},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if benchAllows(st, k, c.up, c.method, c.path) != c.want {
					b.Fatal("unexpected decision")
				}
			}
		})
	}
}

func BenchmarkSplitRoute(b *testing.B) {
	for name, p := range map[string]string{
		"ok":     "/jira/rest/api/3/issue/ABC-1/comment",
		"reject": "/jira/rest/api/3/issue/%2e%2e/x",
		"dotdot": "/jira/rest/api/3/issue/../x",
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _ = splitRoute(p)
			}
		})
	}
}

func BenchmarkEventAdd(b *testing.B) {
	l := newEventLog(1000)
	ev := Event{Time: time.Now(), Key: "agent", Upstream: "jira", Method: "GET", Path: "/jira/x", Status: 200, Outcome: "forwarded"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.add(ev)
	}
}

func BenchmarkEventAddParallel(b *testing.B) {
	l := newEventLog(1000)
	ev := Event{Time: time.Now(), Key: "agent", Upstream: "jira", Method: "GET", Path: "/jira/x", Status: 200, Outcome: "forwarded"}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.add(ev)
		}
	})
}

func BenchmarkEventSince(b *testing.B) {
	l := newEventLog(1000)
	ev := Event{Time: time.Now(), Key: "agent", Upstream: "jira", Method: "GET", Path: "/jira/x", Status: 200, Outcome: "forwarded"}
	for i := 0; i < 1500; i++ {
		l.add(ev)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(l.since(1450, 200)) != 50 {
			b.Fatal("unexpected count")
		}
	}
}

func BenchmarkRateLimit(b *testing.B) {
	g := benchGateway(b, "http://127.0.0.1:1", 10, 1<<30)
	k := benchLookup(g.state.Load(), agentKey)
	// A clock shared by all runs that only moves forward, so the window
	// resets every simulated minute and the limit is never exhausted.
	start := time.Now()
	var clock atomic.Int64
	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !benchTake(g, k, start.Add(time.Duration(clock.Add(1))*time.Microsecond)) {
				b.Fatal("limited")
			}
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				benchTake(g, k, start.Add(time.Duration(clock.Add(1))*time.Microsecond))
			}
		})
	})
}

// Adapters so benchmarks stay identical across internal refactors.
func benchLookup(st *runtimeState, key string) *runtimeKey { return st.lookupKey(key) }
func benchAllows(_ *runtimeState, k *runtimeKey, up, method, path string) bool {
	return k.allows(up, method, path)
}
func benchTake(_ *Gateway, k *runtimeKey, now time.Time) bool { return k.take(now) }
