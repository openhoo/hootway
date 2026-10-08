package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// KeyPrefix marks Hootway virtual keys so they are recognisable in logs and
// secret scanners.
const KeyPrefix = "hw_"

// Gateway is an http.Handler that authenticates virtual keys, enforces grants
// and forwards permitted requests with the real upstream credential. Its
// configuration can be replaced atomically while serving.
type Gateway struct {
	state     atomic.Pointer[runtimeState]
	log       *slog.Logger
	now       func() time.Time
	getenv    func(string) string
	transport http.RoundTripper
	events    *eventLog

	limMu   sync.Mutex
	windows map[string]*window // by key id, survives reloads
}

type runtimeState struct {
	cfg       *Config
	upstreams map[string]*route
	keys      map[string]*Key // by sha256 hex
	problems  map[string]string
}

type route struct {
	up    Upstream
	cred  credential
	err   error
	proxy *httputil.ReverseProxy
}

type window struct {
	start time.Time
	count int
}

// Options customise a Gateway; all fields are optional.
type Options struct {
	Logger    *slog.Logger
	Getenv    func(string) string
	Transport http.RoundTripper
	Now       func() time.Time
	// Lenient lets the gateway start while some upstream credentials cannot
	// be resolved; those upstreams answer 503 until fixed.
	Lenient bool
}

// New resolves all upstream credentials and builds a Gateway.
func New(cfg *Config, opts Options) (*Gateway, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	g := &Gateway{log: opts.Logger, now: opts.Now, getenv: opts.Getenv, transport: opts.Transport,
		events: newEventLog(1000), windows: map[string]*window{}}
	st := g.build(cfg)
	if len(st.problems) > 0 && !opts.Lenient {
		var errs []error
		for name, p := range st.problems {
			errs = append(errs, fmt.Errorf("upstream %q: %s", name, p))
		}
		return nil, errors.Join(errs...)
	}
	for name, p := range st.problems {
		opts.Logger.Warn("upstream credential unavailable", "upstream", name, "problem", p)
	}
	g.state.Store(st)
	return g, nil
}

// Apply atomically replaces the active configuration and returns credential
// problems, keyed by upstream name.
func (g *Gateway) Apply(cfg *Config) map[string]string {
	st := g.build(cfg)
	g.state.Store(st)
	return st.problems
}

// Config returns the active configuration. Callers must not modify it.
func (g *Gateway) Config() *Config { return g.state.Load().cfg }

// Problems returns credential problems of the active configuration.
func (g *Gateway) Problems() map[string]string { return g.state.Load().problems }

func (g *Gateway) build(cfg *Config) *runtimeState {
	st := &runtimeState{cfg: cfg, upstreams: map[string]*route{}, keys: map[string]*Key{}, problems: map[string]string{}}
	for _, up := range cfg.Upstreams {
		r := &route{up: up}
		r.cred, r.err = resolveCredential(up.Auth, g.getenv)
		if r.err != nil {
			st.problems[up.Name] = r.err.Error()
		}
		timeout := time.Duration(up.TimeoutSeconds) * time.Second
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		transport := g.transport
		if transport == nil {
			transport = &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: timeout,
				MaxIdleConnsPerHost:   16,
				IdleConnTimeout:       90 * time.Second,
				ForceAttemptHTTP2:     true,
			}
		}
		name := up.Name
		r.proxy = &httputil.ReverseProxy{
			Rewrite:        r.rewrite,
			Transport:      transport,
			ModifyResponse: r.modifyResponse,
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				g.log.Warn("upstream error", "upstream", name, "error", err.Error())
				infoFrom(req.Context()).outcome = "upstream_error"
				writeError(w, http.StatusBadGateway, "upstream_unreachable", "the upstream request failed")
			},
		}
		st.upstreams[up.Name] = r
	}
	for i := range cfg.Keys {
		k := &cfg.Keys[i]
		st.keys[k.SHA256] = k
	}
	return st
}

// HashKey returns the configuration hash for a virtual key.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// GenerateKey returns a new random virtual key and its hash.
func GenerateKey() (key, hash string, err error) {
	return generate(KeyPrefix)
}

func generate(prefix string) (key, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	key = prefix + base64.RawURLEncoding.EncodeToString(buf)
	return key, HashKey(key), nil
}

type ctxKey struct{}

type requestInfo struct {
	rest    string
	outcome string
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := g.now()
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	st := g.state.Load()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	info := &requestInfo{}
	ev := Event{Method: r.Method, Path: r.URL.EscapedPath()}
	defer func() {
		ev.Time = start
		ev.Status = rec.status
		ev.Outcome = info.outcome
		ev.DurationMS = g.now().Sub(start).Milliseconds()
		g.events.add(ev)
		g.log.Info("request", "key", ev.Key, "upstream", ev.Upstream, "method", ev.Method,
			"path", ev.Path, "status", ev.Status, "outcome", ev.Outcome, "duration_ms", ev.DurationMS)
	}()

	presented := extractKey(r)
	if presented == "" {
		info.outcome = "missing_key"
		rec.Header().Set("WWW-Authenticate", `Bearer realm="hootway"`)
		writeError(rec, http.StatusUnauthorized, "missing_key", "a Hootway virtual key is required")
		return
	}
	k := st.keys[HashKey(presented)]
	if k == nil || k.Disabled || (k.ExpiresAt != nil && !g.now().Before(*k.ExpiresAt)) {
		info.outcome = "invalid_key"
		if k != nil {
			ev.Key = k.ID
		}
		rec.Header().Set("WWW-Authenticate", `Bearer realm="hootway", error="invalid_token"`)
		writeError(rec, http.StatusUnauthorized, "invalid_key", "the virtual key is unknown, disabled or expired")
		return
	}
	ev.Key = k.ID

	name, rest, err := splitRoute(r.URL.EscapedPath())
	if err != nil {
		info.outcome = "bad_path"
		writeError(rec, http.StatusBadRequest, "bad_path", "the request path contains disallowed encodings or dot segments")
		return
	}
	ev.Upstream = name
	rt := st.upstreams[name]
	if rt == nil || !keyAllows(k, name, r.Method, rest) {
		info.outcome = "forbidden"
		writeError(rec, http.StatusForbidden, "forbidden", "this key is not allowed to call this upstream method and path")
		return
	}
	if !g.take(k, g.now()) {
		info.outcome = "rate_limited"
		rec.Header().Set("Retry-After", "60")
		writeError(rec, http.StatusTooManyRequests, "rate_limited", "the key's request rate limit is exhausted")
		return
	}
	if rt.err != nil {
		info.outcome = "upstream_unconfigured"
		writeError(rec, http.StatusServiceUnavailable, "upstream_unconfigured", "the gateway has no usable credential for this upstream")
		return
	}
	info.outcome = "forwarded"
	info.rest = rest
	rt.proxy.ServeHTTP(rec, r.WithContext(contextWith(r.Context(), info)))
}

// Decision explains whether a key may call a method and path.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
	Grant   *Grant `json:"grant,omitempty"`
}

// Explain evaluates the active policy without contacting any upstream.
func (g *Gateway) Explain(keyID, method, path string) Decision {
	st := g.state.Load()
	var k *Key
	for _, c := range st.keys {
		if c.ID == keyID {
			k = c
		}
	}
	switch {
	case k == nil:
		return Decision{Outcome: "invalid_key", Reason: "no key with this id"}
	case k.Disabled:
		return Decision{Outcome: "invalid_key", Reason: "the key is disabled"}
	case k.ExpiresAt != nil && !g.now().Before(*k.ExpiresAt):
		return Decision{Outcome: "invalid_key", Reason: "the key has expired"}
	}
	if u, err := url.Parse(path); err == nil && u.RawQuery != "" {
		path = u.EscapedPath()
	}
	name, rest, err := splitRoute(path)
	if err != nil {
		return Decision{Outcome: "bad_path", Reason: "the path contains dot segments, // or encoded separators"}
	}
	rt := st.upstreams[name]
	if rt == nil {
		return Decision{Outcome: "forbidden", Reason: fmt.Sprintf("there is no upstream named %q", name)}
	}
	for i, gr := range k.Grants {
		if gr.Upstream == name && gr.allows(method, rest) {
			if rt.err != nil {
				return Decision{Outcome: "upstream_unconfigured", Reason: "allowed, but the upstream credential is unavailable: " + rt.err.Error(), Grant: &k.Grants[i]}
			}
			return Decision{Allowed: true, Outcome: "forwarded", Reason: fmt.Sprintf("allowed and forwarded to %s%s", rt.up.base.String(), rest), Grant: &k.Grants[i]}
		}
	}
	return Decision{Outcome: "forbidden", Reason: fmt.Sprintf("no grant allows %s %s on %s", method, rest, name)}
}

func keyAllows(k *Key, upstream, method, path string) bool {
	for _, gr := range k.Grants {
		if gr.Upstream == upstream && gr.allows(method, path) {
			return true
		}
	}
	return false
}

func (g *Gateway) take(k *Key, now time.Time) bool {
	if k.RequestsPerMinute == 0 {
		return true
	}
	g.limMu.Lock()
	defer g.limMu.Unlock()
	w := g.windows[k.ID]
	if w == nil {
		w = &window{}
		g.windows[k.ID] = w
	}
	if now.Sub(w.start) >= time.Minute {
		w.start, w.count = now, 0
	}
	if w.count >= k.RequestsPerMinute {
		return false
	}
	w.count++
	return true
}

// extractKey accepts the virtual key as a bearer token, as the password of
// HTTP basic auth (for clients that only support e-mail + API token), or in
// the X-Hootway-Key header.
func extractKey(r *http.Request) string {
	if v := r.Header.Get("X-Hootway-Key"); v != "" {
		return v
	}
	authz := r.Header.Get("Authorization")
	if scheme, token, ok := strings.Cut(authz, " "); ok {
		switch strings.ToLower(scheme) {
		case "bearer":
			return strings.TrimSpace(token)
		case "basic":
			if _, pass, ok := r.BasicAuth(); ok {
				return pass
			}
		}
	}
	return ""
}

func (rt *route) rewrite(pr *httputil.ProxyRequest) {
	info := infoFrom(pr.In.Context())
	out := pr.Out
	target := *rt.up.base
	out.URL.Scheme = target.Scheme
	out.URL.Host = target.Host
	out.URL.RawPath = target.Path + info.rest
	if p, err := url.PathUnescape(out.URL.RawPath); err == nil {
		out.URL.Path = p
	}
	out.Host = target.Host
	// Never forward caller credentials, cookies or gateway headers.
	for h := range out.Header {
		if isProtectedHeader(h) && h != "Content-Length" && h != "Transfer-Encoding" {
			out.Header.Del(h)
		}
	}
	out.Header.Del("Forwarded")
	out.Header.Del("X-Forwarded-For")
	out.Header.Del("X-Forwarded-Host")
	out.Header.Del("X-Forwarded-Proto")
	for k, v := range rt.up.Headers {
		out.Header.Set(k, v)
	}
	rt.cred.apply(out)
}

func (rt *route) modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	// Keep redirects inside the gateway so the agent never needs the
	// upstream credential to follow them.
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && u.IsAbs() && u.Host == rt.up.base.Host && u.Scheme == rt.up.base.Scheme &&
			strings.HasPrefix(u.EscapedPath(), rt.up.base.Path+"/") {
			rel := "/" + rt.up.Name + strings.TrimPrefix(u.EscapedPath(), rt.up.base.Path)
			if u.RawQuery != "" {
				rel += "?" + u.RawQuery
			}
			resp.Header.Set("Location", rel)
		}
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"code": code, "message": msg}})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
