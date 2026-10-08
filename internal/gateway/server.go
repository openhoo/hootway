package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// KeyPrefix marks Hootway virtual keys so they are recognisable in logs and
// secret scanners.
const KeyPrefix = "hw_"

// Gateway is an http.Handler that authenticates virtual keys, enforces grants
// and forwards permitted requests with the real upstream credential.
type Gateway struct {
	upstreams map[string]*route
	keys      map[string]*keyState // by sha256 hex
	log       *slog.Logger
	now       func() time.Time
}

type route struct {
	up    Upstream
	cred  credential
	proxy *httputil.ReverseProxy
}

type keyState struct {
	Key
	mu          sync.Mutex
	windowStart time.Time
	count       int
}

// Options customise a Gateway; all fields are optional.
type Options struct {
	Logger    *slog.Logger
	Getenv    func(string) string
	Transport http.RoundTripper
	Now       func() time.Time
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
	g := &Gateway{upstreams: map[string]*route{}, keys: map[string]*keyState{}, log: opts.Logger, now: opts.Now}
	for _, up := range cfg.Upstreams {
		cred, err := resolveCredential(up.Auth, opts.Getenv)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", up.Name, err)
		}
		r := &route{up: up, cred: cred}
		timeout := time.Duration(up.TimeoutSeconds) * time.Second
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		transport := opts.Transport
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
		r.proxy = &httputil.ReverseProxy{
			Rewrite:        r.rewrite,
			Transport:      transport,
			ModifyResponse: r.modifyResponse,
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				opts.Logger.Warn("upstream error", "upstream", up.Name, "error", err.Error())
				writeError(w, http.StatusBadGateway, "upstream_unreachable", "the upstream request failed")
			},
		}
		g.upstreams[up.Name] = r
	}
	for _, k := range cfg.Keys {
		g.keys[k.SHA256] = &keyState{Key: k}
	}
	return g, nil
}

// HashKey returns the configuration hash for a virtual key.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// GenerateKey returns a new random virtual key and its hash.
func GenerateKey() (key, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	key = KeyPrefix + base64.RawURLEncoding.EncodeToString(buf)
	return key, HashKey(key), nil
}

type ctxKey struct{}

type requestInfo struct {
	rest string
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := g.now()
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	keyID, upstream, outcome := "", "", ""
	defer func() {
		g.log.Info("request", "key", keyID, "upstream", upstream, "method", r.Method,
			"path", r.URL.EscapedPath(), "status", rec.status, "outcome", outcome,
			"duration_ms", g.now().Sub(start).Milliseconds())
	}()

	presented := extractKey(r)
	if presented == "" {
		outcome = "missing_key"
		rec.Header().Set("WWW-Authenticate", `Bearer realm="hootway"`)
		writeError(rec, http.StatusUnauthorized, "missing_key", "a Hootway virtual key is required")
		return
	}
	ks := g.keys[HashKey(presented)]
	if ks == nil || ks.Disabled || (ks.ExpiresAt != nil && !g.now().Before(*ks.ExpiresAt)) {
		outcome = "invalid_key"
		rec.Header().Set("WWW-Authenticate", `Bearer realm="hootway", error="invalid_token"`)
		writeError(rec, http.StatusUnauthorized, "invalid_key", "the virtual key is unknown, disabled or expired")
		return
	}
	keyID = ks.ID

	name, rest, err := splitRoute(r.URL.EscapedPath())
	if err != nil {
		outcome = "bad_path"
		writeError(rec, http.StatusBadRequest, "bad_path", "the request path contains disallowed encodings or dot segments")
		return
	}
	upstream = name
	rt := g.upstreams[name]
	if rt == nil || !ks.allows(name, r.Method, rest) {
		outcome = "forbidden"
		writeError(rec, http.StatusForbidden, "forbidden", "this key is not allowed to call this upstream method and path")
		return
	}
	if !ks.take(g.now()) {
		outcome = "rate_limited"
		rec.Header().Set("Retry-After", "60")
		writeError(rec, http.StatusTooManyRequests, "rate_limited", "the key's request rate limit is exhausted")
		return
	}
	outcome = "forwarded"
	ctx := r.Context()
	r = r.WithContext(contextWith(ctx, &requestInfo{rest: rest}))
	rt.proxy.ServeHTTP(rec, r)
}

func (k *keyState) allows(upstream, method, path string) bool {
	for _, gr := range k.Grants {
		if gr.Upstream == upstream && gr.allows(method, path) {
			return true
		}
	}
	return false
}

func (k *keyState) take(now time.Time) bool {
	if k.RequestsPerMinute == 0 {
		return true
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if now.Sub(k.windowStart) >= time.Minute {
		k.windowStart, k.count = now, 0
	}
	if k.count >= k.RequestsPerMinute {
		return false
	}
	k.count++
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
