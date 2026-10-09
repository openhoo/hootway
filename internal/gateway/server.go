package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"sort"
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

	trMu       sync.Mutex
	transports map[transportKey]*http.Transport // shared across reloads
}

// transportKey identifies a shared transport: response header timeout and
// outbound route (egress.id may contain proxy credentials; memory only).
type transportKey struct {
	timeout time.Duration
	egress  string
}

type runtimeState struct {
	cfg       *Config
	upstreams map[string]*route
	keys      map[[sha256.Size]byte]*runtimeKey // by SHA-256 of the virtual key
	problems  map[string]string
	// origins indexes routes by scheme://host:port for proxy requests,
	// longest base path first.
	origins map[string][]*route
	ca      *proxyCA // nil unless proxy mode has a usable CA
	caErr   error
}

// runtimeKey is a configured key with its grants compiled and its rate
// limiter window resolved once per configuration load.
type runtimeKey struct {
	*Key
	hash   [sha256.Size]byte
	grants []compiledGrant
	window *window // nil when the key is not rate limited
}

type route struct {
	up       Upstream
	basePath string
	escBase  string // escaped base path, for matching proxy request paths
	cred     credential
	egress   egress
	err      error
	proxy    *httputil.ReverseProxy
}

type window struct {
	mu    sync.Mutex
	start time.Time
	count int
}

// bufferPool recycles the copy buffers of all reverse proxies.
type bufferPool struct{ p sync.Pool }

const proxyBufferSize = 32 << 10

func (b *bufferPool) Get() []byte {
	if v, ok := b.p.Get().(*[]byte); ok {
		return *v
	}
	return make([]byte, proxyBufferSize)
}

func (b *bufferPool) Put(buf []byte) {
	if cap(buf) != proxyBufferSize {
		return
	}
	buf = buf[:proxyBufferSize]
	b.p.Put(&buf)
}

var proxyBuffers = &bufferPool{}

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
		events: newEventLog(1000), windows: map[string]*window{}, transports: map[transportKey]*http.Transport{}}
	st := g.build(cfg)
	if (len(st.problems) > 0 || st.caErr != nil) && !opts.Lenient {
		var errs []error
		for name, p := range st.problems {
			errs = append(errs, fmt.Errorf("upstream %q: %s", name, p))
		}
		if st.caErr != nil {
			errs = append(errs, fmt.Errorf("proxy: %w", st.caErr))
		}
		return nil, errors.Join(errs...)
	}
	for name, p := range st.problems {
		opts.Logger.Warn("upstream credential unavailable", "upstream", name, "problem", p)
	}
	if st.caErr != nil {
		opts.Logger.Warn("proxy CA unavailable; https proxying is disabled", "problem", st.caErr.Error())
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
	st := &runtimeState{cfg: cfg, upstreams: map[string]*route{}, keys: make(map[[sha256.Size]byte]*runtimeKey, len(cfg.Keys)),
		problems: map[string]string{}, origins: map[string][]*route{}}
	if cfg.Proxy != nil && cfg.Proxy.CACertFile != "" {
		st.ca, st.caErr = loadProxyCA(cfg.Proxy.CACertFile, cfg.Proxy.CAKeyFile)
	}
	for _, up := range cfg.Upstreams {
		r := &route{up: up}
		if up.base != nil {
			r.basePath = up.base.Path
			r.escBase = strings.TrimRight(up.base.EscapedPath(), "/")
			o := originKey(up.base.Scheme, up.base.Host)
			st.origins[o] = append(st.origins[o], r)
		}
		var credErr, egErr error
		r.cred, credErr = resolveCredential(up.Auth, g.getenv)
		r.egress, egErr = resolveEgress(up.OutboundProxy, cfg.OutboundProxy, g.getenv)
		if r.err = errors.Join(credErr, egErr); r.err != nil {
			st.problems[up.Name] = r.err.Error()
		}
		timeout := time.Duration(up.TimeoutSeconds) * time.Second
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		transport := g.transport
		if transport == nil {
			transport = g.sharedTransport(timeout, r.egress)
		}
		name := up.Name
		r.proxy = &httputil.ReverseProxy{
			Rewrite:        r.rewrite,
			Transport:      transport,
			BufferPool:     proxyBuffers,
			ModifyResponse: r.modifyResponse,
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				g.log.LogAttrs(req.Context(), slog.LevelWarn, "upstream error",
					slog.String("upstream", name), slog.String("error", err.Error()))
				infoFrom(req.Context()).outcome = "upstream_error"
				writeError(w, http.StatusBadGateway, "upstream_unreachable", "the upstream request failed")
			},
		}
		st.upstreams[up.Name] = r
	}
	for _, rs := range st.origins {
		sort.SliceStable(rs, func(i, j int) bool { return len(rs[i].escBase) > len(rs[j].escBase) })
	}
	g.limMu.Lock()
	live := make(map[string]bool, len(cfg.Keys))
	for i := range cfg.Keys {
		k := &cfg.Keys[i]
		rk := &runtimeKey{Key: k, grants: compileGrants(k.Grants)}
		if _, err := hex.Decode(rk.hash[:], []byte(k.SHA256)); err != nil {
			continue // validated configs never get here; an undecodable hash matches nothing
		}
		if k.RequestsPerMinute > 0 {
			w := g.windows[k.ID]
			if w == nil {
				w = &window{}
				g.windows[k.ID] = w
			}
			rk.window = w
		}
		live[k.ID] = true
		st.keys[rk.hash] = rk
	}
	// Forget windows of removed keys so the map does not grow without bound.
	for id := range g.windows {
		if !live[id] {
			delete(g.windows, id)
		}
	}
	g.limMu.Unlock()
	return st
}

// sharedTransport returns the gateway-owned transport for a response header
// timeout and outbound route. Transports are reused across configuration
// reloads so connection pools are kept warm and old pools are not leaked on
// every Apply.
func (g *Gateway) sharedTransport(timeout time.Duration, eg egress) *http.Transport {
	g.trMu.Lock()
	defer g.trMu.Unlock()
	tk := transportKey{timeout, eg.id}
	if t := g.transports[tk]; t != nil {
		return t
	}
	t := &http.Transport{
		Proxy:                 eg.proxy,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	g.transports[tk] = t
	return t
}

// lookupKey finds the runtime key for a presented virtual key. Keys are
// indexed by their SHA-256, so lookup time does not depend on how much of a
// guessed key matches; the final comparison is constant time as well.
func (st *runtimeState) lookupKey(presented string) *runtimeKey {
	sum := sha256.Sum256([]byte(presented))
	rk := st.keys[sum]
	if rk == nil || subtle.ConstantTimeCompare(rk.hash[:], sum[:]) != 1 {
		return nil
	}
	return rk
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
	proxied bool // forward-proxy request: keep absolute redirects as they are
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && !r.URL.IsAbs() {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	if r.Method == http.MethodConnect {
		g.serveConnect(w, r)
		return
	}
	rs := &reqState{rec: statusRecorder{ResponseWriter: w, status: http.StatusOK}, start: g.now()}
	path := r.URL.EscapedPath()
	rs.ev = Event{Method: r.Method, Path: path}
	// Deferred so the request is recorded even when the reverse proxy aborts
	// the handler with http.ErrAbortHandler.
	defer g.finish(r, rs)
	if r.URL.IsAbs() {
		// Absolute-form request target: the client uses Hootway as an HTTP
		// proxy for the upstream's real URL.
		rs.ev.Proxy = true
		g.serveProxied(rs, r, r.URL.Scheme, r.URL.Host, nil)
		return
	}
	g.serve(rs, r, path)
}

// reqState groups the per-request bookkeeping into a single allocation.
type reqState struct {
	rec   statusRecorder
	info  requestInfo
	ev    Event
	start time.Time
}

func (g *Gateway) finish(r *http.Request, rs *reqState) {
	ev := &rs.ev
	ev.Time = rs.start
	ev.Status = rs.rec.status
	ev.Outcome = rs.info.outcome
	ev.DurationMS = g.now().Sub(rs.start).Milliseconds()
	g.events.add(*ev)
	if g.log.Enabled(r.Context(), slog.LevelInfo) {
		g.log.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("key", ev.Key), slog.String("upstream", ev.Upstream), slog.String("method", ev.Method),
			slog.String("path", ev.Path), slog.Int("status", ev.Status), slog.String("outcome", ev.Outcome),
			slog.Int64("duration_ms", ev.DurationMS))
	}
}

func (g *Gateway) serve(rs *reqState, r *http.Request, path string) {
	st := g.state.Load()
	k := g.authenticate(rs, st, extractKey(r), false)
	if k == nil {
		return
	}
	name, rest, err := splitRoute(path)
	if err != nil {
		rs.info.outcome = "bad_path"
		writeStaticError(&rs.rec, http.StatusBadRequest, errBadPath)
		return
	}
	g.forward(rs, r, st, k, name, rest)
}

// validKey returns the active key for a presented virtual key, or nil.
func (g *Gateway) validKey(st *runtimeState, presented string) (k *runtimeKey, ok bool) {
	k = st.lookupKey(presented)
	return k, k != nil && !k.Disabled && (k.ExpiresAt == nil || g.now().Before(*k.ExpiresAt))
}

// authenticate checks the presented key and writes the rejection itself.
// Proxy requests are challenged with 407 so clients send proxy credentials.
func (g *Gateway) authenticate(rs *reqState, st *runtimeState, presented string, proxy bool) *runtimeKey {
	rec, info := &rs.rec, &rs.info
	status, challenge := http.StatusUnauthorized, "WWW-Authenticate"
	if proxy {
		status, challenge = http.StatusProxyAuthRequired, "Proxy-Authenticate"
	}
	if presented == "" {
		info.outcome = "missing_key"
		if proxy {
			rec.Header().Set(challenge, `Basic realm="hootway"`)
		} else {
			rec.Header().Set(challenge, `Bearer realm="hootway"`)
		}
		writeStaticError(rec, status, errMissingKey)
		return nil
	}
	k, ok := g.validKey(st, presented)
	if !ok {
		info.outcome = "invalid_key"
		if k != nil {
			rs.ev.Key = k.ID
		}
		if proxy {
			rec.Header().Set(challenge, `Basic realm="hootway"`)
		} else {
			rec.Header().Set(challenge, `Bearer realm="hootway", error="invalid_token"`)
		}
		writeStaticError(rec, status, errInvalidKey)
		return nil
	}
	rs.ev.Key = k.ID
	return k
}

// forward enforces grants, rate limit and credential availability for an
// authenticated request to upstream name and forwards it. Rejections never
// reach the upstream.
func (g *Gateway) forward(rs *reqState, r *http.Request, st *runtimeState, k *runtimeKey, name, rest string) {
	rec, info, ev := &rs.rec, &rs.info, &rs.ev
	ev.Upstream = name
	rt := st.upstreams[name]
	if rt == nil || !k.allows(name, r.Method, rest) {
		info.outcome = "forbidden"
		writeStaticError(rec, http.StatusForbidden, errForbidden)
		return
	}
	if !k.take(g.now()) {
		info.outcome = "rate_limited"
		rec.Header().Set("Retry-After", "60")
		writeStaticError(rec, http.StatusTooManyRequests, errRateLimited)
		return
	}
	if rt.err != nil {
		info.outcome = "upstream_unconfigured"
		writeStaticError(rec, http.StatusServiceUnavailable, errUnconfigured)
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
	var rk *runtimeKey
	for _, c := range st.keys {
		if c.ID == keyID {
			rk = c
		}
	}
	var k *Key
	if rk != nil {
		k = rk.Key
	}
	switch {
	case k == nil:
		return Decision{Outcome: "invalid_key", Reason: "no key with this id"}
	case k.Disabled:
		return Decision{Outcome: "invalid_key", Reason: "the key is disabled"}
	case k.ExpiresAt != nil && !g.now().Before(*k.ExpiresAt):
		return Decision{Outcome: "invalid_key", Reason: "the key has expired"}
	}
	var name, rest string
	if u, err := url.Parse(path); err == nil && u.IsAbs() {
		// A real upstream URL, as an agent would request it through proxy mode.
		var ok bool
		name, rest, ok = st.matchOrigin(u.Scheme, u.Host, u.EscapedPath())
		switch {
		case checkPath(orRoot(u.EscapedPath())) != nil:
			return Decision{Outcome: "bad_path", Reason: "the path contains dot segments, // or encoded separators"}
		case !ok:
			return Decision{Outcome: "forbidden", Reason: "no upstream has this origin and base path"}
		}
	} else {
		if err == nil && u.RawQuery != "" {
			path = u.EscapedPath()
		}
		name, rest, err = splitRoute(path)
		if err != nil {
			return Decision{Outcome: "bad_path", Reason: "the path contains dot segments, // or encoded separators"}
		}
	}
	rt := st.upstreams[name]
	if rt == nil {
		return Decision{Outcome: "forbidden", Reason: fmt.Sprintf("there is no upstream named %q", name)}
	}
	// Use the same compiled grants as ServeHTTP so explanations never
	// diverge from enforcement.
	for _, cg := range rk.grants {
		if cg.allows(name, method, rest) {
			gr := &k.Grants[cg.index]
			if rt.err != nil {
				return Decision{Outcome: "upstream_unconfigured", Reason: "allowed, but the upstream credential is unavailable: " + rt.err.Error(), Grant: gr}
			}
			return Decision{Allowed: true, Outcome: "forwarded", Reason: fmt.Sprintf("allowed and forwarded to %s%s", rt.up.base.String(), rest), Grant: gr}
		}
	}
	return Decision{Outcome: "forbidden", Reason: fmt.Sprintf("no grant allows %s %s on %s", method, rest, name)}
}

// allows evaluates the key's precompiled grants; default deny.
func (k *runtimeKey) allows(upstream, method, path string) bool {
	for i := range k.grants {
		if k.grants[i].allows(upstream, method, path) {
			return true
		}
	}
	return false
}

// take consumes one request from the key's fixed one-minute window. Each key
// has its own lock, so keys never contend with each other.
func (k *runtimeKey) take(now time.Time) bool {
	w := k.window
	if w == nil || k.RequestsPerMinute == 0 {
		return true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
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
	base := rt.up.base
	out.URL.Scheme = base.Scheme
	out.URL.Host = base.Host
	out.URL.RawPath = rt.basePath + info.rest
	if p, err := url.PathUnescape(out.URL.RawPath); err == nil {
		out.URL.Path = p
	}
	out.Host = base.Host
	// Never forward caller credentials, cookies or gateway headers.
	for h := range out.Header {
		if isProtectedHeader(h) && h != "Content-Length" && h != "Transfer-Encoding" {
			delete(out.Header, h)
		}
	}
	delete(out.Header, "Forwarded")
	delete(out.Header, "X-Forwarded-For")
	delete(out.Header, "X-Forwarded-Host")
	delete(out.Header, "X-Forwarded-Proto")
	for k, v := range rt.up.Headers {
		out.Header.Set(k, v)
	}
	rt.cred.apply(out)
}

func (rt *route) modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	if rt.cred.auth.Type == "query" {
		// The injected query credential must never come back to the caller
		// in a URL the upstream echoes.
		resp.Header.Del("Refresh")
		for _, h := range [...]string{"Location", "Content-Location"} {
			if v := resp.Header.Get(h); v != "" {
				resp.Header.Set(h, stripQueryParam(v, rt.cred.auth.Name))
			}
		}
	}
	// Keep redirects inside the gateway so the agent never needs the
	// upstream credential to follow them. Proxy clients follow absolute
	// redirects through the proxy themselves.
	if loc := resp.Header.Get("Location"); loc != "" && !infoFrom(resp.Request.Context()).proxied {
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

// stripQueryParam removes name from the query of the URL reference v. An
// unparsable reference that still carries the parameter is dropped entirely.
func stripQueryParam(v, name string) string {
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Has(name) {
		q.Del(name)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func encodeError(code, msg string) []byte {
	b, err := json.Marshal(errorBody{errorDetail{code, msg}})
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// Pre-encoded bodies of the gateway's own rejections.
var (
	errMissingKey   = encodeError("missing_key", "a Hootway virtual key is required")
	errInvalidKey   = encodeError("invalid_key", "the virtual key is unknown, disabled or expired")
	errBadPath      = encodeError("bad_path", "the request path contains disallowed encodings or dot segments")
	errForbidden    = encodeError("forbidden", "this key is not allowed to call this upstream method and path")
	errRateLimited  = encodeError("rate_limited", "the key's request rate limit is exhausted")
	errUnconfigured = encodeError("upstream_unconfigured", "the gateway has no usable credential for this upstream")
)

func writeStaticError(w http.ResponseWriter, status int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeStaticError(w, status, encodeError(code, msg))
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
