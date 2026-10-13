package gateway

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*.gz
var webFS embed.FS

const sessionCookie = "hootway_admin"
const maxAdminSessions = 256

// Admin serves the web console and the admin API. It must run on a listener
// that agent sandboxes cannot reach.
type AdminServer struct {
	gw         *Gateway
	path       string // config file; empty disables persistence
	tokenHash  string
	gatewayURL string

	mu       sync.Mutex // serialises config mutations
	sessMu   sync.Mutex
	sessions map[string]time.Time
}

// NewAdmin creates the console. tokenHash is the SHA-256 of the admin token.
func NewAdmin(gw *Gateway, configPath, tokenHash, gatewayURL string) *AdminServer {
	return &AdminServer{gw: gw, path: configPath, tokenHash: tokenHash, gatewayURL: gatewayURL, sessions: map[string]time.Time{}}
}

// GenerateAdminToken returns a random admin token and its hash.
func GenerateAdminToken() (string, string, error) { return generate("hwa_") }

func (a *AdminServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
		a.api(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	asset, ok := webAssets[strings.TrimPrefix(r.URL.Path, "/")]
	if !ok {
		asset = webAssets["index.html"] // client-side routes
	}
	asset.serve(w, r)
}

// webAsset is an embedded console file. The sources in web/ are embedded
// only as their gzip -9n form (scripts/compress-web.sh; a test keeps them in
// sync), which keeps the gzip encoder out of the binary. Clients without
// gzip support get the body decompressed once at startup.
type webAsset struct {
	typ, etag, gzETag string
	raw, gz           []byte
}

var webAssets = loadWebAssets()

func loadWebAssets() map[string]*webAsset {
	types := map[string]string{".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8"}
	assets := map[string]*webAsset{}
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".gz")
		if !ok || e.IsDir() {
			continue
		}
		gz, err := fs.ReadFile(webFS, "web/"+e.Name())
		if err != nil {
			panic(err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			panic(err)
		}
		raw, err := io.ReadAll(zr)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(raw)
		gzSum := sha256.Sum256(gz)
		a := &webAsset{typ: types[filepath.Ext(name)], etag: `"` + hex.EncodeToString(sum[:8]) + `"`,
			gzETag: `"` + hex.EncodeToString(gzSum[:8]) + `"`, raw: raw, gz: gz}
		if a.typ == "" {
			a.typ = "application/octet-stream"
		}
		assets[name] = a
	}
	return assets
}

func (a *webAsset) serve(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", a.typ)
	h.Set("Cache-Control", "no-cache")
	h.Set("Vary", "Accept-Encoding")
	body, etag := a.raw, a.etag
	ae := strings.Join(r.Header.Values("Accept-Encoding"), ",")
	if a.gz != nil && acceptsGzip(ae) {
		h.Set("Content-Encoding", "gzip")
		body, etag = a.gz, a.gzETag
	} else if encodingQuality(ae, "identity", 1) <= 0 {
		http.Error(w, "no acceptable content encoding", http.StatusNotAcceptable)
		return
	}
	h.Set("ETag", etag)
	for _, tag := range strings.Split(strings.Join(r.Header.Values("If-None-Match"), ","), ",") {
		tag = strings.TrimSpace(tag)
		if tag == "*" || strings.TrimPrefix(tag, "W/") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func acceptsGzip(ae string) bool {
	return encodingQuality(ae, "gzip", 0) > 0
}

// Repeated codings and parameters use their lowest quality, so a later value
// cannot override an explicit refusal. Invalid qvalues are refused as well.
func encodingQuality(ae, encoding string, fallback float64) float64 {
	wildcard, explicit := -1.0, -1.0
	for _, part := range strings.Split(ae, ",") {
		fields := strings.Split(part, ";")
		name := strings.TrimSpace(fields[0])
		if !strings.EqualFold(name, encoding) && name != "*" {
			continue
		}
		quality, hasQuality := 1.0, false
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			q := parseEncodingQuality(strings.TrimSpace(value))
			if !hasQuality || q < quality {
				quality = q
			}
			hasQuality = true
		}
		if strings.EqualFold(name, encoding) {
			if explicit < 0 || quality < explicit {
				explicit = quality
			}
		} else if wildcard < 0 || quality < wildcard {
			wildcard = quality
		}
	}
	if explicit >= 0 {
		return explicit
	}
	if wildcard >= 0 {
		return wildcard
	}
	return fallback
}

func parseEncodingQuality(value string) float64 {
	if value == "" || value[0] != '0' && value[0] != '1' {
		return 0
	}
	if len(value) > 1 {
		if value[1] != '.' || len(value) > 5 {
			return 0
		}
		for i := 2; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' || value[0] == '1' && value[i] != '0' {
				return 0
			}
		}
	}
	q, _ := strconv.ParseFloat(value, 64)
	return q
}

func (a *AdminServer) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if path == "/session" {
		// Login and logout change state too: require the console header so a
		// cross-site form cannot plant or end a session (login CSRF).
		if r.Method != http.MethodGet && r.Header.Get("X-Hootway-Console") != "1" {
			writeError(w, http.StatusForbidden, "csrf", "missing console header")
			return
		}
		switch r.Method {
		case http.MethodPost:
			a.login(w, r)
		case http.MethodDelete:
			a.logout(w, r)
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]bool{"authenticated": a.authenticated(r)})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported method")
		}
		return
	}
	if !a.authenticated(r) {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "sign in with the admin token")
		return
	}
	if r.Method != http.MethodGet && r.Header.Get("X-Hootway-Console") != "1" {
		writeError(w, http.StatusForbidden, "csrf", "missing console header")
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case path == "/state" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, a.state())
	case path == "/events" && r.Method == http.MethodGet:
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		writeJSON(w, http.StatusOK, map[string]any{"events": a.gw.events.since(after, 200)})
	case path == "/explain" && r.Method == http.MethodPost:
		var req struct{ Key, Method, Path string }
		if !decode(w, r, &req) {
			return
		}
		writeJSON(w, http.StatusOK, a.gw.Explain(req.Key, strings.ToUpper(strings.TrimSpace(req.Method)), strings.TrimSpace(req.Path)))
	case path == "/probe" && r.Method == http.MethodPost:
		a.probe(w, r)
	case path == "/keys" && r.Method == http.MethodPost:
		a.createKey(w, r)
	case len(parts) == 2 && parts[0] == "keys" && r.Method == http.MethodPut:
		a.updateKey(w, r, parts[1])
	case len(parts) == 2 && parts[0] == "keys" && r.Method == http.MethodDelete:
		a.mutate(w, func(c *Config) (any, error) {
			i := keyIndex(c, parts[1])
			if i < 0 {
				return nil, errNotFound
			}
			c.Keys = append(c.Keys[:i], c.Keys[i+1:]...)
			return map[string]string{"deleted": parts[1]}, nil
		})
	case len(parts) == 3 && parts[0] == "keys" && parts[2] == "rotate" && r.Method == http.MethodPost:
		key, hash, err := GenerateKey()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "could not generate a key")
			return
		}
		a.mutate(w, func(c *Config) (any, error) {
			i := keyIndex(c, parts[1])
			if i < 0 {
				return nil, errNotFound
			}
			c.Keys[i].SHA256 = hash
			return map[string]string{"id": parts[1], "key": key}, nil
		})
	case len(parts) == 2 && parts[0] == "upstreams" && r.Method == http.MethodPut:
		a.putUpstream(w, r, parts[1])
	case len(parts) == 2 && parts[0] == "upstreams" && r.Method == http.MethodDelete:
		var removed Upstream
		a.mutateThen(w, func(c *Config) (any, error) {
			i := upstreamIndex(c, parts[1])
			if i < 0 {
				return nil, errNotFound
			}
			for _, k := range c.Keys {
				for _, g := range k.Grants {
					if g.Upstream == parts[1] {
						return nil, errors.New("key " + k.ID + " still has a grant for this upstream")
					}
				}
			}
			removed = c.Upstreams[i]
			c.Upstreams = append(c.Upstreams[:i], c.Upstreams[i+1:]...)
			return map[string]string{"deleted": parts[1]}, nil
		}, func(ok bool) {
			if ok {
				a.removeUpstreamSecrets(removed)
			}
		})
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown endpoint")
	}
}

type keyInput struct {
	ID                string     `json:"id"`
	Description       string     `json:"description"`
	ExpiresAt         *time.Time `json:"expires_at"`
	Disabled          bool       `json:"disabled"`
	RequestsPerMinute int        `json:"requests_per_minute"`
	Grants            []Grant    `json:"grants"`
}

func (in keyInput) apply(k *Key) {
	k.Description = strings.TrimSpace(in.Description)
	k.ExpiresAt = in.ExpiresAt
	k.Disabled = in.Disabled
	k.RequestsPerMinute = in.RequestsPerMinute
	k.Grants = in.Grants
}

func (a *AdminServer) createKey(w http.ResponseWriter, r *http.Request) {
	var in keyInput
	if !decode(w, r, &in) {
		return
	}
	in.ID = strings.TrimSpace(in.ID)
	key, hash, err := GenerateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not generate a key")
		return
	}
	a.mutate(w, func(c *Config) (any, error) {
		if keyIndex(c, in.ID) >= 0 {
			return nil, errors.New("a key with this id already exists")
		}
		k := Key{ID: in.ID, SHA256: hash}
		in.apply(&k)
		c.Keys = append(c.Keys, k)
		return map[string]string{"id": k.ID, "key": key}, nil
	})
}

func (a *AdminServer) updateKey(w http.ResponseWriter, r *http.Request, id string) {
	var in keyInput
	if !decode(w, r, &in) {
		return
	}
	if in.ID != "" && in.ID != id {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "the body id must match the URL; renaming a key is not supported")
		return
	}
	a.mutate(w, func(c *Config) (any, error) {
		i := keyIndex(c, id)
		if i < 0 {
			return nil, errNotFound
		}
		in.apply(&c.Keys[i])
		return map[string]string{"id": id}, nil
	})
}

var errNotFound = errors.New("not found")
var errPreconditionFailed = errors.New("precondition failed")

// mutate applies fn to a copy of the configuration, validates it, persists it
// and only then activates it.
func (a *AdminServer) mutate(w http.ResponseWriter, fn func(*Config) (any, error)) {
	a.mutateThen(w, fn, nil)
}

// mutateThen is mutate with a callback, run under the lock, that learns
// whether the new configuration became active.
func (a *AdminServer) mutateThen(w http.ResponseWriter, fn func(*Config) (any, error), done func(ok bool)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ok := false
	if done != nil {
		defer func() { done(ok) }()
	}
	next, err := a.gw.Config().clone()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not copy configuration")
		return
	}
	result, err := fn(next)
	if errors.Is(err, errPreconditionFailed) {
		writeError(w, http.StatusPreconditionFailed, "precondition_failed", "an upstream with this name already exists")
		return
	}
	if errors.Is(err, errNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such item")
		return
	}
	if err == nil {
		next, err = next.clone() // validate
	}
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	if err := a.persist(next); err != nil {
		writeError(w, http.StatusInternalServerError, "persist_failed", "configuration could not be saved: "+err.Error())
		return
	}
	a.gw.Apply(next)
	ok = true
	writeJSON(w, http.StatusOK, result)
}

func (a *AdminServer) persist(c *Config) error {
	if a.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(a.path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.path), ".hootway-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.path)
}

type stateKey struct {
	ID                string     `json:"id"`
	Description       string     `json:"description,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	Disabled          bool       `json:"disabled"`
	Expired           bool       `json:"expired"`
	RequestsPerMinute int        `json:"requests_per_minute"`
	Grants            []Grant    `json:"grants"`
	Fingerprint       string     `json:"fingerprint"`
	Stats             KeyStats   `json:"stats"`
}

type stateUpstream struct {
	Upstream
	Problem string `json:"problem,omitempty"`
}

func (a *AdminServer) state() any {
	st := a.gw.state.Load()
	cfg := st.cfg
	stats, fwd, denied := a.gw.events.snapshot()
	problems := st.problems
	now := a.gw.now()
	keys := make([]stateKey, 0, len(cfg.Keys))
	for _, k := range cfg.Keys {
		keys = append(keys, stateKey{ID: k.ID, Description: k.Description, ExpiresAt: k.ExpiresAt, Disabled: k.Disabled,
			Expired: k.ExpiresAt != nil && !now.Before(*k.ExpiresAt), RequestsPerMinute: k.RequestsPerMinute,
			Grants: k.Grants, Fingerprint: HashKey("hootway key fingerprint:" + k.SHA256)[:8], Stats: stats[k.ID]})
	}
	ups := make([]stateUpstream, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		ups = append(ups, stateUpstream{Upstream: u, Problem: problems[u.Name]})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	outbound := ""
	if op := cfg.OutboundProxy; op != nil {
		outbound = "direct, no proxy"
		if !op.Direct && op.parsed != nil {
			outbound = op.parsed.String()
		}
	}
	return map[string]any{
		"proxy":          cfg.Proxy != nil,
		"proxy_https":    st.ca != nil,
		"outbound_proxy": outbound,
		"gateway_url":    a.gatewayURL,
		"persistent":     a.path != "",
		"secret_storage": a.path != "",
		"upstreams":      ups,
		"keys":           keys,
		"totals":         map[string]int64{"forwarded": fwd, "denied": denied},
	}
}

func (a *AdminServer) login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Token string }
	if !decode(w, r, &req) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(HashKey(req.Token)), []byte(a.tokenHash)) != 1 {
		time.Sleep(300 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "invalid_token", "that admin token is not valid")
		return
	}
	sid, _, err := generate("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not create a session")
		return
	}
	a.sessMu.Lock()
	now := time.Now()
	if c, err := r.Cookie(sessionCookie); err == nil {
		delete(a.sessions, HashKey(c.Value)) // replace this browser's session
	}
	for h, exp := range a.sessions { // bound memory: drop expired sessions
		if !now.Before(exp) {
			delete(a.sessions, h)
		}
	}
	if len(a.sessions) >= maxAdminSessions {
		var oldestHash string
		var oldest time.Time
		for h, exp := range a.sessions {
			if oldestHash == "" || exp.Before(oldest) {
				oldestHash, oldest = h, exp
			}
		}
		delete(a.sessions, oldestHash)
	}
	a.sessions[HashKey(sid)] = now.Add(12 * time.Hour)
	a.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: secureAdminCookie(r), MaxAge: 12 * 3600})
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (a *AdminServer) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessMu.Lock()
		delete(a.sessions, HashKey(c.Value))
		a.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: secureAdminCookie(r)})
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

// TLS termination may happen at an operator's reverse proxy. Its protocol
// header can opt into Secure, but cannot disable direct TLS protection. Plain
// localhost HTTP remains supported without a forwarded HTTPS indication.
func secureAdminCookie(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func (a *AdminServer) authenticated(r *http.Request) bool {
	if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
		return subtle.ConstantTimeCompare([]byte(HashKey(strings.TrimPrefix(authz, "Bearer "))), []byte(a.tokenHash)) == 1
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	exp, ok := a.sessions[HashKey(c.Value)]
	if ok && !time.Now().Before(exp) {
		delete(a.sessions, HashKey(c.Value))
		return false
	}
	return ok
}

func keyIndex(c *Config, id string) int {
	for i, k := range c.Keys {
		if k.ID == id {
			return i
		}
	}
	return -1
}

func upstreamIndex(c *Config, name string) int {
	for i, u := range c.Upstreams {
		if u.Name == name {
			return i
		}
	}
	return -1
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		if _, oversized := err.(*http.MaxBytesError); oversized {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body must be at most 1 MiB")
		} else {
			writeError(w, http.StatusBadRequest, "bad_json", "could not read the request body")
		}
		return false
	}
	if err := checkJSONObject(data); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body is not valid JSON: "+err.Error())
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		// Decoder errors can contain an unknown field name or other input.
		// Never reflect body text: the console accepts pasted credentials.
		writeError(w, http.StatusBadRequest, "bad_json", "request body has unknown fields or invalid field types")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
