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
	typ, etag string
	raw, gz   []byte
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
		a := &webAsset{typ: types[filepath.Ext(name)], etag: `"` + hex.EncodeToString(sum[:8]) + `"`, raw: raw, gz: gz}
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
	h.Set("ETag", a.etag)
	h.Set("Vary", "Accept-Encoding")
	if inm := r.Header.Get("If-None-Match"); inm != "" && (inm == a.etag || strings.Contains(inm, a.etag)) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := a.raw
	if a.gz != nil && acceptsGzip(r.Header.Get("Accept-Encoding")) {
		h.Set("Content-Encoding", "gzip")
		body = a.gz
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func acceptsGzip(ae string) bool {
	for _, part := range strings.Split(ae, ",") {
		name, q, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") {
			return strings.ReplaceAll(strings.TrimSpace(q), " ", "") != "q=0"
		}
	}
	return false
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
		var up Upstream
		if !decode(w, r, &up) {
			return
		}
		name := parts[1]
		a.mutate(w, func(c *Config) (any, error) {
			if up.Name == "" {
				up.Name = name
			}
			if up.Name != name {
				return nil, errors.New("the body name must match the URL; renaming an upstream is not supported")
			}
			i := upstreamIndex(c, name)
			if i < 0 {
				c.Upstreams = append(c.Upstreams, up)
				return up, nil
			}
			c.Upstreams[i] = up
			return up, nil
		})
	case len(parts) == 2 && parts[0] == "upstreams" && r.Method == http.MethodDelete:
		a.mutate(w, func(c *Config) (any, error) {
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
			c.Upstreams = append(c.Upstreams[:i], c.Upstreams[i+1:]...)
			return map[string]string{"deleted": parts[1]}, nil
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
	key, hash, err := GenerateKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not generate a key")
		return
	}
	a.mutate(w, func(c *Config) (any, error) {
		if keyIndex(c, in.ID) >= 0 {
			return nil, errors.New("a key with this id already exists")
		}
		k := Key{ID: strings.TrimSpace(in.ID), SHA256: hash}
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

// mutate applies fn to a copy of the configuration, validates it, persists it
// and only then activates it.
func (a *AdminServer) mutate(w http.ResponseWriter, fn func(*Config) (any, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	next, err := a.gw.Config().clone()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not copy configuration")
		return
	}
	result, err := fn(next)
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
	cfg := a.gw.Config()
	stats, fwd, denied := a.gw.events.snapshot()
	problems := a.gw.Problems()
	now := a.gw.now()
	keys := make([]stateKey, 0, len(cfg.Keys))
	for _, k := range cfg.Keys {
		keys = append(keys, stateKey{ID: k.ID, Description: k.Description, ExpiresAt: k.ExpiresAt, Disabled: k.Disabled,
			Expired: k.ExpiresAt != nil && !now.Before(*k.ExpiresAt), RequestsPerMinute: k.RequestsPerMinute,
			Grants: k.Grants, Fingerprint: k.SHA256[:8], Stats: stats[k.ID]})
	}
	ups := make([]stateUpstream, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		ups = append(ups, stateUpstream{Upstream: u, Problem: problems[u.Name]})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	return map[string]any{
		"gateway_url": a.gatewayURL,
		"persistent":  a.path != "",
		"upstreams":   ups,
		"keys":        keys,
		"totals":      map[string]int64{"forwarded": fwd, "denied": denied},
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
	for h, exp := range a.sessions { // bound memory: drop expired sessions
		if now.After(exp) {
			delete(a.sessions, h)
		}
	}
	a.sessions[HashKey(sid)] = now.Add(12 * time.Hour)
	a.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 12 * 3600})
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (a *AdminServer) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessMu.Lock()
		delete(a.sessions, HashKey(c.Value))
		a.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
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
	if ok && time.Now().After(exp) {
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
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "request body is not valid JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
