// Package gateway implements Hootway's credential-injecting reverse proxy.
package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config is the complete gateway configuration. It never contains upstream
// secrets or virtual keys in plaintext: secrets are read from environment
// variables or files, and keys are stored as SHA-256 hashes.
type Config struct {
	Listen    string     `json:"listen"`
	Admin     *Admin     `json:"admin,omitempty"`
	Upstreams []Upstream `json:"upstreams"`
	Keys      []Key      `json:"keys"`
}

// Admin configures the web console and admin API. It is served on its own
// listener so agent sandboxes that can reach the gateway cannot reach it.
type Admin struct {
	Listen string `json:"listen,omitempty"`
	// TokenSHA256 is the SHA-256 of the admin token. HOOTWAY_ADMIN_TOKEN may
	// supply the token instead.
	TokenSHA256 string `json:"token_sha256,omitempty"`
}

// Upstream is an API that Hootway can call on behalf of agents.
type Upstream struct {
	// Name is the route prefix: requests to /<name>/... go to this upstream.
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	BaseURL     string `json:"base_url"`
	Auth        Auth   `json:"auth"`
	// Headers are additional fixed headers set on every upstream request.
	Headers map[string]string `json:"headers,omitempty"`
	// TimeoutSeconds bounds a single upstream round trip. Default 60.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`

	base *url.URL
}

// Auth describes how the real credential is injected.
type Auth struct {
	// Type is one of: bearer, basic, header, query, none.
	Type string `json:"type"`
	// Header or query parameter name for type header/query.
	Name string `json:"name,omitempty"`
	// Username for basic auth (for Jira Cloud: the account e-mail).
	Username    string `json:"username,omitempty"`
	UsernameEnv string `json:"username_env,omitempty"`
	// Exactly one of SecretEnv or SecretFile supplies the secret value.
	SecretEnv  string `json:"secret_env,omitempty"`
	SecretFile string `json:"secret_file,omitempty"`
	// Prefix is prepended to the secret for type header (e.g. "Token ").
	Prefix string `json:"prefix,omitempty"`
}

// Key is a virtual key handed to an agent.
type Key struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	// SHA256 is the lowercase hex SHA-256 of the full virtual key.
	SHA256    string     `json:"sha256"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Disabled  bool       `json:"disabled,omitempty"`
	// RequestsPerMinute limits this key across all grants; 0 means unlimited.
	RequestsPerMinute int     `json:"requests_per_minute,omitempty"`
	Grants            []Grant `json:"grants"`
}

// Grant allows a key to call specific methods and paths on one upstream.
type Grant struct {
	Upstream string   `json:"upstream"`
	Methods  []string `json:"methods"`
	// Paths are upstream-relative patterns. "*" matches one path segment,
	// a trailing "/**" matches the prefix itself and any deeper path.
	Paths []string `json:"paths"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadConfig reads and validates a JSON configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// ParseConfig parses and validates JSON configuration bytes.
func ParseConfig(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("parse config: trailing data")
	}
	return &cfg, nil
}

// clone returns a validated deep copy of the configuration.
func (c *Config) clone() (*Config, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8787"
	}
	var errs []error
	if c.Admin != nil {
		if c.Admin.Listen == "" {
			c.Admin.Listen = "127.0.0.1:8788"
		}
		if c.Admin.TokenSHA256 != "" && !hashPattern.MatchString(c.Admin.TokenSHA256) {
			errs = append(errs, errors.New("admin: token_sha256 must be 64 lowercase hex characters"))
		}
	}
	if c.Upstreams == nil {
		c.Upstreams = []Upstream{}
	}
	if c.Keys == nil {
		c.Keys = []Key{}
	}
	upstreams := map[string]bool{}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if !namePattern.MatchString(u.Name) {
			errs = append(errs, fmt.Errorf("upstream %q: name must match %s", u.Name, namePattern))
		}
		if upstreams[u.Name] {
			errs = append(errs, fmt.Errorf("upstream %q: duplicate name", u.Name))
		}
		upstreams[u.Name] = true
		base, err := url.Parse(u.BaseURL)
		if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
			errs = append(errs, fmt.Errorf("upstream %q: base_url must be an absolute http(s) URL", u.Name))
		} else if base.RawQuery != "" || base.Fragment != "" || base.User != nil {
			errs = append(errs, fmt.Errorf("upstream %q: base_url must not contain query, fragment or userinfo", u.Name))
		} else {
			base.Path = strings.TrimRight(base.Path, "/")
			u.base = base
		}
		if err := u.Auth.validate(); err != nil {
			errs = append(errs, fmt.Errorf("upstream %q: %w", u.Name, err))
		}
		for h := range u.Headers {
			if isProtectedHeader(h) {
				errs = append(errs, fmt.Errorf("upstream %q: header %q cannot be set statically", u.Name, h))
			} else if !validHeaderName(h) || strings.ContainsAny(u.Headers[h], "\r\n\x00") {
				errs = append(errs, fmt.Errorf("upstream %q: header %q has an invalid name or value", u.Name, h))
			}
		}
		if u.TimeoutSeconds < 0 {
			errs = append(errs, fmt.Errorf("upstream %q: timeout_seconds must be positive", u.Name))
		}
	}
	keyIDs := map[string]bool{}
	hashes := map[string]bool{}
	for _, k := range c.Keys {
		if !namePattern.MatchString(k.ID) {
			errs = append(errs, fmt.Errorf("key %q: id must match %s", k.ID, namePattern))
		}
		if keyIDs[k.ID] {
			errs = append(errs, fmt.Errorf("key %q: duplicate id", k.ID))
		}
		keyIDs[k.ID] = true
		if !hashPattern.MatchString(k.SHA256) {
			errs = append(errs, fmt.Errorf("key %q: sha256 must be 64 lowercase hex characters", k.ID))
		}
		if hashes[k.SHA256] {
			errs = append(errs, fmt.Errorf("key %q: duplicate sha256", k.ID))
		}
		hashes[k.SHA256] = true
		if k.RequestsPerMinute < 0 {
			errs = append(errs, fmt.Errorf("key %q: requests_per_minute must be positive", k.ID))
		}
		if len(k.Grants) == 0 {
			errs = append(errs, fmt.Errorf("key %q: at least one grant is required", k.ID))
		}
		for _, g := range k.Grants {
			if !upstreams[g.Upstream] {
				errs = append(errs, fmt.Errorf("key %q: unknown upstream %q", k.ID, g.Upstream))
			}
			if len(g.Methods) == 0 || len(g.Paths) == 0 {
				errs = append(errs, fmt.Errorf("key %q: grant for %q needs methods and paths", k.ID, g.Upstream))
			}
			for _, m := range g.Methods {
				if m != "*" && m != strings.ToUpper(m) {
					errs = append(errs, fmt.Errorf("key %q: method %q must be uppercase or *", k.ID, m))
				}
			}
			for _, p := range g.Paths {
				if err := validatePattern(p); err != nil {
					errs = append(errs, fmt.Errorf("key %q: path %q: %w", k.ID, p, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (a Auth) validate() error {
	switch a.Type {
	case "none":
		if a.SecretEnv != "" || a.SecretFile != "" {
			return errors.New("auth type none must not reference a secret")
		}
		return nil
	case "bearer", "basic":
	case "header", "query":
		if a.Name == "" {
			return fmt.Errorf("auth type %s requires name", a.Type)
		}
		if !validHeaderName(a.Name) {
			return fmt.Errorf("auth name %q is not a valid token", a.Name)
		}
		if a.Type == "header" && isProtectedHeader(a.Name) && !strings.EqualFold(a.Name, "Authorization") {
			return fmt.Errorf("auth header %q is not allowed", a.Name)
		}
	default:
		return fmt.Errorf("unknown auth type %q", a.Type)
	}
	if (a.SecretEnv == "") == (a.SecretFile == "") {
		return errors.New("exactly one of secret_env or secret_file is required")
	}
	if a.Type == "basic" && (a.Username == "") == (a.UsernameEnv == "") {
		return errors.New("basic auth requires exactly one of username or username_env")
	}
	if strings.ContainsAny(a.Prefix+a.Username, "\r\n\x00") || strings.Contains(a.Username, ":") {
		return errors.New("prefix and username must not contain line breaks, NUL or (username) colons")
	}
	return nil
}

func validatePattern(p string) error {
	if !strings.HasPrefix(p, "/") {
		return errors.New("must start with /")
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		if s == "**" && i != len(segs)-1 {
			return errors.New("** is only allowed as the final segment")
		}
		if s == "." || s == ".." {
			return errors.New("dot segments are not allowed")
		}
		if strings.Contains(s, "*") && s != "*" && s != "**" {
			return errors.New("* must be a whole segment")
		}
	}
	return nil
}

// validHeaderName reports whether s is a non-empty RFC 9110 token, which is
// also a safe query parameter name.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}
