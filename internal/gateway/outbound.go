package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OutboundProxy routes Hootway's own upstream connections through a proxy.
// Set at the top level it applies to every upstream; set on an upstream it
// overrides the top level. Without any outbound_proxy, the standard
// HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables apply.
type OutboundProxy struct {
	// URL is an http, https, socks5 or socks5h proxy URL without credentials.
	URL string `json:"url,omitempty"`
	// Direct connects without any proxy, ignoring the environment.
	Direct bool `json:"direct,omitempty"`
	// Optional proxy credentials; the password is never inlined.
	Username    string `json:"username,omitempty"`
	UsernameEnv string `json:"username_env,omitempty"`
	SecretEnv   string `json:"secret_env,omitempty"`
	SecretFile  string `json:"secret_file,omitempty"`

	parsed *url.URL
}

func (p *OutboundProxy) validate() error {
	if p.Direct {
		if p.URL != "" || p.Username != "" || p.UsernameEnv != "" || p.SecretEnv != "" || p.SecretFile != "" {
			return errors.New("outbound_proxy: direct must not be combined with url or credentials")
		}
		return nil
	}
	u, err := url.Parse(p.URL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return errors.New("outbound_proxy: url must be an absolute http, https, socks5 or socks5h URL (or set direct)")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("outbound_proxy: unsupported scheme %q", u.Scheme)
	}
	if u.User != nil {
		return errors.New("outbound_proxy: url must not contain credentials; use username and secret_env or secret_file")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("outbound_proxy: url must not contain a path, query or fragment")
	}
	if p.Username != "" && p.UsernameEnv != "" {
		return errors.New("outbound_proxy: set at most one of username or username_env")
	}
	if p.SecretEnv != "" && p.SecretFile != "" {
		return errors.New("outbound_proxy: set at most one of secret_env or secret_file")
	}
	if (p.SecretEnv != "" || p.SecretFile != "") && p.Username == "" && p.UsernameEnv == "" {
		return errors.New("outbound_proxy: a proxy password needs username or username_env")
	}
	if strings.ContainsAny(p.Username, ":\r\n\x00") {
		return errors.New("outbound_proxy: username must not contain colons, line breaks or NUL")
	}
	p.parsed = &url.URL{Scheme: u.Scheme, Host: u.Host}
	return nil
}

// egress is a resolved outbound route. id identifies the transport it needs;
// it may contain proxy credentials and is kept in memory only.
type egress struct {
	id    string
	proxy func(*http.Request) (*url.URL, error)
	desc  string // safe for display: never contains credentials
}

var envEgress = egress{id: "env", proxy: http.ProxyFromEnvironment, desc: "environment"}

// resolveEgress returns the outbound route for an upstream: its own
// outbound_proxy, else the top-level one, else the environment.
func resolveEgress(up, top *OutboundProxy, getenv func(string) string) (egress, error) {
	p := up
	if p == nil {
		p = top
	}
	if p == nil {
		return envEgress, nil
	}
	if p.Direct {
		return egress{id: "direct", desc: "direct"}, nil
	}
	if p.parsed == nil {
		return egress{}, errors.New("outbound proxy is not validated")
	}
	u := *p.parsed
	user := p.Username
	if p.UsernameEnv != "" {
		user = getenv(p.UsernameEnv)
		if user == "" {
			return egress{}, fmt.Errorf("outbound proxy: environment variable %s is empty", p.UsernameEnv)
		}
		if strings.ContainsAny(user, ":\r\n\x00") {
			return egress{}, fmt.Errorf("outbound proxy: environment variable %s contains a colon or line break", p.UsernameEnv)
		}
	}
	if user != "" {
		if p.SecretEnv != "" || p.SecretFile != "" {
			pass, err := readSecret(p.SecretEnv, p.SecretFile, getenv)
			if err != nil {
				return egress{}, fmt.Errorf("outbound proxy: %w", err)
			}
			u.User = url.UserPassword(user, pass)
		} else {
			u.User = url.User(user)
		}
	}
	fixed := &u
	return egress{id: u.String(), proxy: func(*http.Request) (*url.URL, error) { return fixed, nil }, desc: p.parsed.String()}, nil
}
