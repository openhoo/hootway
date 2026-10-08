package gateway

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// credential is a resolved, ready-to-inject upstream credential.
type credential struct {
	auth  Auth
	value string // header value or query value
}

func resolveCredential(a Auth, getenv func(string) string) (credential, error) {
	if a.Type == "none" {
		return credential{auth: a}, nil
	}
	secret, err := readSecret(a.SecretEnv, a.SecretFile, getenv)
	if err != nil {
		return credential{}, err
	}
	switch a.Type {
	case "bearer":
		return credential{auth: a, value: "Bearer " + secret}, nil
	case "basic":
		user := a.Username
		if a.UsernameEnv != "" {
			user = getenv(a.UsernameEnv)
			if user == "" {
				return credential{}, fmt.Errorf("environment variable %s is empty", a.UsernameEnv)
			}
			if strings.ContainsAny(user, ":\r\n\x00") {
				return credential{}, fmt.Errorf("environment variable %s contains a colon or line break", a.UsernameEnv)
			}
		}
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + secret))
		return credential{auth: a, value: "Basic " + token}, nil
	case "header":
		return credential{auth: a, value: a.Prefix + secret}, nil
	case "query":
		return credential{auth: a, value: secret}, nil
	}
	return credential{}, fmt.Errorf("unknown auth type %q", a.Type)
}

func readSecret(env, file string, getenv func(string) string) (string, error) {
	var v string
	if env != "" {
		v = getenv(env)
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", env)
		}
	} else {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		v = strings.TrimRight(string(data), "\r\n")
	}
	if v == "" || strings.ContainsAny(v, "\r\n\x00") {
		return "", errors.New("secret is empty or contains line breaks")
	}
	return v, nil
}

func (c credential) apply(r *http.Request) {
	switch c.auth.Type {
	case "bearer", "basic":
		r.Header.Set("Authorization", c.value)
	case "header":
		r.Header.Set(c.auth.Name, c.value)
	case "query":
		q := r.URL.Query()
		q.Set(c.auth.Name, c.value)
		r.URL.RawQuery = q.Encode()
	}
}

// isProtectedHeader reports headers that are owned by the gateway or the
// transport and must not be supplied statically or by credentials.
func isProtectedHeader(h string) bool {
	switch http.CanonicalHeaderKey(h) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Host", "Content-Length",
		"Transfer-Encoding", "Connection", "Upgrade", "Te", "Trailer", "Keep-Alive", "Proxy-Connection":
		return true
	}
	return strings.HasPrefix(http.CanonicalHeaderKey(h), "X-Hootway-")
}
