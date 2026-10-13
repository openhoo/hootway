package gateway

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
)

// credential is a resolved, ready-to-inject upstream credential.
type credential struct {
	auth   Auth
	value  string // header value or query value
	secret string // unencoded secret, retained only for response sanitising
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
		if !validHeaderValue(secret) {
			return credential{}, errors.New("secret contains invalid HTTP header control bytes")
		}
		return credential{auth: a, value: "Bearer " + secret, secret: secret}, nil
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
		return credential{auth: a, value: "Basic " + token, secret: secret}, nil
	case "header":
		if !validHeaderValue(a.Prefix + secret) {
			return credential{}, errors.New("credential contains invalid HTTP header control bytes")
		}
		return credential{auth: a, value: a.Prefix + secret, secret: secret}, nil
	case "query":
		return credential{auth: a, value: secret, secret: secret}, nil
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
		data, err := readCredentialFile(file)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		v = strings.TrimRight(string(data), "\r\n")
	}
	if v == "" || strings.ContainsAny(v, "\r\n\x00") {
		return "", errors.New("secret is empty or contains line breaks")
	}
	if len(v) > maxSecretLen {
		return "", errors.New("secret exceeds 8 KiB")
	}
	return v, nil
}

// File paths are intentionally selected by the operator (including absolute
// paths and symlink aliases), not by gateway callers. A credential source must
// be a bounded regular file: never open a device or block on a named pipe.
func readCredentialFile(path string) ([]byte, error) {
	const maxFileLen = maxSecretLen + 2 // allow a terminal CRLF at the value limit
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("the credential source must be a regular file")
	}
	if st.Size() > maxFileLen {
		return nil, errors.New("credential file exceeds 8 KiB plus a terminal CRLF")
	}
	// Recheck the opened object as well. O_NONBLOCK keeps a raced replacement
	// with a FIFO from hanging before that recheck; it does not affect regular
	// file reads (and is ignored by Windows' ordinary file opener).
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, errors.New("the credential source must be a regular file")
	}
	if !os.SameFile(st, opened) {
		return nil, errors.New("the credential file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileLen+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileLen {
		return nil, errors.New("credential file exceeds 8 KiB plus a terminal CRLF")
	}
	return data, nil
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
	h = http.CanonicalHeaderKey(h)
	switch h {
	case "Authorization", "Proxy-Authorization", "Cookie", "Host", "Content-Length",
		"Transfer-Encoding", "Connection", "Upgrade", "Te", "Trailer", "Keep-Alive", "Proxy-Connection", "Forwarded",
		"X-Http-Method-Override", "X-Http-Method", "X-Method-Override", "X-Original-Method", "X-Original-Url", "X-Rewrite-Url":
		return true
	}
	return strings.HasPrefix(h, "X-Hootway-") || strings.HasPrefix(h, "X-Forwarded-")
}
