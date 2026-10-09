package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The console can store a pasted upstream secret write-only: it is written to
// a 0600 file in a "secrets" directory next to the config file and referenced
// through auth.secret_file. The value is never returned, logged or kept in
// the config itself.

const maxSecretLen = 8 << 10

type upstreamInput struct {
	Upstream
	// Secret, when set, replaces the upstream credential with a managed
	// secret file. It is write-only.
	Secret string `json:"secret,omitempty"`
}

func (a *AdminServer) secretDir() string {
	if a.path == "" {
		return ""
	}
	dir, err := filepath.Abs(filepath.Join(filepath.Dir(a.path), "secrets"))
	if err != nil {
		return ""
	}
	return dir
}

// managedSecret reports whether file was written by the console.
func (a *AdminServer) managedSecret(file string) bool {
	dir := a.secretDir()
	return dir != "" && file != "" && filepath.Dir(filepath.Clean(file)) == dir
}

func (a *AdminServer) removeManagedSecret(file string) {
	if a.managedSecret(file) {
		_ = os.Remove(file)
	}
}

func checkSecret(s string) error {
	if s == "" || len(s) > maxSecretLen || strings.ContainsAny(s, "\r\n\x00") {
		return errors.New("the secret must be a single line of at most 8 KiB")
	}
	return nil
}

// writeSecret stores secret in a new uniquely named 0600 file and returns its
// path. Existing files are never overwritten, so a failed save cannot damage
// the active credential.
func (a *AdminServer) writeSecret(name, secret string) (string, error) {
	dir := a.secretDir()
	if dir == "" {
		return "", errors.New("secrets can only be stored when the gateway runs with a writable config file; use an environment variable instead")
	}
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("upstream name must match %s", namePattern)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+"-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(secret)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func (a *AdminServer) putUpstream(w http.ResponseWriter, r *http.Request, name string) {
	var in upstreamInput
	if !decode(w, r, &in) {
		return
	}
	up := in.Upstream
	if up.Name == "" {
		up.Name = name
	}
	if up.Name != name {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "the body name must match the URL; renaming an upstream is not supported")
		return
	}
	var written string
	if in.Secret != "" {
		if up.Auth.Type == "none" {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "auth type none takes no secret")
			return
		}
		if err := checkSecret(in.Secret); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
			return
		}
		p, err := a.writeSecret(name, in.Secret)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "secret_storage", err.Error())
			return
		}
		written = p
		up.Auth.SecretEnv, up.Auth.SecretFile = "", p
	}
	var previous string
	a.mutateThen(w, func(c *Config) (any, error) {
		i := upstreamIndex(c, name)
		if i < 0 {
			c.Upstreams = append(c.Upstreams, up)
		} else {
			previous = c.Upstreams[i].Auth.SecretFile
			c.Upstreams[i] = up
		}
		return up, nil
	}, func(ok bool) {
		switch {
		case !ok:
			a.removeManagedSecret(written)
		case previous != up.Auth.SecretFile:
			a.removeManagedSecret(previous)
		}
	})
}

// probeRequest asks the console to test a credential with one GET request.
// Either Name (an active upstream) or Upstream (an unsaved draft, optionally
// with a pasted Secret) is given.
type probeRequest struct {
	Name     string    `json:"name"`
	Upstream *Upstream `json:"upstream"`
	Secret   string    `json:"secret"`
	Path     string    `json:"path"`
}

type probeResult struct {
	OK      bool   `json:"ok"`
	Status  int    `json:"status,omitempty"`
	Message string `json:"message"`
}

// probe sends GET <base><path> with the credential and reports only the
// status. Redirects are not followed and the body is discarded.
func (a *AdminServer) probe(w http.ResponseWriter, r *http.Request) {
	var req probeRequest
	if !decode(w, r, &req) {
		return
	}
	if _, rest, err := splitRoute("/x" + req.Path); err != nil || !strings.HasPrefix(req.Path, "/") || strings.ContainsAny(req.Path, "?#") || rest != req.Path {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "the test path must be a plain absolute path")
		return
	}
	var up Upstream
	var cred credential
	var eg egress
	switch {
	case req.Upstream != nil:
		up = *req.Upstream
		if up.Name == "" {
			up.Name = "draft"
		}
		getenv := a.gw.getenv
		if req.Secret != "" {
			if err := checkSecret(req.Secret); err != nil {
				writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
				return
			}
			const draftEnv = "HOOTWAY_DRAFT_SECRET"
			up.Auth.SecretEnv, up.Auth.SecretFile = draftEnv, ""
			getenv = func(k string) string {
				if k == draftEnv {
					return req.Secret
				}
				return a.gw.getenv(k)
			}
		}
		cfg := &Config{Upstreams: []Upstream{up}}
		if op := a.gw.Config().OutboundProxy; op != nil {
			cp := *op // validate sets parsed; never touch the active config
			cfg.OutboundProxy = &cp
		}
		if err := cfg.validate(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
			return
		}
		up = cfg.Upstreams[0]
		c, err := resolveCredential(up.Auth, getenv)
		if err != nil {
			writeJSON(w, http.StatusOK, probeResult{Message: "credential unavailable: " + err.Error()})
			return
		}
		cred = c
		if eg, err = resolveEgress(up.OutboundProxy, cfg.OutboundProxy, a.gw.getenv); err != nil {
			writeJSON(w, http.StatusOK, probeResult{Message: err.Error()})
			return
		}
	default:
		rt := a.gw.state.Load().upstreams[req.Name]
		if rt == nil {
			writeError(w, http.StatusNotFound, "not_found", "no such upstream")
			return
		}
		if rt.err != nil {
			writeJSON(w, http.StatusOK, probeResult{Message: "credential unavailable: " + rt.err.Error()})
			return
		}
		up, cred, eg = rt.up, rt.cred, rt.egress
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, http.MethodGet, up.base.Scheme+"://"+up.base.Host+up.base.Path+req.Path, nil)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "could not build the test request")
		return
	}
	out.Header.Set("Accept", "application/json")
	for k, v := range up.Headers {
		out.Header.Set(k, v)
	}
	cred.apply(out)
	transport := a.gw.transport
	if transport == nil {
		transport = a.gw.sharedTransport(15*time.Second, eg)
	}
	res, err := transport.RoundTrip(out)
	if err != nil {
		msg := "could not reach " + up.base.Host
		if eg.desc != "" && eg.desc != "environment" && eg.desc != "direct" {
			msg += " through proxy " + eg.desc
		}
		writeJSON(w, http.StatusOK, probeResult{Message: msg})
		return
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	result := probeResult{Status: res.StatusCode, OK: res.StatusCode >= 200 && res.StatusCode < 300}
	switch {
	case result.OK:
		result.Message = "the credential works"
	case res.StatusCode == 401:
		result.Message = "the upstream rejected the credential"
	case res.StatusCode == 403:
		result.Message = "the credential is valid but lacks permission for this check"
	case res.StatusCode >= 300 && res.StatusCode < 400:
		result.Message = "the upstream redirected, usually to a login page: check the URL and credential"
	case res.StatusCode == 404:
		result.Message = "not found: check the URL"
	default:
		result.Message = "the upstream answered " + http.StatusText(res.StatusCode)
	}
	writeJSON(w, http.StatusOK, result)
}
