package gateway

import (
	"errors"
	"strings"
)

var errUnsafePath = errors.New("unsafe request path")

// splitRoute splits an escaped request path into the upstream name and the
// upstream-relative path. It rejects encodings that could make the path seen
// by the policy differ from the path interpreted by the upstream.
func splitRoute(escaped string) (name, rest string, err error) {
	lower := strings.ToLower(escaped)
	for _, bad := range []string{"%2f", "%5c", "%2e", "%00", "\\", "//"} {
		if strings.Contains(lower, bad) {
			return "", "", errUnsafePath
		}
	}
	if !strings.HasPrefix(escaped, "/") {
		return "", "", errUnsafePath
	}
	trimmed := strings.TrimPrefix(escaped, "/")
	name, rest, _ = strings.Cut(trimmed, "/")
	rest = "/" + rest
	for _, seg := range strings.Split(rest, "/") {
		if seg == "." || seg == ".." {
			return "", "", errUnsafePath
		}
	}
	return name, rest, nil
}

// matchPath matches an upstream-relative escaped path against a grant pattern.
func matchPath(pattern, path string) bool {
	ps := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	xs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(xs) > 1 && xs[len(xs)-1] == "" {
		xs = xs[:len(xs)-1] // tolerate one trailing slash
	}
	for i, p := range ps {
		if p == "**" {
			return true
		}
		if i >= len(xs) {
			return false
		}
		if p != "*" && p != xs[i] {
			return false
		}
		if p == "*" && xs[i] == "" {
			return false
		}
	}
	return len(xs) == len(ps)
}

func (g Grant) allows(method, path string) bool {
	methodOK := false
	for _, m := range g.Methods {
		if m == "*" || m == method {
			methodOK = true
			break
		}
	}
	if !methodOK {
		return false
	}
	for _, p := range g.Paths {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}
