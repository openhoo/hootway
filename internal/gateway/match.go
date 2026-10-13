package gateway

import (
	"errors"
	"strings"
)

var errUnsafePath = errors.New("unsafe request path")

// checkQuery rejects syntax that net/url and ReverseProxy would silently
// discard while parsing the query. A valid query is forwarded byte for byte
// unless the route intentionally replaces its credential parameter.
func checkQuery(query string) error {
	for i := 0; i < len(query); i++ {
		switch query[i] {
		case ';':
			return errUnsafePath
		case '%':
			if i+2 >= len(query) {
				return errUnsafePath
			}
			_, hiOK := sensitiveHexDigit(query[i+1])
			_, loOK := sensitiveHexDigit(query[i+2])
			if !hiOK || !loOK {
				return errUnsafePath
			}
			i += 2
		}
	}
	return nil
}

// splitRoute splits an escaped request path into the upstream name and the
// upstream-relative path. It rejects encodings that could make the path seen
// by the policy differ from the path interpreted by the upstream: encoded
// slashes, backslashes, dots, percent signs and control bytes (in any case), raw backslashes,
// empty segments ("//") and "." or ".." segments. It does not allocate.
func splitRoute(escaped string) (name, rest string, err error) {
	if !strings.HasPrefix(escaped, "/") || hasUnsafeEncoding(escaped) {
		return "", "", errUnsafePath
	}
	trimmed := escaped[1:]
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		name, rest = trimmed[:i], trimmed[i:]
	} else {
		name, rest = trimmed, "/"
	}
	if hasDotSegment(rest) {
		return "", "", errUnsafePath
	}
	return name, rest, nil
}

// checkPath applies the same rejections as splitRoute to a complete escaped
// path, for proxy requests that carry no route prefix.
func checkPath(escaped string) error {
	if !strings.HasPrefix(escaped, "/") || hasUnsafeEncoding(escaped) || hasDotSegment(escaped) {
		return errUnsafePath
	}
	return nil
}

// hasDotSegment reports whether the "/"-prefixed path p has a "." or ".."
// segment.
func hasDotSegment(p string) bool {
	for s := p[1:]; ; {
		seg, more := nextSegment(&s)
		if seg == "." || seg == ".." {
			return true
		}
		if !more {
			return false
		}
	}
}

// hasUnsafeEncoding rejects separators, percent signs (which enable nested
// decoding), control bytes, servlet path parameters and empty segments.
func hasUnsafeEncoding(p string) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\', ';':
			return true
		case '/':
			if i+1 < len(p) && p[i+1] == '/' {
				return true
			}
		case '%':
			if i+2 < len(p) {
				hi, lo := p[i+1], p[i+2]|0x20 // lower-case letters only
				if (hi == '2' && (lo == 'f' || lo == 'e' || lo == '5')) || (hi == '5' && lo == 'c') || (hi == '3' && lo == 'b') ||
					(hi == '0' || hi == '1') || (hi == '7' && lo == 'f') {
					return true
				}
			}
		}
	}
	return false
}

// nextSegment returns the next "/"-separated segment of *s and advances *s.
// more is false when the returned segment is the last one, mirroring
// strings.Split semantics (an empty string has one empty segment).
func nextSegment(s *string) (seg string, more bool) {
	if i := strings.IndexByte(*s, '/'); i >= 0 {
		seg, *s = (*s)[:i], (*s)[i+1:]
		return seg, true
	}
	seg, *s = *s, ""
	return seg, false
}

// pathPattern is a grant path pattern split into segments once at load time.
type pathPattern []string

func compilePattern(pattern string) pathPattern {
	return strings.Split(strings.TrimPrefix(pattern, "/"), "/")
}

// match reports whether an upstream-relative escaped path matches. "*"
// matches exactly one non-empty segment, a final "**" matches the prefix
// itself and anything below it, and one trailing slash on the path is
// tolerated. It does not allocate.
func (pp pathPattern) match(path string) bool {
	xs := strings.TrimPrefix(path, "/")
	if strings.HasSuffix(xs, "/") {
		xs = xs[:len(xs)-1] // tolerate one trailing slash
	}
	more := true
	for _, p := range pp {
		if p == "**" {
			return true
		}
		if !more {
			return false
		}
		var x string
		x, more = nextSegment(&xs)
		if p == "*" {
			if x == "" {
				return false
			}
		} else if p != x {
			return false
		}
	}
	return !more
}

// matchPath matches an upstream-relative escaped path against a grant pattern.
func matchPath(pattern, path string) bool {
	return compilePattern(pattern).match(path)
}

func methodAllowed(methods []string, method string) bool {
	for _, m := range methods {
		if m == "*" || m == method {
			return true
		}
	}
	return false
}

func (g Grant) allows(method, path string) bool {
	if !methodAllowed(g.Methods, method) {
		return false
	}
	for _, p := range g.Paths {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}

// compiledGrant is a Grant with its path patterns split once per
// configuration load so request matching never allocates.
type compiledGrant struct {
	index    int // position in Key.Grants
	upstream string
	methods  []string
	paths    []pathPattern
}

func compileGrants(grants []Grant) []compiledGrant {
	out := make([]compiledGrant, len(grants))
	for i, g := range grants {
		cg := compiledGrant{index: i, upstream: g.Upstream, methods: g.Methods, paths: make([]pathPattern, len(g.Paths))}
		for j, p := range g.Paths {
			cg.paths[j] = compilePattern(p)
		}
		out[i] = cg
	}
	return out
}

func (cg *compiledGrant) allows(upstream, method, path string) bool {
	if cg.upstream != upstream || !methodAllowed(cg.methods, method) {
		return false
	}
	for _, p := range cg.paths {
		if p.match(path) {
			return true
		}
	}
	return false
}
