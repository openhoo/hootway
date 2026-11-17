package gateway

import "testing"

func TestEmptyCredentialsAreNotUsableConfig(t *testing.T) {
	c := Config{Admin: &Admin{TokenSHA256: HashKey("")}}
	if err := c.validate(); err == nil {
		t.Fatal("empty administrator credential was accepted")
	}
}

func TestConfiguredEndpointsRequireUsablePorts(t *testing.T) {
	for _, tc := range []struct {
		addr  string
		valid bool
	}{
		{"http://example.test:", false}, {"https://example.test:65536", false},
		{"http://::1:80", false}, {"http://example.test:0", false},
		{"https://example.test", true}, {"http://[::1]:65535", true},
	} {
		cfg := Config{Upstreams: []Upstream{{Name: "fixture", BaseURL: tc.addr, Auth: Auth{Type: "none"}}}}
		if err := cfg.validate(); (err == nil) != tc.valid {
			t.Errorf("upstream %s: err=%v", tc.addr, err)
		}
		op := OutboundProxy{URL: tc.addr}
		if err := op.validate(); (err == nil) != tc.valid {
			t.Errorf("egress %s: err=%v", tc.addr, err)
		}
	}
	for _, addr := range []string{"http://proxy.test?", "http://proxy.test#"} {
		op := OutboundProxy{URL: addr}
		if err := op.validate(); err == nil {
			t.Errorf("accepted a query or fragment on %s", addr)
		}
	}
}

func TestGrantsRequireUsableEscapedPaths(t *testing.T) {
	for _, pattern := range []string{"/team/%", "/team/%4x", "/item/a b", "/item/line\nbreak", "/team/"} {
		if validatePattern(pattern) == nil {
			t.Errorf("accepted an unusable grant %q", pattern)
		}
	}
	for _, pattern := range []string{"/", "/team", "/team/*", "/item/a%20b", "/team/**"} {
		if err := validatePattern(pattern); err != nil {
			t.Errorf("valid grant %q: %v", pattern, err)
		}
	}
}
