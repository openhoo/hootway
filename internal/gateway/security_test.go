package gateway

import (
	"net/http"
	"strings"
	"testing"
)

// A cross-site form can POST text/plain JSON; without the console header the
// login must be refused and no session cookie set (login CSRF).
func TestLoginRequiresConsoleHeader(t *testing.T) {
	c, _, _ := newConsole(t, "http://127.0.0.1:1")
	req, _ := http.NewRequest("POST", c.srv.URL+"/api/session", strings.NewReader(`{"token":"`+adminToken+`"}`))
	req.Header.Set("Content-Type", "text/plain")
	res, err := c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || len(res.Cookies()) != 0 {
		t.Fatalf("login without console header: %d cookies=%d", res.StatusCode, len(res.Cookies()))
	}
	if code, _ := c.call("GET", "/api/state", nil, true); code != 401 {
		t.Fatalf("session was created: %d", code)
	}
	if code, _ := c.call("DELETE", "/api/session", nil, false); code != 403 {
		t.Fatalf("logout without console header: %d", code)
	}
}

// PUT /api/upstreams/<new> with a different body name used to create an
// upstream under the body name, bypassing the URL the operator addressed.
func TestUpstreamPutNameMismatchRejected(t *testing.T) {
	c, gw, _ := newConsole(t, "http://127.0.0.1:1")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	code, _ := c.call("PUT", "/api/upstreams/new", map[string]any{"name": "other", "base_url": "https://example.com",
		"auth": map[string]string{"type": "none"}}, true)
	if code != 422 {
		t.Fatalf("name mismatch: %d", code)
	}
	for _, u := range gw.Config().Upstreams {
		if u.Name == "other" || u.Name == "new" {
			t.Fatalf("upstream %q was created", u.Name)
		}
	}
}

func TestConfigRejectsHeaderInjection(t *testing.T) {
	base := func(up string) string {
		return `{"upstreams":[` + up + `],"keys":[]}`
	}
	cases := map[string]string{
		"crlf header value":   `{"name":"a","base_url":"https://x","auth":{"type":"none"},"headers":{"X-A":"v\r\nX-Evil: 1"}}`,
		"bad header name":     `{"name":"a","base_url":"https://x","auth":{"type":"none"},"headers":{"X A":"v"}}`,
		"empty header name":   `{"name":"a","base_url":"https://x","auth":{"type":"none"},"headers":{"":"v"}}`,
		"bad auth header":     `{"name":"a","base_url":"https://x","auth":{"type":"header","name":"X:Y","secret_env":"S"}}`,
		"crlf prefix":         `{"name":"a","base_url":"https://x","auth":{"type":"header","name":"X-Key","prefix":"a\r\nb","secret_env":"S"}}`,
		"colon in username":   `{"name":"a","base_url":"https://x","auth":{"type":"basic","username":"a:b","secret_env":"S"}}`,
		"proxy-connection":    `{"name":"a","base_url":"https://x","auth":{"type":"none"},"headers":{"Proxy-Connection":"x"}}`,
		"bad query auth name": `{"name":"a","base_url":"https://x","auth":{"type":"query","name":"a&b=c","secret_env":"S"}}`,
	}
	for name, up := range cases {
		if _, err := ParseConfig([]byte(base(up))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseConfig([]byte(base(`{"name":"a","base_url":"https://x","auth":{"type":"header","name":"X-Api-Key","prefix":"Token ","secret_env":"S"},"headers":{"X-Atlassian-Token":"no-check"}}`))); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestCredentialRejectsUnsafeEnvValues(t *testing.T) {
	a := Auth{Type: "basic", UsernameEnv: "U", SecretEnv: "S"}
	env := map[string]string{"U": "a:b", "S": "s"}
	if _, err := resolveCredential(a, func(k string) string { return env[k] }); err == nil {
		t.Fatal("username with colon accepted")
	}
	env = map[string]string{"U": "u", "S": "s\x00x"}
	if _, err := resolveCredential(a, func(k string) string { return env[k] }); err == nil {
		t.Fatal("secret with NUL accepted")
	}
}

// Rejected requests must never reach the upstream.
func TestRejectionsNeverReachUpstream(t *testing.T) {
	var got seen
	up := newUpstream(t, &got)
	g, _ := testGateway(t, up.URL, nil)
	for _, target := range []string{
		"/jira/rest/api/3/issue/%2e%2e/x", "/jira/rest/api/3/issue/A%2f1", "/jira//rest/api/3/issue/A",
		"/jira/rest/api/3/issue/A/../../x", "/jira/rest/api/3/issue/A%5c1", "/jira/rest/api/3/issue/A%00",
		"/jira/rest/api/3/project/X", "/other/rest/api/3/issue/A",
	} {
		got = seen{}
		rec := do(g, "GET", target, agentKey, nil)
		if rec.Code < 400 || got.method != "" {
			t.Errorf("%s: status %d, upstream called=%v", target, rec.Code, got.method != "")
		}
	}
	got = seen{}
	if rec := do(g, "GET", "/jira/rest/api/3/issue/A", "hw_wrong", nil); rec.Code != 401 || got.method != "" {
		t.Fatalf("bad key: %d", rec.Code)
	}
}
