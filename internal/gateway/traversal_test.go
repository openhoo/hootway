package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Servlet containers treat "..;" and path parameters as dot segments, so any
// semicolon would let the upstream see a different path from the policy.
func TestRejectsSemicolonPathParameters(t *testing.T) {
	for _, p := range []string{
		"/jira/rest/api/3/search/..;/admin",
		"/jira/rest/api/3/search/..;/..;/..;/admin",
		"/jira/rest/api/3/search/x;jsessionid=1",
		"/jira/rest/api/3/search/x%3B/..",
		"/jira/rest/api/3/search/x%3b",
	} {
		var got seen
		up := newUpstream(t, &got)
		g, _ := testGateway(t, up.URL, nil)
		rec := do(g, "GET", p, agentKey, nil)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "bad_path" {
			t.Errorf("%s: got %d %s", p, rec.Code, rec.Body.String())
		}
		if got.method != "" {
			t.Errorf("%s: upstream was called", p)
		}
	}
}

func TestQuerySecretNeverLeaksThroughRedirects(t *testing.T) {
	const secret = "real-secret"
	for _, loc := range []string{
		"SELF/q/next?api_key=" + secret + "&page=2",
		"https://elsewhere.example/x?api_key=" + secret,
		"/relative?api_key=" + secret,
	} {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l := strings.Replace(loc, "SELF", "http://"+r.Host, 1)
			w.Header().Set("Location", l)
			w.Header().Set("Content-Location", l)
			w.Header().Set("Refresh", "0; url="+l)
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(up.Close)
		g, _ := testGateway(t, up.URL, func(c *Config) {
			c.Upstreams[0].BaseURL = up.URL + "/q"
			c.Upstreams[0].Auth = Auth{Type: "query", Name: "api_key", SecretEnv: "JIRA_TOKEN"}
			c.Upstreams[0].Headers = nil
		})
		rec := do(g, "GET", "/jira/rest/api/3/issue/A-1", agentKey, nil)
		for k, vs := range rec.Header() {
			for _, v := range vs {
				if strings.Contains(v, secret) {
					t.Errorf("%s: header %s leaks secret: %s", loc, k, v)
				}
			}
		}
		if rec.Code != http.StatusFound || rec.Header().Get("Location") == "" {
			t.Errorf("%s: got %d %v", loc, rec.Code, rec.Header())
		}
	}
}
