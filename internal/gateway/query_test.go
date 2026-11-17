package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryAuthPreservesUnrelatedFieldsOnRequestAndRedirect(t *testing.T) {
	const original = "z=1&flag&tag=x+y&tag=x%20y&symbol=%2f"
	var sent string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.URL.RawQuery
		w.Header().Set("Location", "#details")
		w.WriteHeader(http.StatusFound)
	}))
	defer up.Close()
	g, _ := testGateway(t, up.URL, func(c *Config) {
		c.Upstreams[0].Auth = Auth{Type: "query", Name: "api_key", SecretEnv: "JIRA_TOKEN"}
	})
	rec := do(g, "GET", "/jira/redirect?api_key=old&"+original+"&api%5fkey=other", agentKey, nil)
	if rec.Code != 302 || sent != original+"&api_key=real-secret" {
		t.Errorf("credential replacement changed the unrelated query fields (status %d)", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/jira/redirect?"+original+"#details" {
		t.Error("the rewritten redirect changed the unrelated query fields")
	}
}
