package gateway

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStaleConsoleEditsPreserveCurrentPolicyAndCredential(t *testing.T) {
	c, g, path := newConsole(t, "http://unused.test")
	c.call("POST", "/api/session", map[string]string{"token": adminToken}, true)
	key := keyInput{ID: "reader", Grants: []Grant{{Upstream: "jira", Methods: []string{"GET"}, Paths: []string{"/items"}}}}
	if code, _ := c.call("POST", "/api/keys", key, true); code != 200 {
		t.Fatal("could not create fixture key")
	}
	revision := func(collection string) map[string]string {
		t.Helper()
		_, state := c.call("GET", "/api/state", nil, true)
		item := state[collection].([]any)[0].(map[string]any)
		rev, _ := item["revision"].(string)
		// Even an unknown or absent revision must never match an edited item.
		return map[string]string{"If-Match": `"` + rev + `"`}
	}
	keyTag, upTag := revision("keys"), revision("upstreams")
	newUp := upstreamInput{Upstream: Upstream{BaseURL: "http://unused.test", Auth: Auth{Type: "bearer"}}, Secret: "demo-new"}
	if code, _ := c.call("PUT", "/api/upstreams/jira", newUp, true, upTag); code != 200 {
		t.Fatal("an edit using the current upstream revision failed")
	}
	file := g.Config().Upstreams[0].Auth.SecretFile
	key.Disabled = true
	if code, _ := c.call("PUT", "/api/keys/reader", key, true, keyTag); code != 200 {
		t.Fatal("an unrelated upstream edit invalidated the key revision")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key.Disabled = false
	newUp.Secret = "discard-this-draft"
	for _, tc := range []struct {
		method, path string
		body         any
		tag          map[string]string
	}{
		{"PUT", "/api/keys/reader", key, keyTag},
		{"POST", "/api/keys/reader/rotate", nil, keyTag},
		{"DELETE", "/api/keys/reader", nil, keyTag},
		{"PUT", "/api/upstreams/jira", newUp, upTag},
		{"DELETE", "/api/upstreams/jira", nil, upTag},
	} {
		if code, _ := c.call(tc.method, tc.path, tc.body, true, tc.tag); code != 412 {
			t.Fatalf("stale %s %s: status %d", tc.method, tc.path, code)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(saved, after) || !g.Config().Keys[0].Disabled {
		t.Fatal("a stale request changed the active or persisted policy")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(file), "*"))
	if err != nil || len(files) != 1 || files[0] != file {
		t.Fatal("a stale upstream edit changed the managed credential files")
	}
	keyTag = revision("keys")
	if code, _ := c.call("DELETE", "/api/keys/reader", nil, true, keyTag); code != 200 {
		t.Fatal("current key revision did not allow deletion")
	}
	upTag = revision("upstreams")
	if code, _ := c.call("DELETE", "/api/upstreams/jira", nil, true, upTag); code != 200 {
		t.Fatal("current upstream revision did not allow deletion")
	}
	if code, _ := c.call("PUT", "/api/upstreams/jira", newUp, true, upTag); code != 412 || len(g.Config().Upstreams) != 0 {
		t.Fatal("a stale edit recreated a deleted connection")
	}
}
