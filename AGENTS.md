# Hootway

Hootway is a credential boundary. A change that lets an agent reach a path, method or secret it was not granted is a security bug.

- Default deny. Only explicit grants forward; rejected requests must never reach an upstream.
- Never log or return key values, upstream secrets, request bodies or upstream cookies.
- Keep policy path and forwarded path identical; reject ambiguous encodings instead of normalising them.
- Store only SHA-256 hashes of virtual keys in configuration and tests.
- The web console (`internal/gateway/web`, embedded, no build step) runs on a separate listener; never mount admin routes on the gateway handler.
- Console and admin API must never return key values after creation, key hashes, or secret values.
- Standard library only unless a dependency is clearly justified.
- Run `gofmt -l .`, `go vet ./...` and `go test -race -cover ./...` before publishing.
- Contributor workflow: `skills/hootway-development`. User workflow: `skills/hootway-agent-access`.
