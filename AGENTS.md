# Hootway

Hootway is a credential boundary. A change that lets an agent reach a path, method or secret it was not granted is a security bug.

- Default deny. Only explicit grants forward; rejected requests must never reach an upstream.
- Never log or return key values, upstream secrets, request bodies or upstream cookies.
- Keep policy path and forwarded path identical; reject ambiguous encodings instead of normalising them.
- Store only SHA-256 hashes of virtual keys in configuration and tests.
- The web console (`internal/gateway/web`, embedded precompressed; run `scripts/compress-web.sh` after edits) runs on a separate listener; never mount admin routes on the gateway handler.
- Console and admin API must never return key values after creation, key hashes, or secret values.
- Standard library only unless a dependency is clearly justified.
- Run `gofmt -l .`, `go vet ./...`, `go test -race -cover ./...` and the benchmark smoke `go test -run '^$' -bench . -benchtime 100x ./...` before publishing.
- Keep the binary and image small: no new imports without checking `scripts/footprint.sh`; the image stays `scratch` + CA bundle + UID 65532. No UPX.
- Contributor workflow: `skills/hootway-development`. User workflow: `skills/hootway-agent-access`.
