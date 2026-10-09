---
name: hootway-development
description: Develop, test and review the Hootway credential-injecting API gateway source. Use when changing Hootway's Go code, configuration schema, security behaviour, CI or documentation in the openhoo/hootway repository.
---

# Hootway development

Hootway is a security boundary between agent sandboxes and real API credentials.

## Layout

- `cmd/hootway` — CLI (`serve`, `check`, `key new`, `key hash`, `admin token`, `version`); exit 0/1/2, graceful SIGINT/SIGTERM drain.
- `internal/gateway/config.go` — strict JSON schema and validation.
- `internal/gateway/match.go` — route splitting, unsafe-path rejection, grant matching.
- `internal/gateway/secrets.go` — credential resolution/injection and protected headers.
- `internal/gateway/server.go` — key auth, rate limit, reverse proxy, response sanitising, audit log.
- `internal/gateway/admin.go` — console + admin API: token sessions, CSRF header, validate → persist atomically → apply.
- `internal/gateway/admin_secrets.go` — write-only console secrets (`secrets/` next to the config, `0600`, unique names, removed on replace/delete) and `POST /api/probe`.
- `internal/gateway/web/presets.js` — New-key wizard presets: variants (cloud/self-hosted), token page URLs, test path, read/write grants. Keep grants narrow and token links pointing at the vendor's own page.
- `internal/gateway/events.go` — in-memory activity ring buffer and per-key stats.
- `internal/gateway/web/` — plain HTML/CSS/JS console, embedded as `*.gz` — run `scripts/compress-web.sh` after edits (a test fails on stale assets).
- `examples/jira.json` — reference configuration, validated in CI.
- `scripts/build-release.sh` — reproducible release archives; `scripts/footprint.sh` — binary size per target.
- `Dockerfile` — cross-compiled static binary on `scratch` with a CA bundle, UID 65532; `.dockerignore` is an allowlist.

## Rules

1. Default deny: add a failing rejection test before widening any match.
2. Every rejection test must assert the upstream was not called.
3. Never print secrets or keys; tests use fake values and `HashKey`.
4. New config fields must be validated in `validate()` and documented in README's table.
5. Keep dependencies to the standard library. Before adding an import to the binary, check its size cost with `scripts/footprint.sh` (avoid e.g. `net/http/pprof`, `text/template`, `errors.As` in hot or tiny paths).
6. Performance changes need before/after numbers from `go test -run '^$' -bench . -benchmem -count 6 ./internal/gateway` (compare with `benchstat`).

## Checks

```sh
gofmt -l . && go vet ./... && go test -race -cover ./...
go build -o /tmp/hootway ./cmd/hootway
key_hash=$(printf 'hw_ci' | /tmp/hootway key hash)
sed "s/replace-with-output-of-hootway-key-new-000000000000000000000000/$key_hash/" examples/jira.json > /tmp/ci.json
JIRA_EMAIL=ci@example.com JIRA_API_TOKEN=ci /tmp/hootway check -config /tmp/ci.json
go test -run '^$' -bench . -benchtime 100x ./...
```

For Dockerfile or release changes: `docker build -t hootway:dev .`, `IMAGE=hootway:dev scripts/footprint.sh`, and run the image against an HTTPS upstream to prove the CA bundle works. `actionlint` and `zizmor` must be clean for workflow changes.

For console changes: `node --check internal/gateway/web/app.js`, `scripts/compress-web.sh`, run `HOOTWAY_ADMIN_TOKEN=hwa_demo hootway serve -config … -admin-listen 127.0.0.1:8788`, and check login, empty states, key create/rotate/delete, activity and check in light/dark and at 390px width. Refresh `docs/screenshots` when the UI changes.

For proxy behaviour changes, also run `hootway serve` against a local test upstream and exercise allowed and denied requests with curl.
