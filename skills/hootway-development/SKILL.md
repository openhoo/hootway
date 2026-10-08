---
name: hootway-development
description: Develop, test and review the Hootway credential-injecting API gateway source. Use when changing Hootway's Go code, configuration schema, security behaviour, CI or documentation in the openhoo/hootway repository.
---

# Hootway development

Hootway is a security boundary between agent sandboxes and real API credentials.

## Layout

- `cmd/hootway` — CLI (`serve`, `check`, `key new`, `key hash`, `version`).
- `internal/gateway/config.go` — strict JSON schema and validation.
- `internal/gateway/match.go` — route splitting, unsafe-path rejection, grant matching.
- `internal/gateway/secrets.go` — credential resolution/injection and protected headers.
- `internal/gateway/server.go` — key auth, rate limit, reverse proxy, response sanitising, audit log.
- `examples/jira.json` — reference configuration, validated in CI.

## Rules

1. Default deny: add a failing rejection test before widening any match.
2. Every rejection test must assert the upstream was not called.
3. Never print secrets or keys; tests use fake values and `HashKey`.
4. New config fields must be validated in `validate()` and documented in README's table.
5. Keep dependencies to the standard library.

## Checks

```sh
gofmt -l . && go vet ./... && go test -race -cover ./...
go build -o /tmp/hootway ./cmd/hootway
key_hash=$(printf 'hw_ci' | /tmp/hootway key hash)
sed "s/replace-with-output-of-hootway-key-new-000000000000000000000000/$key_hash/" examples/jira.json > /tmp/ci.json
JIRA_EMAIL=ci@example.com JIRA_API_TOKEN=ci /tmp/hootway check -config /tmp/ci.json
```

For proxy behaviour changes, also run `hootway serve` against a local test upstream and exercise allowed and denied requests with curl.
