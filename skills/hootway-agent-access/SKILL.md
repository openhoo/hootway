---
name: hootway-agent-access
description: Give an agent sandbox scoped access to a logged-in API such as Jira through a Hootway gateway and virtual key, or call an API through Hootway from inside a sandbox. Use when setting up Hootway keys and grants, or when an agent was handed a Hootway URL and hw_ key.
---

# Hootway agent access

Hootway replaces a real API credential with a revocable virtual key (`hw_…`) and per-key method/path grants.

## Inside a sandbox (you were given a Hootway URL and key)

- Call `<HOOTWAY_URL>/<upstream>/<normal API path>` with `Authorization: Bearer hw_…`.
  If a tool only supports e-mail + token, use any username and the `hw_…` key as password.
- If you were given a proxy instead (`HTTPS_PROXY=http://…:hw_…@hootway…`), call the real API URL through it; for https trust the provided Hootway CA certificate (`SSL_CERT_FILE` etc.). `407` means the proxy key is missing or invalid; `403 not_an_upstream` means that host is not configured.
- Do not search for or ask for the real upstream credential.
- `401 missing_key|invalid_key`: key absent, wrong, disabled or expired — ask the operator.
- `403 forbidden`: method/path not granted — report the exact method and path you need instead of trying other paths.
- `400 bad_path`: remove `..`, `//` or encoded slashes/dots from the path.
- `429 rate_limited`: wait for `Retry-After` seconds.
- `502 upstream_unreachable`: upstream failed; for writes the result may be uncertain — read back before retrying.
- `503 upstream_unconfigured`: the gateway has no usable credential for that upstream — ask the operator; do not retry in a loop.

## Operator setup

1. Install a signed binary from <https://github.com/openhoo/hootway/releases/latest>, `docker pull openhoo/hootway:latest` (Docker Hub; also `ghcr.io/openhoo/hootway`), or `go install github.com/openhoo/hootway/cmd/hootway@latest`.
2. `hootway key new` — give the `hw_…` key to the agent, store only the `sha256`.
3. Write `hootway.json` (see [references/config.md](references/config.md)). Keep real secrets in environment variables or files referenced by `secret_env` / `secret_file`.
4. Grant the smallest set: read paths with `GET`, writes only on specific endpoints. `*` = one segment, final `/**` = subtree.
5. `hootway check -config hootway.json` (exit 0 = valid and all secrets resolved), then `hootway serve -config hootway.json`.
6. Run Hootway outside the sandbox; allow the sandbox network to reach Hootway, not the upstream.
7. Optional console: `hootway admin token`, then `HOOTWAY_ADMIN_TOKEN=hwa_… hootway serve -config hootway.json -admin-listen 127.0.0.1:8788`. **New key** offers presets (Jira, Confluence, Bitbucket, GitLab, GitHub, Gitea/Forgejo, Linear, Plane, Sentry, Grafana, Notion): it asks cloud vs. self-hosted, opens the token page, stores the pasted token write-only under `secrets/` next to the config and suggests read-only or read-write grants. Create/rotate keys, watch Activity and use Check to test a method and path without calling the upstream. Never expose the console to the sandbox network.
8. Optional proxy mode for tools that cannot change their base URL: add `"proxy": {}` (plus `hootway proxy ca` and `ca_cert_file`/`ca_key_file` for https upstreams), give the sandbox `HTTPS_PROXY=http://agent:hw_…@<gateway>` and only the CA certificate. If Hootway itself needs an egress proxy, set `outbound_proxy` (top level or per upstream; `{"direct": true}` bypasses it).
9. Verify one allowed and one denied request with curl before handing over the key.
10. Revoke in the console (Disable/Delete, applied immediately) or set `"disabled": true` / `expires_at` in the file and restart (SIGTERM drains in-flight requests).
11. In the container image (`scratch`, UID 65532) mount the config directory readable by 65532, writable if console edits should persist; probe liveness with HTTP `GET /healthz`.
