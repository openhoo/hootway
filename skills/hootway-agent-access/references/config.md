# Hootway configuration reference

```json
{
  "listen": "127.0.0.1:8787",
  "upstreams": [
    {
      "name": "jira",
      "base_url": "https://your-site.atlassian.net",
      "auth": { "type": "basic", "username_env": "JIRA_EMAIL", "secret_env": "JIRA_API_TOKEN" },
      "headers": { "X-Atlassian-Token": "no-check" }
    },
    {
      "name": "github",
      "base_url": "https://api.github.com",
      "auth": { "type": "bearer", "secret_file": "/run/secrets/github-token" },
      "headers": { "Accept": "application/vnd.github+json" }
    }
  ],
  "keys": [
    {
      "id": "triage-agent",
      "sha256": "<from hootway key new>",
      "expires_at": "2026-12-31T23:59:59Z",
      "requests_per_minute": 120,
      "grants": [
        { "upstream": "jira", "methods": ["GET"], "paths": ["/rest/api/3/issue/*", "/rest/api/3/search/**"] },
        { "upstream": "jira", "methods": ["POST"], "paths": ["/rest/api/3/issue/*/comment"] },
        { "upstream": "github", "methods": ["GET"], "paths": ["/repos/acme/app/**"] }
      ]
    }
  ]
}
```

Auth types: `basic` (username/username_env + secret), `bearer`, `header` (`name`, optional `prefix`), `query` (`name`), `none`.

Exactly one of `secret_env` / `secret_file`. Unknown fields are rejected. Static headers cannot set `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`, `Content-Length`, `X-Hootway-*` or hop-by-hop headers. `timeout_seconds` (default 60) bounds the upstream response header wait; `requests_per_minute` `0` means unlimited.

Requests: `<listen>/<upstream name><upstream path>`; `GET /healthz` is unauthenticated.

Web console (optional, separate listener):

```json
"admin": { "listen": "127.0.0.1:8788", "token_sha256": "<from hootway admin token>" }
```

Or set `HOOTWAY_ADMIN_TOKEN` and pass `-admin-listen`. Console changes are validated, saved atomically to the config file and applied live.
Console-stored tokens (New key wizard) live in `secrets/` next to the config file as `0600` files referenced by `secret_file`; mount that directory writable for UID 65532 in containers.

Proxy mode (agents keep real URLs; `HTTPS_PROXY=http://any:hw_…@<listen>`):

```json
"proxy": { "ca_cert_file": "hootway-ca.pem", "ca_key_file": "hootway-ca-key.pem" }
```

`"proxy": {}` is enough for `http://` upstreams. For `https://` upstreams create the CA with `hootway proxy ca` and install only the certificate in the sandbox trust store (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, …). Only configured upstream origins are reachable; grants, rate limits and credential injection are the same as for `/<name>/…` requests.

Outbound proxy (Hootway → upstream), top level or per upstream:

```json
"outbound_proxy": { "url": "http://proxy:3128", "username": "gw", "secret_env": "PROXY_PASSWORD" }
"outbound_proxy": { "direct": true }
```

Schemes `http`, `https`, `socks5`, `socks5h`; no credentials in `url`. Without it, `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` from the gateway environment apply.
