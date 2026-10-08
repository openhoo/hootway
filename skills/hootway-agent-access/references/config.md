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

Exactly one of `secret_env` / `secret_file`. Unknown fields are rejected. Static headers cannot set `Authorization`, `Cookie`, `Host` or hop-by-hop headers.

Requests: `<listen>/<upstream name><upstream path>`; `GET /healthz` is unauthenticated.
