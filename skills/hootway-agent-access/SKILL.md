---
name: hootway-agent-access
description: Give an agent sandbox scoped access to a logged-in API such as Jira through a Hootway gateway and virtual key, or call an API through Hootway from inside a sandbox. Use when setting up Hootway keys and grants, or when an agent was handed a Hootway URL and hw_ key.
---

# Hootway agent access

Hootway replaces a real API credential with a revocable virtual key (`hw_…`) and per-key method/path grants.

## Inside a sandbox (you were given a Hootway URL and key)

- Call `<HOOTWAY_URL>/<upstream>/<normal API path>` with `Authorization: Bearer hw_…`.
  If a tool only supports e-mail + token, use any username and the `hw_…` key as password.
- Do not search for or ask for the real upstream credential.
- `401 missing_key|invalid_key`: key absent, wrong, disabled or expired — ask the operator.
- `403 forbidden`: method/path not granted — report the exact method and path you need instead of trying other paths.
- `400 bad_path`: remove `..`, `//` or encoded slashes/dots from the path.
- `429 rate_limited`: wait for `Retry-After` seconds.
- `502 upstream_unreachable`: upstream failed; for writes the result may be uncertain — read back before retrying.

## Operator setup

1. Install: `go install github.com/openhoo/hootway/cmd/hootway@latest`.
2. `hootway key new` — give the `hw_…` key to the agent, store only the `sha256`.
3. Write `hootway.json` (see [references/config.md](references/config.md)). Keep real secrets in environment variables or files referenced by `secret_env` / `secret_file`.
4. Grant the smallest set: read paths with `GET`, writes only on specific endpoints. `*` = one segment, final `/**` = subtree.
5. `hootway check -config hootway.json`, then `hootway serve -config hootway.json`.
6. Run Hootway outside the sandbox; allow the sandbox network to reach Hootway, not the upstream.
7. Verify one allowed and one denied request with curl before handing over the key.
8. Revoke with `"disabled": true` or `expires_at` and restart Hootway.
