Hootway lets agent sandboxes call logged-in APIs such as Jira with scoped virtual keys instead of real credentials.

## Changes in 0.4.1

- Activity announces proxied requests as "via proxy" to screen readers instead of reading the arrow glyph
- Refreshed console screenshots for proxy mode and outbound proxies; container image size updated in the README

## Changes in 0.4.0

### Proxy mode

- Hootway can also be used as an HTTP(S) proxy (`"proxy": {}`): agents keep the real API URL and send their virtual key as the proxy password; the same grants, rate limits and credential injection apply
- `https://` upstreams are intercepted with short-lived per-host certificates from a CA created by `hootway proxy ca`; tunnels need a valid key, only configured upstream hosts are reachable, and keys are rechecked on every request inside a tunnel
- Activity marks proxied requests and logs their real URL; Check accepts real upstream URLs

### Outbound proxy

- `outbound_proxy` routes Hootway's own upstream connections through an `http`, `https`, `socks5` or `socks5h` proxy, with optional credentials from env or file; upstreams can override it or connect directly, also in the console
- Without it, `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` apply as before

Binaries grow by about 0.6 MB for the TLS server and certificate issuing.

## Changes in 0.3.0

### New key presets

- New key wizard with presets for Jira, Confluence, Bitbucket (Cloud and Data Center), GitLab, GitHub (incl. Enterprise Server), Gitea/Forgejo, Linear, Plane, Sentry, Grafana and Notion: choose cloud or self-hosted, get sent to the right (prefilled where supported) token page, paste and test the token, then create a scoped key
- The console can store a pasted upstream token write-only in a `0600` file under `secrets/` next to the config; replaced or deleted upstreams remove their managed file
- `POST /api/probe` tests a saved or draft upstream credential with one `GET` and returns only the status

## Changes in 0.2.1

- The signed multi-arch image is now also published to Docker Hub: `docker pull openhoo/hootway` (same digest as `ghcr.io/openhoo/hootway`)

## Changes in 0.2.0

### Security

- Reject `;` and `%3B` in request paths: servlet upstreams such as Jira treat `..;` as `..`, which let a `/**` grant reach paths outside it
- `query` auth: the injected secret is stripped from `Location`/`Content-Location` and `Refresh` is dropped, so redirects cannot echo it back
- Console login/logout require the console header (login CSRF); upstream PUT rejects mismatched names
- Configuration rejects CR/LF/NUL in static headers, prefixes and usernames, and invalid header or query names

### Performance and footprint

- Gateway hot paths about 51% faster (benchmark geomean), 80% less memory per forwarded request, allocation-free grant matching and path checks
- Connection pools and rate-limit windows survive config reloads; activity polling is 46× cheaper
- Smaller binaries (about −74 KB) with the console embedded precompressed and served with ETags (−69% on the wire)
- Web console: focus handling, loading/error states, non-overlapping polling and accessibility fixes; screenshots 58% smaller

### Packaging

- Smaller container image: `scratch` with only the static binary, a CA bundle and a non-root user (UID/GID 65532); no shell, libc or tzdata
- Release archives are compressed with `gzip -9`/`zip -9` and contain only the binary, `LICENSE`, `README.md` and example configs
- CLI: exit status `2` for usage errors, `serve -h` help, listen-address errors reported before startup, a second `SIGINT`/`SIGTERM` skips the 15-second drain
- CI: benchmark smoke run, docs-only changes skip CI, release image waits for verified binaries and is smoke-tested after signing

## Highlights

- Virtual keys (`hw_…`), stored only as SHA-256, with expiry, disable and per-minute limits
- Per-key method and path grants; default deny, unsafe paths rejected before upstream
- Credential injection: basic (Jira e-mail + API token), bearer, custom header, query
- Caller credentials and cookies stripped, upstream `Set-Cookie` removed, redirects kept in the gateway
- Zen web console on a separate listener: keys, upstreams, live activity and policy check; changes validated, saved atomically and applied live
- Static binaries for Linux, macOS and Windows; multi-arch image `openhoo/hootway` (Docker Hub) and `ghcr.io/openhoo/hootway`
- Agent skills: `npx skills add openhoo/hootway --skill hootway-agent-access`

Verify an archive: `cosign verify-blob --bundle <file>.sigstore.json --certificate-identity-regexp 'https://github.com/openhoo/hootway/' --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>` or `gh attestation verify <file> -R openhoo/hootway`.
