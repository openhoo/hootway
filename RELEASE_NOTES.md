Hootway lets agent sandboxes call logged-in APIs such as Jira with scoped virtual keys instead of real credentials.

## Changes since 0.2.0

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
