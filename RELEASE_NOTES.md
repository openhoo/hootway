First public release of Hootway: an API gateway that lets agent sandboxes call logged-in APIs such as Jira with scoped virtual keys instead of real credentials.

- Virtual keys (`hw_…`), stored only as SHA-256, with expiry, disable and per-minute limits
- Per-key method and path grants; default deny, unsafe paths rejected before upstream
- Credential injection: basic (Jira e-mail + API token), bearer, custom header, query
- Caller credentials and cookies stripped, upstream `Set-Cookie` removed, redirects kept in the gateway
- Zen web console on a separate listener: keys, upstreams, live activity and policy check; changes validated, saved atomically and applied live
- Static binaries for Linux, macOS and Windows; multi-arch image `ghcr.io/openhoo/hootway`
- Agent skills: `npx skills add openhoo/hootway --skill hootway-agent-access`

Verify an archive: `cosign verify-blob --bundle <file>.sigstore.json --certificate-identity-regexp 'https://github.com/openhoo/hootway/' --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>` or `gh attestation verify <file> -R openhoo/hootway`.
