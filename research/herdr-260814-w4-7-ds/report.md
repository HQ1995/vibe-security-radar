# unr-adj4-slice-7 adjudication — verdict-first

**Verdict: 25/25 FALSE_POSITIVE (no_ai_origin / wrong_edge). 0 countable. 0 UNKNOWN. 0 BLOCKED.**

Every candidate AI commit diff was fetched via git smart-HTTP into the bare pool and read
directly (no GitHub API, no blame/SZZ). In every row the candidate AI commits do not author,
rewrite, or materially contribute to the advisory's named mechanism, so `ai_hunk_gate` and
`but_for_gate` fail and no row is countable. Missing fix/release evidence stays `UNKNOWN`.

## Breakdown by repository

- **snowflake-connector-python** (TLS hostname) — mitmproxy/pyOpenSSL dep bumps + auth-callback flag; not TLS verification.
- **udisks x2** (LUKS header authz) — module-manager/daemon-util/NVMe leak fixes; not LUKS D-Bus methods.
- **varnish** (workspace overflow) — vmod_tls/mgt_tls/ecdh_curve; not HTTP/1 pipeline workspace.
- **plane** (asset cross-tenant) — issue-list/favicon/member-role/webhook fixes; not asset API.
- **keycloak** (partialImport FGAP) — JWT validator/streaming/clients-initial-access/CLI; not partialImport.
- **wazuh x6** (authd/shell injection/token/curl -k) — get_config list wrap + docs only; wrong component.
- **frappe x2** (stored XSS) — sole candidate is esbuild.js build-signal handling; not formatters.
- **Inputmask** (prototype pollution) — paste/alternation fixes; not extend.js deep merge.
- **NixOS/nixpkgs x6** (dnsmasq) — advisories name upstream dnsmasq; candidates are gnutls/frigate packaging edits.
- **cmder** (.cmd overflow) — GitHub Actions workflow edits; not .cmd parsing.
- **CowAgent x2** (browser tool / channel authz) — CI/desktop-packaging/wecom_bot path refactor; not browser_tool.py or channel.py.
- **next-ai-draw-io** (XFF disclosure) — provider cases + npm-audit removal + model-selector UI; no X-Forwarded-For change.

## Gate totals

identity PASS 25; ai_hunk FAIL 25; topology UNKNOWN 25; but_for FAIL 25;
fix_reversal UNKNOWN 25; release UNKNOWN 25; uniqueness PASS 25.

No acceptance replay is required: there are zero PASS proposals.
