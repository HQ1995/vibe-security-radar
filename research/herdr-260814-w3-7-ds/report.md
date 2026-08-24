# unr-adj3-slice-7 adjudication — verdict-first

**Verdict: 25/25 FALSE_POSITIVE (no_ai_origin / wrong_edge). 0 countable. 0 UNKNOWN. 0 BLOCKED.**

All 65 candidate AI commit diffs were fetched via git smart-HTTP into the bare pool and read
directly (no GitHub API, no blame/SZZ). In every row the candidate AI commits do not author,
rewrite, or materially contribute to the advisory's named mechanism, so `ai_hunk_gate` and
`but_for_gate` fail and no row is countable. Missing fix/release evidence stays `UNKNOWN`, never
converted to FAIL. The local advisory-database clone was refreshed via `git fetch` to reach the
August-2026 unreviewed advisories (open5gs/bc-java/JeecgBoot/openwrt).

## Breakdown by repository

- **pyod** (deserialize) — candidates are lunar/suod/sos/dif/lof model fixes; not persistence.load.
- **Mantle-UI/mantle-ui** (prototype pollution) — advisory names primefaces/primereact (cross-bound);
  the one ObjectUtils candidate is a CodeQL autofix that ADDS a `__proto__`/`prototype`/`constructor`
  guard to `mutateFieldData`, i.e. a remediation, not the root cause.
- **adminer** (cookie injection) — candidates are SQLite/MariaDB driver edits; not header handling.
- **open5gs x2** (HSS/freeDiameter) — candidates are MME DNS selection + PFCP handler hardening; wrong subsystem.
- **llama.cpp** (grammar overflow) — jinja/conv2d/chat/speculative; not llama-grammar.cpp.
- **kubernetes/kubernetes** (ingress-nginx) — advisory names ingress-nginx (separate repo); candidates are client-go/deps.
- **hayabusa** (HTML report XSS) — 3 one-line changes (metrics borrow, regex, JSON trim); not HTML rendering.
- **bacnet-stack** (tag OOB read) — rpm/wpm/bacpropstates decode hardening + schedule overflow fix; not bacnet_tag_number_decode.
- **JeecgBoot** (SSRF) — Dockerfile/Minio/OpenApi; not /airag/chat/send.
- **bc-java x2** (FIPS zeroisation / entropy retry) — ISAAC/HQC/HAETAE/XMSS/TLS; not FIPS finalize or native entropy.
- **growi** (ReDoS) — AiAssistant UI + CodeQL autofixes + one-liners; no new regex.
- **fluidsynth** (null deref) — DLS/seq_queue/portamento/CI; not fluid_synth_monopoly.c.
- **NixOS/nix x2** (prefetch traversal / NAR recursion) — libstore refactors; not fetcher/unpack or NAR parser.
- **SIPp/sipp** (arg overflow) — message.cpp + recv-timeout CSV substitution; not sipp.cpp command-line args.
- **mattermost-plugin-google-drive** (channel authz) — plugin.json/linter/telemetry/deferClose; no membership-validation change.
- **eclipse-openvsx/openvsx** (unpkg CSP) — webui dep bumps + XXE fix; not unpkg headers.
- **openwrt/luci x6** (XSS/path traversal/ACL) — dhcp/wireless/String.format/ocserv; none of the six named apps.

## Gate totals

identity PASS 25; ai_hunk FAIL 25; topology UNKNOWN 25; but_for FAIL 25;
fix_reversal UNKNOWN 25; release UNKNOWN 25; uniqueness PASS 25.

No acceptance replay is required: there are zero PASS proposals.
