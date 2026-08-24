# herdr-260814-w4-6-ds - slice 6 (unr-adj4) adjudication

**Verdict first: 25/25 FALSE_POSITIVE, 0 countable.** For every row the candidate
AI commits do not author the vulnerable hunk of the named mechanism; they are
unrelated fixes/refactors (one row is cross-bound to Cockpit CMS). `ai_hunk_gate`
and `but_for_gate` FAIL, so no row closes the seven gates.

## Result

- assigned 25, reviewed 25, FALSE_POSITIVE 25, CONFIRM 0, NARROW 0, UNKNOWN 0
- terminal=true on all rows; zero proposed acceptances

## Per-repository evidence

- **fosrl/pangolin** (token reuse authz): candidates are CrowdSec install-token
  display and validators.ts domain-label/regex edits; none touch authz middleware.
- **pimcore/admin-ui-classic-bundle** (grid id-filter SQLi): candidates are 2FA
  reset authz, version-management authz, and ElementController permission-aware
  pagination/dependency scans; none touches the id-column-filter SQL WHERE.
- **cockpit-project/cockpit** (2 rows): logs-UI command injection candidates are
  pam-ssh-add exit-status, tls port byte-order, and an overview-cards TSX port -
  unrelated. The second row (CVE-2026-58467) names **Cockpit CMS** (a PHP CMS,
  Cockpit-HQ/Cockpit), a different repository -> cross-bound.
- **simdjson/simdjson** (escape_and_append int overflow): candidates replace the
  integer writer (write_uint_jeaiii), fix GCC-16 reflection warnings, and edit a
  benchmark writeup; none modifies `string_builder::escape_and_append()`.
- **ggml-org/llama.cpp** (3 rows, json-schema-to-grammar + jinja parser):
  candidates are ggml CUDA/metal fused-GDN ops; none touches
  common/json-schema-to-grammar.cpp or common/jinja/parser.cpp.
- **awslabs/mcp** (DocumentDB read-only bypass): candidate edits the
  bedrock-kb-retrieval server, a different MCP server.
- **CERTCC/cveClient** (2 rows, API-key protection + cveInterface.js XSS):
  candidate updates CI actions; neither mechanism area touched.
- **RT-Thread/rt-thread** (4 rows, CAN handler + lwp_syscall): candidates are a
  FinSH shell prompt fix (no AI marker) and a gd32 UART driver; none touches the
  SWM341/ls1c CAN handlers or lwp_syscall.c.
- **pglombardo/PasswordPusher** (access-endpoint brute force): candidates are
  Permissions-Policy headers, email docs/copy, log filtering, and a FORCE_SSL
  rewrite; none adds the missing rate-limit.
- **OpenNMS/opennms** (2 rows, Measurements JEXL + v2 Alarm REST authz):
  candidates are a Primevue UI migration, rest docs, and NodeRestService/search
  filters; neither Measurements nor Alarm REST touched.
- **apconw/Aix-DB** (missing auth on /llm/process_llm_out): candidates are all
  CLI tooling (aix-db-cli), not the server endpoint auth.
- **OpenCTI-Platform/opencti** (2 rows, 2020-era /graphql XSS + static/css
  traversal): candidates are backend jsonMapper/upsert/campaign-resolver
  changes; neither pre-existing surface touched.
- **hickory-dns/hickory-dns** (cross-zone cache poisoning): candidates are
  connection-timeout, prometheus gzip, and TTL-clamping changes in cache.rs;
  none changes the cache zone-keying/query-association.
- **makeplane/plane** (intake description_html XSS): candidates are favicon SSRF
  fix, member-role privilege fix, and issue webhook dispatch; intake untouched.
- **pinpoint-apm/pinpoint** (2 rows, session cookie flags + webhook SSRF):
  candidates are controller validation, a React agent-list hook, and a CLAUDE.md
  config; neither session-cookie nor webhook-registration path touched.

## Gate summary

identity_gate=PASS (first-party unreviewed advisory names mechanism + CVE);
ai_hunk_gate=FAIL (AI-marked commits do not author the vulnerable hunk);
topology_gate=FAIL; but_for_gate=FAIL; fix_reversal_gate=FAIL;
release_gate=FAIL; uniqueness_gate=PASS.

## Disagreements with stored labels

Upstream triage marked these KEEP on commit-subject overlap. Deep adjudication
of the actual diffs overturns every KEEP: overlaps are superficial and no
candidate introduces the named mechanism.
