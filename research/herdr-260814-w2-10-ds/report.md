# Wave-2 7-gate adjudication - unr-adj2-slice-10 (verdict-first)

## Verdict: 0 countable / 24 FALSE_POSITIVE / 1 CONFIRM-proposal (not countable)

Every candidate commit diff was fetched via git smart-HTTP into
`/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>` and read (no GitHub
API, no blame/SZZ). 24 of 25 rows are false positives: the AI-marked candidates
are in modules unrelated to the mechanism named by the advisory, so no AI commit
introduces that mechanism. One row - `GHSA-G77C-P776-CWHW` (Intina47/context-sync,
CVE-2026-7062) - is a genuine AI-origin candidate: the AI-authored root commit
creates the vulnerable file. It is reported as a CONFIRM **proposal**, but
`fix_reversal_gate` and `release_gate` stay UNKNOWN because the unreviewed
first-party object has an empty `affected[]` and names no fix commit. No row
closes all seven gates, so nothing is forwarded for leader replay as countable.

## Method note (divergence from the prior adj* lanes)

The sibling `herdr-260814-adj1-ds` run concluded "mechanism not named" by reading
only `summary`/`description` of the unreviewed advisories. Those fields are empty,
but the mechanism is named in the `details` field of every one of these
unreviewed objects (e.g. "OS command injection in src/git-integration.ts",
"udev ... local root execution"). This run uses `details` as the authoritative
mechanism text, so `identity_gate` is evaluated on its merits (PASS: repository +
mechanism + public identity are named) rather than blanket UNKNOWN.

## Gate convention

- `identity_gate` PASS: first-party `details` names repository, mechanism, identity.
- `ai_hunk_gate` FAIL (24 rows): read every candidate diff; none authors the
  vulnerable hunk/file.
- `ai_hunk_gate` PASS (1 row): AI-authored commit creates the vulnerable file.
- `topology_gate` PASS: candidates are independent atomic commits; no
  carrier/squash/import authorship transfer.
- `but_for_gate` FAIL (24): removing the candidate does not eliminate the
  mechanism. PASS (1): removing the AI-authored file removes the sink.
- `fix_reversal_gate` UNKNOWN (all): no minimum fix commit named in the
  unreviewed object (`affected[]` empty).
- `release_gate` UNKNOWN (all): no vulnerable/fixed artifact containment
  evidence in the first-party object.
- `uniqueness_gate` PASS (all): no case is already counted in
  `orchestrator-260814-ghsa200-canonical84/ledger.jsonl` or `foundation.jsonl`.

## The one candidate worth leader attention

**GHSA-G77C-P776-CWHW / CVE-2026-7062 (Intina47/context-sync).**
Root commit `918fdc2d00fed90413f40efb68a13cdc24ed27c6` ("Add Docker MCP
integration with Dockerfile, mcp.json, and comprehensive documentation"),
authored by `copilot-swe-agent[bot]`, is a root commit that adds
`src/git-integration.ts` as a new 385-line file. Its `getDiff()` and
`isTracked()` methods interpolate an unescaped `filepath` into
`execSync("git ... -- \"${filepath}\" ...")` - the exact OS command-injection
surface named by the advisory. Removing the commit removes the file, so
`identity_gate`, `ai_hunk_gate`, `topology_gate`, `but_for_gate` and
`uniqueness_gate` all PASS. The two blocking gates are `fix_reversal_gate` and
`release_gate`: the advisory's `affected[]` is empty and its references point
only to NVD, issue #31, a public-exploit mirror, and VulDB - no fix commit or
fixed version is named, so the reversal and release-containment legs cannot be
closed from first-party evidence. Treat this as a strong lead, not a closed case:
the leader should locate the post-v2.0.0 fix of `git-integration.ts` before this
could ever be countable.

## Per-row reasoning (24 FALSE_POSITIVE)

- **GHSA-7P49-G593-X646** (halo-dev/halo) - comment-submission DoS. Candidates
  are setup/UI commits (system-protection finalizer, upvotes widget, color
  input, tag color); none touch the comment endpoint. no_ai_origin.
- **GHSA-396H-M3PM-FPM5 / 52RM-R39V-FWV9 / HC7R-6254-88W5 / JF3X-2PF6-C45W /
  X53V-PXF5-CHX6 / H639-9H3V-CF49** (systemd/systemd) - udev, Delegate=yes
  assert, nspawn escape, machined varlink, IPC null-element assert, tmpfiles
  symlink. Candidates are networkd/resolved/nspawn/test commits; the nspawn
  candidate `af5126568af6` is a bind-mount fix for boot_id/kmsg, not the
  "crafted optional config file" escape. no_ai_origin.
- **GHSA-HC32-C5XW-9F2M / W2PQ-XVQR-7FQW** (frappe/erpnext) - POS XSS. Candidates
  are Italy-regional field renames, VAT rates, pandas->pure-Python; none touch
  the POS cart. no_ai_origin.
- **GHSA-3W7G-Q5X7-JG2R / 853R-VXG2-55R2 / 8CJF-MHHJ-2C5P / 5J5V-R5QF-P5C4**
  (apache/zeppelin) - CSRF/CORS, LDAP injection (LdapRealm, incomplete fix of
  CVE-2024-31867), LDAP injection (ActiveDirectoryGroupRealm), path traversal
  (FileSystemNotebookRepo). Candidates are ZEPPELIN-6400 interpreter refactors,
  FlexmarkParser, timeout parsing, a Selenium test, and web/TS config; none touch
  CORS, LdapRealm, ActiveDirectoryGroupRealm, or FileSystemNotebookRepo.
  no_ai_origin.
- **GHSA-GRVF-XRW5-JXHC** (thiagoralves/OpenPLC_v3) - authenticated RCE via
  hardware-config upload (CVE-2021-47770). Candidates are Simulink-layer fix,
  runtime-version header, FILE: line extraction, HTTPS/SSL/blocking-mode changes;
  all fixes/features, none introduces the hardware-layer upload sink. no_ai_origin.
- **GHSA-XXV9-73GC-96FM** (ModelTC/LightLLM) - pickle.loads RCE in PD
  disaggregation. Candidates are chat-template and shared-memory/shm_utils
  commits; none touch the PD WebSocket pickle path. no_ai_origin.
- **GHSA-CH4H-8W5C-3G8G** (timeplus-io/proton) - OOB write in vendored
  `base/poco/Foundation/src inflate.C`. Candidates are rand-distribution, NATS,
  watermark, Pulsar-upgrade, streaming-CTE commits; none touch vendored Poco.
  no_ai_origin.
- **GHSA-3XV9-7R7G-8Q6F / X2X5-GJ4J-P6QW** (radareorg/radare2) - PDB-parser
  command injection, project-deletion path traversal. Candidates are a
  1-line `anal_tp.c` edit and `wasi-browser.sh` CI commits; none touch the PDB
  parser or project deletion. no_ai_origin.
- **GHSA-93WG-JRMM-CX46 / WWCX-37RF-X4FR / QVHX-Q8VJ-H6R5** (Dolibarr/dolibarr) -
  RCE via commonobject/actions_addupdatedelete/cronjob. Candidates are
  addtimespent PHP8 fix, email-template reload, bank-journal, Email-Collector
  commits; none touch the three RCE files. no_ai_origin.
- **GHSA-9QQM-G68P-FHHP** (VoltAgent/voltagent) - improper authorization in
  `handleGetMemoryConversation` (memory.handlers.ts). Candidates are scrollbar
  CSS, AG-UI events, tool-call adapter, NestJS example, workflow examples,
  upstream merge; none touch memory.handlers.ts. no_ai_origin.
- **GHSA-Q796-5G5H-CQCC / 3J25-MJX3-PWG4** (HKUDS/Vibe-Trading) - DNS-rebinding
  auth bypass, memory_type path traversal. Candidates are docker/loopback,
  advisory-registry/exception-sanitization, Ollama URL normalization, GHCR
  workflow, SSE timeout, swarm-payload sanitization, and `_tokenize` fixes.
  These are hardening/fixes; none introduces the auth bypass or the
  memory_type path-write traversal. no_ai_origin.

## Evidence

- Slice: `autoresearch/orchestrator-260814-ghsa200-canvas/sweep/unr-adj2-slice-10.jsonl`
  (sha256 `ae3f40a5...`).
- Contract: `autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md`
  (sha256 `cbd04ef2...`).
- Advisory objects: `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/unreviewed/...`
  (21 rows) plus `origin/main` of the same repo for the four late-July Zeppelin
  advisories (fetched via git smart-HTTP, not GitHub API).
- Candidate diffs: `/home/hanqing/.cache/ghsa200-sweep-fetch/<owner>__<repo>`
  (73 unique SHAs fetched blobless; every diff read).
