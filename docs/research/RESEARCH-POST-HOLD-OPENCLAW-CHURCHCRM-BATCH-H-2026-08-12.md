# Post-hold Batch H: OpenClaw / ChurchCRM causal closure

Audit date: 2026-08-12 (America/New_York)

## Answer

This bounded 24-row frontier adds **no countable component**:

| Repository | Rows | PASS | REJECT | UNKNOWN |
|---|---:|---:|---:|---:|
| OpenClaw | 17 | 0 | 16 | 1 |
| ChurchCRM | 7 | 0 | 7 | 0 |
| Total | 24 | **0** | **23** | **1** |

The sole `UNKNOWN` is OpenClaw QQBot media upload (`GHSA-fwgr-fpv9-vf5x`). Its regression and release containment are real, but the exact vulnerable PR member has no AI marker; the Cursor trailers belong to other members of the squash. It therefore cannot be promoted from PR-routing evidence to AI causality.

These rows are non-counting route controls. They do not raise the canonical `199` broad released source envelope and do not make the ledger integration-ready.

## Admission rule

A row can enter the component ledger only if all four conditions close:

1. the first-party advisory identity and mechanism are exact;
2. removing the candidate removes or materially narrows that advisory mechanism;
3. AI provenance attaches to the causal hunk or an indivisible causal unit, not merely to a squash sibling, formatter, later fix, or unrelated file;
4. for a released row, the candidate is contained in a vulnerable release and the closure is absent there but present in the fixed release.

An AI-authored remediation is not an origin. An incomplete remediation can count, but only when that remediation is itself AI-attributed and the later advisory closes its residual.

## OpenClaw row decisions

All advisory links below are the repository's first-party advisories. The local evidence repository is `/home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw`.

| Row | Decision | Public identity | Audited edge or anchor | Minimum causal finding |
|---|---|---|---|---|
| H01 | UNKNOWN | [GHSA-fwgr-fpv9-vf5x](https://github.com/openclaw/openclaw/security/advisories/GHSA-fwgr-fpv9-vf5x) | `5e72e39c1852` -> `b860a0d4d0d9` | `5e72e39c` removes the earlier AI SSRF guard and ships in `v2026.4.22`; `b860a0d4` is absent there and present in `v2026.5.28`. But the exact PR member `ce2f0b2a2e1c` has no AI marker. The only `Made-with: Cursor` members, `96484107cf10` and `7bc86ec66ab3`, concern TTS/shared utilities, not the media URL path. |
| H02 | REJECT | [GHSA-p5xh-frrh-cmgj](https://github.com/openclaw/openclaw/security/advisories/GHSA-p5xh-frrh-cmgj) | `f71ee71787c7` -> `d2ddc26e89bf` | The vulnerable MS Teams group actions originate in `f71ee717`; that atomic commit has no first-party AI marker. Earlier AI work concerns different action paths. |
| H03 | REJECT | [GHSA-52xj-c9p8-78cv](https://github.com/openclaw/openclaw/security/advisories/GHSA-52xj-c9p8-78cv) | `02182d5a3031` -> `b6a3f2988c66` | The non-owner MCP regression is the human `02182d5a` refactor. Existing loopback infrastructure predates it; no causal AI hunk was found. |
| H04 | REJECT | [GHSA-mgvr-6gvw-3rgr](https://github.com/openclaw/openclaw/security/advisories/GHSA-mgvr-6gvw-3rgr) | `ba06376c7955` -> `21410d1c3247` | `ba06376c` creates the sandbox exec-server HTTP relay and has no AI marker. The later guard is a remediation, not evidence that AI created the sink. |
| H05 | REJECT | [GHSA-f6p7-6326-vf7v](https://github.com/openclaw/openclaw/security/advisories/GHSA-f6p7-6326-vf7v) | `264906454800` -> `300794520b96` | `26490645` is a partial requester check and `30079452` closes cross-provider moderation. Neither causal unit carries a first-party AI marker. |
| H06 | REJECT | [GHSA-cf2p-f286-mphf](https://github.com/openclaw/openclaw/security/advisories/GHSA-cf2p-f286-mphf) | `29cb1e3c7edd` -> `2a21de632239` | The HTTP owner-tool policy lineage is human-authored. The final owner gate cannot be reclassified as an AI origin. |
| H07 | REJECT | [GHSA-wgq8-x5wm-g4rw](https://github.com/openclaw/openclaw/security/advisories/GHSA-wgq8-x5wm-g4rw) | `154f439c8103` -> `8b0eac7927d5` | The operator install-policy hardening leaves wrapper coverage incomplete, but `154f439c` has no AI marker. This is a real residual with no AI attribution. |
| H08 | REJECT | [GHSA-fh38-965w-f6c3](https://github.com/openclaw/openclaw/security/advisories/GHSA-fh38-965w-f6c3) | false candidate `b7e0decf0cd3` | The `[AI]` commit changes shared sender matching and iMessage handling; it does not create or modify the WhatsApp `ctx.From` group-ID authorization path. |
| H09 | REJECT | [GHSA-v4f6-x5g5-2g4g](https://github.com/openclaw/openclaw/security/advisories/GHSA-v4f6-x5g5-2g4g) | closure `f0d8048aa3b4` | Native web-search policy enforcement fixes an older feature. No AI-attributed origin or incomplete-remediation candidate was found for the affected native-search path. |
| H10 | REJECT | [GHSA-v7hx-r36p-f68m](https://github.com/openclaw/openclaw/security/advisories/GHSA-v7hx-r36p-f68m) | closure `9dbe25e0f68d` | Requester authorization infrastructure and mutation paths predate the fix; no same-mechanism AI causal hunk was found. |
| H11 | REJECT | [GHSA-3pmr-x9g8-m55r](https://github.com/openclaw/openclaw/security/advisories/GHSA-3pmr-x9g8-m55r) | `264906454800` -> `300794520b96` | Same non-AI Discord remediation lineage as H05, but a distinct guild-action advisory. It remains a non-counting control, not a second AI component. |
| H12 | REJECT | [GHSA-wxm8-ghhq-q688](https://github.com/openclaw/openclaw/security/advisories/GHSA-wxm8-ghhq-q688) | `26644c4b897c` -> `9497629c1e89` | `26644c4b` genuinely adds an incomplete DNS/redirect SSRF defense and `9497629c` adds dispatcher pinning. The incomplete remediation has no AI marker, so the mechanism cannot enter the AI census. |
| H13 | REJECT | [GHSA-3x84-qq85-fj65](https://github.com/openclaw/openclaw/security/advisories/GHSA-3x84-qq85-fj65) | false candidate `0314d67d87fa`; closure `ade5ac03506e` | The `[AI]` commit normalizes trailing dots. It does not add CDP WebSocket discovery or the missing discovered-URL policy check. |
| H14 | REJECT | [GHSA-jhfx-v2j8-x3m6](https://github.com/openclaw/openclaw/security/advisories/GHSA-jhfx-v2j8-x3m6) | `eaad4ad1be38` / `d10669629d73` -> `26b97369226e` | The HTTP model-override inputs originate in non-AI commits. The admin gate is a later fix. |
| H15 | REJECT | [GHSA-m38g-vpwj-mpg9](https://github.com/openclaw/openclaw/security/advisories/GHSA-m38g-vpwj-mpg9) | `d8b927ee6a9f` / `ae7f18e5033d` -> `ee81082f57e2` / `c6f5725906dc` | The vulnerable OpenShell mirror/symlink operations originate in non-AI commits; later closure does not change that attribution. |
| H16 | REJECT | [GHSA-v54h-q2vx-vgg4](https://github.com/openclaw/openclaw/security/advisories/GHSA-v54h-q2vx-vgg4) | origin family `d9f9e93deeac`; closure family `97699494492a` / `62550710bfec` / `2c3d7f5badbe` | The token-bearing Teams service URL flow is human-origin; no AI causal hunk closes the attribution gate. |
| H17 | REJECT | [GHSA-prwc-c6w5-mmgr](https://github.com/openclaw/openclaw/security/advisories/GHSA-prwc-c6w5-mmgr) | origin family `dd2faa376492`; same closure family as H16 | This advisory is a related Bot Framework service-URL mechanism, but its origin also lacks an AI marker. It is not counted separately or jointly. |

### QQBot topology detail

The first-party advisory declares `>2026.4.20, <2026.5.28`, fixed in `2026.5.28`. The repository proves:

- `49db424c8001` is an `[AI-assisted]` security fix that adds direct-upload URL validation;
- squash carrier `5e72e39c1852` is contained in `v2026.4.22` and drops that guard in the new engine API;
- atomic member `ce2f0b2a2e1c` performs the vulnerable API simplification;
- `b860a0d4d0d9` is absent from `v2026.4.22` and contained in `v2026.5.28`;
- GitHub PR 67960 has 40 members. Only `96484107cf10` and `7bc86ec66ab3` carry Cursor trailers, and their deltas are unrelated to the vulnerable URL forwarding.

This is exactly the boundary where a squash-level marker is routing evidence but not attribution proof.

## ChurchCRM row decisions

The local evidence repository is `/home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm`.

| Row | Decision | Public identity | Audited edge or anchor | Minimum causal finding |
|---|---|---|---|---|
| H18 | REJECT | [GHSA-frj8-mpcx-44g9](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-frj8-mpcx-44g9) | `d74f5bbc0d77` -> `cdd8de9a0ce8` | The advisory explicitly scopes the vulnerable family-view `href` and says person-view already escapes the link. Family-view blame is `d74f5bbc`, and raw `PeopleCustomField` link construction dates to `f0a07754`; neither is AI-attributed. Copilot `6b82eb3e` adds a person template but does not cause the advisory's family sink. |
| H19 | REJECT | [GHSA-mrr9-jxqx-xv62](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-mrr9-jxqx-xv62) | `3bfacc72495f` -> `50d9b0576b29` | The unsafe first/middle/last-name inputs are human `3bfacc72`. Claude `24549b21` only changes responsive attributes on the already-unsafe suffix line and preserves the vulnerability; this is refactor preservation, not contribution. |
| H20 | REJECT | [GHSA-jx45-q5vj-h2wm](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-jx45-q5vj-h2wm) | `59ea722383e5` -> `10520f164268` | Raw `$_GET['Return']` and its sink predate the 2025-2026 AI history. The automated agent authored the final cast fix only. |
| H21 | REJECT | [GHSA-369j-c5w2-48m4](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-369j-c5w2-48m4) | `73db2e5167b2` -> `33bfcec3424c` | `73db2e51` introduces the unescaped dashboard address. Cursor `38e5d24d` mechanically reformats the same expression without adding a surface or widening input reachability. |
| H22 | REJECT | [GHSA-4qpj-3hw2-52g8](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-4qpj-3hw2-52g8) | `c2d2aef4c10e` -> `f310c2e06a02` | Blame assigns all four vulnerable inline action handlers to human `c2d2aef4`. Claude `6ef78813` changes a different shared action-menu renderer and is non-causal for these admin-user sinks. |
| H23 | REJECT | [GHSA-6rgg-mrx3-92w7](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-6rgg-mrx3-92w7) | `c0228fae92d3` -> `ae2b73550452` | `c0228fae` is a genuine incomplete SQLi remediation: sequential substitution can re-scan an earlier escaped value. It has no first-party AI marker, so it is a useful negative control but not an AI incomplete-remediation row. |
| H24 | REJECT | [GHSA-4wmp-3v34-g7q8](https://github.com/ChurchCRM/CRM/security/advisories/GHSA-4wmp-3v34-g7q8) | `e06f2a258727` -> `00e0b17c901f` | Person property GET/DELETE routes and the group-level `MenuOptions` boundary blame to human `e06f2a25` (2023). Later AI-touched translation/sanitization commits do not add the missing `EditRecords` authorization. |

## Reproducible checks

```zsh
# Exact first-party advisory state and release range
gh api repos/openclaw/openclaw/security-advisories/ghsa-fwgr-fpv9-vf5x \
  --jq '[.state,.withdrawn_at,.vulnerabilities]'
gh api repos/ChurchCRM/CRM/security-advisories/ghsa-frj8-mpcx-44g9 \
  --jq '[.state,.withdrawn_at,.description,.vulnerabilities]'

# QQBot release containment
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  merge-base --is-ancestor 5e72e39c1852a82e8002187b7c9b0c84214e0b08 v2026.4.22
! git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  merge-base --is-ancestor b860a0d4d0d91d07ef4506b1ff03e213b743512e v2026.4.22
git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw \
  merge-base --is-ancestor b860a0d4d0d91d07ef4506b1ff03e213b743512e v2026.5.28

# ChurchCRM exact sink blame examples
git -C /home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm \
  blame -L 790,810 50d9b0576b29^ -- src/FamilyEditor.php
git -C /home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm \
  blame 33bfcec3424c^ -- src/skin/js/MainDashboard.js
git -C /home/hanqing/.cache/cve-analyzer/repos/churchcrm_crm \
  blame f310c2e06a02^ -- src/admin/views/users.php
```

The `gh api` calls read public first-party advisories and do not print credentials.

## Boundary and remaining work

This is a targeted closure of the strongest remaining OpenClaw/ChurchCRM candidates, not an exhaustive re-audit of every advisory in either repository. `REJECT` means the tested route cannot support AI causality under the stated rule; it does not deny that the underlying vulnerability exists. `UNKNOWN` is intentionally retained where exact AI attribution cannot be isolated.

No row in this batch is proposed for the canonical component count. The final-200 claim remains on HOLD pending full-ledger alias, semantic fingerprint, release-containment, and conservation closure with `integration_ready=true`.
