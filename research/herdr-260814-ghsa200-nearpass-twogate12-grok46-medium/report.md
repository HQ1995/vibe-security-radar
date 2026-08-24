# Two-gate 12 near-PASS review

Verdict first: 0 PASS proposals, 11 NARROW, 1 UNKNOWN. Assigned 12, reviewed 12, unreviewed 0. Conservation 12=12+0. start_count=81 (frozen canonical81). current_leader_accepted_count=82 (canonical82 at 6800d212, ledger sha256 58daeb72fdcb8355f311d36a1d784fe445af60ca34d72273a89421b6943e6b23). packet_delta=0. Canonical81 overlap is 0. Canonical82 strict overlap is 0 for all 12 IDs. Publication and greater-than-200 stay HOLD. Worker PASS is a proposal only; this packet emits none and does not admit cases.

Selection was frozen before research in selected-12.jsonl (sha256 c4257548b392033594b015bc505b7ae107f537db9b771f3cb1cdada7ec28328a): remaining fp211 NARROW or UNKNOWN mechanisms with exactly two non-PASS seven-gate values, sorted by ordinal, after excluding public IDs already handled in nearpass-release5, nearpass-hardgate8, contributor-butfor11, fp211-confirm11-closure, and canonical81 strict IDs. Canonical81 remains the frozen start input. Canonical82 is the current leader-accepted count and is not an admission by this packet.

## NARROW / UNKNOWN (uncounted)

| ID | Repo | Unresolved gates | Minimal counterexample |
| --- | --- | --- | --- |
| GHSA-FWPR-59HH-GR98 | DeepMyst/Mysti | identity, release | Unreviewed GHSA, repo 404. Text says upgrade to 0.4.0 while v0.4.0 peels to the AI candidate. No tag contains 6d709229. |
| GHSA-42M6-XH7C-6XM4 | steipete/codexbar | identity, ai_hunk, topology, but_for, fix_reversal | Unreviewed GHSA, repo 404. ProviderHTTPClient.swift is absent at Claude 8348c85c and present at human f62bb8c8. Closer edits that human file. |
| GHSA-2M67-CXXQ-C3H8 | qhkm/zeptoclaw | topology, but_for, fix_reversal, release | Member fe70dcd4 is not a tag ancestor; pdf_read blobs differ. Parent filesystem already has the symlink seam. Git v0.7.5 already contains closer f50c17e1. |
| GHSA-Q9J6-XCVX-PX63 | coollabsio/coolify | but_for, fix_reversal | Parent GetLogs.php already interpolates {$this->container}. Assigned closer is a merge. |
| GHSA-4MPW-WCJ4-V9PP | coollabsio/coolify | ai_hunk UNKNOWN, but_for | Conductor auto-commit has no Claude/Copilot trailer. Backup API is not the mongodump interpolator and is not an explicit AI security attempt. |
| GHSA-GC24-PX2R-5QMF | maziggy/bambuddy | identity, but_for, fix_reversal | Omnibus hardcoded JWT plus many unauthenticated routes. Candidate adds one debug sink. Closers are API-wide auth. |
| GHSA-HFF7-CCV5-52F8 | openclaw/openclaw | but_for, fix_reversal | Parent openai-http.ts already calls authorizeGatewayConnect. Closer scopes Tailscale to websocket product-wide. |
| GHSA-Q447-RJ3R-2CGH | openclaw/openclaw | topology, but_for, fix_reversal | Member is not in tags. GHSA names multiple webhook handlers. Closer edits 20 files. |
| GHSA-C339-W3CQ-2RJR | coollabsio/coolify | but_for | Parent Updates.php already lacks isInstanceAdmin. Candidate only adds an isCloud skip. |
| GHSA-Q6QF-4P5J-R25G | openclaw/openclaw | but_for | Parent and candidate image-tool.ts both lack workspaceOnly. Candidate is a reachability change. |
| GHSA-3636-3MQQ-Q7X9 | MISP/MISP | identity, fix_reversal, release | Unreviewed GHSA, repo 404. Listed patch d3adfe1a is already in v2.5.39. True closer 8aa2bb6d is first in v2.5.40. |
| GHSA-Q5PP-GVJG-H7V4 | microsoft/apm | but_for | Parent already has find_agent_files glob/read_text. Candidate adds a Claude-agents deploy call site. |

## Contract notes

AI carrier or trailer does not transfer authorship onto a human hunk. Old sibling bugs, pure refactors, remediation-only commits, and routing evidence are not causal proof. Incomplete remediation would require an explicit AI-authored security attempt that shipped vulnerable, with the GHSA residual at the same boundary and a later exact reversal. None of these 12 meet that rule. PASS_proposal requires all seven gates PASS. None do. This packet does not admit cases and does not edit the canonical ledger.
