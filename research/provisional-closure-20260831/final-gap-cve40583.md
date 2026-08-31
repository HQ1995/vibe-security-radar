# CVE-2026-40583 final gap review

Audit date: 2026-08-30 (America/New_York)  
Class: `alias-ff3fa870e1a23f5c964f7fb2`  
Repository: `UltraDAGcom/core`  
Protocol: [`docs/AUDIT-PROTOCOL.md`](../../docs/AUDIT-PROTOCOL.md)  
Primary local clone: `.ai-slop/state/legacy87/clones/UltraDAGcom_core`

## Disposition

**HOLD / `BLOCKED`, not `NOT_AI` and not `FALSE_POSITIVE`.** The source-level causal chain closes: AI-marked `361e71d4329b672482531122117631ec5358953a` is the atomic first writer of the disclosed mutation-before-authorization path, its immediate parent lacks that path, and `45bcf7064741897319b6196d3d9f9e1307093511` is the minimum direct reversal. Publication does not close because every recovered public tag predates the BIC. The official record's affected `= 0.1` assertion therefore has no Git-containment witness and conflicts with the only `v0.1.0` tag in the complete local history.

The correct ledger action is to preserve the causal evidence but move the row out of the publishable AI set until an immutable vulnerable release artifact is recovered. The draft below clears `site_scope`, `site_tier`, `vulnerable_release`, and `fixed_release`; it does not retain or invent `published_at`, `publication_status`, `publication_issues`, or `advisory_url` fields.

## Advisory mechanism and identity

The current [CVE JSON record](https://cveawg.mitre.org/api/cve/CVE-2026-40583) is `PUBLISHED`, names source advisory `GHSA-q8wx-2crx-c7pp`, and describes an unauthorized, signed `SmartOp::Vote` that passes signature/nonce/balance prechecks but is rejected only after fee and nonce mutation. The finalized error path then increments the nonce again; the resulting state/supply-accounting mismatch can halt the node. The CVE references both `45bcf706…` and `2f5a3a23…` and claims affected product version `= 0.1`.

The old `UltraDAGcom/core` repository API and repository-advisory URL currently return `404`, but the same Git objects are reachable in the current [`sumitshahorg/core`](https://github.com/sumitshahorg/core) repository (GitHub repository ID `1207252079`; current `main` is `4ee795be9b7f3f41f0dc04d1608207c63c57671a`). The current repository releases API returns an empty list. Namespace movement or loss of the advisory page does not withdraw the still-published CVE and is not grounds for `FALSE_POSITIVE`. The canonical `repo` field remains the advisory-time identity `ultradagcom/core`; current object URLs should use `sumitshahorg/core`.

## BIC and immediate-parent boundary

- BIC: `361e71d4329b672482531122117631ec5358953a`
- Immediate parent: `8fc13090d657934b74bcdc6f770433f60cb81130`
- Shape: one parent; author and committer `Johan <johan@struijk.it>`; 2026-03-27.
- AI marker on the BIC itself: `Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`.
- `git log --all -S 'pub fn apply_smart_op_tx' -- crates/ultradag-coin/src/state/engine.rs` returns only the BIC. The immediate parent contains no `apply_smart_op_tx`.
- The BIC adds the complete causal order: outer finalized handling calls `apply_smart_op_tx` and increments nonce again on error; inside the new function, `self.debit(&tx.from, tx.fee)` and `self.increment_nonce(&tx.from)` occur before `is_council_member` in the `Vote` and `CreateProposal` branches.
- Blame at the parent of the direct fix attributes the surviving fee debit, nonce increment, and later council checks to `361e71d…`. No finer surviving public member is available, and the commit is not a merge/squash aggregate requiring decomposition.

This satisfies the atomic first-writer, parent-absence, BIC-local AI, and but-for requirements. The fix author's AI marker is irrelevant to root attribution.

## Minimum direct fix

`45bcf7064741897319b6196d3d9f9e1307093511` is the minimum direct reversal for the disclosed governance path. Its diff:

- moves `Vote`/`CreateProposal` council authorization ahead of fee debit and nonce mutation;
- removes the outer error-path second nonce increment; and
- adds regression coverage for authorization-before-mutation behavior.

`2f5a3a237ea519b48d71e6e3093c89f60694c7be` is later, broader defense-in-depth. Its own message calls `45bcf706…` the prior Vote/CreateProposal fix and extends the validate/mutate/apply split across more than fifteen other SmartOp types. It is not the minimum fix for the CVE-scoped path and must not replace `45bcf706…` in `minimum_fix_set`.

Ancestry is valid in both directions: `361e71d…` is an ancestor of `45bcf706…`, and `45bcf706…` is an ancestor of `2f5a3a23…`. Intervening unrelated commits do not become carriers; `carrier_set=[]` is correct.

## Release contradiction

The local clone is non-shallow, has 781 reachable commits, has no missing reachable object, and passes `git fsck --full --no-reflogs`. Its recovered public tags are:

| tag | peeled commit | relation to BIC |
|---|---|---|
| `v0.1.0` | `3b0589a20bc3afebed861f664ceb6167a6785770` | 513 commits before `361e71d…` |
| `latest` | `a82ffe846349f2d6f9d36f4518cf63847e854bdf` | 402 commits before `361e71d…` |

`git tag --contains` returns nothing for the BIC, direct fix, or later hardening. Thus neither a vulnerable witness containing `361e71d…` without `45bcf706…` nor a fixed witness containing the direct fix exists among recovered public tags. `vulnerable_release.version=0.1.0` is false as a containment claim and must be cleared; `fixed_release` remains null.

One nuance prevents a stronger claim that no public binary ever existed: at the BIC, `.github/workflows/build-and-publish.yml` built each `main` push and overwrote a prerelease named `latest`, recording `${{ github.sha }}` in the body. Historical workflow runs and mutable prerelease assets are no longer recoverable from the current repository, so there is no immutable artifact-to-SHA witness. This does not rescue the false `v0.1.0` witness; it defines the exact remaining gap.

Required closure evidence is an immutable public release artifact that contains `361e71d…` but not `45bcf706…`. A mutable default branch or the CVE's bare version string is insufficient.

## Seven evidence gates

| gate | result | evidence |
|---|---|---|
| identity | `PASS` | Published CVE and source advisory identity describe the exact SmartOp Vote mutation/order path and cite both relevant fixes. |
| ai_hunk | `PASS` | The BIC itself carries the Claude Opus 4.6 co-author trailer and adds the vulnerable lines. |
| topology | `PASS` | One-parent atomic first writer; parent lacks the function; full-history `-S` search yields no earlier writer or finer public member. |
| but_for | `PASS` | Parent has no reachable SmartOp application path; BIC adds both early mutation and later authorization rejection. |
| fix_reversal | `PASS` | `45bcf706…` moves authorization before mutation and removes the second nonce increment. |
| release | `FAIL` | All recovered tags predate the BIC; the claimed `= 0.1` release is contradicted by the actual `v0.1.0` tag. Historical mutable `latest` assets are unavailable and cannot substitute for containment evidence. |
| uniqueness | `PASS` | The full BIC SHA occurs in only this class in the current canonical ledger export; `2f5a3a23…` is follow-up hardening under the same advisory, not another origin case. |

An independent clean review reproduced the same seven-gate vector, BIC/parent boundary, `45bcf706…` minimum fix, `2f5a3a23…` follow-up classification, and `HOLD` disposition. It also identified the current repository namespace and the historical mutable-`latest` nuance incorporated above.

## Complete Neon patch draft — do not apply

This is one physical JSONL line with the live `expected_revision=1`, the complete current row plus the corrections above, and `assessment_ids=[]`.

```json
{"expected_revision":1,"row":{"advisories":2,"advisory_ids":["CVE-2026-40583","GHSA-Q8WX-2CRX-C7PP"],"advisory_ids_source":"CVE_AWG_FORMAL_ALIAS_20260830","class_id":"alias-ff3fa870e1a23f5c964f7fb2","dossier_best":null,"ledger_best":"BLOCKED","legacy87":{"adjudication_note":"Claude Opus 4.6 co-authored commit 361e71d creating SmartOp execution logic where fee debit and nonce increment occurred before validating operation authorization (such as council membership for votes). When unauthorized votes failed, state was already mutated, triggering supply invariant panics. Fixes 45bcf706 and 2f5a3a23 restructured apply_smart_op_tx into a three-phase validate-before-mutate pattern.","ai_role":"","bug_semantics":"UltraDAG SmartOp processing debited transaction fees and incremented nonces before checking operation-specific preconditions (e.g. council membership for governance Vote/CreateProposal), causing state mutation on failed operations, burning fees into nowhere, and halting nodes on supply invariant mismatch. Sink: crates/ultradag-coin/src/state/engine.rs:3920-3940.","case_id":"CVE-2026-40583","flaw_origin":"Commit 361e71d4329b672482531122117631ec5358953a (Johan + Claude Opus 4.6, 2026-03-27, Co-Authored-By: Claude Opus 4.6) added the initial SmartOp implementation in apply_smart_op_tx with debit-then-validate ordering."},"repo":"ultradagcom/core","round6_research":{},"site_scope":null,"site_tier":null,"squash_audit":[{"ai_marker":"commit Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>author Johansubject (#NNNN)SmartOp + squash","bug_semantics":" supply invariant haltCVE-2026-40583/GHSA-q8wx-2crx-c7ppapply_smart_op_tx tx.fee>0 self.debit + increment_nonce match Vote/CreateProposal is_council_member—— council nonce/ SmartOp::Vote fee nonce apply + supply exit 101fix 45bcf7062026-04-12 Vote/CreateProposal council fee/nonce nonce fix 2f5a3a23 15+ SmartOp validate-before-mutate ","case_id":"CVE-2026-40583","class_id":"alias-ff3fa870e1a23f5c964f7fb2","decomposed_shas":[],"evidence":"osv CVE-2026-40583 (GHSA-q8wx-2crx-c7pp): non-council attacker submits signed SmartOp::Vote passing signature/nonce/balance prechecks but failing authorization only after state mutation; 361e71d4 diff adds apply_smart_op_tx with fee debit + increment_nonce executed before the match-branch is_council_member checks for Vote/CreateProposal (engine.rs +64); fix 45bcf706 (2026-04-12) moves council checks before fee/nonce mutation and removes double nonce increment, explicitly citing 'fee burned without operation success', 'nonce incremented twice', 'supply accounting mismatch triggering fatal node halt (exit code 101)'; fix 2f5a3a23 (same day) restructures ALL SmartOp types into validate/mutate/apply phases and refers to 'Qwen's prior fix'; 361e71d4 is a new-function introduction (no pre-existing apply_smart_op_tx), no (#N), single theme","flaw_origin":" = crates/ultradag-coin/src/state/engine.rs apply_smart_op_txfee debit + increment_nonce Vote/CreateProposal is_council_member 361e71d42026-03-27, Johan + Claude Opus 4.6 co-authordiff 45bcf706 2f5a3a23 AIQwen ","introducer_sha":"361e71d4329b672482531122117631ec5358953a","reasoning":"advisory 361e71d4 apply_smart_op_txClaude Opus 4.6 commit shard 45bcf706/2f5a3a23 AI => CONFIRMAI_ROOT_CAUSE","repo":"ultradagcom/core","squash_decomposed":false,"verdict":"AI_ROOT_CAUSE"}],"squash_audit_verdict":"CONFIRM","squash_decomposed":false,"status":"BLOCKED","candidate_set":["361e71d4329b672482531122117631ec5358953a"],"carrier_set":[],"minimum_fix_set":["45bcf7064741897319b6196d3d9f9e1307093511"],"gates":{"identity":"PASS","ai_hunk":"PASS","topology":"PASS","but_for":"PASS","fix_reversal":"PASS","release":"FAIL","uniqueness":"PASS"},"gates_source":"research/provisional-closure-20260831/final-gap-cve40583.md","scope_statement":"Attribution is limited to the SmartOp Vote/CreateProposal path where fee and nonce mutation preceded council authorization; 2f5a3a237ea519b48d71e6e3093c89f60694c7be is broader follow-up hardening, not the minimum direct fix.","vulnerable_release":null,"fixed_release":null,"unresolved_reason":"The CVE claims affected version 0.1, but annotated v0.1.0 peels to 3b0589a20bc3afebed861f664ceb6167a6785770, 513 commits before the BIC; tag latest is 402 commits before it. No immutable public tag or artifact proves containment of 361e71d4329b672482531122117631ec5358953a without 45bcf7064741897319b6196d3d9f9e1307093511; historical mutable latest prerelease assets and their build SHAs are unavailable.","causal_research":{"advisory_ids":["CVE-2026-40583","GHSA-Q8WX-2CRX-C7PP"],"ai_marker":"The BIC commit message carries Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>.","bug_semantics":"A signed SmartOp::Vote from a non-council account passed signature, nonce, and balance prechecks; apply_smart_op_tx then debited its fee and incremented its nonce before council authorization returned an error, while finalized error handling incremented the nonce again, creating a supply-accounting mismatch and fatal node halt.","case_id":"CVE-2026-40583","class_id":"alias-ff3fa870e1a23f5c964f7fb2","decomposed_shas":[],"direct_fix_sha":"45bcf7064741897319b6196d3d9f9e1307093511","evidence":["The current PUBLISHED CVE record maps CVE-2026-40583 to GHSA-q8wx-2crx-c7pp, describes the unauthorized SmartOp::Vote mutation order, and claims affected version = 0.1.","Local full-history clone .ai-slop/state/legacy87/clones/UltraDAGcom_core is non-shallow, has 781 reachable commits, no missing reachable objects, and a clean git fsck.","The same commit objects are currently reachable under sumitshahorg/core (GitHub repository ID 1207252079), whose releases API is empty; the old UltraDAGcom/core namespace and advisory URL return 404.","Single-parent 361e71d4329b672482531122117631ec5358953a first adds apply_smart_op_tx; parent 8fc13090d657934b74bcdc6f770433f60cb81130 has no SmartOp application function. The added code debits fee and increments nonce before the Vote/CreateProposal council check and adds an outer error-path nonce increment.","Commit 45bcf7064741897319b6196d3d9f9e1307093511 moves Vote/CreateProposal council checks before mutation and removes the outer second nonce increment, directly reversing the disclosed path.","Commit 2f5a3a237ea519b48d71e6e3093c89f60694c7be explicitly describes 45bcf706 as the prior Vote/CreateProposal fix and broadens validate-before-mutate to all SmartOp types.","Annotated tag v0.1.0 peels to 3b0589a20bc3afebed861f664ceb6167a6785770 and tag latest to a82ffe846349f2d6f9d36f4518cf63847e854bdf; both precede the BIC, and no tag contains the BIC or either fix."],"fix_sha":"45bcf7064741897319b6196d3d9f9e1307093511","flaw_origin":"Single-parent commit 361e71d4329b672482531122117631ec5358953a first added apply_smart_op_tx and the exact mutation-before-authorization order; immediate parent 8fc13090d657934b74bcdc6f770433f60cb81130 lacks SmartOp application.","introducer_parent":"8fc13090d657934b74bcdc6f770433f60cb81130","introducer_parent_absent":true,"introducer_sha":"361e71d4329b672482531122117631ec5358953a","reasoning":"The advisory mechanism, atomic BIC, immediate-parent absence, BIC-local AI marker, and minimum direct reversal all close. Strict released-case admission does not: every recovered public tag predates the BIC, so the claimed affected release is contradicted. HOLD is therefore required; NOT_AI and FALSE_POSITIVE would both misstate the verified evidence.","remaining_gap":"Recover an immutable public artifact tied to a specific Git SHA that contains 361e71d4329b672482531122117631ec5358953a but not 45bcf7064741897319b6196d3d9f9e1307093511. Current tags actively contradict version 0.1; historical mutable latest prerelease assets and workflow runs are unavailable.","repo":"ultradagcom/core","squash_decomposed":false,"verdict":"BLOCKED"}},"assessment_ids":[]}
```

No Neon, ledger export, publisher, site artifact, or Git commit was modified by this review.
