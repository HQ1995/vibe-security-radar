# Round12 six-case deep adjudication

Date: 2026-08-30  
Scope: `w009`, `w030`, `w033`, `w034`, `w035`, `w046`  
Mode: read-only adjudication; no primary, report, or ledger record was changed.

## Outcome

| Case | Primary | Grok proposal | Deep adjudication | Landing action |
|---|---|---|---|---|
| `w009` | `FALSE_POSITIVE` | `AI_ROOT_CAUSE` | **`AI_CODE_FLAWED` / `AI_INCOMPLETE_REMEDIATION`** | Replace the primary verdict and record the advisory as still unpatched. Do not use `2749bc0...` as a direct fix. |
| `w030` | `NOT_AI`, wrong BIC | BIC correction | **`NOT_AI`, correction confirmed** | Replace BIC `f0d6a2f...` with `6ac5687...`; keep direct fix `f22b9dff...`. |
| `w033` | `EVIDENCE_GAP` | `NOT_AI` | **`EVIDENCE_GAP`** | Reject the proposed close until Adobe binds CVE-2025-54263 to AC-15021 or another exact patch. |
| `w034` | `EVIDENCE_GAP` | `EVIDENCE_GAP` | **`EVIDENCE_GAP`** | Keep open; no first-party CVE-to-component/hunk mapping exists in the inspected material. |
| `w035` | `EVIDENCE_GAP` | `EVIDENCE_GAP` | **`EVIDENCE_GAP`** | Keep open; AC-14924 is a strong candidate, not a CVE-bound direct fix. |
| `w046` | `EVIDENCE_GAP` | `NOT_AI` | **`EVIDENCE_GAP` at record level; substantively human-origin** | Reject Grok's single-BIC/single-fix record. Preserve the multi-path matrix until the schema can encode it without loss and remaining carrier history is closed. |

The only class change that is safe to land from these six is `w009: FALSE_POSITIVE -> AI_CODE_FLAWED`. `w030` is a BIC-only correction. The four current gaps remain gaps.

## Method and claim boundary

- Applied `docs/AUDIT-PROTOCOL.md`: vulnerability mechanism first, then smallest public first-write, immediate-parent absence, affected/fixed release reachability, direct remediation, and BIC-local AI attribution.
- Used CVE CNA records, vendor advisories, official repositories, official release tags/notes, and official package artifacts. Secondary summaries were not used to close a case.
- All shell, Git, and network work was bound to NUMA node 1 with `numactl --cpunodebind=1 --membind=1`.
- Missing promisor objects were treated fail-closed. Bounded exact-object fetches were allowed only where needed and did not change a checked-out branch or worktree.
- `independent-review/collect_independent_review.py`'s `complete: true` is structural only. It does not validate Git object existence, causal correctness, CVE-to-hunk identity, or corrected-field consistency.

## w009 — CVE-2026-74878

Final verdict: **`AI_CODE_FLAWED`**, specifically AI-authored incomplete remediation. The case is not a false positive and is not `AI_ROOT_CAUSE` under this project's remediation/origin distinction.

Primary sources: [CVE CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-74878), [vendor advisory GHSA-h45m-mgcp-q388](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-h45m-mgcp-q388), and the official `jahlives/openssl_encrypt` repository and PyPI artifacts.

### Closed chain

- Candidate/BIC: `1b6f732232018609189c863a165a11aaa89db250`.
- Parent: `c21f2a81b6bc6999c4067d1b2e4ea6d97448d037`.
- The candidate adds `TOTPRateLimiter`, process-local `attempts` and `lockouts`, `_rate_limiter = TOTPRateLimiter()`, and the `verify_code()` enforcement call. The parent lacks all four.
- The BIC has explicit `Generated with Claude Code` and `Co-Authored-By: Claude Sonnet 4.5` markers.
- Public PyPI `1.4.0b3` through `1.4.0b8` are `<1.4.0` artifacts that contain the in-memory limiter. The stable `1.3.x` line lacks the Pepper server component.

### Why it is incomplete remediation

The parent already accepted repeated TOTP and backup-code attempts without a TOTP-specific failure counter or lockout. `1b6f732...` is explicitly a security fix for that pre-existing brute-force surface. It narrows the risk for one process but leaves the CNA-described multi-worker and restart bypass. This matches the project's `AI_CODE_FLAWED` precedent: the AI wrote an incomplete guard, not the original exposed verification path.

### Claimed fix is not a fix

`2749bc0949b34a5921a35fb4a3f1856fc51916de` adds `DatabaseBackend`, but:

- `TOTPRateLimiter(..., backend=None)` still selects `InMemoryBackend()`;
- `TOTPService._rate_limiter = TOTPRateLimiter()` passes no backend;
- no production path constructs or injects `DatabaseBackend`;
- the split official server repository still uses the in-memory default.

Therefore `direct_fix_sha` must be `null`, with a confirmed-unpatched record. The CNA's `1.4.0 unaffected` statement is contradicted by the official Git tree and PyPI `1.4.0` artifact. The route also has an mTLS prerequisite, so the CNA's `PR:N` severity narrative should not be repeated as a verified code fact.

## w030 — CVE-2026-8417

Final verdict: **`NOT_AI`**, with a landing-ready BIC correction.

Primary sources: [Concrete CMS CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-8417), [9.5.1 release notes](https://documentation.concretecms.org/9-x/developers/introduction/version-history/951-release-notes), and the official repository.

### Correct lifecycle

- BIC: `6ac5687f09b766158e43932ebbf5367d5e787792`.
- Parent: `f955acab4deaa9d088ddeafe4076a2a8b08d0e93`.
- Direct fix: `f22b9dff59454391a50a255a39995bf635deea9e`.
- BIC author/committer: Andrew Embler; no AI marker, so `ai_marker.state = ABSENT`.

`6ac5687...` first adds the public package-upgrade action in `trunk/web/concrete/controllers/dashboard/install.php`: package lookup reaches `upgradeCoreData()` and `upgrade()` without a request-method or CSRF-token check. The immediate parent lacks the action and sink, while other destructive actions already use the token service.

The primary BIC `f0d6a2f9...` is a 2012 override restructure. Its parent already contains the CSRF-less `do_update()` body. Intermediate commits move the action, rename it, and add `canInstallPackages()` but do not add CSRF protection.

`f22b9dff...` closes the exact edge by requiring POST, validating `update_addon`, and changing the UI to a token-bearing POST form. `9.5.0` contains the corrected BIC and not the fix; `9.5.1` contains both.

## w033 — CVE-2025-54263

Final verdict: **`EVIDENCE_GAP`**. Grok's proposed `NOT_AI` close is not acceptable.

Primary sources: [Adobe CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-54263), [APSB25-94](https://helpx.adobe.com/security/products/magento/apsb25-94.html), and official Magento history.

### Strong candidate, missing identity binding

`485febbd60a1eb28da779024c6c27f856e28ed39` (`AC-15021`) is a strong semantic candidate:

- Login-as-Customer persists `admin_id`, `customer_id`, and a secret.
- Before the candidate fix, revoking the LAC ACL, removing role membership, or moving an admin to a role without LAC did not delete the authentication row.
- The candidate adds role/user hooks that delete the row, so the storefront impersonation session becomes invalid.

The candidate matches the CNA phrase "maintain unauthorized access", and its blobs are present in all inspected fixed release lines and absent in affected predecessors. If Adobe binds this CVE to AC-15021, the likely human-origin BIC is `dd15e184efe63d3fa5ebdf6d7906ef5874b5fdf2`, parent `2c4dbba9111184299cba2935b26b23011566ee65`.

That binding does not currently exist in the public CNA record, APSB25-94, commit message, or release notes. The same release contains multiple authorization patches. Semantic fit plus release co-membership is not first-party CVE-to-hunk identity.

### Grok record defects

- It assigns the exact BIC/fix pair already used by `w032` / CVE-2025-54267, although the CNA descriptions and impacts differ.
- Its `introducer_parent_absent=false` contradicts its own evidence that the parent lacks the LoginAsCustomer mechanism.
- AC-15021's permission-revocation behavior fits CVE-2025-54263 more closely than CVE-2025-54267. This does not close `w033`; it also means the current `w032` close should be reopened for CVE-to-hunk identity review.

Required evidence: an Adobe/Magento mapping from CVE-2025-54263 to AC-15021, `485febbd...`, or an isolated official patch that uniquely identifies the same hunk.

## w034 — CVE-2025-49550

Final verdict: **`EVIDENCE_GAP`**.

Primary sources: [Adobe CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-49550), [APSB25-50](https://helpx.adobe.com/security/products/magento/apsb25-50.html), and official Magento history.

Adobe discloses only CWE-863, no authentication, required user interaction, limited confidentiality impact, affected/fixed release lines, and reporter identity. It does not identify a protected resource, endpoint, component, or patch ID.

The fixed releases contain several competing first-party authorization/confidentiality changes:

- `e56d704d...` / AC-13752: Downloadable guest-checkout enforcement;
- `47c388a0...` / ACP2E-1339: REST guest checkout when disabled;
- `d1273365...` / AC-13917: quote/original-order ownership validation;
- `30744601...` / AC-14087: CMS block DataProvider authorization behavior;
- `8c99a594...` / LYNX-838: GraphQL information exposure, but only on 2.4.8 and inconsistent with the CNA's older affected lines and UI requirement.

Selecting any one of these as the CVE's fix would be inference. The packaging release commits are squash snapshots, not atomic CVE members. Required evidence is an Adobe CVE-to-component, CVE-to-AC/VULN/LYNX, isolated patch, or proprietary Adobe Commerce patch mapping.

## w035 — CVE-2025-54266

Final verdict: **`EVIDENCE_GAP`**.

Primary sources: [Adobe CNA record](https://cveawg.mitre.org/api/cve/CVE-2025-54266), [APSB25-94](https://helpx.adobe.com/security/products/magento/apsb25-94.html), and official Magento history.

### Strong candidate chain

`26f1ac7f8a6fec6d36465832dfb960b84a74ba1c` (`AC-14924`) is the strongest direct-fix candidate. It applies HTML-plus-JavaScript contextual escaping to translated strings placed in admin `onclick`/confirmation JavaScript. The plausible source-to-sink is persisted inline translation data flowing through `__()` into unescaped JavaScript attributes. Equivalent fixed blobs appear in all four inspected fixed release lines.

The earliest surviving public carrier candidate for the general form sink is `4bdbf6b6ebc4b53dbde9483df745cfca7e864a36`, but it is a "Merged commits from the original repository" aggregate with a team identity. Its finer original member cannot be reconstructed, so BIC-local AI attribution remains `UNKNOWN`.

Adobe never binds CVE-2025-54266 to AC-14924 or these files. APSB25-94 contains another stored-XSS CVE and other XSS-relevant changes. Consequently the candidate chain cannot be promoted to a direct fix/BIC. Required evidence is an Adobe or credited-researcher CVE-to-field and CVE-to-patch mapping, followed by recoverable atomic BIC provenance.

## w046 — CVE-2026-21448

Final verdict: **retain `EVIDENCE_GAP` for the current record**. The known causal objects are human-authored, so the substantive direction is `NOT_AI`, but Grok's corrected record loses necessary paths.

Primary sources: [CVE CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-21448), [Bagisto vendor advisory](https://github.com/bagisto/bagisto/security/advisories/GHSA-5j4h-4f72-qpm6), [PR #11063](https://github.com/bagisto/bagisto/pull/11063), and official repository tags.

### Correct mechanism

This is stored Vue client-side template injection, not demonstrated recursive Blade SSTI or server-side RCE:

1. Checkout/account validators accept address strings containing Vue delimiters.
2. The strings are stored in address/order data.
3. Blade HTML escaping leaves `{{...}}` delimiters intact.
4. Shop and Admin mount the compiler-capable Vue build on server-rendered `#app` DOM.
5. Vue compiles the emitted text, so `{{7*7}}` becomes `49`.

The advisory's expression-evaluation PoC is real. The gathered evidence does not prove the advisory's RCE impact claim.

### Multi-path BIC matrix

| Surface | BIC | Parent | Boundary |
|---|---|---|---|
| Saved customer-address display | `371012a6beb4594e54c0f97bd0cc483796a8d8e8` | `1bff70bd7b5213eb24539f9f8839f3c8c183a537` | Replaces hardcoded `One` cells with persisted address fields inside an existing Vue root. |
| Admin order/invoice/shipment address surfaces | `d00bb078a1880451c4875f3d5b4e7827c487f609` | `3d92544aadf96f774ad443333fdd7898902880ba` | Adds dynamic shared sales-address rendering; parent has only hardcoded order-address content. |
| Customer order-detail address | `d3b73f517cb07a3ee3b6f4361f67d5ab6d5276c9` | `0b9568132497b959c68dbcbf51488f2780f13c0d` | First identified dynamic customer order-detail address surface. |
| Admin refund address | `53baa66db9d2d1db44f65944e7a26dad290a6d84` | `ac48a20822b8f6d747fbae7d3f077dfaf751cf03` | First identified dynamic refund address surface. |

These are single-parent, named-human commits from 2018–2019 with no BIC-local AI/generator trailer. A closed human record must use `ai_marker.state = ABSENT`, not Grok's non-schema `HUMAN`.

### Required fix set

- `ce5b5d66ba163ff6ad652a32313788bfc2eca201`: primary shared address/name remediation and saved-address list remediation. Its parent `9f2c032...` is changelog-only despite its security-fix subject.
- `6e87a661778878c7115d56a7dbb8c11bb21b8346`: adds `v-pre` to Admin order/invoice/refund/shipment content slots.
- `5090a7e65b65a49f39c3545ba76db4cdbd39316d`: protects desktop and mobile customer order-address blocks.

They form a linear ancestry, are absent from `v2.3.9`, and are ancestors of `v2.3.10`. `ce5b5d66...` alone is not the complete release remediation.

### Why the Grok correction cannot land

- It records only `371012...`, omitting independently introduced Admin, refund, and customer-order surfaces.
- It records only `ce5b5d66...`, omitting two required later fix members.
- It uses `ai_marker.state = HUMAN` rather than the established `ABSENT` state.
- Promisor gaps prevented a full continuity replay for every later carrier of the earliest saved-address sink.

The record can close only after the schema or case format can preserve the complete BIC/parent and fix-member matrices, and the remaining carrier continuity is replayed. Do not misuse `decomposed_shas`: these are independent surface first-writes, not members of one squash.

## Ledger implications

For these six cases alone:

- one class correction: `w009 -> AI_CODE_FLAWED`;
- one landing-ready BIC correction: `w030`;
- four cases remain `EVIDENCE_GAP`: `w033`, `w034`, `w035`, `w046`;
- one out-of-scope dependency should be reopened: `w032`, because its current BIC/fix pair is the same unbound AC-15021 chain disputed in `w033`.

No ledger totals should be changed until the accepted corrections are physically written and validated by the primary owner.
