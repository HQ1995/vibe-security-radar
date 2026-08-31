# Canonical 246 reader-summary audit

## Result

The current canonical publication cohort contains **246 cases**. This audit rewrote **14 cases across 32 existing summary-map IDs**:

- **4 cases / 6 IDs** contained commit SHAs or audit-only wording such as `squash` and `AI commit`.
- **8 cases / 20 IDs** exposed implementation filenames, function names, or long raw token lists instead of explaining the vulnerable behavior.
- **2 cases / 6 IDs** had their PraisonAI mechanisms assigned to the opposite advisory identity. The same six entries had both `summary` and `mechanism` corrected.

No map keys were added. Existing clear summaries were preserved. The final in-memory publisher projection resolves all 246 cases to reader prose that passes `public_explanation`, `AUDIT_IDENTIFIER_RE`, and the explicit `PR #` rejection.

## Scope and source of truth

- Canonical ledger: `artifacts/funnel-account-20260817.jsonl`
- Ledger snapshot SHA-256: `fd46605f25ee4c90fbae3e7376b6e67514383b214cee6226850ecffd52b83e60`
- Cohort predicate: `status in {AI_ROOT_CAUSE, AI_CODE_FLAWED}` and `site_publication.publish is not false`
- Summary map: `research/gate-campaign-20260830/summaries-by-alias.json`
- Final map SHA-256: `89b6b91f8422fcfdf17208961c42e4d4a2ed1a980e56a680c548ab9015406324`

The review used the current ledger evidence and existing raw Git/advisory findings. It did not infer fixes, sole AI authorship, or advisory-wide causation beyond the recorded scope.

## Exact changed IDs

| Canonical class | Changed map IDs | Reason | Final reader summary |
|---|---|---|---|
| `alias-010f70c5d8fa86368c907fce` | `ALIAS-010F70C5D8FA86368C907FCE`, `CVE-2025-70040`, `GHSA-V9V4-F5WM-PHH4` | Embedded introducer SHA and vague impact | Claude-generated logging code wrote upload credentials and signed request URLs to debug output. Anyone able to read the logs could recover sensitive tokens and request data. |
| `alias-ed9b3734b369568d840f0ed2` | `ALIAS-ED9B3734B369568D840F0ED2` | Embedded fix SHA and advisory-wide overstatement | Claude-generated code put the cloud-token validation endpoint behind a read-only permission even though it performed write-level provider actions. A read-only API token could therefore trigger those actions. |
| `alias-7e22d7fa18af10c1d907af89` | `GHSA-2664-HR5V-554W` | Audit-only `squash` terminology | Claude-assisted sandbox code left JavaScript function prototypes mutable. An authenticated workflow author could combine that flaw with an allowed import to escape the sandbox. |
| `alias-db82daf2886088440e14b14f` | `GHSA-Q8HH-M6V5-4F3X` | Audit-only `AI commit` wording; aggregate advisory needed a scope boundary | Cursor-assisted access-control code let ordinary session tokens skip admin-only scope checks. A signed-in non-admin could read user records and system logs; separate code caused the advisory's other exposed routes. |
| `alias-08f4ee97e5be53cda71a58d8` | `ALIAS-08F4EE97E5BE53CDA71A58D8`, `CVE-2026-14611`, `GHSA-FWPR-59HH-GR98` | Filename and parameter-name prose | AI-written per-project memory code let a remote caller choose a workspace path and expose project resources. |
| `alias-ec754f179ba2cc618a27a98b` | `ALIAS-EC754F179BA2CC618A27A98B`, `CVE-2026-13591`, `GHSA-4PQR-V6C3-X77J` | Filename and private-field prose | AI-written contact tracking trusted a caller-controlled channel type when deciding whether a conversation was authorized, allowing remote access under complex conditions. |
| `alias-6cc43b070d8c0d98ab41f2c2` | `ALIAS-6CC43B070D8C0D98AB41F2C2`, `CVE-2025-55526`, `GHSA-C7RR-QHWX-6Q49` | Function and filename prose | AI-written workflow-download code failed to confine caller-controlled filenames to the workflow directory, allowing arbitrary file reads through traversal. |
| `alias-7c96b769d0e8d26817538aa3` | `ALIAS-7C96B769D0E8D26817538AA3`, `CVE-2026-76760`, `GHSA-WFX9-6H8H-F3GM` | Raw file/argument description obscured the fail-open authentication | AI-written webhook code treated an empty configured token as authenticated, then passed a caller-supplied command to a shell, enabling unauthenticated remote code execution. |
| `alias-606ffd0fe0d4adb8a222028f` | `ALIAS-606FFD0FE0D4ADB8A222028F`, `CVE-2026-2393` | Raw source path | AI-written webhook dispatch sent requests to attacker-controlled URLs without destination validation, exposing internal services and data. |
| `alias-5215e36f51cb38d13f3063ba` | `ALIAS-5215E36F51CB38D13F3063BA`, `CVE-2026-46383` | Raw source filename | AI-written archive extraction accepted Windows absolute-path entries while probing legacy bundles, allowing file overwrite during apm install. |
| `alias-32624290ded12d479653d429` | `ALIAS-32624290DED12D479653D429`, `CVE-2026-44788` | Internal API name; scope needed to remain on the AI-added asynchronous path | Copilot SWE-agent added an asynchronous archive-extraction path without validating directory-entry names. Traversal, combined with symlinks, could write outside the target root. |
| `alias-e8e15a41dbb7f098796c61f7` | `ALIAS-E8E15A41DBB7F098796C61F7`, `CVE-2026-50180` | Long raw list of database functions | Claude-authored SQL validation used an incomplete function denylist, allowing database users with sufficient privileges to read server files. |
| `alias-8eff3fc4b483b48c2ceb498e` | `ALIAS-8EFF3FC4B483B48C2CEB498E`, `CVE-2026-57132`, `GHSA-8CCJ-P46R-JWQQ` | Wrongly carried the Sandlock mechanism | Cursor-assisted authentication code let disabled mode bypass token verification for requests from any host. A remote caller could invoke agents without a credential. |
| `alias-9638cedab2290ab95b10127c` | `ALIAS-9638CEDAB2290AB95B10127C`, `CVE-2026-57144`, `GHSA-6JCQ-6546-QRRW` | Wrongly carried the agent-authentication mechanism | Copilot-assisted sandbox code silently fell back to a weaker subprocess backend when Landlock was unavailable. Sandboxed code could then access files or networks outside configured limits. |

The count is therefore **32 unique changed summary IDs**. For the last two classes, those same **6 IDs** also received corrected mechanism text.

## PraisonAI identity correction

The canonical ledger distinguishes the two advisories:

- `alias-8eff3fc4b483b48c2ceb498e` / CVE-2026-57132 / GHSA-8CCJ-P46R-JWQQ: Cursor-assisted candidate `179cab02…`; the defect is the host-independent disabled-authentication bypass; direct fix `51fe7f9c…` restricts it to loopback-bound use.
- `alias-9638cedab2290ab95b10127c` / CVE-2026-57144 / GHSA-6JCQ-6546-QRRW: Copilot-assisted candidate `4ee7d298…`; the defect is the silent Landlock-to-subprocess downgrade; direct fix `55dc751c…` removes the implicit fallback and fails closed.

The map previously assigned these mechanisms to the opposite three-key groups. All six aliases now agree with their canonical class evidence.

## Validation

Read-only validation used the publisher's current `build_case`, `merge_duplicate_identities`, and `ai_summary_overlay` functions in memory; it did not invoke the writer or export generated site data.

| Check | Result |
|---|---:|
| JSON parse | PASS |
| Map keys | 720 |
| Canonical prospective cases | 246 |
| Cases with at least one mapped summary identity | 246 / 246 |
| Cohort-related map keys checked | 615 |
| Overlay failures | 0 |
| Final summary gate failures | 0 |
| Cohort map entries failing `public_explanation` / identifier checks | 0 |
| Exact changed-summary assertions | 32 / 32 |
| Corrected PraisonAI mechanism assertions | 6 / 6 |

No ledger, database, publisher, test, generated-site, or export file was changed by this task, and no commit was created.
