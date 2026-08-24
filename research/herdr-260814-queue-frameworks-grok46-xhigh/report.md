# Queue frameworks four: all REJECT (canonical93 untouched)

Terminal review of four frozen next-queue identities. PASS_proposal=0.
Canonical93 stays 93 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none.
Conservation 4=4+0. Did not pad. GHSA-3VCP-CHFH-F6R2 is excluded because a later terminal review already REJECTED it.

## Freeze

Source packet `autoresearch/herdr-260814-nextqueue-v2-grok46-low` assignment sha256 `5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3` cases sha256 `5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf`.
CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical93 ledger sha256 `6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d`.
First-party github-reviewed tree HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No GitHub API. No credentials. No retained clone or page in the owned directory.

Frozen rows (source assigned_order preserved as metadata; packet order 1-4):

1. GHSA-GJX9-J8F8-7J74 HubSpot/jinjava CWE-1336
2. GHSA-QHJ8-Q5R6-8Q6J matrix-org/matrix-rust-sdk CWE-682
3. GHSA-R4WM-X892-VJMX nestjs/nest CWE-863
4. GHSA-2V6M-6XW3-6467 fleetdm/fleet CWE-200,CWE-201

Routing, shared SHA, trailer on a squash carrier, AI-on-fix, inherited old bugs, sibling fields, incomplete hardening that only reduces risk, and a fix in the same repo are not causal proof.

## Verdicts

| case_id | verdict | FAIL/NARROW gates | class |
| --- | --- | --- | --- |
| GHSA-GJX9-J8F8-7J74 | REJECT | ai_hunk, but_for, fix_reversal, release | sibling AstFilterChain plus 2022 ForTag |
| GHSA-QHJ8-Q5R6-8Q6J | REJECT | ai_hunk, but_for, fix_reversal | sibling LowPriority filter; listed SHA changelog-only |
| GHSA-R4WM-X892-VJMX | REJECT | ai_hunk, but_for, fix_reversal | sibling Copilot review / RMQ Autofix |
| GHSA-2V6M-6XW3-6467 | REJECT | ai_hunk, topology, but_for, fix_reversal | squash Claude trailer on hosts API |

### GHSA-GJX9-J8F8-7J74 -- REJECT

Identity PASS: first-party repo advisory names HubSpot/jinjava ForTag sandbox bypass / ObjectMapper allowlist bypass. Maven package `com.hubspot.jinjava:jinjava`. Advisory JSON sha256 `3490f83eae1e3680da4b20866a724cb19f536ca1b02174f5f3ea8efc1008314c`.

AI candidates are four atomic Claude Opus 4.5 trailers on a filter-chain cleanup. Tip `eb83265f` rewrites `AstFilterChain.appendStructure` to `params.appendStructure()`. They never touch `ForTag.java` or `JinjavaBeanELResolver.java`.

Minimum listed fixes `3d02e504` and `c7328dce` are two-parent merges. The ForTag closer peel is `71a8003a4` (Jack Smith): `getReadMethod().invoke(val)` becomes `interpreter.resolveProperty`. Blame of the deleted invoke at parent `03758f3a` is `12a9336e` (2022-02-22). That is an inherited old bug. ObjectMapper denylist peel `f5c4dd530` is also human.

eb83265f is absent from `jinjava-2.8.2` (peel `122f112b`, last 2.8 vulnerable tag, still has getReadMethod) and first present in `jinjava-2.8.3` (peel `867dde77`), which already contains the closer. 2.7.5 already has the old invoke; 2.7.6 has resolveProperty; AI is on neither 2.7 tag. Maven Central POMs 2.8.2/2.8.3/2.7.5/2.7.6 are HTTP 200. release_gate FAILs the required conjunction that a vulnerable artifact contains the AI contribution.

but_for FAIL: remove the Claude commits and ForTag still introspects getters. Not incomplete remediation: no AI-authored ForTag or ObjectMapper guard.

### GHSA-QHJ8-Q5R6-8Q6J -- REJECT

Identity PASS: first-party advisory names `RoomMember::normalized_power_level()` panic on `Int::MIN` in matrix-sdk-base. Advisory JSON sha256 `82c488d00cadae189d478d62aac08e04292ebc826f31eb907cc47603b16c164b`.

Pre-fix candidates are Copilot SWE-agent author_identity hits that add LowPriority / NonLowPriority UI filters under `matrix-sdk-ui` and FFI room_list. Path overlap with the panic helper is empty.

Listed SHA `ce3b67f8` is changelog-only (`bindings/matrix-sdk-ffi/CHANGELOG.md` backtick edit). It is not in `matrix-sdk-base-0.14.1`. Real closer `476fe5f9` (Damir Jelic, no AI trailer) clamps `normalize_power_level`. Blame of `try_into.expect` at the parent is human `80262f2f`.

`matrix-sdk-base-0.14.0` peel `9ffe5aa6` lacks `476fe5f9`. `matrix-sdk-base-0.14.1` peel `5ef3ecac` contains it. crates.io crate archives 0.14.0 sha256 `800d9917ab3d14fb209f324ee5dea79f7bc77a79e6287b82aa24a38600fce136` and 0.14.1 sha256 `b14659a7e902ea8a821ec217f36b168fb4c79020d91b912175ac188b6c364225` are HTTP 200. Formal panic containment PASSes release_gate and does not create AI origin. A prior REJECT of the listed changelog SHA was not inherited; the Copilot candidates were tested independently and still fail ai_hunk, but_for, and fix_reversal.

### GHSA-R4WM-X892-VJMX -- REJECT

Identity PASS: first-party advisory names Fastify `originalUrl` middleware regex versus `routerOptions` canonicalization mismatch in `@nestjs/platform-fastify`. Advisory JSON sha256 `8fc9967575736c46d7b4200edff6afa3a1b60866dde3f95dde6673139cfd373e`.

AI candidates: Copilot review trailer on a statusCode check in `packages/core/router/router-response-controller.ts`; Copilot review trailer on a TCP exception constructor; Copilot Autofix of RMQ `routingKey` backslash escaping. None touch `fastify-adapter.ts`. Later AI review is insufficient. Same-repo Autofix of a different CWE is not this mechanism.

Listed `fd8d073e` is a two-parent merge. Peel `d74e9a8c` (Kamil Mysliwiec, no AI trailer) introduces `sanitizeUrl`. Blame of the skip at the parent is human `a412dccf` (2023) plus human `c4cedda1` (2025-12-29 decoded-char middie bypass). The 2025 commit is a prior human incomplete rem of the same Fastify boundary, not an AI guard.

`v11.1.13` peel `e3a958ac` lacks `sanitizeUrl`. `v11.1.14` peel `5d31df7e` contains the closer. npm packuments 11.1.13 sha256 `de97b5b9f9b915bdefbfe9a79b9cdbd0f8de5849f4500d6adae937bd89ef7285` and 11.1.14 sha256 `ce1251484296086c10813e385fdb626e95baf8d5405716419a255b4c6db9d092` are HTTP 200. release_gate PASS for advisory containment only.

### GHSA-2V6M-6XW3-6467 -- REJECT

Identity PASS: first-party advisory names Google Calendar service-account private key returned to Observer via the config API. Advisory JSON sha256 `17fc7ce95727fc18769e95dc119e971849b33c7b5d6cc90c781171c3aea98bf2`.

Candidate `5bf82e29` is GitHub squash `#36009` adding hosts `device_status` / `pending_action`. Trailer `Co-authored-by: Claude <noreply@anthropic.com>` sits on the squash carrier. Members were not peeled. Topology FAIL: trailer on a squash carrier is not member authorship.

Closer `23fc6804` (Tim Lee, `#38687`, no AI trailer) adds `GoogleCalendar ApiKey.SetMasked` inside `AppConfig.Obfuscate`. Only file overlap is `integration_core_test.go`, and the hunks are different tests (populate_device_status versus IsMasked calendar assertions). Sibling fields.

`Obfuscate()` at the closer parent already masked SMTP/Jira/Zendesk (blame `1ebfbb14`, 2023) and omitted Google Calendar. That is a human omitted sibling integration, not AI incomplete remediation.

`fleet-v4.80.0` peel `adaef7e0` contains the candidate and not the closer. `fleet-v4.80.1` peel `5c2a408a` contains the closer. proxy.golang.org info timed out; git tags are the pinned first-party release evidence. release_gate PASS for advisory containment only.

## Uniqueness and claim boundary

All four identities are absent from canonical93 strict 93. They do not share a counted mechanism with each other. CVE aliases are not counting units. packet_delta=0. Canonical ledger was not edited.

GHSA-3VCP-CHFH-F6R2 remains excluded: `herdr-260814-new-surface-unseen20-grok46-high` already issued a terminal REJECT (sibling KRI endpoint on old CORS/admin). This packet does not reopen it.

Prefer zero PASS over one false positive.

## Replay

`zsh replay.zsh` must print `REPLAY_OK reviewed=4 PASS=0 REJECT=4 packet_delta=0 canonical_strict=93 equation=4=4+0` twice with byte-identical stdout and empty stderr. No GitHub API. No ledger edits. No commit or push.

## Input hashes (SHA-256)

- CONTRACT.md `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- source assignment.jsonl `5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3`
- source cases.jsonl `5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf`
- canonical93 ledger.jsonl `6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d`
- canonical93 summary.json `cf8a3eb231830303803e2e1a198207b2a8e117990a675982e8d9e346c9cc46c0`
