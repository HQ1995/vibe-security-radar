# Reintroduction discovery - verdict first

**PASS proposals: 0.** Publication and any more-than-200 claim remain HOLD. Worker PASS would be a proposal only; this packet does not admit one.

This lane required a first-party GHSA identity outside the frozen strict 73 set and outside pending discovery proposal `GHSA-F38V-77QJ-H4JQ`, with all seven gates exactly PASS: a parent already safe for the advisory invariant, an atomic commit with its own explicit AI marker that reintroduces or disables that invariant, a vulnerable released artifact containing that AI hunk, and a later first-party minimum closer restoring the same invariant.

Thirty identities were deep-reviewed (cap 30). Conservation: assigned 30 = reviewed 30 + unreviewed 0. No unreviewed row was inferred as REJECT. Prefer zero PASS to weak causality.

## NARROW (4)

1. **GHSA-2MXR-P26X-MJ73** (`kerberosmansour/hulumi`) is the strongest AI reintroduction shape in the packet and still fails. Parent of `0d5c4d2e` hard-codes startup-hardened `objectLockEnabled: true`. Atomic `0d5c4d2e` (single parent, `Co-authored-by: Claude Opus 4.7`) adds `objectLock: false` on the AccountFoundation audit-delivery bucket. Closer `070da5d3` is a later security squash that keeps the opt-out and adds deny-`s3:DeleteObject*` plus EventDataStore; the first-party advisory says Object Lock is intentionally not re-enabled. Dual release containment fails: peel of v1.3.2 (`53e9bafa`) contains neither candidate nor closer; peel of v1.4.0 (`f5f95fd2`) contains both. npm `@hulumi/baseline` 1.3.2 was published before the AI commit; 1.4.0 already contains the closer. Whole-advisory but-for is also NARROW because forceDestroy forwarding and sandbox-tier drop are not proved to be introduced by `0d5c4d2e`.

2. **GHSA-7X5Q-8F6H-RJRC** (conductor GraalJS `HostAccess.ALL`) remains identity-NARROW: independent global object is unreviewed with empty `vulnerabilities`, and the repo advisory 404s. Same identity bar as `GHSA-4FXP`. Topology stays NARROW (carrier vs member). Not counted.

3. **GHSA-CW23-QWR7-C655** (ironclaw High-pattern weakening) is unreviewed with empty vulns. Claude member `b20880c1` is not an ancestor of `ironclaw-v0.29.1`. Do not transfer member authorship onto the later carrier or tag blob.

4. **GHSA-P8RR-9CVG-CX5J** (AutoBangumi private/loopback re-allow) has an AI-marked reallow (`61ff20fe`, Claude Opus 4.6) but the global object is unreviewed, the repo advisory 404s, and published closer `487bdfec` still allows private/loopback. Fix reversal of the exact denylist fails.

## REJECT classes (26)

Human same-sink regressions with no AI marker on the disable commit: Echo `GHSA-PGVM` (parent already `path.Clean`), Open WebUI `GHSA-HCWP` (`f962bae98` dropped `DOMPurify.sanitize` from FileItemModal `excelHtml` after v0.8.0 was safe; closer `3746339cf` restores it), HAPI `GHSA-FGV2` (human `3871cc69` removed host-equality), Apktool `GHSA-M8MH` (Igor Eisberg `e10a045` removed `BrutIO.sanitizePath()`), Ray `GHSA-MW35` (Srinath `f6d21db1` put `cloudpickle.loads` back), pymdown `GHSA-62Q4` (2023-05-15, before May 2025), AVideo `GHSA-HG8Q` (CLI `die()` commented out in 2022-2023).

Wrong class for this lane: Open WebUI `GHSA-JWF8` is origin of `excelHtml`, not the later regression; Astro `GHSA-VJ59`, Flowise `GHSA-52FH` / `GHSA-XC48`, SiYuan `GHSA-P4M3`, Craft Commerce `GHSA-R54V`, GitPython `GHSA-WVPP`, AVideo `GHSA-GHCV`, Open WebUI `GHSA-FQ3V`, and SafeInstall `GHSA-XRMC` are incomplete-remediation residuals or sibling-path gaps. Koel `GHSA-W79M` and Distribution `GHSA-6PJF` are new-route copies that never received the existing guard. Gitea `GHSA-VRHC` is a later human weakening of an AI predicate. Neutron `GHSA-QMC5` is a 2015 RBAC regression. tj-actions `GHSA-GQ52` cites the closer, not an AI origin. Paperclip `GHSA-FPW4`, Laravel-Mediable `GHSA-XV8G`, and CI4MS `GHSA-8RH5` lack an AI-marked disable of a completed parent guard. CodeChecker `GHSA-G839` is published 2025-03-03, outside coverage.

`GHSA-WVPP` also fails uniqueness: it is a residual of already-counted `GHSA-R9MR`.

## Claim boundary

This packet does not edit the canonical ledger, publication data, or other worker directories. It does not rebuild the 48-case strict-released lower bound. It does not support a more-than-200 claim. Replay is fail-fast zsh against frozen input hashes and primary git/advisory objects.

## Terminal

Review is closed. No further candidates. All 30 assigned identities have nonpositive dispositions persisted in `cases.jsonl` and `work/dispositions.json`. One leftover identity fetch (`GHSA-6RMH-7XCM-CPXJ`) is recorded as not assigned and is not inferred as REJECT.
