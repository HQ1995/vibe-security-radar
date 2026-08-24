# cf3 two-gate-5 independent closure

Verdict first: **0 PASS_PROPOSAL**. Assigned **5**. Reviewed **5**. Conservation **5=5+0**. **5 REJECT**. Canonical87 stays **87**. Accepted-pending GHSA-8RW6 is not this batch. packet_delta **0**. Prior unseen-twogate5/nearpass rows were hypotheses only. Worker PASS is proposal only. Seven gates must be exact PASS; none are. Fatal gate FAIL is REJECT.

## Bindings (independent)

Carrier authorship is not transferred. Shared SHA is routing only. CVE aliases are not counting units.

### GHSA-37MF-VQ43-5QP9 (ChurchCRM/CRM) REJECT

Identity PASS: published repo advisory names PluginInstaller.php PHP-under-webroot RCE, not withdrawn. Global /advisories 404.

AI hunk PASS: Claude member `095bf81b` (n_parents=1) introduces `PluginInstaller.php` with `php` in `ALLOWED_EXTENSIONS`.

Topology FAIL: member is not an ancestor of squash `de417ffa` or `7.3.3`. Installer blobs three-way unequal. Release FAIL. But-for FAIL: deleting the member does not change `7.3.3`. Fix reversal PASS: `1b4e2c70` equals `7.4.0` installer blob and adds community `.htaccess` deny. Uniqueness PASS versus canonical87, GHSA-8RW6, GHSA-JX5R, and cf3 assignments.

### GHSA-3FP5-V549-9V66 (openclaw/openclaw) REJECT

Identity PASS: published repo advisory names flock wrapper durable allow-always bypass, patched 2026.6.9.

AI hunk FAIL: `8e41c118` is a human GitHub squash with `[AI]` PR branding and no Co-Authored-By trailer. It edits time/script unwrap. `unwrapFlockInvocation` is absent. But-for FAIL: flock is a sibling wrapper added by `55d1324c`. Topology PASS (direct atomic in tags). Release PASS: `v2026.6.6` contains the candidate and not the fix; `v2026.6.9` contains the fix. Fix reversal PASS for the named flock residual. Uniqueness PASS; nextqueue routing-only never_pass is not a counted collision.

### GHSA-J4CX-JVQ7-79VM (openclaw/openclaw) REJECT

Identity PASS: published repo advisory names trajectory export redaction, patched 2026.6.1.

AI hunk FAIL: `17ceca86` has `[AI]` PR branding and does not edit `src/trajectory/export.ts`. Parent and candidate share blob `fbbd7e1b`. But-for FAIL: closer `19fb9f12` is a sibling walker. Topology PASS. Release PASS on git tags `v2026.5.28` / `v2026.6.1`. Uniqueness PASS.

### GHSA-JX5R-P82P-2P8M (ChurchCRM/CRM) REJECT

Identity PASS: published repo advisory names three GET-delete pages, not withdrawn.

AI hunk PASS: `6ef78813` n_parents=1 Co-Authored-By Claude Sonnet 4.6 introduces `FundRaiserDelete.php`. Parent already has the other two named pages.

Topology FAIL: member is not an ancestor of squash `ede1bfb0` or `7.2.2`. Released blob `2963cd58` != member `80acd007`. Tag `7.3.2` is absent. Release FAIL. But-for FAIL. Fix reversal PASS: `f1c11f9f` removes the legacy file by `7.4.3`. Uniqueness PASS versus GHSA-37MF and canonical87.

### GHSA-QJPC-QF9M-XWMR (openclaw/openclaw) REJECT

Identity PASS: github-reviewed global GHSA plus published repo advisory, patched 2026.5.18.

AI hunk FAIL: `0e702f10` has `[AI]` branding plus later Claude review. `connect-policy.ts` blob `27284609` is unchanged. Parent already skips pairing when `trustedProxyAuthOk`. But-for FAIL. Topology PASS. Release PASS on git tags `v2026.5.12` / `v2026.5.18`. Fix reversal PASS: `96fba91b` stops the trusted-proxy pairing skip. Uniqueness PASS.

## Conservation

5 assigned = 5 reviewed + 0 unreviewed. PASS_PROPOSAL=0. cve_aliases_counted=false. canonical87_overlap=0. 8rw6_overlap=false.

## Claim boundary

Canonical87 HOLD remains 87. GHSA-8RW6 stays accepted-pending and is not admitted here. Publication and greater-than-200 remain HOLD. No commit or push.
