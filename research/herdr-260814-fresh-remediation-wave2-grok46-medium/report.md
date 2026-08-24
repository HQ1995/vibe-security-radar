# Fresh incomplete-remediation wave2 (net-new first-party GHSA)

Verdict first: **0 PASS**. Frozen **11** (cap 20, not padded). Reviewed **11**. Fully closed **10 REJECT**. Remaining **1 UNKNOWN**. AI prior-attempt hits **0**. Packet delta **0**. Canonical85 stays **85**. Publication and more-than-200 remain **HOLD**. Worker PASS is a proposal only and is not issued.

This lane requires an AI-authored commit that explicitly attempted a security guard, a vulnerable release that contained that attempt, and a later exact closer of the same residual bypass. Ordinary vulnerable feature origins, sibling-path wiring, generic AI markers, and squash-from-fork trailer transfer are out of lane.

## Sources (read-only)

- Canonical85 ledger sha256 `2927924603a76a2565d9c244c3b79f70d4693c127f1bc6fcc63e8099172ba568`
- Canonical85 summary sha256 `47209f841a5cb793ae6146b4247990fd2af1d4e50d3d881e0b53904f850bbd0c`
- Canonical85 manifest sha256 `5781078c8b286a454b647c84447fa8c9ff4dc2068f3c45acb45acddb50167abd`
- Advisory cache `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database` git HEAD `a42c436870111aa3f221257c9d56126a93173ccc` (2026-08-13T20:57:17+00:00). Used read-only.
- Repo clones under `/home/hanqing/.cache/cve-analyzer/repos` and `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones` used read-only. No clone was fetched into owned `work/`.
- Exclusion union count **1211** (canonical85 counted 85 plus 1136 identities already terminal in prior 260814 remediation/directroot packets; overlap 10). Exact set: `work/exclusion_ids.txt`. Packet list: `work/exclusion_meta.json`.

## Screen

Local github-reviewed 2025-2026 JSON: 12817 files. Strong incomplete-remediation language: 427. First-party: 367. Summary named incomplete fix for/of CVE|GHSA: 69. After exclusion and unique-repo freeze: **11**. Did not pad to 20. Did not expand past the freeze.

## Seven gates

identity, exact AI hunk authorship of the prior security attempt, topology/atomic member, but-for, exact minimum-fix reversal on the same path, vulnerable+fixed release containment, uniqueness versus canonical85.

## Frozen set

| n | ID | Repository | Verdict | Reason |
|---|---|---|---|---|
| 1 | GHSA-28PQ-6QXG-WG5R | axllent/mailpit | REJECT | sibling_path_not_same_mechanism |
| 2 | GHSA-4744-96P5-MP2J | pyload/pyload | REJECT | human_prior_attempt_not_ai |
| 3 | GHSA-48P8-G2FX-3WWM | argoproj/argo-workflows | UNKNOWN | merge_from_fork_members_unrecovered_no_squash_transfer |
| 4 | GHSA-56M6-8Q75-F2RW | imagemagick/imagemagick | REJECT | human_prior_and_no_same_path_overlap |
| 5 | GHSA-5879-4FMR-XWF2 | wwbn/avideo | REJECT | human_prior_attempt_not_ai |
| 6 | GHSA-FXQJ-RQCC-2CMP | postcss/postcss | REJECT | human_prior_attempt_not_ai |
| 7 | GHSA-HXVH-4H3W-PRP9 | nuxt/nuxt | REJECT | human_prior_attempt_not_ai |
| 8 | GHSA-P4M3-MGMM-C664 | siyuan-note/siyuan | REJECT | human_prior_attempt_not_ai |
| 9 | GHSA-RHFG-J8JQ-7V2H | openclaw/openclaw | REJECT | sibling_path_not_same_mechanism |
| 10 | GHSA-RJRW-MJQ6-HPMM | goshs-labs/goshs | REJECT | human_prior_and_no_same_path_overlap |
| 11 | GHSA-X677-9FXG-V5C5 | traefik/traefik | REJECT | sibling_cross_cohort_and_human_closer |

### GHSA-28PQ-6QXG-WG5R REJECT

Prior GHSA-fpxj capped POST /api/v1/send only. Closer caps sibling JSON endpoints via middleWareFunc.

Original vulnerability: `CVE-2026-45710` / `GHSA-FPXJ-M5Q8-FPHW`. Prior attempt `136bdde953966f27f572105f43c9ecdf95a91253`. AI marker: none_on_prior_atomic_message.

Tag v1.30.0 contains prior 136bdde and not closer 5754c82. Closer is in v1.30.1+.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL; release PASS; uniqueness PASS.

Counterevidence:

- Advisory title names sibling-endpoint residual. This packet does not infer causality across sibling handlers.
- Prior 136bdde author Ralph Slooten <axllent@gmail.com> has no AI trailer.
- Closer extends a body cap to other JSON endpoints. That is not reversal of an AI-authored send.go guard.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/axllent_mailpit log -1 --format=%an%n%s 136bdde953966f27f572105f43c9ecdf95a91253`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/axllent_mailpit merge-base --is-ancestor 136bdde953966f27f572105f43c9ecdf95a91253 5754c821d344cfc7104e5dfeb35b4678d822e11f`

### GHSA-4744-96P5-MP2J REJECT

Residual storage_folder write after human GHSA-r7mc closer f5e284fcdfea.

Original vulnerability: `CVE-2026-33509` / `GHSA-R7MC-X6X7-CQXX`. Prior attempt `f5e284fcdfeaf08436bb03e5fcf697aaac659d8b`. AI marker: none_on_prior_atomic_message.

Local clone has no git tags containing prior f5e284fc or closer c4cf995a. No residual tag interval was proved. GitHub Releases were not queried.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release UNKNOWN; uniqueness PASS.

Counterevidence:

- Prior attempt f5e284fcdfea author GammaC0de has no AI trailer.
- Both commits touch src/pyload/core/api/__init__.py. Residual public artifacts were not proved from tags.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/pyload_pyload log -1 --format=%an%n%s f5e284fcdfeaf08436bb03e5fcf697aaac659d8b`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/pyload_pyload merge-base --is-ancestor f5e284fcdfeaf08436bb03e5fcf697aaac659d8b c4cf995a2803bdbe388addfc2b0f323277efc0e1`

### GHSA-48P8-G2FX-3WWM UNKNOWN

ArtifactGC nested PodSpecPatch residual after the CVE-2026-31892 / GHSA-3775 allow-list. Closers are merge-from-fork objects.

Original vulnerability: `CVE-2026-31892` / `GHSA-3WF5-G532-RCRR`. Prior attempt `4cac12c75de720889ad2cae8a6cc63c566b1d8d8`. AI marker: claude_on_merge_from_fork_closer_and_intermediate_allowlist_not_transferred.

Tags v4.0.2-v4.0.5 contain human prior 4cac12c75de7 and not closer 277e9cef0ad1. Intermediate Claude-marked 2727f3f70167 is first contained by v4.0.5. Fork members of the merge objects are unrecovered. Missing evidence stays UNKNOWN.

Gates: identity PASS; ai_hunk UNKNOWN; topology UNKNOWN; but_for UNKNOWN; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS.

Counterevidence:

- Named CVE-2026-31892 attempt 4cac12c75de7 has no AI trailer. Paths are operator.go, not merge.go.
- 2727f3f70167 Co-authored-by Claude Opus 4.6 is a single-parent Merge commit from fork. Squash transfer of that trailer to unrecovered members is refused.
- Closer 277e9cef0ad1 is also Merge commit from fork with Claude. AI on the closer is not AI incomplete remediation.
- GHSA-3775 is already terminal in prior 260814 remediation packets and is not re-admitted.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows log -1 --format=%P%n%B 4cac12c75de720889ad2cae8a6cc63c566b1d8d8`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows log -1 --format=%P%n%B 2727f3f701677d467dfb5e053c57237cbc752c3c`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/argoproj_argo-workflows log -1 --format=%P%n%B 277e9cef0ad16d7eaaab253573d0695951a65dbd`

### GHSA-56M6-8Q75-F2RW REJECT

Closer 649d74981 touches MagickCore/utility.c. Prior GHSA-xcjm lock d1bf6bcf3 touches policy.c and blob.c. Same-path reversal was not proved.

Original vulnerability: `CVE-2026-49219` / `GHSA-XCJM-WQFF-M669`. Prior attempt `d1bf6bcf357fef944280263892dadf84fbb2211d`. AI marker: none_on_prior_atomic_message.

Tags 7.1.2-24 and 7.1.2-25 contain prior d1bf6bcf3 and not closer 649d74981. Closer is in 7.1.2-26+.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL; release PASS; uniqueness PASS.

Counterevidence:

- Prior d1bf6bcf3 author Cristy has no AI trailer.
- No overlapping code paths between prior policy.c/blob.c and closer utility.c. Sibling-path inference is refused.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/imagemagick_imagemagick diff-tree --no-commit-id --name-only -r d1bf6bcf357fef944280263892dadf84fbb2211d`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/imagemagick_imagemagick diff-tree --no-commit-id --name-only -r 649d74981b2314430e15225781734ec4b79df4df`

### GHSA-5879-4FMR-XWF2 REJECT

deleteDump path-validation residual after human 941decd6d19e on plugin/CloneSite/cloneServer.json.php.

Original vulnerability: `CVE-2026-33293` / `GHSA-XMJM-86QV-G226`. Prior attempt `941decd6d19e2e694acb75e86317d10fbb560284`. AI marker: none_on_prior_atomic_message.

Tags 26.0 and 29.0 contain prior 941decd6d19e and not closer 3c729717c26f. Closer has no containing tags in this clone. GitHub Releases were not queried.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release UNKNOWN; uniqueness PASS.

Counterevidence:

- Prior 941decd6d19e author Daniel Neto has no AI trailer.
- Same file plugin/CloneSite/cloneServer.json.php. Residual closer tags were not recovered.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/wwbn_avideo log -1 --format=%an%n%s 941decd6d19e2e694acb75e86317d10fbb560284`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/wwbn_avideo merge-base --is-ancestor 941decd6d19e2e694acb75e86317d10fbb560284 3c729717c26f160014a5c86b0b6accdbd613e7b2`

### GHSA-FXQJ-RQCC-2CMP REJECT

previous-map.js residual after human Load only .map source maps commit c64b7488d273.

Original vulnerability: `GHSA-6G55-P6WH-862Q` / `GHSA-6G55-P6WH-862Q`. Prior attempt `c64b7488d2731dfa16213739b42c34faf5a9eba3`. AI marker: none_on_prior_atomic_message.

Tags 8.5.12-8.5.19 contain prior c64b7488d273 and not closer 7beca139e70f. Closer has no containing tags in this clone. GitHub Releases were not queried.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release UNKNOWN; uniqueness PASS.

Counterevidence:

- Prior c64b7488d273 author Andrey Sitnik has no AI trailer.
- Same file lib/previous-map.js. Fixed public artifact tags were not recovered.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/postcss_postcss log -1 --format=%an%n%s c64b7488d2731dfa16213739b42c34faf5a9eba3`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/postcss_postcss merge-base --is-ancestor c64b7488d2731dfa16213739b42c34faf5a9eba3 7beca139e70f9075c6b19700fcb00dd8033e5da8`

### GHSA-HXVH-4H3W-PRP9 REJECT

Case-fold residual on packages/nitro-server/src/index.ts and packages/nuxt/src/app/composables/manifest.ts after human 3f3e3fa7b5ee.

Original vulnerability: `CVE-2026-53721` / `GHSA-MM7M-92G8-7M47`. Prior attempt `3f3e3fa7b5eec8e495f4f8ce0a54813a8875a11e`. AI marker: none_on_prior_atomic_message.

Tags v3.21.7-v3.21.9 contain prior 3f3e3fa7b5ee and not closer 619963309e08. Closer is in v3.21.10+ and v4.5.1+.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS.

Counterevidence:

- Prior 3f3e3fa7b5ee author Daniel Roe has no AI trailer.
- Same nitro-server and manifest files. Human incomplete remediation is out of lane.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/nuxt_nuxt log -1 --format=%an%n%s 3f3e3fa7b5eec8e495f4f8ce0a54813a8875a11e`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/nuxt_nuxt merge-base --is-ancestor 3f3e3fa7b5eec8e495f4f8ce0a54813a8875a11e 619963309e082190bac4a26b05f2dd155b039b81`

### GHSA-P4M3-MGMM-C664 REJECT

Double-encoding residual after human GHSA-hjh7 lock bb481e1290c4. Both touch kernel/server/serve.go.

Original vulnerability: `CVE-2026-41894` / `GHSA-HJH7-R5W8-5872`. Prior attempt `bb481e1290c4a34255652ede85a546504505d2a7`. AI marker: none_on_prior_atomic_message.

Tag v3.6.5 contains prior bb481e1290c4 and not closer 0bc765c54a8a. Closer is in v3.7.0.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal PASS; release PASS; uniqueness PASS.

Counterevidence:

- Prior bb481e1290c4 author Daniel <845765@qq.com> has no AI trailer.
- Same serve.go lock-commit surface. Human incomplete remediation is out of lane.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/siyuan-note_siyuan log -1 --format=%an%n%s bb481e1290c4a34255652ede85a546504505d2a7`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/siyuan-note_siyuan merge-base --is-ancestor bb481e1290c4a34255652ede85a546504505d2a7 0bc765c54a8aadb9565147c6a4eaaaafae30800a`

### GHSA-RHFG-J8JQ-7V2H REJECT

Closer routes sibling channel extensions through fetchWithSsrFGuard. Prior tlon Urbit harden bfa7d21e997b has zero overlapping code paths with closer f92c92515bd4.

Original vulnerability: `CVE-2026-28476` / `GHSA-PG2V-8XWH-QHCC`. Prior attempt `bfa7d21e997baa8e3437657d59b1e296815cc1b1`. AI marker: claude_on_closer_not_prior.

Multiple v2026.2.* tags contain prior bfa7d21e997b and not closer f92c92515bd4.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL; release PASS; uniqueness PASS.

Counterevidence:

- Prior bfa7d21e997b author Peter Steinberger has no AI trailer.
- Closer f92c92515bd4 carries Co-authored-by Claude. That is the closer, not the prior security attempt.
- Zero overlapping code paths. Wiring pre-existing sibling extensions is not incomplete-remediation causality.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw log -1 --format=%an%n%s bfa7d21e997baa8e3437657d59b1e296815cc1b1`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/openclaw_openclaw log -1 --format=%an%n%s%n%B f92c92515bd439a71bd03eb1bc969c1964f17acf`

### GHSA-RJRW-MJQ6-HPMM REJECT

Prior GHSA-c29w lock eddb0365b44d touches sanity/checks.go. Closer 32f4a0e1790a touches sftpserver/sftpserver.go. Same-path reversal was not proved.

Original vulnerability: `CVE-2026-40884` / `GHSA-C29W-QQ4M-2GCV`. Prior attempt `eddb0365b44d37b7c718d1f0aeb3d5ee03e97789`. AI marker: none_on_prior_atomic_message.

Local clone has no git tags containing prior eddb0365b44d or closer 32f4a0e1790a. GitHub Releases were not queried.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL; release UNKNOWN; uniqueness PASS.

Counterevidence:

- Prior eddb0365b44d author Patrick Hener has no AI trailer.
- Zero overlapping code paths (sanity/checks.go versus sftpserver/sftpserver.go). Sibling-path inference is refused.

Commands:

- `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/goshs-labs__goshs log -1 --format=%an%n%s eddb0365b44d37b7c718d1f0aeb3d5ee03e97789`
- `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/goshs-labs__goshs diff-tree --no-commit-id --name-only -r 32f4a0e1790a709f722d0f3b2341f139d003180a`

### GHSA-X677-9FXG-V5C5 REJECT

Advisory names a cross-cohort sibling of Forwarded-header underscore handling. Closer 108a5264473a adds an entrypoint option and does not touch pkg/middlewares/auth. CVE-2026-33433 prior commit refs are absent from the newest advisory JSON.

Original vulnerability: `CVE-2026-33433` / `GHSA-QR99-7898-VR7C`. Prior attempt `unrecovered`. AI marker: advisory_prose_ai_disclosure_is_not_commit_authorship.

Closer 108a5264473a is in tags v2.11.51 / v3.6.22 / v3.7.6. Named CVE-2026-33433 prior SHA was not recovered from commit refs. Residual interval versus that prior stays UNKNOWN. GitHub Releases were not queried.

Gates: identity PASS; ai_hunk FAIL; topology UNKNOWN; but_for FAIL; fix_reversal FAIL; release UNKNOWN; uniqueness PASS.

Counterevidence:

- Closer 108a5264473a author Baptiste Mayelle has no AI trailer.
- Closer files are entrypoint config and docs, not pkg/middlewares/auth/basic_auth.go. Cross-cohort sibling inference is refused.
- Advisory AI-assistance disclosure is reporter-side analysis, not a commit trailer on a prior security attempt.

Commands:

- `git -C /home/hanqing/.cache/cve-analyzer/repos/traefik_traefik log -1 --format=%an%n%s%n%B 108a5264473a2cbc8f12d6d691a3c6553cdf2c1b`
- `git -C /home/hanqing/.cache/cve-analyzer/repos/traefik_traefik diff-tree --no-commit-id --name-only -r 108a5264473a2cbc8f12d6d691a3c6553cdf2c1b`

## Count boundary

Assigned 11 = REJECT 10 + UNKNOWN 1 + PASS 0 + BLOCKED 0. Equation `11=10+1+0+0`. No PASS proposals. Canonical ledger was not edited. Fetched clones under owned work/: none.

