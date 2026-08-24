# Canonical87 HOLD snapshot

Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 87 first-party GHSA identities. It extends the frozen canonical86 snapshot in orchestrator-260814-ghsa200-canonical86 by appending exactly one leader-accepted identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical86 meaning and are not flipped by counting GHSA-V52W. This packet does not support a greater-than-200 claim.

Composition: every canonical86 ledger row is preserved byte-for-byte and in order. The prior 86 counted rows stay byte-identical. Terminal hostile red-team KEEP GHSA-V52W-28XH-V562 is appended at ordinal 87. Count is by first-party GHSA identity once. CVE aliases are stored and never counted. This identity has no CVE alias.

The admitted identity at ordinal 87 is GHSA-V52W-28XH-V562, repository kozou-dev/kozou, class AI_DIRECT_ROOT. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. Counted bundled issues are 1 and 2 only, on the new MCP Streamable HTTP startHttpServer.ts surface. Bundled issues 3 and 4 are excluded. REST body #164 is excluded. candidate_set is 4f86724bd1 (PR #20 member). carrier_set is bc9dc69d62 (mainline squash). minimum_fix_set is 7c3ae2e3b7. All seven contract gates are PASS. Public npm @kozou/mcp 1.8.0 / git tag v1.8.0 contains the unguarded HTTP server. Public npm 1.8.1 / git tag v1.8.1 contains Host/Origin and the streaming body cap. Mechanism key and fingerprint are unique versus canonical86.

Admission source is the compact hostile packet herdr-260814-v52w-hostile-grok46-low. Inherited negative controls remain rejected and absent from strict rows.

Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-V52W is a new identity (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 16. new_append_identities is exactly GHSA-V52W-28XH-V562. append_identities is the prior 16 followed by that one (17). new_identities_append is true. same_id_source_layer_promoted is false. The hostile red-team packet admits this row at authority rank 45. Discovery tabs and worker-only PASS are not loaded. Raw pages, tarballs, and owned clones are not committed; the builder consumes v52w_acceptance.json plus immutable canonical86 tracked artifacts.

Every counted row has all seven contract gates equal to the string PASS. Null and NA fail closed. Candidate, carrier, and minimum-fix sets are sorted unique 40-hex SHAs. Cartesian candidate times fix pairs are not invented.

Status HOLD until leader review.
