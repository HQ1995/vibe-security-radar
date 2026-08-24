# Canonical86 HOLD snapshot

Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 86 first-party GHSA identities. It extends the frozen canonical85 snapshot in orchestrator-260814-ghsa200-canonical85 by appending exactly one leader-replayed identity. Integration_ready is false. Publication_ready is false. Causal admission is false. Global HOLD fields keep the inherited canonical85 meaning and are not flipped by counting GHSA-FRVJ. This packet does not support a greater-than-200 claim.

Composition: every canonical85 ledger row is preserved byte-for-byte and in order. The prior 85 counted rows stay byte-identical. Terminal hostile red-team KEEP GHSA-FRVJ-C5QP-XJ4W is appended at ordinal 86. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.

The admitted identity at ordinal 86 is GHSA-FRVJ-C5QP-XJ4W, alias CVE-2026-59221, repository open-webui/open-webui, class AI_INCOMPLETE_REMEDIATION. leader_strict_case_accepted is true. That flag is strict-set inclusion after leader replay; it does not flip global causal_admission. candidate_set is 0354775917. carrier_set is empty. minimum_fix_set is 05098d25. The Claude-coauthored candidate rewrote _sanitize_proxy_path from one unquote pass to a range(8) loop. The first-party advisory names the 9x residual of that cap. The minimum fix fail-closes the same loop. All seven contract gates are PASS. Remediation patch-delta is PASS. Public PyPI 0.9.6 contains the attempt sanitizer without fail-closed. Public PyPI 0.10.0 contains the exact reversal. Mechanism key and fingerprint distinguish this residual from uncounted GHSA-R2WG.

Worker PASS in herdr-260814-fresh-strict-grok46-xhigh is proposal only and lower authority than the hostile review. Inherited negative controls remain rejected and absent from strict rows.

Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer. Same-id upgrades still do not append. GHSA-FRVJ is a new identity (in_fp211_212=false, action=APPEND). Conservation prior_append_identities stays the prior 15. new_append_identities is exactly GHSA-FRVJ-C5QP-XJ4W. append_identities is the prior 15 followed by that one (16). new_identities_append is true. same_id_source_layer_promoted is false. The hostile red-team packet admits this row at authority rank 44; the worker packet is recorded at rank 43 and does not admit the row. Discovery tabs and worker-only PASS are not loaded. Raw wheels, pages, and owned clones are not committed; the builder consumes frvj_acceptance.json plus immutable canonical85 tracked artifacts.

Every counted row has all seven contract gates equal to the string PASS. Null and NA fail closed. Candidate, carrier, and minimum-fix sets are sorted unique 40-hex SHAs. Cartesian candidate times fix pairs are not invented.

Status HOLD until leader review.
