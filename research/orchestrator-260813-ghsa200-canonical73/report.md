# Canonical73 HOLD snapshot

Verdict first: this directory is an immutable HOLD snapshot of canonical strict count 73 first-party GHSA identities. It extends the leader-verified canonical72 snapshot in orchestrator-260813-ghsa200-canonical71 by appending exactly one independently red-teamed identity, GHSA-Q855-8RH5-JFGQ. Integration_ready is false. Publication_ready is false. Causal admission is false. This packet does not support a more-than-200 claim.

Composition: the prior 72 exact strict IDs, plus terminal Q855 red-team KEEP 1. Corrected baseline 47 (fp211 released-admitted 48 minus GHSA-4FXP-2M36-QV64), plus terminal netnew22 red-team KEEP 21 (GHSA-7C3W-FXGH-FRC7 NARROW excluded), plus independent Actual/Gogs red-team KEEP 2, plus terminal B3 red-team KEEP 2, plus Q855. GHSA-F38V-77QJ-H4JQ, GHSA-4FXP-2M36-QV64, and GHSA-7C3W-FXGH-FRC7 remain noncounting. Count is by first-party GHSA identity once. CVE aliases are stored and never counted.

Source conservation is separate from the counted set: 211 fp211 hypotheses and 212 source GHSA cases remain in the source layer, including dual ordinal-200 identities GHSA-3J8Q-FWPJ-F8J5 and GHSA-JJCJ-H3CM-P7X7. Same-id upgrades rewrite overlay fields and do not append. Only GHSA-6P9M-Q3JP-47H4, GHSA-G39V-CVJH-8FPF, GHSA-PF93-J98V-25PV, and GHSA-Q855-8RH5-JFGQ are absent from the 212 and append.

Authority is the named PACKET_AUTHORITY table. Glob order is not authority. Discovery tabs and worker-only PASS are not loaded. Direct-root mining PASS on Q855 is a proposal only; independent Q855 red-team KEEP is the terminal admission edge. GHSA-7C3W-FXGH-FRC7 cannot be KEEP. GHSA-F38V-77QJ-H4JQ cannot be KEEP. GHSA-4FXP-2M36-QV64 cannot be KEEP: final-candidate review NARROW on identity_gate supersedes the old fp211 released-admitted flag because the repo advisory is 404 and the global GHSA has empty vulnerabilities and no repository object. Filebrowser ordinal 165 remains FALSE_POSITIVE and ordinal 166 remains CONFIRM; shared SHAs do not merge identities.

GHSA-Q855-8RH5-JFGQ is unique versus the prior 72 and versus sibling ha-mcp identities GHSA-FMFG-9G7C-3VQ7, GHSA-G39V-CVJH-8FPF, and GHSA-PF93-J98V-25PV. Vulnerable containment is git tag v7.5.0 / PyPI 7.5.0. First non-prerelease reversal is v7.7.0 / PyPI 7.7.0. Global first_patched 7.10.0 is also fixed and still contains the same 9f5b085a ingress guard.

Every counted row has all seven contract gates equal to the string PASS. Null and NA fail closed. Candidate, carrier, and minimum-fix sets are sorted unique 40-hex SHAs. Cartesian candidate times fix pairs are not invented. Git replay of the 26 KEEP upgrade/append rows is fail-fast with empty stderr on success.

Status HOLD until leader review.
