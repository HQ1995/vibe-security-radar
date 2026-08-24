# fp211 CONFIRM-11 closure

Verdict first: 1 PASS proposal (GHSA-QF5V-M7P4-95RP) and 10 NARROW. Assigned 11, reviewed 11, unreviewed 0. Conservation 11=11. Canonical strict count stays 81. Publication and greater-than-200 stay HOLD. Worker PASS is a proposal for independent xhigh red-team, not admission.

The old overlay claim that ten rows have all seven gates PASS with released_publication_admitted=false, and that GHSA-4FXP is the lone identity NARROW, is routing. Independent replay from first-party GHSA objects, git ancestry, blame, and public artifacts does not reproduce ten closures.

## PASS proposals for xhigh red-team

1. GHSA-QF5V-M7P4-95RP fission/fission AI_INCOMPLETE_REMEDIATION. Landed Claude squash e484df84 authors dangerousCapabilities (six caps, no SYS_TIME). Go module v1.24.0 contains that map (blame e484df84) and not closer 2569b42b. Go module v1.25.0 contains the allowlist closer. Unreleased member 2db76f65 is Claude-marked but not a tag ancestor; it is not counted. Distinct from GHSA-M63V. GitHub v1.24.0 is marked prerelease; the public Go proxy version is the containment artifact.

## NARROW (uncounted)

| ID | Repo | Unresolved gate | Why not strict |
| --- | --- | --- | --- |
| GHSA-4FXP-2M36-QV64 | Roskus/prospero-flow-crm | identity_gate | Unreviewed empty-range GHSA; repo advisory 404. Independent release PASSes v4.6.0 residual versus v5.5.3 closer. |
| GHSA-4MR5-G6F9-CFRH | MervinPraison/PraisonAI | but_for_gate | Identity and 4.6.39/4.6.40 exist. Shipped _blocked_attrs at v4.6.39 is human 9ef5391c, not Claude 3cd664bf. |
| GHSA-94P4-4CQ8-9G67 | gitpython-developers/GitPython | but_for_gate | GPT clone expand_vars=False. Remote.create polish_url default is an old sibling. 3.1.52-3.1.54 is not but-for. |
| GHSA-G8MR-85JM-7XHM | vitest-dev/vitest | release_gate | v3.2.4 lacks the Codex backport. v3.2.5 contains candidate and CDP closer. Same-first-tag. |
| GHSA-M63V-2G9W-2W6V | fission/fission | topology_gate, release_gate | Member not in tags. v1.24.0 already equals Container closer 695d3e97. Advisory <=1.23.0 is the pre-AI hole. |
| GHSA-P52P-4VMG-4VQ3 | nesquena/hermes-webui | identity_gate, topology_gate | Unreviewed GHSA. Overlay carrier is a merge whose second parent is the closer. v0.51.357 config blob != Claude member. |
| GHSA-P538-C434-8V24 | gitpython-developers/GitPython | but_for_gate | GPT guards iter_items. Commit.count --output is the old sibling. Closer is Sebastian Thiel with a GPT trailer. |
| GHSA-P5RM-JG5C-8C77 | microsoft/kiota | topology_gate, release_gate | Member not in tags. v1.33.0 is the pre-decode blob. v1.34.0 already equals the complete closer. |
| GHSA-X2W7-XR2G-QHJR | ArnasDon/wacrm | identity_gate, release_gate | Unreviewed GHSA. Zero tags. Advisory bound 73041bf already contains the closer. |
| GHSA-X8QQ-M4QC-RPJ5 | Roskus/prospero-flow-crm | identity_gate, release_gate | Unreviewed GHSA. v4.6.0 lacks OrderReadController. v5.5.3 blob equals the closer. Distinct from 4FXP. |

## Contract notes

OSV introduced, commit subjects, marker presence, and prior CONFIRM labels were not treated as causal proof. An AI-marked carrier was not used to transfer authorship onto a human member. Different GHSAs in the same repository stayed distinct. NA/null fail closed.

## Red-team focus on the PASS row

Re-blame dangerousCapabilities at v1.24.0. Confirm proxy.golang.org v1.24.0 Origin.Hash equals ce617120. Decide whether GitHub prerelease=true on v1.24.0 is fatal given the Go module. Confirm uniqueness against GHSA-M63V and against canonical81 (no fission identity counted). Do not update the canonical ledger from this packet.
