# Provisional closure audit — shard 02

Date: 2026-08-31
Scope: the twelve cases assigned to shard 02. This report is a read/replay
adjudication; it does not mutate canonical data or publication output.

## Decision rule

I read `docs/AUDIT-PROTOCOL.md` in full and rechecked the first-party advisory,
the smallest public introducing delta and its parent, the direct fix, and
release containment where an artifact exists. Gate order below is
`identity, ai_hunk, topology, but_for, fix_reversal, release, uniqueness`.
`NARROW`, `UNKNOWN`, and `FAIL` are deliberately not promoted to `PASS`.

## Results

| Case | Recommended gates (`I, A, T, B, F, R, U`) | Decision | What is actually missing |
|---|---|---|---|
| `GHSA-4P6X-RJ5H-HG93` | `PASS, PASS, PASS, PASS, NARROW, UNKNOWN, PASS` | `RESEARCH_GAP` | A released vulnerable artifact and a complete fix; the code evidence is already present. |
| `GHSA-WVPP-8HX9-P66J` | `PASS, PASS, PASS, NARROW, PASS, PASS, PASS` | `READY_TO_BACKFILL` | Classification and the incomplete-remediation chain, not source evidence. |
| `GHSA-8X5V-CPV7-8JJP` | `PASS, FAIL, PASS, PASS, PASS, PASS, PASS` | `NOT_AI_REVIEW` | The true BIC is human-authored; current AI-root attribution is wrong. |
| `CVE-2026-47211` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` | Atomic PR-member/carrier wiring and a narrow scope statement. |
| `GHSA-PQH8-P93P-2RX7` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` | Existing evidence was not wired into gates or scope. |
| `GHSA-8JQH-598V-RFXC` | `PASS, PASS, PASS, PASS, PASS, UNKNOWN, PASS` | `RESEARCH_GAP` | The atomic fix is recoverable, but no tag/release proves the advisory's `<=0.7.0` release boundary. |
| `GHSA-RFR2-MQ9M-X2QX` | `PASS, FAIL, PASS, PASS, PASS, PASS, PASS` | `NOT_AI_REVIEW` | The BIC is a 2021 human commit; the later AI commit is remediation context. |
| `GHSA-WJHR-76VG-2HVC` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` | Patch-equivalent rewritten candidate/fix carriers. |
| `GHSA-5383-J2P9-QFG3` | `PASS, PASS, PASS, PASS, PASS, PASS, FAIL` | `RESEARCH_GAP` | Same mechanism/fix as a first-party GHSA and a conflicting CNA range; do not publish twice. |
| `GHSA-2JCC-MXV7-P3F9` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` | Squash carrier wiring for both the candidate and fix. |
| `GHSA-P8RR-9CVG-CX5J` | `PASS, PASS, PASS, PASS, FAIL, FAIL, PASS` | `RESEARCH_GAP` | The claimed 3.2.8 fix does not reverse internal-network probing. |
| `GHSA-VCV2-R9JH-99M5` | `PASS, PASS, PASS, PASS, PASS, PASS, PASS` | `READY_TO_BACKFILL` | Current publication points at the wrong repository and drops one candidate and the carrier. |

## Case-level corrections and primary evidence

### GHSA-4P6X-RJ5H-HG93 — `RESEARCH_GAP`

- Keep `candidate_set=[db1d0cc4cd52589116360428b7504fd0ca748b3e]`,
  parent `39a2326ec37894ae245be07d8da91ba045b9c70b`, and
  `minimum_fix_set=[]`. The candidate creates `importRiveFile.ts`, passes raw
  `libraryId` to `saveLibrary`, and carries both the Claude trailer and the
  generated-with-Claude marker.
- Keep this explicitly unpatched. Set `unresolved_reason` to: repository has
  no Git tags/releases; CVE-2026-19288 calls it a rolling release and says
  version information is unavailable; issue 2 remains open; no complete fix
  commit is known. Do not invent a vulnerable or fixed version.
- Primary evidence: [CVE-2026-19288](https://www.cve.org/CVERecord?id=CVE-2026-19288),
  [candidate commit](https://github.com/astralisone/rive-mcp-server-core/commit/db1d0cc4cd52589116360428b7504fd0ca748b3e),
  and [open issue 2](https://github.com/astralisone/rive-mcp-server-core/issues/2).

### GHSA-WVPP-8HX9-P66J — `READY_TO_BACKFILL`

- Keep `candidate_set=[e8d0fbf774d1f6baa3b481adfe48bd262e43b453]`
  and `minimum_fix_set=[96a888f4d782cb2f80452148e48e60ce4af6d541]`,
  but replace `AI_DIRECT_ROOT` with `AI_INCOMPLETE_REMEDIATION` (ledger
  projection `AI_CODE_FLAWED`). The advisory itself identifies a bypass of
  the incomplete `e8d0...` remediation.
- Add the causal chain: human parser origin
  `039bfe373c990fc6db3808d255abaff91235e82f` -> AI guard
  `701ce32fe5ba8cb622c0e0342a376a6beb47d738` -> AI incomplete follow-up
  `e8d0...` (checks split tokens but omits the joined-token branch) -> complete
  fix `96a888...`. Limit the claim to the incomplete-remediation bypass; this
  is why `but_for=NARROW`, not a claim that AI originated the old parser.
- Releases are `<=3.1.57` vulnerable and `3.1.58` fixed.
- Primary evidence: [reviewed GHSA](https://github.com/advisories/GHSA-wvpp-8hx9-p66j),
  [AI incomplete remediation](https://github.com/gitpython-developers/GitPython/commit/e8d0fbf774d1f6baa3b481adfe48bd262e43b453),
  and [complete fix](https://github.com/gitpython-developers/GitPython/commit/96a888f4d782cb2f80452148e48e60ce4af6d541).

### GHSA-8X5V-CPV7-8JJP — `NOT_AI_REVIEW`

- Replace the current AI candidate with human BIC
  `0753409e7b18ffe4fc95a0a821f605d25b58ccad`, parent
  `b78dabb442dacd5430f0e8777aa65accf3d78c08`; set AI provenance to null and
  final verdict/status to `NOT_AI`.
- `0753409...` first installs the flawed literal
  `ipaddress.ip_address(ip).is_global` predicate and is contained in v0.9.0.
  AI-marked `051cbc65c63926e39db9e94c643545ed42a0ff5a` and its main-line form
  `854440f703c625f8cfc1b52c7e81aac67b6143c5` are later hardening attempts,
  not the BIC. Retain them only as remediation context.
- Keep direct fix `1717b493d83c86afa82aa8bc50139250852dd2f3`;
  affected range is `>=0.9.0,<0.11.0`, fixed `0.11.0`.
- Primary evidence: [reviewed GHSA](https://github.com/advisories/GHSA-8x5v-cpv7-8jjp),
  [human BIC](https://github.com/open-webui/open-webui/commit/0753409e7b18ffe4fc95a0a821f605d25b58ccad),
  and [fix](https://github.com/open-webui/open-webui/commit/1717b493d83c86afa82aa8bc50139250852dd2f3).

### CVE-2026-47211 / GHSA-C4M7-2GWP-VW76 — `READY_TO_BACKFILL`

- Restore the atomic edge:
  `candidate_set=[d30b61759b8efe4554978438abbcc5a9d698d055]`,
  `carrier_set=[4aaf9147a6c6f76aecc775defcd1a542537cf01f]`, and
  `minimum_fix_set=[4e70b760b4eb157469b58645339ba831f6513d37]`.
  `d30b...` is the Claude Opus 4.5 PR member; `4aaf...` is the released squash
  carrier. Later Claude commit `3da3cebc59da717cac32813f19dd1b821775df6c`
  connects project `.env` loading to that execution-affecting selector.
- Add formal alias `GHSA-C4M7-2GWP-VW76`, vulnerable tag `v0.38.2`, fixed tag
  `v0.39.0`, and scope: only the `ClaudeCodeAdapter` `OUROBOROS_CLI_PATH`
  source-to-execution chain. Do not attribute sibling selectors or the whole
  project-dotenv advisory to `d30b...`.
- Primary evidence: [first-party advisory](https://github.com/q00/ouroboros/security/advisories/GHSA-c4m7-2gwp-vw76),
  [carrier](https://github.com/Q00/ouroboros/commit/4aaf9147a6c6f76aecc775defcd1a542537cf01f),
  [source connector](https://github.com/Q00/ouroboros/commit/3da3cebc59da717cac32813f19dd1b821775df6c),
  and [fix](https://github.com/Q00/ouroboros/commit/4e70b760b4eb157469b58645339ba831f6513d37).

### GHSA-PQH8-P93P-2RX7 — `READY_TO_BACKFILL`

- Keep `candidate_set=[66ff2a7c8bedc23939d6d70ab4c3bdce53673843]`,
  parent `c11191125271e676109e78fef32df4a61bfa4ce6`, and
  `minimum_fix_set=[15d3546c0618ffbaeaeca477337e08e92f2151bc]`.
  The candidate is authored by `copilot-swe-agent[bot]`.
- Add scope: only raw `timeframe` interpolation newly added in
  `list-vulnerabilities.ts` and `get-events-for-cluster.ts`. Do not claim
  origin of the parent's existing `list-problems`, `list-exceptions`,
  `clusterId`, or `additionalFilter` sinks. Classification remains
  `AI_NEW_SURFACE_CONTRIBUTOR`.
- Record candidate containment in npm/git tag 1.2.0 and fix containment in
  2.1.1; advisory range is `<2.1.1`, fixed `2.1.1`.
- Primary evidence: [reviewed GHSA](https://github.com/advisories/GHSA-pqh8-p93p-2rx7),
  [candidate](https://github.com/dynatrace-oss/dynatrace-mcp/commit/66ff2a7c8bedc23939d6d70ab4c3bdce53673843),
  and [fix](https://github.com/dynatrace-oss/dynatrace-mcp/commit/15d3546c0618ffbaeaeca477337e08e92f2151bc).

### GHSA-8JQH-598V-RFXC — `RESEARCH_GAP`

- Keep candidate `b7b362ae427ccf4b33b8e8cd147f16410f3ce800`,
  but replace `minimum_fix_set=[23838a9959550e975d732ae08a44a3a2f0cc084b]`
  with atomic fix
  `minimum_fix_set=[7d1ddbfdb8296058ab787f7c57b8943c0214d14d]`.
  `23838a...` is the two-parent merge, not the smallest fix.
- Add formal alias `CVE-2026-67530` and repair candidate/fix code-evidence URLs.
  Set `unresolved_reason`: the repository has no Git tags and no GitHub
  releases, so neither candidate containment in `<=0.7.0` nor a released fixed
  artifact can be reproduced. The advisory's patched SHA is not a release.
- Primary evidence: [repo advisory](https://github.com/arnasdon/wacrm/security/advisories/GHSA-8JQH-598V-RFXC),
  [CVE-2026-67530](https://www.cve.org/CVERecord?id=CVE-2026-67530),
  [candidate](https://github.com/arnasdon/wacrm/commit/b7b362ae427ccf4b33b8e8cd147f16410f3ce800),
  and [atomic fix](https://github.com/arnasdon/wacrm/commit/7d1ddbfdb8296058ab787f7c57b8943c0214d14d).

### GHSA-RFR2-MQ9M-X2QX — `NOT_AI_REVIEW`

- Keep the code edge but change the attribution: BIC
  `5609aa5bd79a18d6f77066e6d6321d7f37349fea`, parent
  `69e9c5c1c593c7fb1cb941b21e9200aa8c0acf69`, is a human-authored 2021
  commit with no AI marker. Set verdict/status `NOT_AI`, clear AI fields, and
  remove `AI_CODE_FLAWED` from the public case.
- AI commit `f6d4cbd...` is later partial hardening, not the BIC. Keep direct
  fix `5fdba4a09f2d7a9996a504975b7ef7d63e3715bb`; vulnerable releases are
  `>=0.9.1,<=0.60.2`, fixed `0.61.0`.
- Primary evidence: [reviewed GHSA](https://github.com/advisories/GHSA-rfr2-mq9m-x2qx),
  [human BIC](https://github.com/koxudaxi/datamodel-code-generator/commit/5609aa5bd79a18d6f77066e6d6321d7f37349fea),
  and [fix](https://github.com/koxudaxi/datamodel-code-generator/commit/5fdba4a09f2d7a9996a504975b7ef7d63e3715bb).

### GHSA-WJHR-76VG-2HVC — `READY_TO_BACKFILL`

- Use candidate `21aea2d95b823a15c81a3efe87566de5dcc3befc`, released
  rewrite/carrier `e36613f3e490da51e37458a53fae36c75686533d`, and released
  minimum fix `8256b577190b446e279c81b845d8e27d0ea1fbf5`.
  Candidate/carrier have identical stable patch-id and identical affected-file
  contents; the advisory fix `77a3837...` and `8256b...` likewise have the
  same stable patch-id. This is one rewritten lineage, so uniqueness passes.
- Record vulnerable `0.3.4`, fixed `0.3.5`. Retain `77a3837...` as atomic
  patch provenance, not as the release-contained `minimum_fix_set` value.
- Primary evidence: [first-party advisory](https://github.com/cyberjunky/python-garminconnect/security/advisories/GHSA-wjhr-76vg-2hvc),
  [AI candidate](https://github.com/cyberjunky/python-garminconnect/commit/21aea2d95b823a15c81a3efe87566de5dcc3befc),
  [released candidate rewrite](https://github.com/cyberjunky/python-garminconnect/commit/e36613f3e490da51e37458a53fae36c75686533d),
  and [released fix](https://github.com/cyberjunky/python-garminconnect/commit/8256b577190b446e279c81b845d8e27d0ea1fbf5).

### GHSA-5383-J2P9-QFG3 / CVE-2026-61462 — `RESEARCH_GAP`

- The AI candidate `c156ac7675207e3dbc0c6a4b3ed6931dc96513c2`
  adds three artifact endpoints with unencoded `jobId`; fix
  `e2a81a047ab8750fa5bfa1763b5d85e5616f3994` encodes those exact sinks.
  Narrow classification to `AI_NEW_SURFACE_CONTRIBUTOR`, because the parent
  already has the same unsafe `jobId` pattern in trace/play/retry/cancel.
- For this narrowed surface, use affected `>=2.1.18,<2.1.32` and fixed
  `2.1.32`; the CNA's current `<2.1.18`/`2.1.18` range is contradicted by Git
  tag containment and the repository's first-party GHSA.
- `GHSA-7C3W-FXGH-FRC7` is the same repository, `job_id` path-traversal
  mechanism, and `e2a81a...` fix, with `<2.1.32` / `2.1.32`. Set a duplicate
  relation or exclude this provisional row; do not count both. Because the CNA
  has not declared a formal alias, do not silently merge public IDs. This
  unresolved dedupe/identity conflict keeps `uniqueness=FAIL`.
- Primary evidence: [first-party GHSA-7C3W](https://github.com/zereight/gitlab-mcp/security/advisories/GHSA-7c3w-fxgh-frc7),
  [CVE-2026-61462](https://www.cve.org/CVERecord?id=CVE-2026-61462),
  [candidate](https://github.com/zereight/gitlab-mcp/commit/c156ac7675207e3dbc0c6a4b3ed6931dc96513c2),
  and [fix](https://github.com/zereight/gitlab-mcp/commit/e2a81a047ab8750fa5bfa1763b5d85e5616f3994).

### GHSA-2JCC-MXV7-P3F9 — `READY_TO_BACKFILL`

- Restore the squash edge: candidate PR member
  `58adc823453286a8f6edb19572d59a73b73db292`, carrier
  `d886cb40c4fe95fa69ca7029a88ac7fcf7690a6e`, and released minimum fix
  `c01d48dae4806e11f2041163c92d9ad7d34632bd`. The candidate's Claude-marked
  hunk removes the explicit external-reference guard on a false invariant.
- Retain PR #974's atomic member only as fix provenance; `c01d48...` is its
  main-line squash and is absent from v1.18.0 but present in v1.18.1.
  Candidate carrier is first present by v1.13.2. This candidate/carrier
  distinction resolves the prior uniqueness ambiguity.
- Primary evidence: [reviewed GHSA](https://github.com/advisories/GHSA-2jcc-mxv7-p3f9),
  [AI PR member](https://github.com/oasdiff/oasdiff/commit/58adc823453286a8f6edb19572d59a73b73db292),
  [carrier](https://github.com/oasdiff/oasdiff/commit/d886cb40c4fe95fa69ca7029a88ac7fcf7690a6e),
  and [released fix](https://github.com/oasdiff/oasdiff/commit/c01d48dae4806e11f2041163c92d9ad7d34632bd).

### GHSA-P8RR-9CVG-CX5J — `RESEARCH_GAP`

- Keep AI BIC `61ff20fef663aaac88add4f5d72fd560ed6d2abd`, parent
  `17de8fa8fedda662733e6a94cc7d1e6f3dfed398`: it removes `_validate_url(host)`
  from the unauthenticated `/setup/test-downloader` path.
- Reject `487bdfec545e805ae416e6ddf28651bd274d6a73` as a complete fix. It checks
  only URL scheme, explicitly permits private/loopback addresses, and still
  performs `client.get(host)`. Distinct responses continue to expose an
  internal-service reachability oracle. Tag 3.2.8 contains this commit but not
  a semantic reversal of the advisory's internal-network SSRF/probing path.
- Set `minimum_fix_set=[]`, `unpatched=true`, and `unresolved_reason`: no
  complete later guard or fixed artifact has been found; 3.2.8 is only partial
  remediation. A narrower information-disclosure-only row would require a new
  advisory-scope adjudication and proof that the oracle was removed.
- Primary evidence: [CVE-2026-59101](https://www.cve.org/CVERecord?id=CVE-2026-59101),
  [AI BIC](https://github.com/EstrellaXD/Auto_Bangumi/commit/61ff20fef663aaac88add4f5d72fd560ed6d2abd),
  and [insufficient proposed fix](https://github.com/EstrellaXD/Auto_Bangumi/commit/487bdfec545e805ae416e6ddf28651bd274d6a73).

### GHSA-VCV2-R9JH-99M5 — `READY_TO_BACKFILL`

- Move the case to canonical component `alias-8fde3b61bfb7a8b43050519d` and source
  repository `ruvnet/agentic-flow`; the current `ruvnet/ruflo` source is a
  downstream dependency consumer. Merge/retire the contaminated separate
  component that currently owns the GHSA ID.
- Restore `candidate_set=[319c98616bc968b6810c6c0b49e04806e7379530,
  2a1e2777dd6a993f678d9596dd7c6c4fd0c444d9]`,
  `carrier_set=[68e60a86c92db19c62fe175295a21b073033b31f]`, and
  `minimum_fix_set=[a0f9c2bf95b6203b3e1b24f92a7e390d6774de13]`.
- Preserve per-edge topology: `319c986... -> 68e60a... -> a0f9c2...`
  (`merge_member`) and `2a1e277... -> null -> a0f9c2...` (`direct_commit`).
  Do not attach carrier `68e60a...` to the second origin. `0c2ec967...` is the
  fix merge; it is not the minimum semantic fix.
- Release evidence is npm `agentic-flow@2.0.13` gitHead
  `aa33d2f07a16da6b9cdfc7c9dede4ffde86c1208` containing both candidates and
  npm 2.0.14 gitHead `a0f9c2...`. Add formal alias `CVE-2026-58195` and keep
  `AI_DIRECT_ROOT`.
- Primary evidence: [first-party GHSA](https://github.com/ruvnet/agentic-flow/security/advisories/GHSA-vcv2-r9jh-99m5),
  [CVE-2026-58195](https://www.cve.org/CVERecord?id=CVE-2026-58195),
  [first candidate](https://github.com/ruvnet/agentic-flow/commit/319c98616bc968b6810c6c0b49e04806e7379530),
  [second candidate](https://github.com/ruvnet/agentic-flow/commit/2a1e2777dd6a993f678d9596dd7c6c4fd0c444d9),
  and [atomic fix](https://github.com/ruvnet/agentic-flow/commit/a0f9c2bf95b6203b3e1b24f92a7e390d6774de13).

## Closure accounting

- `READY_TO_BACKFILL`: 6
- `RESEARCH_GAP`: 4
- `NOT_AI_REVIEW`: 2
- Total: 12 distinct assigned cases.

The true evidence gaps are the missing release artifact for `4P6X`, the
missing release boundary for `8JQH`, the duplicate/CNA conflict for `5383`,
and the non-reversing purported fix for `P8RR`. The other eight cases are
canonical/publication wiring or attribution corrections; no additional
source hunt is required before applying those corrections.
