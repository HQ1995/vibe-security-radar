# fp211 unseen UNKNOWN remainder (exact 4)

Verdict first: **0 PASS**. GHSA-CGJ8-7M5Q-X5GV and GHSA-MF7V-X7R6-FQ57 stay **NARROW**. GHSA-48P8-G2FX-3WWM and GHSA-FP43-VJ7G-PG92 stay **UNKNOWN** because private-fork members and OmniFaces blob/tag bytes are missing. Worker PASS is a proposal and this packet emits none. packet_delta=0. Canonical strict count remains **84**. Publication and more-than-200 claims remain **HOLD**. Causal admission is false.

## Scope

Leader freeze, no padding or substitution, ordinal order:

1. ord116 GHSA-CGJ8-7M5Q-X5GV (ai_hunk+but_for)
2. ord129 GHSA-48P8-G2FX-3WWM (ai_hunk+topology+but_for)
3. ord153 GHSA-MF7V-X7R6-FQ57 (ai_hunk+topology+but_for+fix_reversal+release)
4. ord154 GHSA-FP43-VJ7G-PG92 (ai_hunk+but_for+fix_reversal+release)

Other remaining fp211 UNKNOWN rows (ord51 singlegate, ord53 threegate, ord56/ord84 releaseonly) are out of scope. Inherited fp211 PASS values are routing only. Atomic AI members are never transferred onto merge/squash/rebase carriers or Conductor auto-commits. Trailer transfer is forbidden. Incomplete remediation requires an explicit AI security attempt and a same-boundary patch delta.

Conservation: assigned = reviewed + unreviewed = 4 + 0 = 4.

## Per-case

### GHSA-CGJ8-7M5Q-X5GV (116, coollabsio/coolify) - NARROW

Identity PASS on the published repository advisory (global /advisories JSON 404). Conductor e1fe5863 adds the TrustHosts Cache::get early-return. AI-hunk FAIL: no AI marker. Topology NARROW: any-ancestor of v4.0.0-beta.437, absent from first-parent. But-for NARROW: the skip is material for host validation, but ResetPassword url(route) and TrustProxies '*' already existed, and the change is not AI. Claude e1d4b468 reverses TrustHosts and uses base_url(); v4.0.0-beta.471 ships unmarked merge 98569e4e ResetPassword and still has the circular TrustHosts skip. Release NARROW. Uniqueness PASS versus counted GHSA-X9QH.

### GHSA-48P8-G2FX-3WWM (129, argoproj/argo-workflows) - UNKNOWN

Identity PASS on reviewed GHSA plus repository advisory. 251bb231/2727f3f7 are single-parent merge-from-fork objects with Claude trailers that add wholesale ArtifactGC. Fork members are unrecovered, so AI-hunk, topology, and but-for stay UNKNOWN. Incomplete-remediation same-boundary delta on merge.go is visible in 358cc396/277e9cef but is not permission to infer authorship. Fix-reversal PASS. Release PASS: v3.7.14/v4.0.5 first-parent contain the candidates; v3.7.15/v4.0.6 peel to the closers. Uniqueness PASS versus uncounted GHSA-3WF5/GHSA-3775.

### GHSA-MF7V-X7R6-FQ57 (153, MISP/MISP) - NARROW

Identity NARROW: unreviewed GHSA, empty affected, repository advisory 404. Atomic Claude bc182d55 id-strips Event.php freetext/module create paths. AI-hunk PASS at that file. Topology NARROW: any-ancestor of v2.5.42, not first-parent. But-for NARROW for the multi-controller advisory. Fix-reversal FAIL: 025f7115 is Taxonomy.php and leaves the Event.php blob unchanged. Release NARROW: candidate and listed closer appear together in v2.5.42. Uniqueness PASS versus counted GHSA-243V.

### GHSA-FP43-VJ7G-PG92 (154, omnifaces/omnifaces) - UNKNOWN

Identity PASS on reviewed GHSA plus repository advisory. Atomic Claude aa42da36 names the forged combined-resource boundary. Blob contents are missing (blob:none). AI-hunk UNKNOWN. Topology PASS from commit metadata (one parent, no carrier). But-for NARROW: HashParam, push, and source-map are sibling families. Fix-reversal FAIL: a52b9246 is SourceMapResourceHandler only. Release UNKNOWN: no git tag contains either SHA; 5.4.2 is absent; no hashed Maven bytes. Uniqueness PASS versus uncounted GHSA-VP6R.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=84. current_leader_accepted_count=84. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
