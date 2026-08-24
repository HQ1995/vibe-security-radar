# fp211 unseen two-gate remainder (exact 8)

Verdict first: **0 PASS**. Seven rows stay **NARROW**. GHSA-WJHR-76VG-2HVC is **UNKNOWN** because git tags named 0.3.4/0.3.5 do not contain the candidate or the fix and this packet has no hashed registry bytes. Worker PASS is a proposal and this packet emits none. packet_delta=0. Canonical strict count remains **84**. Publication and more-than-200 claims remain **HOLD**. Causal admission is false.

## Scope

Leader freeze, no padding or substitution, ordinal order:

1. ord80 GHSA-RQPP-RJJ8-7WV8 (but_for+fix_reversal)
2. ord86 GHSA-7X5Q-8F6H-RJRC (topology+fix_reversal)
3. ord95 GHSA-G5CG-8X5W-7JPM (topology+but_for)
4. ord98 GHSA-5GVR-V6QV-H5MM (topology+fix_reversal)
5. ord100 GHSA-C4M7-2GWP-VW76 (topology+but_for)
6. ord108 GHSA-WJHR-76VG-2HVC (topology+release)
7. ord115 GHSA-MGXW-V6RH-WCV6 (topology+but_for)
8. ord124 GHSA-G353-MGV3-8PCJ (identity+topology)

Other unseen two-gate rows are out of scope. Inherited fp211 PASS values are routing only. Atomic AI members are never transferred onto merge/squash/rebase carriers. Trailer transfer is forbidden. Incomplete remediation is not used: none of these eight is an explicit same-boundary security-attempt residual.

Conservation: assigned = reviewed + unreviewed = 8 + 0 = 8.

## Per-case

### GHSA-RQPP-RJJ8-7WV8 (80, openclaw/openclaw) - NARROW

Identity PASS on the reviewed first-party advisory. Atomic Claude 079af0d0 adds hasTokenAuth device skip. AI-hunk PASS. Topology NARROW: any-ancestor of v2026.3.11, absent from first-parent walks of 8000 commits. But-for NARROW: the GHSA invariant is unbound scopes; the AI hunk does not bind scopes. Fix-reversal NARROW: 5e389d5e clears unbound scopes, a later residual. Release NARROW for first-parent containment of the counted member. Uniqueness PASS versus canonical84; shared SHA is not dedupe.

### GHSA-7X5Q-8F6H-RJRC (86, conductor-oss/conductor) - NARROW

Identity NARROW: unreviewed GHSA, empty affected, no repository advisory. Atomic Claude 840ec19c replaces Nashorn --no-java with GraalJS HostAccess.ALL. AI-hunk PASS. But-for PASS for that guard weakening. Topology NARROW: member is not first-parent of v3.21.21; unmarked merge d874e6e5 is. Fix-reversal NARROW: 87a7d96a ships in v3.30.0/v3.30.1 with js.load residual; c691e35e is the second hop and first-parent of v3.30.2. Release NARROW. Uniqueness PASS.

### GHSA-G5CG-8X5W-7JPM (95, openclaw/openclaw) - NARROW

Identity PASS. Atomic Claude 01d568c9 is not a tag ancestor. Carrier 483fba41 is any-ancestor of v2026.3.28, not first-parent. heartbeat-runner.ts member blob equals carrier and differs from the tag. But-for NARROW: parent already scheduled exec-event heartbeats. Fix a30214a6 first-parent of v2026.3.31. Release NARROW. Uniqueness PASS.

### GHSA-5GVR-V6QV-H5MM (98, thedotmack/claude-mem) - NARROW

Identity PASS on the reviewed GHSA. Atomic Claude 924a11ee introduces delimiter-free concat plus slice(0,16). Member is not an ancestor of mega-squash c6f93298 or v11.0.0. Carrier is first-parent of v11.0.0 and mixed-tool. Fix f32fda8b is a two-parent merge that inserts a NUL delimiter and still truncates. Topology, fix-reversal, and release NARROW. Uniqueness PASS.

### GHSA-C4M7-2GWP-VW76 (100, Q00/ouroboros) - NARROW

Identity PASS. Atomic Claude d30b6175 adds OUROBOROS_CLI_PATH. Member is not an ancestor of squash 4aaf9147. Adapter blobs are pairwise unequal versus v0.38.2. GHSA names untrusted project .env RCE, a sibling of the CLI-path override. Fix 4e70b760 is first-parent of v0.39.0 and is the .env denylist. Topology, but-for, fix-reversal, and release NARROW. Uniqueness PASS.

### GHSA-WJHR-76VG-2HVC (108, cyberjunky/python-garminconnect) - UNKNOWN

Identity PASS. Atomic Claude 21aea2d9 dump() under umask. But-for PASS. Fix 77a3837f is the atomic 0o600/0o700 closer. Topology NARROW: listed carrier f74174a5 is Merge commit from fork whose second parent is the fix. Release UNKNOWN: tags 0.3.4 and 0.3.5 exist and contain neither commit; no hashed PyPI artifacts. Uniqueness PASS.

### GHSA-MGXW-V6RH-WCV6 (115, nesquena/hermes-webui) - NARROW

Identity NARROW: unreviewed GHSA, repo advisory 404. Atomic Claude d2b27f6f adds profiles. Parent already had unscoped sessions search. Member any-ancestor of v0.51.268; routes.py blob unequal. Fix member 8d8ae89d adds _profiles_match and is not a tag ancestor. Carrier 2c7b5300 peels v0.51.269. Distinct from GHSA-VVFR. Uniqueness PASS.

### GHSA-G353-MGV3-8PCJ (124, openclaw/openclaw) - NARROW

Identity PASS on the first-party encryptKey webhook advisory after removing GHSA-xh72 aliases. Atomic Claude b0c67ea0 replaces "webhook mode not implemented". Member is not a tag ancestor. Carrier 5c2cb6c5 is first-parent of v2026.2.12. Fix 7844bc89 is first-parent of v2026.3.12. Topology and release NARROW. Uniqueness PASS versus XH72 and Q447.

## Claim boundary

This packet does not edit tracked files, canonical ledgers, publication data, or other worker directories. It does not commit or push. Worker PASS remains a proposal; this packet has zero PASS. packet_delta=0. start_count=84. current_leader_accepted_count=84. Publication stays HOLD. Greater-than-200 remains unsupported.

Status is **TERMINAL**. Expansion stopped. No further candidates.
