# GHSA-8G7G / GHSA-56C3 identity re-audit

Date: 2026-08-30  
Scope: `alias-c5a7e76e9787edf4ea076555`, `alias-f8d8e53edbeacc7b689a133b`,
`GHSA-8G7G-HMWM-6RV2`, `GHSA-56C3-VFP2-5QQJ`, and
`CVE-2026-42449`.

## Verdict

**WRONG_BINDING — HOLD the current c5a7 publication.**

- **Do not merge.** The two GHSAs are distinct first-party advisories, not
  aliases or duplicate records.
- **Do not mark either NOT_AI.** Each has a separate AI-marked causal commit
  and a separate direct fix.
- The safe resolution is an **atomic two-row un-fold/split**: restore c5a7 to
  `GHSA-56C3-VFP2-5QQJ` / `CVE-2026-42449`, and restore f8d8 as the canonical
  `GHSA-8G7G-HMWM-6RV2` row scoped only to advisory issue (1), the raw URL path
  segments.
- Until both rows and their publication overrides are changed in one release
  transaction and the rebuilt catalog passes the gates, c5a7 must remain
  **HOLD**. A one-row patch would either keep the wrong identity or make one of
  the two valid cases disappear.

## Official identity comparison

| Field | GHSA-8G7G-HMWM-6RV2 | GHSA-56C3-VFP2-5QQJ |
|---|---|---|
| Repository / package | `czlonkowski/n8n-mcp` / npm `n8n-mcp` | Same repository and package |
| Official identifiers | GHSA only; GitHub reports **no known CVE** | GHSA plus **CVE-2026-42449** |
| Mechanism | One advisory bundling three independently reported issues: unencoded caller IDs in API URL path segments, redirect-following SSRF, and unredacted telemetry payloads | SDK embedder `SSRFProtection.validateUrlSync()` lacks IPv6 checks; IPv4-mapped/private IPv6 bypasses the IPv4-only guard and forwards `x-n8n-api-key` |
| CWE | CWE-22, CWE-200, CWE-918; this catalog claim is narrowly issue (1) / CWE-22 | CWE-918 |
| Affected / fixed | `< 2.50.1`; fixed `2.50.1` | `>= 2.47.4, < 2.47.14`; fixed `2.47.14` |
| Repository advisory publication | `2026-05-04T10:14:44Z` | `2026-04-22T20:37:28Z` |
| Global Advisory Database publication | `2026-05-08T17:00:09Z` | `2026-04-30T18:12:54Z` |
| Withdrawal / CVE state | `withdrawn_at=null`; no CVE | `withdrawn_at=null`; CVE.org state `PUBLISHED` |
| Direct fix | `1cfe9c6bddb4b1634e6e23323c18ea35fd196999` | `9639f757853149f0cb16663cc8b6b6468f27a25f` |

Primary sources:

- [GHSA-8G7G GitHub advisory](https://github.com/advisories/GHSA-8g7g-hmwm-6rv2)
  and [repository advisory API](https://api.github.com/repos/czlonkowski/n8n-mcp/security-advisories/GHSA-8g7g-hmwm-6rv2)
- [GHSA-56C3 GitHub advisory](https://github.com/advisories/GHSA-56c3-vfp2-5qqj)
  and [repository advisory API](https://api.github.com/repos/czlonkowski/n8n-mcp/security-advisories/GHSA-56c3-vfp2-5qqj)
- [CVE-2026-42449 CVE.org record](https://cveawg.mitre.org/api/cve/CVE-2026-42449)

The identifiers have no cross-membership. Same repository, package, and one
shared CWE are not alias evidence. The mechanisms, release intervals, fix
objects, publication dates, and reporters are different.

## Independent causal check

### GHSA-8G7G-HMWM-6RV2: keep as AI_DIRECT_ROOT on f8d8

- Candidate
  [`74f05e937fa7d94babe3507510caa17ce17a698c`](https://github.com/czlonkowski/n8n-mcp/commit/74f05e937fa7d94babe3507510caa17ce17a698c)
  is single-parent (`150de3d1...`) and adds `src/services/n8n-api-client.ts`
  from absent to present. It creates raw interpolations such as
  `/workflows/${id}`, `/executions/${id}`, and `/credentials/${id}`. Its commit
  message says `Generated with Claude Code` and carries
  `Co-Authored-By: Claude`.
- Direct fix
  [`1cfe9c6bddb4b1634e6e23323c18ea35fd196999`](https://github.com/czlonkowski/n8n-mcp/commit/1cfe9c6bddb4b1634e6e23323c18ea35fd196999)
  wraps those path values with `encodeApiPathSegment` and is the fix referenced
  by the advisory.
- The admissible catalog scope is **only advisory issue (1)**. The redirect
  SSRF and telemetry siblings in the same advisory must not be attributed to
  candidate 74f05e93 without their own causal proof.

Result: identity, AI hunk, topology, but-for, fix reversal, release, and
uniqueness are independently **PASS** for the narrow path-segment claim.

### GHSA-56C3-VFP2-5QQJ / CVE-2026-42449: keep as AI_INCOMPLETE_REMEDIATION on c5a7

- Candidate
  [`d9d847f230923d96e0857ccecf3a4dedcc9b0096`](https://github.com/czlonkowski/n8n-mcp/commit/d9d847f230923d96e0857ccecf3a4dedcc9b0096)
  is single-parent (`643c98bc...`), carries
  `Co-authored-by: Claude Opus 4.6`, and first adds the synchronous
  `validateUrlSync()` guard. The new method blocks named metadata hosts,
  localhost, and IPv4 private ranges but contains no IPv6 gate.
- The candidate is the official fix for the earlier published
  [GHSA-4GGG-H7PH-26QR](https://github.com/advisories/GHSA-4ggg-h7ph-26qr) /
  [CVE-2026-39974](https://cveawg.mitre.org/api/cve/CVE-2026-39974), whose fixed
  release is `2.47.4`. Those IDs describe the preceding remediation context;
  they are **not aliases** of GHSA-56C3.
- GHSA-56C3's affected interval begins at exactly `2.47.4`. Direct fix
  [`9639f757853149f0cb16663cc8b6b6468f27a25f`](https://github.com/czlonkowski/n8n-mcp/commit/9639f757853149f0cb16663cc8b6b6468f27a25f)
  extends the same validator with IPv4-mapped/compatible IPv6, 6to4, NAT64,
  ULA, link-local, and site-local handling and releases `2.47.14`.

Result: the exact residual of the Claude-coauthored IPv4-only remediation is
closed by 9639f757. The seven gates remain **PASS** for this identity, but none
of GHSA-8G7G's path-segment gates may be inherited by it.

## Current wrong binding

Read-only `ledger_store.py get` on 2026-08-30 confirmed both live rows are at
revision 1:

1. `alias-c5a7e76e9787edf4ea076555` has the correct underlying
   `advisory_ids=[CVE-2026-42449, GHSA-56c3-vfp2-5qqj]`, but its
   `site_publication.canonical_case_id`, contribution class, introducer, and
   published candidate/fix were overwritten with GHSA-8G7G / 74f05e93 /
   1cfe9c6b evidence. Its `squash_audit` also mixes three unrelated advisories.
2. `alias-f8d8e53edbeacc7b689a133b` has the correct sole advisory ID
   `GHSA-8g7g-hmwm-6rv2` and the correct 74f05e93 -> 1cfe9c6b chain, but is
   `publish:false`, incorrectly `folded_into` c5a7.
3. `scripts/tp_publication_overrides.json` keys the 74f05e93 / 1cfe9c6b
   override to c5a7, perpetuating the swap.
4. `web/src/generated/research-data.json` consequently contains only
   GHSA-8G7G under class c5a7 and contains no GHSA-56C3 or CVE-2026-42449
   case. At the inspected snapshot, `case_count=254`; a correct split is a net
   **+1 unique case**, assuming no concurrent census changes.

The `artifacts/ledger-summary.md` statement that f8d8 and c5a7 were the same
official GHSA is therefore false.

## Exact field delta required

Apply the following as one transaction; if that cannot be guaranteed, land
only a HOLD marker and do not publish either mutation.

### c5a7 (expected revision 1)

- Preserve `advisory_ids` exactly as
  `["CVE-2026-42449","GHSA-56c3-vfp2-5qqj"]`.
- Set `site_publication.publish=true`,
  `canonical_case_id="GHSA-56C3-VFP2-5QQJ"`, and
  `contribution_class="AI_INCOMPLETE_REMEDIATION"`.
- Set `site_scope="AI_INCOMPLETE_FIX"` and retain
  `site_tier="ALL_GATES_PASS"` only with the GHSA-56C3-specific new audit.
- Set `candidate_set=["d9d847f230923d96e0857ccecf3a4dedcc9b0096"]`,
  `carrier_set=[]`, and
  `minimum_fix_set=["9639f757853149f0cb16663cc8b6b6468f27a25f"]`.
- Set all seven gate fields to `PASS`; cite
  `research/orchestrator-260814-ghsa200-canonical94/ledger.jsonl` and this
  re-audit as their source. Do not reuse the path-segment gate text.
- Set the release boundary to first vulnerable `v2.47.4`, last vulnerable
  `v2.47.13`, fixed `v2.47.14`.
- Replace the mixed `squash_audit` with GHSA-56C3-only evidence. In its
  `ir_chain`, record GHSA-4GGG/CVE-2026-39974 as the preceding remediation
  context, not aliases; attempted remediation is d9d847f2 and final closure is
  9639f757.

### f8d8 (expected revision 1)

- Preserve `advisory_ids=["GHSA-8g7g-hmwm-6rv2"]`.
- Replace `site_publication` with `publish=true`,
  `canonical_case_id="GHSA-8G7G-HMWM-6RV2"`, and
  `contribution_class="AI_DIRECT_ROOT"`; delete `folded_into` and
  `kept_class_id`.
- Set `site_scope="AI_ROOT_CAUSE"` and `site_tier="ALL_GATES_PASS"` using
  the new seven-gate path-segment audit, not the old inherited fold.
- Set `candidate_set=["74f05e937fa7d94babe3507510caa17ce17a698c"]`,
  `carrier_set=[]`, and
  `minimum_fix_set=["1cfe9c6bddb4b1634e6e23323c18ea35fd196999"]`.
- Set the scope statement explicitly to advisory issue (1): caller-controlled
  IDs interpolated into n8n API URL path segments. Exclude redirect SSRF and
  telemetry payload exposure.
- Set affected `<2.50.1`, fixed `2.50.1`.

### Required companion publication changes

- Move the 74f05e93 / 1cfe9c6b publication override from c5a7 to f8d8.
- Add a c5a7 override for d9d847f2 / 9639f757 and the GHSA-56C3 release,
  code-evidence, and fix-object witnesses.
- Regenerate the catalog; require exactly one case for each GHSA, only
  `CVE-2026-42449` as the GHSA-56C3 alias, and no cross-aliasing.

## JSONL proposal boundary

There is deliberately **no single-row ledger-store JSONL proposal**: it would
be unsafe. The machine-readable transaction intent is below, but the leader
must compose it into two full-row `expected_revision:1` patches plus the
companion override changes before applying it.

```json
{"operation":"ATOMIC_UNFOLD_PROPOSAL","hold_if_not_atomic":true,"expected_revisions":{"alias-c5a7e76e9787edf4ea076555":1,"alias-f8d8e53edbeacc7b689a133b":1},"restore":{"alias-c5a7e76e9787edf4ea076555":{"case_id":"GHSA-56C3-VFP2-5QQJ","aliases":["CVE-2026-42449"],"contribution_class":"AI_INCOMPLETE_REMEDIATION","candidate_set":["d9d847f230923d96e0857ccecf3a4dedcc9b0096"],"carrier_set":[],"minimum_fix_set":["9639f757853149f0cb16663cc8b6b6468f27a25f"]},"alias-f8d8e53edbeacc7b689a133b":{"case_id":"GHSA-8G7G-HMWM-6RV2","aliases":[],"contribution_class":"AI_DIRECT_ROOT","candidate_set":["74f05e937fa7d94babe3507510caa17ce17a698c"],"carrier_set":[],"minimum_fix_set":["1cfe9c6bddb4b1634e6e23323c18ea35fd196999"],"scope":"advisory issue (1), raw n8n API URL path segments only"}},"required_companion_change":"move publication override 74f05e93/1cfe9c6b from c5a7 to f8d8; add c5a7 d9d847f2/9639f757 evidence"}
```

This proposal is review metadata, **not** accepted input to
`scripts/ledger_store.py`.
