# Strict 200 CVE/GHSA Closure

Date: 2026-08-12

Repository: `/home/hanqing/agents/ai-slop`

Base ledger: `autoresearch/orchestrator-260811-atomic150/strict-ledger-union-v2/ledger.jsonl`

## Result

The strict ledger now contains exactly **200 unique published CVE/GHSA identifiers**:

- **101 CVEs**
- **99 GHSAs**
- **110 unique semantic vulnerability components**
- **120 accepted atomic edge occurrences**
- **119 unique `(AI candidate, fix)` pairs**
- **0 duplicate public IDs**
- **0 malformed public IDs**

This is deliberately an identifier count, not a claim of 200 independent vulnerabilities. CVE/GHSA aliases and same-mechanism duplicate advisories remain grouped into 110 semantic components.

The frozen v2 base contributed 190 IDs across 107 components. V3 adds three causally closed components with two IDs each and four first-party advisory amendments to accepted components:

`190 + (3 × 2) + 4 = 200`.

## Admission boundary

A new component is accepted only when all of these hold:

1. The CVE or GHSA is published and not withdrawn.
2. A concrete atomic commit has an explicit AI marker in its own metadata.
3. The candidate's parent-to-candidate delta creates or materially contributes to the vulnerable mechanism.
4. An atomic security fix reverses that mechanism.
5. Git ancestry connects the atomic AI commit to the atomic fix.
6. A merge or squash carrier is recorded only as topology evidence, never substituted for an unverified member.

OSV `introduced`, version boundaries, same-file overlap, commit subjects, and model votes were used only for routing. None is sufficient for admission.

## Three new causal components

| IDs | Atomic AI cause | Atomic fix | Why causal |
|---|---|---|---|
| `CVE-2026-54447`, `GHSA-WJHR-76VG-2HVC` | `21aea2d95b823a15c81a3efe87566de5dcc3befc` | `77a3837f1f79d486663c9646438e70e8319e1a48` | Claude-coauthored `21aea2d` replaces `garth` with the native DI OAuth client and creates `Client.dump()` using ordinary `mkdir`/`write_text`, exposing the refresh-token store to the process umask. `77a3837` changes that same sink to a `0700` directory and `0600` `O_NOFOLLOW` file. Carrier `f74174a` is not used as the fix edge. |
| `CVE-2026-40583`, `GHSA-Q8WX-2CRX-C7PP` | `361e71d4329b672482531122117631ec5358953a` | `2f5a3a237ea519b48d71e6e3093c89f60694c7be` | Claude-coauthored `361e71d` creates SmartOp and orders fee debit plus nonce increment before operation checks that can fail. `2f5a3a2` completes validate-before-mutate for every SmartOp type. Partial predecessor `45bcf70` fixed only governance operations and is not treated as the complete reversal. |
| `CVE-2026-42212`, `GHSA-92VG-F4FQ-FXM9` | `d1944bca6e984665fb98f5ea824c6c370fd618d6` | `9d0ba808afd143ede448026a5dc681bfdc5c138d` | Claude-coauthored v1.0.0 commit `d1944bc` introduces VMID XML parsing for companion `.vmid` files. `9d0ba80` prohibits DTDs, disables external resolution, and adds entity/document-size bounds. |

First-party sources:

- Garmin: [published GitHub advisory](https://github.com/advisories/GHSA-wjhr-76vg-2hvc), [atomic fix](https://github.com/cyberjunky/python-garminconnect/commit/77a3837f1f79d486663c9646438e70e8319e1a48)
- UltraDAG: [repository advisory](https://github.com/ultradagcom/core/security/advisories/GHSA-q8wx-2crx-c7pp), [complete atomic fix](https://github.com/ultradagcom/core/commit/2f5a3a237ea519b48d71e6e3093c89f60694c7be)
- SolidCAM: [repository advisory](https://github.com/anzory/SolidCAM-GPPL-IDE/security/advisories/GHSA-92vg-f4fq-fxm9), [atomic hotfix](https://github.com/anzory/SolidCAM-GPPL-IDE/commit/9d0ba808afd143ede448026a5dc681bfdc5c138d)

## Four public-ID amendments

These add identifiers, not vulnerability components:

| Existing component | Added public ID | First-party closure |
|---|---|---|
| `CVE-2026-67530` webhook SSRF | `GHSA-8JQH-598V-RFXC` | The [published repository advisory](https://github.com/ArnasDon/wacrm/security/advisories/GHSA-8jqh-598v-rfxc) names the same CVE and fix `23838a99`. |
| `CVE-2026-34510` Windows media/UNC path handling | `GHSA-H3X4-HC5V-V2GM` | The [repository advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-h3x4-hc5v-v2gm) covers the same mechanism and fix `93880717`. Its polluted global object must **not** import `CVE-2026-34426`, which is a different environment-normalization flaw. |
| `CVE-2026-59726` Ruflo unauthenticated MCP bridge RCE | `GHSA-C4HM-4H84-2CF3` | GitHub's repository-advisory API returned `state=published` and `cve_id=CVE-2026-59726` for the [advisory](https://github.com/ruvnet/ruflo/security/advisories/GHSA-c4hm-4h84-2cf3). |
| `CVE-2026-58195` agentic-flow MCP command injection | `GHSA-VCV2-R9JH-99M5` | GitHub's repository-advisory API returned `state=published` and `cve_id=CVE-2026-58195` for the [advisory](https://github.com/ruvnet/agentic-flow/security/advisories/GHSA-vcv2-r9jh-99m5). |

## Negative controls retained

The following tempting cases were not used to reach 200:

- **SolidCAM `CVE-2026-42213`**: the same v1.0.2 hotfix also repairs `inc` path traversal, but the clickable-`inc` feature originates in `492e7fe7df74a6d0b68afeb63c1f15333b901e99`, which has no explicit AI attribution. Sharing a fix with the XXE component is not enough.
- **UltraDAG `CVE-2026-42278`**: the decisive derived-pocket authorization change is `c21e8dcd5281cb4b0fda21529ed74ba46e62d873`, which has no explicit AI marker. Earlier AI-authored SmartAccount code is not promoted over the later human causal change.
- **Trek `CVE-2026-40184` / `CVE-2026-40185`**: vulnerable Immich trip/photo routes blame to human commits `9f807517` and `ef9880a2`; later Claude security-hardening commits do not create the missing trip-authorization checks.
- **CPhalcon `CVE-2026-54736`**: the non-constant-time HMAC comparison blames to human commit `99def424` from 2021. The Claude-assisted 2026 exception refactor preserves it.
- **CPhalcon `CVE-2026-57584`**: the catastrophic `(/.*)*` default-route expression predates the Claude-assisted router performance work; those changes reorganize the already-vulnerable route handling.
- **AutoBangumi `CVE-2026-59101` / `GHSA-P8RR-9CVG-CX5J`** remains unresolved rather than promoted: its first-party fix still permits private and loopback targets, so no exact reversal is available.

## Squash and merge handling

- Garmin fix carrier `f74174a5647e1af78eca1f8f3a0aa5dc5a899947` has atomic fix member `77a3837f1f79d486663c9646438e70e8319e1a48`; the ledger edge ends at the member.
- UltraDAG uses complete atomic fix `2f5a3a2`; partial fix `45bcf70` is history, not the accepted reversal.
- SolidCAM origin and fix are direct atomic commits.
- Existing v2 squash-member edges remain unchanged and continue to require a distinct carrier SHA.

## Artifacts

- Supplement and alias amendments: `autoresearch/orchestrator-260811-atomic150/strict-200-v3/supplement.json`
- Final ledger: `autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl`
- Machine summary: `autoresearch/orchestrator-260811-atomic150/strict-200-v3/summary.json`

SHA-256:

- `supplement.json`: `09a45c145313862f2d60b47cfe1df23bce9a1d7d3b6140592a913a364dfcbd4d`
- `ledger.jsonl`: `0cc19a49406c57026d58a064987f50579f2c47ac016881746c73ccd6c2470a81`
- `summary.json`: `69dd6c35de1455bf9cee88420aed570c576a190a4d143202d01a26cc3d37b81e`
- Canonical ledger JSON hash: `afc810cec757df378cc63be935a53fe6635dbb7ede72bc32035880ffcde23c23`

## Replay

Generate the final ledger from the frozen 190-ID base:

```zsh
uv run --project cve-analyzer python scripts/merge_strict_ai_causal_supplement.py \
  --supplement autoresearch/orchestrator-260811-atomic150/strict-200-v3/supplement.json \
  --output-dir autoresearch/orchestrator-260811-atomic150/strict-200-v3
```

Check the accounting invariants:

```zsh
jq -s '
  def edges: [.[].evidence[]?.accepted_edges[]?];
  {
    components: length,
    component_ids_unique: ([.[].component_id] | unique | length),
    public_id_occurrences: ([.[].public_ids[]] | length),
    public_ids_unique: ([.[].public_ids[]] | unique | length),
    cves: ([.[].public_ids[] | select(startswith("CVE-"))] | length),
    ghsas: ([.[].public_ids[] | select(startswith("GHSA-"))] | length),
    accepted_edge_occurrences: (edges | length),
    accepted_unique_pairs: (edges | map([.candidate_sha,.fix_sha] | join("->")) | unique | length),
    alias_amendments: ([.[].evidence[]? | select(.kind == "public_id_alias_amendment")] | length)
  }
' autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl
```

Expected result:

```json
{
  "components": 110,
  "component_ids_unique": 110,
  "public_id_occurrences": 200,
  "public_ids_unique": 200,
  "cves": 101,
  "ghsas": 99,
  "accepted_edge_occurrences": 120,
  "accepted_unique_pairs": 119,
  "alias_amendments": 4
}
```

Run the merger regression checks:

```zsh
uv run --project cve-analyzer pytest -q scripts/tests/test_apply_strict_causal_adjudications.py
```

Observed: `5 passed`.

## Claim

The defensible claim is:

> The strict artifact contains 200 unique published CVE/GHSA identifiers grouped into 110 semantic vulnerability components. Every component has at least one accepted atomic AI causal edge; the four newly added advisory IDs amend already accepted components. The new admissions do not rely on OSV `introduced`, same-file overlap, a merge/squash carrier, or a model vote as proof.

It is not defensible to call this “200 independent vulnerabilities”; aliases and duplicate publications are intentionally conserved and grouped.
