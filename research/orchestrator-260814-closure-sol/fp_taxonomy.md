# False-positive taxonomy and funnel accounting

## Accounting boundary

The frozen audit starts from 211 mechanism-component hypotheses and maps them to 212 public GHSA cases. At the public-case unit, the dispositions are 65 `CONFIRM`, 84 `NARROW`, 54 `FALSE_POSITIVE`, and 9 `UNKNOWN`; `CONFIRM` plus `NARROW` gives 149 causal-valid cases. The downstream canonical overlay contains 84 strict released first-party GHSA identities, but it is a `HOLD` snapshot rather than a publication admission. Sources: [FINAL_REPORT.md](../orchestrator-260813-fp211-audit/FINAL_REPORT.md), [audit summary.json](../orchestrator-260813-fp211-audit/summary.json), [public_cases.jsonl](../orchestrator-260813-fp211-audit/public_cases.jsonl), and [canonical84 summary.json](../orchestrator-260814-ghsa200-canonical84/summary.json).

| Accounting layer | Exact count | Interpretation |
|---|---:|---|
| Mechanism-component hypotheses | 211 | The audited hypothesis inventory, not a public-case count. |
| Public GHSA cases | 212 | One extra case results from two non-alias ChurchCRM advisories sharing one mechanism component. |
| Public-case `NARROW` | 84 | Causal contribution retained only at the row's narrowed scope; the mechanism-row count is 83. |
| Public-case `UNKNOWN` | 9 | Excluded from the causal-valid count. |
| Public-case `FALSE_POSITIVE` | 54 | Rejected mechanisms classified below. |
| Causal-valid public cases | 149 | `CONFIRM` plus `NARROW`; this is not the strict released count. |
| Canonical strict released first-party GHSA identities | 84 | Downstream multi-lane `HOLD` overlay; publication and integration remain closed. |

The canonical overlay is not a simple subset of the 212-case source table: it preserves the source layer while adding separately reviewed identities from other lanes. The two occurrences of 84 therefore mean different things: 84 narrowed source cases and 84 strict released identities in the downstream overlay.

## The 54 false positives by class

Counts and complete ordinal membership come from [experience.json](../orchestrator-260813-fp211-audit/experience.json). That canonical taxonomy folds capitalization variants in the row-level `false_positive_class` field. Each representative is the corresponding line/ordinal in [final_mechanisms.jsonl](../orchestrator-260813-fp211-audit/final_mechanisms.jsonl).

### `wrong_edge` - 20

Ordinals: 4, 9, 13, 15, 16, 45, 144, 145, 149, 150, 151, 158, 159, 165, 172, 173, 174, 175, 177, 178.

Representative: ordinal 4, `GHSA-GG5M-55JJ-8M5G`; candidate `1d94f7a3e3cebeba404aa4b48cf3d0742750595f`, minimum fix `7d65d5e77e89a199a62d737634eaa26dbb04d037`. The candidate added a Lucene helper, while the advisory and fix concerned a pre-existing Cypher `node_labels` sink, so the candidate/fix pair did not reverse the named mechanism.

### `old_bug_preserving_refactor` - 8

Ordinals: 11, 17, 38, 41, 59, 94, 140, 146.

Representative: ordinal 11, `GHSA-MG93-F9MW-WPGJ`; candidate `e193701defac96a4403470971363faf0e32a84d6`, minimum fix `ba3db953c0d8675e2e3ecc29113a332b570b2cb9`. The AI change copied an unsafe parent ternary into a helper, while the affected release still used the older unsafe path; removing the candidate did not remove the vulnerability.

### `unattempted_env_family` - 7

Ordinals: 202, 203, 204, 205, 207, 208, 209.

Representative: ordinal 202, `GHSA-CCWH-WWPP-6WG5`; candidate `3affd5e8f9ca6e2f51d00bebde6c1c277e8a5161`, minimum fixes `0f3aecb3b76cc8f194ef045ad241bc239025b0ae`, `254872e11bfb60faa7d90cde249f9cd01bae1858`, and `91590132f68aee16ece7061048bdc9917ef6c00b`. A member-only environment-key change was dropped before release and never attempted the sibling key family later named by the advisory.

### `unreleased_commit_only` - 5

Ordinals: 7, 36, 48, 69, 72.

Representative: ordinal 7, `GHSA-GXGQ-RPMR-R8XR`; candidate `2b72d8a7c153e2afb22245ad9e40e0c7d5b1aa70`, minimum fix `e50f15c1c6e131fa7934355eb02b8173b13df415`. Every tag containing the origin also contained the fix, so no vulnerable published artifact contained the candidate without its reversal.

### `not_origin_of_named_mechanism` - 3

Ordinals: 75, 83, 90.

Representative: ordinal 75, `GHSA-5WCW-8JJV-M286`; candidate `20523b918adff4feae378ac9965e204c56b6e3d8`, minimum fix `ebed3bbde1a72a1aaa9b87b63b91e7c04a50036b`. A human commit introduced the Origin-skip predicate later removed by the fix; the AI candidate changed a neighboring trusted-proxy condition.

### `different_invariant` - 2

Ordinals: 190, 206.

Representative: ordinal 190, `GHSA-575V-8HFQ-M3MC`; candidate `3cc8b2a3d0a163bc9e7bc9e5f72bc2b9dde24e74`, minimum fix `a90eb93452f1bec99bfa39ea8c998b742bde9704`. The candidate reused an absolute-path schema check, while the advisory fix closed a distinct runtime ancestor/denied-descendant invariant in another file.

### `human_weakened_ai_predicate` - 1

Ordinal: 168.

Representative: `GHSA-VRHC-JJFC-M3M3`; candidate `eff673fcaf9a4a39d7c1fe93816f7e20a581561e`, minimum fix `fce961b44aa9631f8e9f5d6b3168d16d9a6728af`. The AI member contained the stronger predicate; a later human/squash carrier weakened it, so the residual was not but-for the AI hunk.

### `identity_mismatch` - 1

Ordinal: 68.

Representative: `GHSA-4VFF-6J8J-QHCG`; candidate `473c32270d72252ee6753afc35c3ea4360d169e0`, minimum fix `99043600ee881fd8581185e7590604d9882382cd`. The public identity described credential interpolation that predated the candidate's controller write, and the same candidate SHA was already attached to a different mechanism.

### `not_causal` - 1

Ordinal: 50.

Representative: `GHSA-MQM2-JJX4-44GX`; candidate `687291e596674d0dd6055dc461df183a0364599c`, minimum fix `a5877559dc88ad7a0c935910a652c130489ae2bd`. The new controller wrapper never exercised the shared helper's broken precedence expression, so the fix did not reverse a candidate-created path.

### `preexisting_incomplete_predicate` - 1

Ordinal: 193.

Representative: `GHSA-8V95-QQCM-QP9H`; candidate `1c85eff9b1e65c220dd21375162c412c907204bd`, minimum fix `517ce3df75a97a08bf5e1b8de15604bd574d8fc9`. The incomplete admin predicate already existed in the candidate's parent; the AI change only nested checks inside the pre-existing leak.

### `same_mechanism_duplicate` - 1

Ordinal: 67.

Representative: `GHSA-CJP7-PM9Q-XHQG`; candidate `47bf71cc78d13c06e1eaa4d9842e6f94ddce4bea`, minimum fix `8aa2bb6d1af6e8c57c8d8437cf203acb8bce7a53`. The same candidate, source, sink, and invariant were already represented by ordinal 61; the later public identity did not create a second AI origin.

### `sibling_endpoint_unattempted_old_bug` - 1

Ordinal: 181.

Representative: `GHSA-PRR9-9MP4-5GP2`; candidate `2828e4bf72d486bb11bb81ebf26aa20254b62bae`, minimum fixes `122ebcf0a8f6f187575a42ad3023d8f8c5e9181b` and `44ea3a8d24638ca4a395d641d39f476ae1dc421d`. The AI patch guarded sibling handlers but never touched the already-vulnerable `ListMembers` endpoint later closed by the fix.

### `unattempted_route_preflight` - 1

Ordinal: 191.

Representative: `GHSA-X863-PQJW-HMGF`; candidate `3d93174c4398088066a1de9372ea1103cd713df1`, minimum fix `78f3985c6051673fda7032f37382aeb485488a69`. The candidate guarded an interaction-navigation path but never edited the current-tab act-route preflight named by the advisory.

### `unreleased_counted_as_released` - 1

Ordinal: 109.

Representative: `GHSA-Q8WX-2CRX-C7PP`; candidate `361e71d4329b672482531122117631ec5358953a`, minimum fix `2f5a3a237ea519b48d71e6e3093c89f60694c7be`. The only published tag predated the candidate, so a real commit-only defect could not count as a released case.

### `unreleased_dangerous_revert` - 1

Ordinal: 89.

Representative: `GHSA-686C-7VGV-V3FX`; candidate `f2b9ec2b4ba798a4a28b7b2ffb17dfff2c488c2b`, carrier `9400eaa957fb019b0084bd1c8599ec0f671f17cb`, minimum fix `57b11d405f17492aa789d4b9ff33366f961a37f8`. The dangerous revert and its restoration occurred before every containing tag, leaving no released artifact with the revert but without the fix.

These class counts exhaust all 54 `FALSE_POSITIVE` mechanism dispositions; no rejected row is left unclassified.
