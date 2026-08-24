# fp211 NARROW/UNKNOWN coverage closure

Verdict first: **uncovered=0**. Coverage-only terminal zero packet. Assigned freeze 0, reviewed 0, unreviewed 0. Conservation 0=0+0 for new reviews. Coverage equation **92=92+0**. Canonical strict count remains **84**. packet_delta=0. Publication and more-than-200 stay **HOLD**. This packet emits no PASS proposals and does not reopen gates.

The 92 fp211 mechanism rows with verdict NARROW (83) or UNKNOWN (9) in `autoresearch/orchestrator-260813-fp211-audit/final_mechanisms.jsonl` are covered exactly once each. Counting unit is the mechanism row by ordinal and first-party GHSA identity. Ordinal 200 is one row with two non-alias identities (`GHSA-3J8Q-FWPJ-F8J5`, `GHSA-JJCJ-H3CM-P7X7`); it is counted once.

## Coverage rule

A row is covered only if:

1. its first-party GHSA is a counted `STRICT_RELEASED_CASE` in canonical84, or
2. a terminal/complete bounded packet has an explicit `cases.jsonl` (preferred) or selected/adjudication row for that identity and a terminal result/status.

Raw text mentions, mining dumps, nonterminal packets, inventory/census copies, and the original fp211-audit labels do not count. When a packet has both selected and cases rows, the cases row is the covering source. `also_seen_in` records other terminal packets and is not a second assignment.

## Result

| Quantity | Count |
| --- | ---: |
| Target rows | 92 |
| Covered | 92 |
| Uncovered | 0 |
| Frozen | 0 |
| Canonical84 counted STRICT_RELEASED_CASE | 15 |
| Terminal packet cases.jsonl | 77 |
| Selected-only assignments | 0 |
| Double assignment events | 0 |

## Canonical84 counted (15)

These fp211 NARROW rows were later admitted as counted STRICT_RELEASED_CASE. Source path is `autoresearch/orchestrator-260814-ghsa200-canonical84/ledger.jsonl`.

| Ordinal | GHSA | row_key |
| --- | --- | --- |
| 1 | `GHSA-FMFG-9G7C-3VQ7` | `strict-200-v3:alias-02fb7aeb21b9f4e1ab18fbce` |
| 3 | `GHSA-PWF7-47C3-MFHX` | `strict-200-v3:alias-04f677245516e574c5201c86` |
| 8 | `GHSA-J4XF-96QF-RX69` | `strict-200-v3:alias-12debd2395456ef3aa1dd946` |
| 20 | `GHSA-XW8C-RRVX-F7XQ` | `strict-200-v3:alias-323bf07420daae79c5a0844f` |
| 31 | `GHSA-8JPQ-5H99-FF5R` | `strict-200-v3:alias-5a43c1628113d632bf3692b9` |
| 92 | `GHSA-WV46-V6XC-2QHF` | `strict-200-v3:alias-06ca275f5a582dacb68ec70b` |
| 93 | `GHSA-RG8M-3943-VM6Q` | `strict-200-v3:alias-10470c6830a2c45cfe7539af` |
| 96 | `GHSA-RQP8-Q22P-5J9Q` | `strict-200-v3:alias-e48c6f8662352f3d6e87afad` |
| 99 | `GHSA-7GH7-258J-4MPQ` | `strict-200-v3:alias-3ed594d20d11056d42d54528` |
| 104 | `GHSA-WXHM-2MQ7-7697` | `strict-200-v3:alias-0ae0a984e1b1218e180ef355` |
| 105 | `GHSA-W28W-GP39-M4P6` | `strict-200-v3:alias-3a0294dfd1f9cff8531aacfd` |
| 113 | `GHSA-G3XQ-3GMV-QQ8G` | `post:claude-cache-statusline-injection@canonical` |
| 180 | `GHSA-3WXW-XV34-2FRG` | `post:gitpython-tag-positional-file@canonical` |
| 188 | `GHSA-PV2J-RGHR-V5R9` | `posthold:F07` |
| 211 | `GHSA-JV46-XFWM-36J7` | `posthold:I02` |

## Terminal packet cases (77)

Assigned to the lexicographically preferred 2026-08-14 independent seven-gate packet when one exists; otherwise to the earlier independent review. All 77 assigned sources are `cases.jsonl` rows, not selected freezes.

| Count | Packet |
| ---: | --- |
| 12 | `autoresearch/herdr-260814-ghsa200-nearpass-twogate12-grok46-medium` |
| 10 | `autoresearch/herdr-260814-ghsa200-butfor10-redteam-grok46-xhigh` |
| 8 | `autoresearch/herdr-260814-ghsa200-fp211-unseen-twogate8-grok46-medium` |
| 6 | `autoresearch/herdr-260814-ghsa200-fp211-releaseonly11-grok46-low` |
| 6 | `autoresearch/herdr-260814-ghsa200-fp211-unseen-threegate6a-grok46-low` |
| 6 | `autoresearch/herdr-260814-ghsa200-fp211-unseen-threegate6b-grok46-xhigh` |
| 5 | `autoresearch/herdr-260814-ghsa200-fp211-singlegate5-grok46-xhigh` |
| 5 | `autoresearch/herdr-260814-ghsa200-fp211-unseen-twogate5-grok46-high` |
| 4 | `autoresearch/herdr-260814-ghsa200-fp211-unknown4a-grok46-low` |
| 4 | `autoresearch/herdr-260814-ghsa200-fp211-unknown4b-grok46-xhigh` |
| 3 | `autoresearch/herdr-260814-ghsa200-fp211-identity-butfor3-grok46-high` |
| 3 | `autoresearch/herdr-260814-ghsa200-fp211-topologyonly3-grok46-xhigh` |
| 3 | `autoresearch/herdr-260814-ghsa200-fp211-unseen-hard3-grok46-medium` |
| 1 | `autoresearch/herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh` |
| 1 | `autoresearch/herdr-260814-ghsa200-contributor-butfor11-grok46-xhigh` |

## UNKNOWN (9 of 9 covered)

All nine fp211 UNKNOWN mechanism rows have a terminal independent cases row: ordinals 35, 51, 53, 56, 84, 116, 129, 153, 154.

## What this packet did not do

It did not freeze a new 20-row remainder. It did not independently re-blame git hunks. It did not edit canonical84. It did not treat inventory packet `herdr-260813-ghsa200-gap` or fp211-audit adjudications as coverage. It did not count mining dumps. It did not pad.

## Claim boundary

Worker PASS is a proposal only; this packet has zero PASS and zero reviewed cases. start_count=84. current_leader_accepted_count=84. packet_delta=0. Publication stays HOLD. Greater-than-200 remains unsupported. Incomplete-remediation and carrier-transfer rules were not re-applied here because no new case was opened.

Status is **TERMINAL**. Coverage complete. Uncovered zero.
