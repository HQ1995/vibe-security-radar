# Next canonical overlay design (fp211 → schema 4)

Verdict first: this packet is a design only. It does not rebuild a ledger, admit
cases, or raise the 48-case strict-released lower bound. Integration stays HOLD
until named red-team packets are terminal and a later builder satisfies every
verifier requirement.

## Current fp211 schema (absorbed, not replaced)

The absorbed overlay is `autoresearch/orchestrator-260813-fp211-canonical/`.

- Ledger records: 273 (`schema_version` 3 on component rows).
- Canonical hypotheses: 211, joined 1:1 to `final_mechanisms.jsonl` by `row_key`
  and ordinals 1–211.
- Source first-party GHSA cases: 212 in `public_cases.jsonl` (65 CONFIRM, 84
  NARROW, 54 FALSE_POSITIVE, 9 UNKNOWN). Mechanism verdicts are 65 / 83 / 54 / 9
  because ordinal 200 (`posthold:G01`) binds two non-aliased GHSAs
  (`GHSA-3J8Q-FWPJ-F8J5`, `GHSA-JJCJ-H3CM-P7X7`) to one hypothesis.
- Authoritative edges live in `fp211_adjudication.{candidate_set,carrier_set,minimum_fix_set}`
  as sorted unique 40-hex SHAs. `edge_authority` is that triple.
- Top-level `candidate_fix_edges`, `atomic_fix_members`, and `release_evidence`
  are preserved historical routing evidence only
  (`legacy_top_level_edge_policy = PRESERVED_HISTORICAL_ROUTING_EVIDENCE`).
  The overlay must not invent Cartesian candidate×fix pairs.
- Countable released publication admission today: 48 mechanisms with CONFIRM,
  HIGH, all seven gates exactly `PASS`, and a `*_RELEASED` source tier.
- `row_state` PASS is not publication admission. Source envelopes remain
  input-only. Status HOLD.

## Minimum next overlay

One deterministic HOLD overlay, `schema_version` 4 on preserved component rows,
plus zero or more append-only identity rows. No second ledger family. No
publication rebuild.

### Record kinds

1. `PRESERVED_HYPOTHESIS` — all 211 fp211 rows. `row_key` and `ordinal` are
   immutable. Default overlay state copies `fp211_adjudication`.
2. `PRESERVED_PUBLIC_CASE` — all 212 source GHSA identities. CVE aliases stay
   on the row and are never counting units.
3. `PACKET_AUTHORITY` — named packets with role, terminal flag, and frozen plus
   current hashes. Glob order and file existence are not authority.
4. `SUPERSEDES_EDGE` — explicit `(case_id, from_packet, to_packet, from_verdict,
   to_verdict, authority_rank)`. Applied only when `to_packet.terminal` is true.
5. `APPEND_IDENTITY` — first-party GHSA ids absent from the 212. New `row_key`
   (`ghsa200-next:<CASE_ID>`) and ordinal ≥ 212. Same-id upgrades never append.

### Application order (fail-fast)

1. Pin frozen hashes. Recompute current hashes. If any frozen/current pair that
   is required to be identical differs, exit non-zero.
2. Load only packets listed in `PACKET_AUTHORITY`. Ignore every other glob hit.
3. Drop nonterminal packets. Their rows may be listed PENDING. They cannot
   mutate overlay state.
4. Start from fp211. Apply `SUPERSEDES_EDGE` in increasing `authority_rank`,
   then increasing `edge_id`. Later rank wins. A red-team downgrade at rank 30
   overrides final-review ACCEPT at rank 20. Existence of a contrary vote
   without a named edge is a no-op.
5. Upgrades rewrite overlay fields on the existing hypothesis / public-case
   pair. They do not add rows and do not add GHSA identities.
6. Append only when `case_id` is absent from the 212, overlay_state is KEEP,
   the source packet is terminal, and all seven contract gates equal `PASS`.
7. Count by first-party GHSA once. Shared SHAs do not merge identities.

### Countable predicate

A GHSA is countable only when every contract gate is the string `PASS`:

`identity_gate`, `ai_hunk_gate`, `topology_gate`, `but_for_gate`,
`fix_reversal_gate`, `release_gate`, `uniqueness_gate`.

`NA`, `NARROW`, `UNKNOWN`, `BLOCKED`, `FAIL`, and null all fail the predicate.
Incomplete-remediation rows still require those seven strings to be `PASS`;
`remediation_patch_delta_gate` is an extra proof field, not an eighth counting
gate and not a substitute for `but_for_gate`.

Any required field that is JSON null fails closed.

## Authority table (named, not globbed)

Roles: `frozen_base`, `worker`, `independent_review`, `final_review`,
`redteam`, `census`, `inventory`.

Terminal for this design means the packet's own `status` is a completion token
and `PACKET_AUTHORITY.terminal` is true. Census `forced_inflight` and PARTIAL /
HOLD / STATUS_ABSENT packets are nonterminal.

| Packet | Role | Terminal now | Use |
|---|---|---|---|
| `orchestrator-260813-fp211-canonical` | frozen_base | yes | 211/212 conservation |
| `orchestrator-260813-fp211-audit` (`final_mechanisms`, `public_cases`) | frozen_base | yes | join keys |
| `ghsa200-leader` (`CONTRACT.md`, `baseline.json`) | frozen_base | yes | counting contract |
| `ghsa200-final-candidate-review-codex` | final_review | yes | 32-row bounded review |
| `ghsa200-third-review-upgrade-a` | independent_review | yes | four upgrade-A hypotheses; supersedes stale upgrade-A worker |
| `ghsa200-red-upgrade-a` | redteam | yes | non-authoritative once third-review edge exists |
| `ghsa200-red-upgrade-b-direct` | redteam | yes | KEEP ordinal 122; NARROW 114 and stale 211 |
| `ghsa200-red-upgrade-b-ord211-release` | redteam | yes | KEEP ordinal 211; supersedes missing-v1.0.0 |
| `ghsa200-baseline-increm-even` | independent_review | yes | KEEP 160/164/166/176; KEEP 148 superseded later |
| `ghsa200-baseline-increm-odd` | independent_review | yes | KEEP 137/147/161/171/179 |
| `ghsa200-increm-patchdelta-even` | independent_review | yes | NARROW of upgrade-B incomplete-rem PASSes (even) |
| `ghsa200-increm-patchdelta-odd` | independent_review | yes | NARROW of upgrade-B incomplete-rem PASSes (odd) |
| `ghsa200-incomplete-rem-redteam` | redteam | yes | same six NARROW downgrades |
| `ghsa200-contributor-redteam` | redteam | yes | seven ACCEPT proposals; 7C3W later overridden |
| `ghsa200-commitfirst-gj-grok46-medium` | worker | yes (HOLD slice) | one PASS proposal `GHSA-6P9M-Q3JP-47H4`; not admission |
| `ghsa200-netnew22-redteam-grok46-xhigh` | redteam | **yes** (`REDTEAM_TERMINAL`) | 21 KEEP + 7C3W NARROW; rank 30 overrides final-review ACCEPT |
| `ghsa200-narrow-recovery-a-grok46-xhigh` | independent_review | **no** | `GHSA-7GH7-258J-4MPQ` |
| `ghsa200-narrow-recovery-b-grok46-high` | independent_review | **no** | `GHSA-F38V-77QJ-H4JQ`, `GHSA-G3XQ-3GMV-QQ8G`, `GHSA-PV2J-RGHR-V5R9` |
| `ghsa200-commitfirst-gn` | worker | **no** (PARTIAL) | source of G39V/PF93 only; not authority |
| `ghsa200-unified-verifier` | independent_review | **no** (HOLD) | excluded |
| `ghsa200-proposal-census-grok46-low` | census | yes | inventory of unabsorbed ids; never admission |

Nonterminal packets excluded from mutation: commitfirst-oz, fresh-am,
freshness-qa, current-delta, cross-dedupe, red-upgrade-a-ord20-composite
(third-review already names the ordinal-20 hypothesis), unified-verifier,
and all `STATUS_ABSENT` / PARTIAL inventory packets.

## Explicit supersedes edges

Edges are data. They are not inferred from timestamps or from finding a NARROW
file next to an ACCEPT file.

Required now (sources already terminal):

1. Third-review ACCEPT supersedes upgrade-A worker and red-upgrade-A for
   `GHSA-FMFG-9G7C-3VQ7`, `GHSA-XW8C-RRVX-F7XQ`, `GHSA-WV46-V6XC-2QHF`,
   `GHSA-RG8M-3943-VM6Q`.
2. Ordinal-211 release correction KEEP supersedes red-upgrade-b-direct NARROW
   on `GHSA-JV46-XFWM-36J7`.
3. Final-review NARROW on `GHSA-4FXP-2M36-QV64` (`identity_gate`) supersedes
   baseline-increm-even KEEP for that id.
4. Incomplete-rem red-team / patch-delta independent NARROW supersedes
   upgrade-B PASS for `GHSA-2X93-H3HG-2XFP`, `GHSA-4MR5-G6F9-CFRH`,
   `GHSA-94P4-4CQ8-9G67`, `GHSA-9C3V-684M-579C`, `GHSA-P538-C434-8V24`,
   `GHSA-V396-V7Q4-X2QJ`. Overlay stays NARROW. No append.

Applied now that netnew22 is `REDTEAM_TERMINAL`:

5. **`GHSA-7C3W-FXGH-FRC7` netnew22 NARROW supersedes final-review ACCEPT and
   contributor-redteam ACCEPT.** Failed gate: `but_for_gate` (parent `/trace`
   PoC; Claude copy onto `/artifacts` is not a material delta). Overlay remains
   fp211 NARROW. This edge is mandatory; a builder that emits KEEP/ACCEPT for
   7C3W fails semantic verification.

6. Netnew22 KEEP candidate rebinds supersede final-review / commitfirst-gn
   member SHAs for `GHSA-G39V-CVJH-8FPF` (`1f322cf05…` squash) and
   `GHSA-PF93-J98V-25PV` (`39806871…` squash). Member SHAs that are not tag
   ancestors are not counted. These two ids are the only current APPEND
   identities from that packet.

## Current candidate sets (PENDING / KEEP / NARROW)

Classification uses terminal status only. Recoveries without a terminal
red-team stay PENDING even if their worker status is COMPLETE.

### KEEP (terminal revalidation; already in the 48; do not append)

These nine ids stay on their fp211 hypotheses. Overlay_state KEEP. Count is
unchanged.

| GHSA | ordinal | candidate_set | minimum_fix_set |
|---|---|---|---|
| GHSA-7P8R-X3MC-P8W7 | 160 | `0542a216860fd70c062a4730e620576f62ded057` | `f3c6c905f47831007490f466c5945012e905cc52` |
| GHSA-5RV5-XJ5J-3484 | 164 | `a6d3a3a0bf59c2ab307d0abd91bc126aef5561bc` | `3f1280c69e93297d574e85a2d462d05ebadf1d09` |
| GHSA-8WC8-HF36-MJH9 | 166 | `847d08bdd135e5c3659f2e6dea2f0cd36617af9b` | `64511ce45e3be379e965f7f4fb0929a068d5bb81` |
| GHSA-JM78-9FVV-MHGR | 176 | `1ed1b924f4e2d2ee7bab296df77b978af21853f1` | `a495ccd3b547ccd60b2187215823b72a9c0188bf` |
| GHSA-M4WX-M65X-GHRR | 137 | `46cbbdde4e19b743974c942278080231004146ca` | `86ab819f202c3a8dad88cef5705f2e416c5188d7` |
| GHSA-56C3-VFP2-5QQJ | 147 | `d9d847f230923d96e0857ccecf3a4dedcc9b0096` | `9639f757853149f0cb16663cc8b6b6468f27a25f` |
| GHSA-VC8F-X9PP-WF5P | 161 | `042af9ca7fde2ff599120783e720a17f335bb01c` | `345a6211e1e6f939f96a7090bfeff642c9fcf9e4` |
| GHSA-MV93-W799-CJ2W | 171 | `c417af469f9aa3da8dfef78f996c0fb8c5d1f4c2` | `54538428f79b0c91ba52cda5229856a6edf7ac06` |
| GHSA-5XXX-QHH7-9287 | 179 | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` | `1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6` |

### NARROW (terminal)

| GHSA | Why | candidate_set | minimum_fix_set |
|---|---|---|---|
| GHSA-4FXP-2M36-QV64 | Final-review `identity_gate` NARROW supersedes baseline KEEP. Already in the 48; this is a same-id scope hold, not an append. | `52e5e1938ba7db9191ab75fc6f81d92cf667dd4d` | `86a7d6557bd111518a221f4575ad6e36087e19d3` |
| GHSA-2X93-H3HG-2XFP | Terminal incomplete-rem / patch-delta NARROW supersedes upgrade-B PASS. | `b75ad800a59009fc47eaa3471410f69046150e59` | (fp211 / upgrade-B row; no KEEP) |
| GHSA-4MR5-G6F9-CFRH | same | `3cd664bf7b7db5f774c1e7e3123a1a24c68ba700` | |
| GHSA-94P4-4CQ8-9G67 | same | `8ac5a30519b6f4af85398b9b9d7064ff4d452da2` | |
| GHSA-9C3V-684M-579C | same | `47eb2d48d43452afc4b0160e40a2630e4a38a0ff` | |
| GHSA-P538-C434-8V24 | same | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` | |
| GHSA-V396-V7Q4-X2QJ | same | `c9a26789d88b18f8b4620f37307df2976292d2a0` | |

### KEEP same-id upgrades (netnew22 terminal; present in the 212; do not append)

Listed candidate_sets are the netnew22 hypotheses (squash rebinds included),
not commitfirst-gn members.

| GHSA | Pending overlay | candidate_set | minimum_fix_set |
|---|---|---|---|
| GHSA-FMFG-9G7C-3VQ7 | KEEP if netnew22 terminals KEEP | `39806871c9720bf8afdcf3e061095c0dd63dea7f` | `dc8eaa16a8550f885614655f14b6fd9fe429b278` |
| GHSA-XW8C-RRVX-F7XQ | KEEP | `d42195e10be0d7d9bfb4ec45fecfb83521d3fc67`, `f08e654974f208f90ef6015928ef651982f3224a` | `17a119fe43dd956ef463c1c575a463ffd9a8d95b` |
| GHSA-WV46-V6XC-2QHF | KEEP | `9a3800d8e6e69bc0a125dca5760d47515e746454` | `7ade3553b74ee3f461c4acd216653d5ba411f455` |
| GHSA-RG8M-3943-VM6Q | KEEP | `49c60e9065d98a6848e62c717315eb91eeaa6038` | `8a563d603b70ef6338915f0527bee87282c3bad5` |
| GHSA-MF5G-6R6F-GHHM | KEEP | `03586e3d0057b5975090d50dadcc5bc95b51f977` | `0b4d07337467f4d40a0cc1ced83d45ceaec0863c` |
| GHSA-JV46-XFWM-36J7 | KEEP | `2aeba972d43391175a94c7793b63c6a5709abc48` | `2e456897af3158c175bb490ce7fc51d6241c8922` |
| GHSA-WPXJ-VHFP-HHVM | KEEP | `a3d1733d2691a0d40209c48b01bf9291bf645207` | `6181c4a22eccbeca973c77f4bd023eb795c13786` |
| GHSA-R9MR-M37C-5FR3 | KEEP | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` | `e8d0fbf774d1f6baa3b481adfe48bd262e43b453` |
| GHSA-539M-9XH6-Q6RR | KEEP | `701ce32fe5ba8cb622c0e0342a376a6beb47d738` | `7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca` |
| GHSA-3WXW-XV34-2FRG | KEEP | `3af0c2516c5e18c829da30338614688f6b69b49c` | `1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6` |
| GHSA-5C6W-WWFQ-7QQM | KEEP | `3cd664bf7b7db5f774c1e7e3123a1a24c68ba700` | `179cab02dbec0c1e9b601507a65908e079876004` |
| GHSA-R48C-V28R-PF6V | KEEP | `1201cbd82b2cf6d4b56edfc05c763059a12f9fdb` | `f5f40bd98084466eaf18fe48ea62a0d534caa774` |
| GHSA-3RP5-JJMW-4WV2 | KEEP | `54538428f79b0c91ba52cda5229856a6edf7ac06` | `1ed1b924f4e2d2ee7bab296df77b978af21853f1` |
| GHSA-PWF7-47C3-MFHX | KEEP | `a7c5a0054bcdf34c9ec0f1c20d1356ce54f069b3` | `6b7c6ef5c3875c766893b881b40773cd5605bde3` |
| GHSA-J4XF-96QF-RX69 | KEEP | `2267d58afcc70fe19408b8f0dce108c340f3426d` | `4ed87a667263ed2d422b9d5d5a5d326e099f92c7` |
| GHSA-8JPQ-5H99-FF5R | KEEP | `2267d58afcc70fe19408b8f0dce108c340f3426d` | `5b4121d6011a48c71e747e3c18197f180b872c5d` |
| GHSA-RQP8-Q22P-5J9Q | KEEP | `03586e3d0057b5975090d50dadcc5bc95b51f977` | `980940aa58f862da4e19372597bbc2a9f268d70b` |
| GHSA-WXHM-2MQ7-7697 | KEEP | `a0e6108842a3bfc840a33db819a4415fbdac333d` | `88ac9948d7d37995edbb2f6d36913436626c39e1` |
| GHSA-W28W-GP39-M4P6 | KEEP | `a0e6108842a3bfc840a33db819a4415fbdac333d` | `e4a0ebf49e3a78d5d7796c8480bf9a4f0c54d19e` |

Add to NARROW (mandatory override, already applied):

| GHSA | Why | candidate_set | minimum_fix_set |
|---|---|---|---|
| GHSA-7C3W-FXGH-FRC7 | Netnew22 `but_for_gate` NARROW overrides final-review ACCEPT | `c156ac7675207e3dbc0c6a4b3ed6931dc96513c2` | `e2a81a047ab8750fa5bfa1763b5d85e5616f3994` |

### KEEP append (absent from the 212; terminal netnew22 KEEP)

| GHSA | Pending overlay | candidate_set | minimum_fix_set |
|---|---|---|---|
| GHSA-G39V-CVJH-8FPF | KEEP append | `1f322cf05db736fe3df9c7e16ac87b0cb1c6d30e` | `09c524526b5f945638aa97de6218fadcd233023c` |
| GHSA-PF93-J98V-25PV | KEEP append | `39806871c9720bf8afdcf3e061095c0dd63dea7f` | `dc8eaa16a8550f885614655f14b6fd9fe429b278` |

### PENDING (blocked on missing terminal red-teams)

| GHSA-6P9M-Q3JP-47H4 | KEEP append after independent red-team; worker PASS is not enough | `85ebf175c0f953253247717f72f50fd6aba2d362`, `90f99d5f672ba95cf8cdb1a1d915acb079adb5ef` | `f35a767af74e05342bafc6fdda02c791816426f8`, `e2fae5d0455d4f92c6382433d21c3a16da077d64` |

In-flight recoveries (present in the 212; pending their own terminal red-team):

| GHSA | Packet | candidate_set | minimum_fix_set |
|---|---|---|---|
| GHSA-7GH7-258J-4MPQ | narrow-recovery-a | `a43b6f5c4714fb08b3fe3e5ce560213b229648c1` | `068185751c03b42e726e3c60b718413d5f96c306` |
| GHSA-G3XQ-3GMV-QQ8G | narrow-recovery-b | `7b9322a86a5cae3230c30943bd659d7f67b0387c` | `0a3e3c130e1ec803a2107fe83775d97f5f8f6dde`, `613e4df30547f3e6baf32d161eddc828f171da17` |
| GHSA-F38V-77QJ-H4JQ | narrow-recovery-b | `179cab02dbec0c1e9b601507a65908e079876004` | `e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747` |
| GHSA-PV2J-RGHR-V5R9 | narrow-recovery-b | `179cab02dbec0c1e9b601507a65908e079876004` | `2adfe7e8323f6deec66925cf15a885b6238895e9` |

All remaining 211−(touched) hypotheses stay fp211 as-is, including both ordinal
200 GHSAs.

## Hash temporal roles

Every hash in the overlay manifest has exactly one role:

- `frozen_*` — value captured in this design packet. Replay fails if the file
  bytes no longer match.
- `current_*` — value recomputed at replay. For conservation inputs, current
  must equal frozen. For pending packets, current may move; admission still
  waits on `terminal=true` plus a new frozen pin.
- `overlap_check_*` — live publication/adjudication peek after a later git
  commit. Never used to select or count.

Named frozen pins (design-time):

- `frozen_contract` CONTRACT.md `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- `frozen_leader_baseline` `d92b1f93adcbc519dc335ca7ab07f90d9e64103a0cd6e0cb7b8fdf334f7c3132`
- `frozen_fp211_ledger` `1f0d15a82765c557b67efceaaf41a887c2d078a49f3da84d5f42458043e3e5e6`
- `frozen_fp211_source_manifest` `679dbac540bf2f8dad0a24a85d8fc309c613977a2b58a1ad44b40e5a85798ccb`
- `frozen_fp211_mechanisms` `0d76a1a82082e0c4742686a4466130a3a02ef9245c8f3ce86aa0298ebae701c2`
- `frozen_fp211_public_cases` `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`
- `frozen_final_review_result` `4be2620a548370c845e22c0d7cbe3ed10ab156ef39b1a0432ff4220ff406e528`
- `frozen_final_review_cases` `e275437954890dca07855b5fcfa545f8f1a366fb85a7ee9f067da5b710b2b3da`

Terminal-but-mutable worker and red-team packets are hashed as `current_*`
and must match disk at replay. Recoveries without a terminal red-team stay
`current_*` and cannot mutate overlay state.

## Verification layers (must stay distinct)

1. **Structural** — JSON types, non-null required fields, 211 row_keys, 212
   source GHSAs, ordinal conservation, sorted unique SHA sets, no Cartesian
   `candidate_fix_edges`, English-only, uniqueness of `case_id`.
2. **Git** — executed ancestry, blob, and tag containment for rows whose
   overlay_state is KEEP. Structural success never implies Git success.
3. **Semantic** — filebrowser ordinals 165 FALSE_POSITIVE vs 166 CONFIRM must
   not swap; 7C3W cannot be KEEP; dual ordinal-200 GHSAs stay two cases; shared
   SHA is not duplication; CVE aliases are not counted.

A future `verify.py` must call three functions and fail on the first assertion
in each. This design's `replay.txt` only structurally checks these five files.

## What evidence unlocks integration

Integration_ready becomes true only when all of the following hold:

1. Independent red-team of `GHSA-6P9M-Q3JP-47H4` is terminal, or an explicit
   REJECT/NARROW edge exists. Worker PASS alone never unlocks append.
   Netnew22 is already `REDTEAM_TERMINAL` with 21 KEEP / 1 NARROW (7C3W).
2. Each PASS proposal from narrow-recovery-a and narrow-recovery-b has a
   terminal red-team. Until then those four ids stay PENDING.
3. A builder (not this packet) emits overlay artifacts whose structural, Git,
   and semantic verifiers all PASS, including:
   - 211 preserved hypotheses and 212 preserved GHSA identities;
   - appends only for genuinely absent ids that are KEEP with seven `PASS` gates;
   - 7C3W overlay_state NARROW;
   - 4FXP overlay_state NARROW;
   - no Cartesian edges;
   - countable count still not claimed as >200 unless the seven-gate predicate
     yields that number with zero unresolved PENDING identities in the
     admission set.
4. Leader Git replay of every KEEP append/upgrade is stderr-clean and
   fail-fast.

Until those close, `integration_ready=false`, `publication_ready=false`,
`causal_admission=false`, and the public 200-case claim remains unsupported.

## Non-goals

- No builder, no ledger write, no staging, no commit, no push.
- No consumption of glob-discovered packets.
- No promotion of OSV `introduced`, commit subjects, or model votes.
