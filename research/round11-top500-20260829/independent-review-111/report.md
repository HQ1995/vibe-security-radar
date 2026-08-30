# Independent review of 111 post-389 primaries

Second pass over the 111 frozen Round11 primaries that were not in
`independent-review/` (the original 389). Protocol:
`docs/AUDIT-PROTOCOL.md`. Review findings only; this wave did not
mutate primaries, the ledger, clones, roster, or the website.

## Acceptance

`python3 research/round11-top500-20260829/collect_review_111.py`
exited 0 with `complete: true`.

| Check | Result |
|---|---|
| Assigned workers | 111 unique |
| Physical `wXXX.json` | 111 |
| Missing / extra / duplicate | 0 / 0 / 0 |
| Schema, identity, protocol_checks | all pass |
| Bundle + primary SHA-256 vs assignment freeze | match (`hash_ok`) |
| 111 primaries + ledger `git status` | clean |
| `round11` substring in ledger | 0 |
| Ledger sha256 live | `33954fd68b206cba1a0187abbe9a2b0deff606543cf6a59bdb1b13007d0f5c0a` |

These results are not canonical corrections until a separate
reconciliation checks each proposed field against the cited objects.

## Review-verdict histogram

| Verdict | Count |
|---|---:|
| `CONFIRMED` | 92 |
| `CORRECTION_REQUIRED` | 17 |
| `EVIDENCE_GAP` | 2 |
| `BLOCKED` | 0 |

Primary snapshot at freeze was `NOT_AI` 108, `EVIDENCE_GAP` 2,
`FALSE_POSITIVE` 1. No reviewed row was flipped to an AI TP.

## Verdict flips proposed (2)

| worker | primary | proposed | repo | case |
|---|---|---|---|---|
| w434 | `EVIDENCE_GAP` | `NOT_AI` | gravitl/netmaker | GHSA-hmqr-wjmj-376c |
| w440 | `FALSE_POSITIVE` | `NOT_AI` | kepano/defuddle | GHSA-5mq8-78gm-pjmq |

w434: reviewer says the host-token vs requested-host gap is real at
v1.5.0 and closable as human BIC / fix. w440: reviewer says the XSS
mechanism exists in public git, so the advisory is not a false positive.

## `EVIDENCE_GAP` (2)

- **w350** `free5gc/free5gc` GHSA-5rvc-5cwx-g5x8 — parentless 8364-line
  `Release v1.0.0` snapshot, org placeholder author, no AI marker.
  Named-human authorship not closed.
- **w454** `apache/openmeetings` GHSA-78cg-fc6c-w44w — clone history
  after OPENMEETINGS-1297 SVN restructure starts at disconnected
  parentless roots; atomic pre-import writer not reconstructed.

## `CORRECTION_REQUIRED` (17)

Field/BIC/squash/evidence fixes; proposed causal class stays `NOT_AI`
except the two flips above.

| worker | repo | case | proposed verdict |
|---|---|---|---|
| w393 | kimai/kimai | GHSA-jv9x-w4gm-hwcm | same `NOT_AI` |
| w394 | fluent/fluentd | GHSA-j9cw-hwqf-85w7 | same `NOT_AI` |
| w396 | kcp-dev/kcp | GHSA-3j3q-wp9x-585p | `NOT_AI` (restated) |
| w415 | shamaton/msgpack | GHSA-h9q6-hc68-35rp | same `NOT_AI` |
| w421 | phpoffice/phpspreadsheet | GHSA-hrmw-qprp-wgmc | same `NOT_AI` |
| w425 | intlify/vue-i18n | GHSA-x8qp-wqqm-57ph | same `NOT_AI` |
| w427 | xmldom/xmldom | GHSA-j759-j44w-7fr8 | same `NOT_AI` |
| w434 | gravitl/netmaker | GHSA-hmqr-wjmj-376c | `NOT_AI` (from gap) |
| w440 | kepano/defuddle | GHSA-5mq8-78gm-pjmq | `NOT_AI` (from FP) |
| w442 | zhenorzz/goploy | GHSA-26rh-24rg-j3vv | same `NOT_AI` |
| w445 | jsonata-js/jsonata | GHSA-86vw-mfpg-wwv9 | same `NOT_AI` |
| w465 | authorizerdev/authorizer | GHSA-29rf-f4vv-pvq6 | same `NOT_AI` |
| w470 | nationalsecurityagency/emissary | GHSA-hxf2-gm22-7vcm | same `NOT_AI` |
| w475 | sveltejs/devalue | GHSA-g2pg-6438-jwpf | same `NOT_AI` |
| w480 | eclipse-vertx/vert.x | GHSA-3g76-f9xq-8vp6 | same `NOT_AI` |
| w481 | naver/billboard.js | GHSA-rpc5-pm7q-hjmp | same `NOT_AI` |
| w482 | stefanprodan/podinfo | GHSA-q23m-vm9r-5745 | same `NOT_AI` |

Typical corrections: wrong BIC vs squash landing, `introducer_parent_absent`
boolean, path-rename mistaken for parent absence (w481: first-write is
the 2013 root, not the later rewrite).

## Notes

- One file (`w464.json`) had an illegal JSON `\`` escape in a commit
  subject; it was rewritten with `json.dumps` without changing the
  `CONFIRMED` / `NOT_AI` judgment.
- Four Rhai workflows (`round11-review-111-b1`..`b4`) failed instantly
  (`json_decode` missing). The 111 reviews were done as isolated
  `spawn_subagent` contexts, one per assignment row.
- Do not treat this as ledger landing.
