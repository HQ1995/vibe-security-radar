# Research-work contract

New batches adopting the current contract retain the sidecar introduced in
`2026-09-25.1`: set `reduction.research_contract` to
`causal-work-v1` and freeze the gate invocation with `--research-contract causal-work-v1`.
The option rejects an omitted or different declaration; older frozen batches retain
their existing contract. This is local coordination data, never ledger or site data.

Each decision has a `research` object with `advisory`, `mechanism`, `bic`, `ai`, `fix`
and `versions` entries. The protocol's four questions map onto them: cause is
`mechanism`; impact is `mechanism` (prerequisites, effect) plus `versions` (affected
range); history is `bic`, `fix` and `versions`; AI role is `ai`. Auditors keep the same object in their owned research sidecar,
linked from the sealed report; adjudicators write their own synthesis in the decision.
The existing `basis`, `residual` resolution and per-dimension `missing_fact` describe
the remaining uncertainty. A single entry has this shape (not a prewritten finding):

```json
{
  "evidence_grade": "QUALIFIED_BOUNDARY",
  "work_state": "UNFINISHED",
  "finding": "State the supported causal conclusion, conditions and counterevidence.",
  "evidence": [{"path": "evidence/source.txt", "sha256": "<64 hex>"}],
  "missing_fact": "State the decisive fact still unknown.",
  "next_permitted_route": "original-member",
  "routes": [{
    "id": "original-member",
    "question": "Which parent/child change first introduced the relevant behavior?",
    "source": "upstream repository history",
    "evidence_type": "parent/child source comparison",
    "status": "PENDING"
  }]
}
```

`evidence_grade` is `BOUND`, `QUALIFIED_BOUNDARY` or `UNRESOLVED`. It describes the
supported conclusion, independently of work remaining. `BOUND` need not assert a
vulnerability or an existing fix: an affirmative refutation or the keyed advisory's
documented exclusion of further work can support a scoped conclusion. State that scope;
do not invent code findings for a rejected advisory or extend an absence claim.
A `BOUND` finding has no decisive `missing_fact`: represent it with JSON null, not an
empty string. Genuine remaining gaps use the other evidence grades and a named fact.

`work_state` is `UNFINISHED` while an identified, permitted, decisive investigation
remains, regardless of the grade or case verdict. `next_permitted_route` names a
`PENDING` or `FAILED` route. `COMPLETE` requires a null next route and no unfinished
route; a non-BOUND conclusion also needs a nonempty `missing_fact` and route history.
Completion is the researcher's claim about the recorded questions and evidence available
at that point, not proof that every possible source was discovered. Omitted or invalid
research objects are unassessed, never zero outstanding work.

A route is a question plus an authoritative source and evidence type. Alternate URLs
for the same observation are attempts within that route, not extra research coverage.
Choose routes for the facts they can distinguish; after a decisive answer, do not keep
searching merely to fill source categories. If a planned alternative becomes redundant,
explain its disposition in the supported finding and retain the prior plan in the attempt
history. Completed findings can have an empty route list when primary evidence already
binds them. Investigate a qualified boundary wherever a different available observation
could still change its conclusion.

Routes use `PENDING`, `FAILED`, or one of four terminal observations:

| Status | Meaning |
| --- | --- |
| `ANSWERED` | The source answered the specific question; a supported absence is an answer. |
| `UNAVAILABLE` | The specified evidence is unavailable, with its actual access/source result. |
| `EXHAUSTED` | The recorded, bounded source inquiry ended without answering the missing fact. |
| `PROHIBITED` | An applicable instruction prevents this specific inquiry; retain its authority and scope. |

Every non-PENDING route needs `observation` and `evidence` receipts. A crash, timeout,
rate limit or failed write is `FAILED`, not proof of source absence or exhaustion.
Resource and permission limits remain in force; report affected unfinished work and
continue other authorized questions. Receipts must substantiate the claimed outcome.
The gate checks the declared statuses and pinned bytes, not the truth of their interpretation.

Under this contract, each required `resolutions` entry is an object containing `claims`
(a nonempty account for every assigned lane), `observation`, `reasoning`, `conclusion`
and primary `evidence` receipts. Explain the shared premise when reports agree and why
it holds or fails. Changes made only by the adjudicator still need a resolution. Every
supplied resolution is checked, including optional ones. Existing TP and input-quality
obligations remain.

The reduction gate returns `research_work.worklist` from unfinished entries, including
qualified ones, and reports `evidence_boundaries` and `unassessed_cases` separately.
The list concerns declared research only. A zero-length list neither proves discovery
completeness nor changes `BLOCKED`, missing-lane, execution or publication status.
The leader reviews the choice of questions, counterevidence and terminal observations
before accepting the claimed boundary. Never use route counts as a quality score.

