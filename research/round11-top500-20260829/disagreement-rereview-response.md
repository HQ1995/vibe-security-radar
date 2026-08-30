# Response to disagreement re-research

This is a reply to `disagreement-rereview/report.md` (synthesis of 33
`wXXX.md` files) against `independent-review-disagreement.md` and
`docs/AUDIT-PROTOCOL.md`.

It does not mutate primary records, independent-review files, the
re-research writeups, or the ledger. Recommended verdicts below are
landing guidance, not applied edits.

Headline: **no remaining hard disagreement on the 33 recommended
primary verdicts.** Remaining disagreements are (1) a false PARTIAL
on w006, (2) review-grade inflation that still mixes field errata with
causal failures, (3) fail-closed wording in the re-research README,
and (4) how three accepted `NOT_AI` / `AI_ROOT_CAUSE` rows must be
written into schema fields.

---

## What is accepted

The re-research strengthened the memo’s Class A (authorship) position
and closed several gaps the memo left because it did not re-clone SVN
/ upstream / official source histories.

Accepted primary verdicts, 33/33:

| Primary | Workers |
|---|---|
| `AI_ROOT_CAUSE` | w002, w006, w011, w019, w078 |
| `FALSE_POSITIVE` | w007, w008 |
| `EVIDENCE_GAP` | w122, w180, w289, w312 |
| `NOT_AI` | the other 22, including the seven rows the synthesis listed as overturning the memo (w010, w115, w123, w124, w133, w139, w167) and w395 |

Accepted as real extra first-party work, not as a knock on the original
389 workers (those workers were clone-isolated):

- GitPython path decomposition (w010)
- Adobe Commerce vs Magento Open Source product table (w123)
- CVE-2024-52046 vs CVE-2026-41635 mechanism split (w133)
- Apache SVN r349422 / r349421 (w115, w124, w136)
- Official `Yoast/duplicate-post` vs dist clone (w139)
- LZ4 upstream decoder BIC vs MessagePack vendoring (w167)
- Gradio PR #2256 members (w395)

This response did not re-execute those SVN/Gradio/LZ4 clones. Acceptance
is that the cited object *kind* (exact 40-hex SHA, SVN revision, official
source repo, vendor product table) is the right protocol evidence.

The 111 records completed after the original 389 freeze remain
unreviewed by this chain.

---

## Remaining disagreement 1 — drop the w006 PARTIAL

`disagreement-rereview/report.md` marks w006 `PARTIAL` because the memo
allegedly wanted the independent review recoded `CONFIRMED`.

The memo did not. It said: keep `AI_ROOT_CAUSE`; correct CNA `2.0.0`
lower-bound wording; do not treat the row as an unstable TP.

The re-research recommended outcome is the same as the memo:
`AI_ROOT_CAUSE` + `CORRECTION_REQUIRED` limited to affected-range text
(and the tighter MCP-chain bound from `n8n@2.25.1` is an additional
range fact, not a verdict change).

**Action:** recode the synthesis Decision on w006 from `PARTIAL` to
`AGREE`. Do not list w006 among memo disagreements.

---

## Remaining disagreement 2 — review-grade inflation

The synthesis still reports 24 `CORRECTION_REQUIRED` review verdicts.
That bucket still mixes:

- causal failures (wrong BIC, non-vulnerability, FP overclaim)
- field errata (parent boolean, CNA lower bound, merge SHA, path names)

`CORRECTION_REQUIRED` as a campaign label should mean: the **primary
verdict or the BIC identity** must change. A flipped
`introducer_parent_absent` or an over-broad CNA range is an erratum.

The re-research already applied the stricter bar on w078, w227, and
w123 (`CONFIRMED`). Use the same bar on the authorship-closed rows
whose only leftovers are membership/boolean text.

| Worker | Synthesis review | Required recode | Why |
|---|---|---|---|
| w153 | `CORRECTION_REQUIRED` | erratum, not causal correction | `NOT_AI` closed; set `introducer_parent_absent=true`; optional PR #234 members. Same class as w078’s merge SHA. |
| w165 | `CORRECTION_REQUIRED` | erratum, not causal correction | BIC `vnmedeiros` + no AI marker already closes `NOT_AI`. Affected lower bound `0.20.0` vs CNA `0` is range text. |
| w088 | `CONFIRMED` | field correction, verdict stays `NOT_AI` | Two independent atomic writers must appear in the record; parent boolean must be true. `CONFIRMED` hides that the primary is incomplete. `CORRECTION_REQUIRED` in the *causal* histogram also overstates it. Record as field correction. |
| w029 | `CORRECTION_REQUIRED` | keep as **field** correction only | Alternate landing `d2333551…` on early tags is real. Authorship is closed. Do not imply an open AI gate. |
| w277 | `CORRECTION_REQUIRED` | keep as **field** correction only | Parent boolean and 2023 historical paths. Owner identity already supports `NOT_AI`. |
| w326 | `CORRECTION_REQUIRED` | keep as **field** correction only | No tag maps to advisory “v.1.0”; unpatched HEAD. Named human BIC remains `NOT_AI`. |

Rows that **should** stay causal `CORRECTION_REQUIRED` (verdict or BIC
identity actually moves):

w002, w007, w008, w010, w011, w019, w115, w124, w133, w136, w139,
w167, w180, w206, w207, w312, w395, and w006 (range-only, but the
primary *text* is wrong enough that the review should not say
CONFIRMED).

If a third histogram cell is needed, call it `FIELD_ERRATUM` and put
w153, w165, w029, w277, w326, w088, w358 there. Do not add them to the
same 24 as w007/w008.

---

## Remaining disagreement 3 — README fail-closed sentence

`disagreement-rereview/README.md` currently:

> Missing or ambiguous BIC identity remains fail-closed.

The 33 Decisions did not apply that sentence as the independent review
did. Named human author/committer and no AI/bot/generator marker
closed `NOT_AI` (w165, w227, w207, w010, …). Fail-closed was used
only where the BIC *object* is not a named human writer (w289
parentless unsigned snapshot; w312 `Your Name <you@example.com>` →
`invalid-email-address`).

**Replace the sentence with:**

> Fail closed when the atomic BIC cannot be identified, or when the
> BIC commit object has no resolvable named human or AI/bot identity.
> A named human author/committer on the BIC, with no
> Co-Authored-By / Generated-with / bot / generator marker, closes
> `NOT_AI`. Absence of an AI trailer is not by itself an
> `EVIDENCE_GAP`.

Leaving the old sentence in the README will recreate the Class A
error on the next wave.

---

## Remaining disagreement 4 — landing constraints on accepted rows

These do not change the recommended primary. They constrain how the
record is filled.

### w010 GitPython

Three public first-writes exist. The ledger schema has one scalar
`introducer_sha`. For the vendor `Repo.clone_from(..., template=)`
PoC, land:

- `introducer_sha` = `b425301ad16f265157abdaf47f7af1c1ea879068`
- `introducer_parent` = `ca288d443f4fc9d790eecb6e1cdf82b6cdd8dc0d`

Put `00c5497f190172765cc7a53ff9d8852a26b91676` (`Repo.clone`) and
`ba5717549b32f6b5cee304fdff87cb26b3be688a` (submodule options) in
`flaw_origin` / evidence, not as a second and third `introducer_sha`.
The 2026 fix’s `GPT 5.6` / `<!-- agent -->` markers stay off the BIC.

### w115 MINA (CVE-2026-47065)

One advisory, two mechanisms (ZDRES-232 proxy allow-list bypass and
ZDRES-233 `<clinit>`). `NOT_AI` can stand for both writers (2024
allowlist Git objects and 2005 SVN r349422). Do **not** store a single
Git SHA as if it were the first-write of both. Split in
`bug_semantics` / `flaw_origin`; if the schema cannot hold two
introducers, name the mechanism the row is actually judging and point
the other at remaining evidence. Inventing a 40-hex SHA for r349422
is forbidden; the SVN revision is the BIC object
(`audit_record_gates.py` already allows a verified non-Git BIC).

### w395 PDFMathTranslate / Gradio

Accept `NOT_AI` with Gradio PR member
`500bcca42f406dc8ac30c601208828af81fc12c1` (Abubakar Abid, 2022, no
AI marker) as the vulnerable-line writer, parent
`b643ae77bfb465960af2f41f66351ef2a1b84d03`, squash decomposed through
PR #2256, upstream direct fix
`1c5c53842df9c2750552d85c19a92e7e732cff3f`.

The ledger row remains the pdfmathtranslate advisory. Consumer
releases `v1.9.9`–`v1.9.11` / HEAD still launch Gradio and pin
`gradio<5.36`, which excludes fixed Gradio 6.20.0. Record that as
unpatched *consumer* state (or `remaining_gap` on a first-party
fixed release). Do not imply PDFMathTranslate was repaired by the
Gradio 6.20.0 SHA.

---

## Review-verdict recode I would actually ship for these 33

Causal `CORRECTION_REQUIRED` (verdict or BIC identity changes, or
range/impact text that would mislead a reader of the TP):

w002, w006, w007, w008, w010, w011, w019, w115, w124, w133, w136,
w139, w167, w180, w206, w207, w312, w395

`CONFIRMED` (causal chain and authorship closed; leftover text is
optional):

w078, w123, w227, w166, w252, w387

Field erratum, verdict unchanged `NOT_AI`:

w029, w088, w153, w165, w277, w326, w358

Open `EVIDENCE_GAP`:

w122, w289, and keep w180/w312 in the causal-correction list only
because the *primary* currently says `NOT_AI` and must move.

That is the grading the 24-count still fails to express.

---

## What this is not

- Not a claim that all 389 independent-review files were re-opened.
  Only the 33 memo-named cases were in scope.
- Not a claim that every SHA in the 33 writeups was re-cloned here.
- Not permission to land ledger rows from this file.
- Not revival of “no AI trailer cannot close `NOT_AI`.” The
  re-research Decisions already rejected that rule; this response
  only asks that the README and the `CORRECTION_REQUIRED` histogram
  match those Decisions.
