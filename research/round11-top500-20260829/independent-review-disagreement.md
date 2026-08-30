# Independent-review disagreement

Second-pass findings I do **not** accept as written, and why.

Scope is `research/round11-top500-20260829/independent-review/` (389 files)
against `docs/AUDIT-PROTOCOL.md`. This memo does not mutate primary records,
the ledger, or the independent-review files. It does not re-run clone replay
for every contested SHA; where a disagreement is protocol/standard-of-proof
rather than a git fact, that is stated.

Headline: **280 CONFIRMED / 94 CORRECTION_REQUIRED / 15 EVIDENCE_GAP is a
useful second pass. It is not 389/389 correct.** The important error is a
repeated misread of BIC-only AI attribution. A smaller error is grading.

---

## Protocol I am applying

`docs/AUDIT-PROTOCOL.md`:

- Vulnerability first, AI second.
- The BIC is the smallest commit that first wrote the vulnerable lines. A
  first-write that is the smallest surviving public object is a valid BIC
  when the immediate parent is verifiable and no finer public member can be
  reconstructed.
- **Judge the AI role from signals on that BIC only.**
- `NOT_AI` means a real vulnerability with **human authorship**.
- `FALSE_POSITIVE` means the advisory itself was wrong or withdrawn.
- GitHub `withdrawn_at` is not authoritative; check CVE.org / vendor
  disposition.

`scripts/audit_record_gates.py` refuses to land a closed verdict without
identity, a 40-hex BIC (or verified non-Git BIC), and a fix or explicit
unpatched record. **It does not classify AI vs human.** That judgment is
the BIC-object signals: author/committer identity, Co-Authored-By,
Generated-with, bot emails, agent trailers.

Positive AI on the BIC → `AI_ROOT_CAUSE` / `AI_CODE_FLAWED`.
Named human author/committer, no AI/bot marker on the BIC, parent
absence already proven → `NOT_AI`.

The catalog cannot require a contemporaneous screen recording of a human
typing. If “no trailer does not prove human” were the gate, almost every
pre-2024 CVE would be `EVIDENCE_GAP`. That is not how this ledger has been
closed.

The independent-review README additionally demands affected/fixed release
membership. That is a completeness check. Missing one vendor tag is a
record caveat, not automatic conversion of a closed `NOT_AI` into
`EVIDENCE_GAP`, unless the missing object is the BIC itself.

---

## Class A — authorship fail-closed (disagree on the verdict)

These reviews independently **confirm** mechanism, atomic BIC, parent
absence, squash handling, and the direct fix (or verified unpatched
state). They then fail `bic_only_ai_attribution` solely because a
human-looking Git identity plus absent trailers is “not affirmative
proof of human-only authorship,” and they replace `NOT_AI` with
`EVIDENCE_GAP`.

That standard is not in the protocol. It inverts BIC-only judgment:
the protocol asks what signals are **on the BIC**, not whether an
unobserved AI session can be metaphysically excluded.

### A1. Pure authorship flips (lifecycle already closed)

| worker | repo | GHSA | primary | review wants |
|---|---|---|---|---|
| w165 | tainacan/tainacan | GHSA-cqgm-j57m-cj34 | `NOT_AI` | `EVIDENCE_GAP` |
| w153 | zanllp/infinite-image-browsing | GHSA-cw66-pfp5-82xp | `NOT_AI` | `EVIDENCE_GAP` |
| w227 | mmaitre314/picklescan | GHSA-7jm4-f7vj-6pcc | `NOT_AI` | `EVIDENCE_GAP` |

**w165.** The reviewer’s own checks: mechanism CONFIRMED, BIC
`2dc5cf5c6f6eef3e24fcc07853d5e092766b6823` CONFIRMED (first write of
`geoquery` / `ST_Distance_Sphere` from `/dev/null`), parent
`1ab2f897…` lacks the helper, helper history is only BIC then fix
`579d28d7…`, tags 0.20.0–1.0.3 vulnerable / 1.1.0 fixed. Remaining
gap: “obtain affirmative provenance … that establishes human
authorship.” The BIC object is `vnmedeiros
<vnicius.nm.ba@gmail.com>` dated 2022-12-23, subject `feat: add
geoCoordinateHelper … #692`, empty trailers. That **is** the BIC-only
`NOT_AI` close. I reject the flip.

**w153.** Reviewer: lifecycle, atomic BIC `5f98c26b…`, parent, v1.8.0
/ v1.9.0 boundary, and direct fix `d1a6a818…` all PASS. Fail is only
“`zanllp <qc@zanllp.cn>` plus no trailer does not prove human-only.”
`introducer_parent_absent=false` while the parent lacks the mechanism
is a **boolean field correction**, not a missing BIC. Keep `NOT_AI`;
set `introducer_parent_absent=true`.

**w227.** Same pattern on picklescan BIC
`c1d5abdcc740e0d08a0d12d015d08e1e6f29a67e`. Mechanism, parent,
v0.0.24 / v0.0.25, and the denylist fix all PASS. Copilot on the
**fix** is correctly excluded. The remaining demand for “affirmative
human-only authorship” is the same over-read. Keep `NOT_AI`.

### A2. Authorship flip plus a real but non-causal field error

| worker | repo | GHSA | keep | fix in the record |
|---|---|---|---|---|
| w029 | ibm/mcp-context-forge | GHSA-xm98-3vcf-fph7 | `NOT_AI` | affected tags via alternate landing `d2333551…` |
| w277 | idurar/idurar-erp-crm | GHSA-93xg-c6hj-rp82 | `NOT_AI` | `introducer_parent_absent=true`; historical paths |
| w326 | code100x/cms | GHSA-8qr5-q795-mv79 | `NOT_AI` | no Git tag maps to advisory “v.1.0”; unpatched HEAD |
| w088 | thorsten/phpmyfaq | GHSA-gvqv-x9gq-w33g | `NOT_AI` unless the second path is a second BIC | `introducer_parent_absent=true`; split create vs update writers |

**w029.** BIC `cb5cd12a5882b59a8e441e84e636b2b960dc912f` (Mihai
Criveti, Signed-off-by only), parent absence, squash members, and
fix `63a2900e…` in v1.0.2 independently reproduce. The **release**
correction is real: v0.9.0 / BETA / RC1 contain equivalent landing
`d2333551…`, so excluding them by following only `771ffb8e…` is
wrong. That is `CORRECTION_REQUIRED` on membership text. It is not
an authorship gap. Do not flip the verdict.

**w277.** Database-to-PDF sink first written at `e968bc95…` by
`onfranciis <onukwuf@gmail.com>`, 2023, no trailers; unpatched at
HEAD. Agree the parent-absent flag and 2023 path names need
correction. Disagree that missing trailers reopen authorship.

**w326.** Auth-Key presence-only bypass: BIC
`a60ba45f26cb15e51d5077b8f2e11c5cbd2c29d9` (rishavvajpayee), parent
JWT-checked, squash decomposed, HEAD still vulnerable. No tags and
CVE `n/a` version mean the advisory’s “v.1.0” label is unverifiable,
not that the BIC is unauthored. Record unpatched + no-release-artifact;
keep `NOT_AI`.

**w088.** Mixed. `introducer_parent_absent` must be true (reviewer
replayed parent absence). If the advisory’s create-path is a
**separate** first-write at `781fdb66…`, the record must name both
writers or narrow `bug_semantics` to the update path. That is a
real protocol issue. The extra demand to “affirmatively establish
human authorship” on both SHAs is still Class A and I reject it
once each writer’s commit object is human + unmarked.

### A3. Borderline — do not generalize Class A from these

These two have a **weaker BIC object**, so `EVIDENCE_GAP` can be
defended without adopting the “no trailer ⇒ gap” rule.

**w289 fishcodetech/muteki GHSA-w4x2-2pcx-2cpc.** Root commit
`013ab6bf5fded15dcfcbcfbf94b3a270a79f9260` is parentless, unsigned,
~70k insertions. Mechanism and unpatched HEAD replay. A human GitHub
login on a first public snapshot is weak provenance. I accept
`EVIDENCE_GAP` **for this object shape**. I do not accept using w289
to justify flipping ordinary single-parent feature commits.

**w312 hashcat/hashcat GHSA-jfqq-rfm8-8frm.** BIC
`ef52453de9523f6a010652847b61cb340ed5daa5` is unsigned with
placeholder `Your Name <you@example.com>`; GitHub maps that to
`invalid-email-address`, not the PR submitter. Overflow mechanism,
parent absence, and fix `6f374c4f…` all PASS. Here the identity on
the BIC is **not a named human**. `EVIDENCE_GAP` is available
without rewriting the NOT_AI rule. Keep this distinct from w165.

---

## Class B — missing a vendor tag is not an authorship gap

Several reviews set `review_verdict=EVIDENCE_GAP` (or refuse
CONFIRMED) after the reviewer themselves PASSed mechanism, BIC,
parent, fix, and BIC-only `NOT_AI`, because one Adobe/enterprise
tag is absent from the public clone.

Protocol: understand the lifecycle. It does not say “every CNA
listed tag must exist on `origin` or the causal verdict is open.”
If the BIC and a direct fix are in the inspectable tags, the
missing line is a membership caveat (`remaining_gap` on releases),
not a verdict change.

| worker | repo | GHSA | what the review actually closed | what it still demanded |
|---|---|---|---|---|
| w123 | magento/magento2 | GHSA-xgfm-992v-h2hr | mechanism, BIC `d551d1e3…` (2017 Eric Bohanon, no AI marker), parent, fix `f83cc26c…`, 2.4.5–2.4.9 lines | 2.4.4-p14 / p15 tags not on the public remote |
| w166 | iomad/iomad | GHSA-2xjx-542r-phch | 2016 Derick Turner BIC, parent, IOMAD_405_6 / 500_02 vulnerable, stable **branch** heads fixed | no post-fix 4.5/5.0 **tag** |
| w252 | velocidex/velociraptor | GHSA-2v93-vp82-cjv8 | BIC-only `NOT_AI` supported | vendor 0.75.9 object not in public refs |
| w358 | spring-projects/spring-amqp | GHSA-p5f7-rjhp-pxvc | mechanism, introducer, parent, direct fix, BIC-only `NOT_AI` | enterprise v3.1.15 / v3.1.16 / v2.4.18 |
| w387 | spring-projects/spring-graphql | GHSA-px92-q6rc-6mwv | same pattern | v1.3.8 / enterprise v1.3.9 |

For these I would keep `NOT_AI`, write the missing tags into
`remaining_gap` or evidence, and **not** use `EVIDENCE_GAP` as the
causal verdict. w166 is the cleanest illustration: the reviewer
wrote `bic_only_ai_attribution: CONFIRMED` and still refused to
confirm the record.

Contrast: **w139 yoast-dist/duplicate-post** is a real gap — the
assigned clone is a dist snapshot and the cited source BIC/fix
objects are absent, so BIC-only checks cannot be replayed. I do
not put w139 in this class.

---

## Class C — grading: confirmed causality labeled CORRECTION_REQUIRED

`CORRECTION_REQUIRED` in the campaign report is one bucket. Inside
it:

- 18 records propose a **different verdict**
- 76 only change fields
- ~19 of those 76 only touch `reasoning` / `bug_semantics` /
  `evidence*` / `remaining_gap`

Putting a merge-SHA typo next to “this is not a vulnerability” makes
the 94 look like a 24% primary-error rate. It is not.

**w078 thorsten/phpmyfaq GHSA-jj45-w38g-gfrj.** Primary
`AI_ROOT_CAUSE`. Reviewer CONFIRMED mechanism, BIC
`086c8ad58f91a8e34ea27fabd1ba9ca0b2487f42` (author
`copilot-swe-agent[bot]`), parent, nightlies, and direct fix
`17b7f5b0…`. The only `corrected_fields` entry is `evidence[4]`:
GitHub now returns `merge_commit_sha ff6c01fd…` instead of `none`.
The BIC does not change (same stable patch-id as PR member
`b4c951fd…`). This is an evidence-line erratum. It is not
`CORRECTION_REQUIRED` in the same sense as w007/w008.

**w006 n8n GHSA-h5rm-9fhh-5phj** and **w011 openssl_encrypt
GHSA-gvq9-cmxr-844m.** Causal `AI_ROOT_CAUSE` independently
supported. Corrections are CNA range vs tag containment (w006) and
overstated impact on public/revoke routes (w011). I agree the text
should change. I disagree with filing them as if the TP is unstable.

**w207 redhatinsights/yggdrasil** is the **correct** pattern the
other reviews should have followed: squash landing is not the
atomic BIC; reconstruct PR #112 member `68ec1b65…`; **keep
`NOT_AI`** because the corrected BIC is still Link Dupont +
Signed-off-by. That is how BIC-only attribution is supposed to
work. Class A is inconsistent with w207.

---

## What I am not disagreeing with

So this memo is not “ignore the second pass.”

**Keep as CONFIRMED TPs:** w000, w001, w093, w295, w297.

**Keep `AI_ROOT_CAUSE` after field correction:** w002 (wrong BIC SHA;
true first-write `8a5ed7e6…` is still Claude-marked), w006 (range
wording), w011 (impact wording), w019 (incomplete fix / remaining
sinks — null `fix_sha`, keep scoped AI claim), w078 (merge SHA).

**Accept likely verdict flips (not re-executed this turn; arguments
are specific and falsifiable):**

- w007 openssl_encrypt CORS → `FALSE_POSITIVE` (Bearer is native-client
  explicit, not browser-ambient).
- w008 openssl_encrypt CTR fallback → `FALSE_POSITIVE` (12-byte nonce
  never constructs CTR; fail-closed).
- w206 erupt `FALSE_POSITIVE` → `NOT_AI` (still a real authenticated
  path-escape when `keepUploadFileName=true`; 2019 human BIC; CVE
  PUBLISHED).
- w395 pdfmathtranslate `FALSE_POSITIVE` → `EVIDENCE_GAP` (dependency
  route still launches in the app; advisory not withdrawn; Gradio BIC
  not in the assigned clone).

**Accept real BIC/mechanism gaps** (reviewer showed parent already
vulnerable, import aggregate, or unresolved identity): w010
gitpython; w115 / w124 / w133 / w136 mina; w122 magento advisory
identity; w167 messagepack vendoring; w180 invoiceninja if no
reachable unsanitized sink; w139 dist-only clone.

I have **not** independently re-cloned those last rows in this
sitting. I am not challenging their git facts.

---

## What I would actually change vs the 389-row scoreboard

If the independent-review labels were recoded to the protocol
above:

1. Move Class A1 (w165, w153, w227) from gap/correction back to
   `CONFIRMED` `NOT_AI`, optionally with a one-line `ai_marker`
   clarification.
2. Keep Class A2 as `CORRECTION_REQUIRED` **without** a verdict
   change: w029, w277, w326, and the non-authorship half of w088.
3. Leave w289 and w312 as optional `EVIDENCE_GAP` for object-quality
   reasons, not for the Class A rule.
4. Recode Class B (w123, w166, w252, w358, w387) to CONFIRMED or
   field-only correction, with release caveats in `remaining_gap`.
5. Recode w078 (and similar evidence-only nits) out of the same
   “correction” histogram cell as w007/w008.
6. Do not treat the 111 records completed after the original freeze
   as reviewed. They were never in this second pass.

Net: I disagree with using “absent AI trailer cannot close NOT_AI”
as a campaign rule, and I disagree with collapsing evidence nits,
release-tag holes, and real causal failures into one
`CORRECTION_REQUIRED` count. I do not disagree with the second pass
where it actually moved a BIC, killed a non-vulnerability, or
caught an over-claimed FALSE_POSITIVE.
