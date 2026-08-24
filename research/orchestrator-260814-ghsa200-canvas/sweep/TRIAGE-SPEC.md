# Triage spec (fast): plausibility of an AI commit vs an unreviewed advisory

Read-only. For each row in your slice: ghsa, repo, published, summary, and
recent_ai_commits (sha/date/subject/files/kinds/signals).

Judge ONLY from these fields (no git, no network, no API): does any recent AI
commit plausibly introduce or materially contribute to the mechanism named in
the summary? Plausible = the commit subject/files overlap the mechanism area
(e.g. the feature/route/parser named in the summary). Do not require proof.

Output one JSONL row per input row with the SAME order:
  ghsa, repo, verdict: KEEP | DROP | UNCERTAIN,
  candidate_shas: [sha(s) that look related], reason: one line.

Write triage.jsonl + a counts summary into your owned dir. A KEEP is a
screening hint only; a later deepseek lane adjudicates the seven gates.
