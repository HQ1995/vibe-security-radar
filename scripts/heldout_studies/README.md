# Held-out detector-quality studies

This directory is the permanent, append-only registry for formal held-out studies.
Each study commits its sealed `selection-<sha256>.json` first, then commits the
completed `labels-<sha256>.json` in a later revision.  Every prior study in this
directory is automatically excluded from future selections.

Formal labels use the schema-3 dual-review contract documented in
`scripts/HELDOUT_QUALITY.md`; schema-2 single-auditor labels are rejected.

Templates and working copies stay under `.ai-slop/state/data-refresh/heldout-v1/`.
Formal evaluation accepts only exact selection and label bytes tracked in this
directory.
