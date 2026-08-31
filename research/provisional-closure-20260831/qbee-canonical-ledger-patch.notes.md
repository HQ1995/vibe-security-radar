# qbee canonical publication migration

- Class: `alias-8545a65a3d21ea7ab297ab66` (`qbee-io/transport`; CVE-2026-55828 / GHSA-F9M7-VC86-P6JJ).
- Neon base: revision 2, change set `df53d33c-4109-44a2-9e6e-b607c99658b9`.
- The patch preserves the complete live row and adds the six canonical publication fields formerly held in `scripts/tp_publication_overrides.json`: `description`, `mechanism`, `candidate_set`, `minimum_fix_set`, `vulnerable_release`, and `fixed_release`.
- Existing canonical `repo` remains `qbee-io/transport`; no duplicate `repository` field was added.
- This artifact is staged only. It has not been applied, exported, published, or committed.
