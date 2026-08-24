# unr-adj2-slice-7 adjudication — verdict-first

**Verdict: 25/25 FALSE_POSITIVE (no_ai_origin / wrong_edge). 0 countable. 0 UNKNOWN. 0 BLOCKED.**

Every candidate AI commit diff was fetched via git smart-HTTP into the bare pool
and read directly (no GitHub API, no blame/SZZ). In all 25 rows the candidate
AI commits do not author, rewrite, or materially contribute to the advisory's
named mechanism, so `ai_hunk_gate` and `but_for_gate` fail and the rows are not
countable. Missing fix/release evidence is left `UNKNOWN`, never converted to FAIL.

## Breakdown by repository

- **getgrav/grav — 23 rows.** Five shared AI commits are the only candidates:
  `2c517b01` (upgrade-gating for GPM/Installer/Console), `e3ff054d` (media
  blueprint + 44 translation files), `2dcf9179`/`bf7dd2e6` (one-line Copilot
  comments in Twig3CompatibilityTransformer.php), and `50865058` (regex
  hardening of the Twig2->Twig3 transformer). None touch the advisory surfaces
  (Twig sandbox, Security::detectXss, GPM/Zip, webhook cURL, Blueprint::dynamicData,
  shortcodes, .htaccess). 15 of the 23 name plugin repos (grav-plugin-api /
  admin2 / flex-objects / login / form / scheduler-webhook), which candidates in
  getgrav/grav core cannot introduce.
- **magicblack/maccms10 — 1 row.** CVE-2026-15516 (install controller Index.php
  step5 auth bypass). The five AI commits are batch-AI-SEO UI/JS, i18n keys, and
  plugin icons / AI Content Assistant plugin — none touch the install controller.
- **amule-project/amule — 1 row.** CVE-2026-51105 (OP_SERVERMESSAGE buffer
  overflow). The three Copilot-Autofix candidates touch src/kademlia/net/PacketTracking.cpp
  (flood-tracking int casts) and src/EncryptedStreamSocket.cpp (unsigned compare),
  not the ed2k server-message handler (CHANGELOG: OP_SERVERMESSAGE size validation #447).

## Gate totals

identity PASS 25; ai_hunk FAIL 25; topology UNKNOWN 25; but_for FAIL 25;
fix_reversal UNKNOWN 25; release UNKNOWN 25; uniqueness PASS 25.

No replay.txt acceptance section is required: there are zero PASS proposals.
