# Causal consensus miner versus canonical88

Verdict first: PASS_PROPOSAL=0. Released consensus ranked=0. Causal-only consensus proposals=3. Canonical88 stays 88 and was not edited.

This packet is a read-only miner over existing autoresearch terminal artifacts. It does not admit a row. Worker and same-model copies are not independent authority. Shared SHA is not a duplicate. Release evidence is tracked separately from the six causal gates.

## Method

Scanned structured terminal cases.jsonl, case.json, facts/gates.json, and result.json gate objects under autoresearch herdr-260813-* and herdr-260814-*. snapshot/work/pages/clones were not scanned. Inventory packets are not winning authority. Missing gates were never inferred from verdict text.

A mechanism is grouped by uppercase GHSA plus exact candidate_set and minimum_fix_set. Mechanism_key is a label and does not split the same SHA pair. Shared SHA alone does not merge distinct identities.

Consensus requires at least two genuinely independent terminal packets that agree on those exact sets, with identity, ai_hunk, topology, but_for, fix_reversal, and uniqueness all explicit PASS. Independent roles are hostile, redteam, independent review, campaign, and release-closure. Workers, inventory, and same-campaign-stem or same-model same-role pairs are rejected. Equal-or-stronger causal disagreement fails closed.

Current first-party identity is the github-reviewed advisory object under the local advisory-database clone, not withdrawn. Canonical88 strict identities are excluded.

Released ranking requires the agreeing independent packets to also record release_gate PASS. Causal-only ranking keeps six causal PASS when release is UNKNOWN, NARROW, FAIL, or COMMIT_ONLY. Rank cap for released is 25. This run produced 0 released rows and did not pad.

Manual replay bound is 12 parent/candidate/fix edges. Only 3 consensus candidates existed, so all 3 were replayed on local clones. Did not pad to 12.

## Released ranked list

Empty. No noncanonical mechanism had two independent terminal packets agreeing on exact candidate and minimum-fix sets with all six causal gates PASS and release_gate PASS.

## Causal-only proposals

1. GHSA-8G98-M4J9-QWW5 repo=tailot/taylored release=UNKNOWN n_independent=3
   mechanism taylored.paypal-webhook.unverified-body.purchase-token
   candidate c139c021f68a09d22c2af88641b61c00f67f2af4 fix 57b7634391959dbbdb39b387ac4dc68157cd58a1
   Pair: herdr-260813-ghsa200-narrow-recovery-a-grok46-xhigh and herdr-260813-ghsa200-nearclosed-upgrades-grok46-high. Third independent: herdr-260814-ghsa200-fp211-unknown4a-grok46-low.
   Replay: parent 610281a6 n_parents=1 lacks templates/backend-in-a-box/index.js. Atomic Jules candidate creates /paypal/webhook with webhookEvent = req.body. Atomic Jules closer 57b76343 is the direct child and adds Webhooks.verifyAndGetWebhookEvent. Only local tag 8.2.4 contains candidate and closer.

2. GHSA-VH5J-5FHQ-9XWG repo=tailot/taylored release=UNKNOWN n_independent=3
   mechanism taylored.get-patch.token_used_at.select-then-update-race
   candidate 57b7634391959dbbdb39b387ac4dc68157cd58a1 fix fdf67a6fba0deae30912905a79fb5a9e83751a79
   Same three independent packets as GHSA-8G98. Shared SHA 57b76343 is the PayPal fix there and the incomplete-rem candidate here; it is not a duplicate.
   Replay: atomic Jules 57b76343 adds SELECT then UPDATE token_used_at. Human closer fdf67a6f (parent f4d21045, n_parents=1) switches /get-patch to one UPDATE ... AND token_used_at IS NULL. 57b76343 is an ancestor of the closer. Only tag 8.2.4 contains both.

3. GHSA-G8MR-85JM-7XHM repo=vitest-dev/vitest release=NARROW n_independent=2
   mechanism vitest.browser.rpc.cdp-ungated-when-allowWrite-false
   candidate af88b1f5d82844a4761ea9a977156c98e2b14ca8 fix 385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7
   Pair: herdr-260814-cf3-confirm5-grok46-high (campaign, grok46-high) and herdr-260814-ghsa200-fp211-confirm11-closure-grok46-medium (independent, grok46-medium).
   Replay: parent 5a7d56e2 rpc blob 7619c5f0 has ungated cdp.send. Atomic Codex candidate af88b1f5 adds canWrite and leaves cdp.send ungated (blob 358ac355). Direct-child Codex closer 385a1aef adds assertCdpAllowed (blob 72818584). Tag v3.2.4 peel c666d149 has the parent blob. Tag v3.2.5 peel 2cbad0a9 has candidate and closer. Same-first-tag. Release stays NARROW.

## Fail-closed

GHSA-7C3W-FXGH-FRC7 had two independent six-PASS rows, but later equal-or-stronger redteam/campaign rows record but_for_gate NARROW. Excluded.

## Rejects that are not proposals

Canonical88 already holds 32 identities that meet this consensus test; they are counted there and are not listed here.
Single-packet six-PASS rows (including GHSA-H2V8-4C3F-VQGV) are not consensus.
Worker-plus-one-independent pairs are not two independent packets.

## Claim boundary

This is not a count of admitted AI-causal cases. Worker PASS remains a proposal. Publication and more-than-200 stay HOLD. Canonical88 ledger and summary were read, hashed, and left unchanged.

Status TERMINAL. No network. No new clones. No promotion. No commit.
