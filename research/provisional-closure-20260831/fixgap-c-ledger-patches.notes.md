# Canonical fix-data closure: GHSA-M4WX and GHSA-R48C

Date: 2026-08-30

This note backs the two rows in `fixgap-c-ledger-patches.jsonl`. Both direct-fix objects are present in the local first-party Git clones, so neither row needs `unresolved_reason`.

## GHSA-M4WX-M65X-GHRR — patriksimek/vm2

- Canonical row: `alias-8e90b10e3e67d6523b66923e`, expected revision `2`.
- AI-side candidate: `46cbbdde4e19b743974c942278080231004146ca`. Its commit body carries `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- Minimum complete fix: `86ab819f202c3a8dad88cef5705f2e416c5188d7`.
- `01a7552add345d5a6862623884e6b79a85bf0568` is an ancestor and an intermediate repair: it closes omitted/falsy `require`, but its strict `nesting === true` and truthiness test still leave truthy non-boolean `nesting` and truthy primitive/function `require` shapes. `86ab819f...` is therefore the minimum complete closure retained in `minimum_fix_set`.
- `git merge-base --is-ancestor 46cbbdde... 86ab819f...` and `git merge-base --is-ancestor 01a7552a... 86ab819f...` both returned `0`.
- The selected candidate hunk is the exact `46cbbdde^..46cbbdde` constructor guard. The selected fix hunk is the exact `86ab819f^..86ab819f` structural guard in `lib/nodevm.js`.
- Primary sources: [advisory](https://github.com/patriksimek/vm2/security/advisories/GHSA-M4WX-M65X-GHRR), [candidate commit](https://github.com/patriksimek/vm2/commit/46cbbdde4e19b743974c942278080231004146ca), [fix commit](https://github.com/patriksimek/vm2/commit/86ab819f202c3a8dad88cef5705f2e416c5188d7).

Patch fingerprints over the newline-joined displayed hunk text:

- candidate: `8ffbe6491c5211cff22378213ec20e0111409b83d2d7be6666752272fb09deb3`
- fix: `fdb6d612ba5a1bc32eb5043047e084545d4e20c1dc2dd6adcafa6d9fdca4b817`

## GHSA-R48C-V28R-PF6V — modelcontextprotocol/registry

- Canonical row: `alias-df787a23a3ac89c4e14c8a5e`, expected revision `2`.
- Released AI-side origin/carrier: `1201cbd82b2cf6d4b56edfc05c763059a12f9fdb` (`v1.7.5`). Its body says `Generated with Claude Code` and carries the Claude Opus 4.7 co-author trailer.
- The historical member `257eb178cfb05335c68f793a5b1fba16c32e3769` is PR decomposition evidence, not the release-line origin. The canonical candidate and carrier are therefore both `1201cbd8...`; the displayed candidate hunks are its exact parent diff.
- Minimum complete fix: `f5f40bd98084466eaf18fe48ea62a0d534caa774` (`v1.7.7`). `v1.7.6` resolves to `db438962092c444d3b734b70644bc7a2694418a5` and lacks the fix.
- `git merge-base --is-ancestor 1201cbd8... f5f40bd9...` returned `0`; local tags resolve to `v1.7.5=1201cbd8...`, `v1.7.6=db438962...`, and `v1.7.7=f5f40bd9...`.
- The selected candidate hunks show the dialer wiring and the incomplete `isBlockedIP` boundary. The selected direct-fix hunk adds fail-fast CIDR parsing and the four missing ranges: 6to4 `2002::/16`, NAT64 `64:ff9b::/96`, local-use NAT64 `64:ff9b:1::/48`, and site-local `fec0::/10`.
- Primary sources: [advisory](https://github.com/modelcontextprotocol/registry/security/advisories/GHSA-R48C-V28R-PF6V), [candidate/carrier commit](https://github.com/modelcontextprotocol/registry/commit/1201cbd82b2cf6d4b56edfc05c763059a12f9fdb), [fix commit](https://github.com/modelcontextprotocol/registry/commit/f5f40bd98084466eaf18fe48ea62a0d534caa774).

Patch fingerprints over the newline-joined displayed hunk text:

- candidate: `f7e60098401caee031354790e06f88edca6a4920c9a58f6a146cd5dea1a1ed0d`
- fix: `133f36b0a87d02f9d755eb1326cf790835e0a4746eb73110d2324167ff371a51`

## Validation

- Two physical JSONL lines; both parse with `json.loads`.
- Both `expected_revision` values match the live ledger snapshot used to build the patch.
- `scripts.ledger_store.validate_update` passes for both complete-row replacements.
- Every candidate/fix hunk has a non-empty, hunk-specific annotation; every declared anchor occurs in its role's displayed diff.
- Both stored patch SHA-256 values recompute exactly from the displayed hunk text.
- This work did not run `ledger_store.py apply`, export, publisher, or commit.
