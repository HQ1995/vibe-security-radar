# Candidate/Fix Edge Accounting for a 12-Case Held-Out Study

- **Status:** FROZEN_CANDIDATE_ACCOUNTING_COMPLETE
- **Freeze date:** 2026-08-09
- **Study window:** 2025-05-01 through 2026-08-09
- **Population:** 51,218 candidate/fix edge units across 12 already-numbered held-out vulnerability cases
- **Source SHA-256:** `ac7fa00e85bc7063cd2f09a9b3d3e5c2201403ffc6d672e91a55270f578343ee`
- **Final ledger SHA-256:** `cde1b3dfd50f5a832c72939134d783c1c5457bb29daf296bdc1dac44abb103e7`

## Denominator map

51,218 units are candidate/fix edges, not 51,218 vulnerabilities.

4,168 public-AI-bound units are attribution-bearing candidates, not 4,168 confirmed AI-causal vulnerabilities.

Patch-level semantic review covered 4,168 units; the other 47,050 received attribution accounting only.

## What this closes—and what it does not

This run exhaustively accounts for every unit in the frozen v5 held-out candidate inventory. It proves processing conservation inside that finite inventory: every source unit appears exactly once in the final ledger, every unit with public AI-binding evidence received DeepSeek triage and patch review, and every held-out positive edge was present in the reviewed candidate set.

This is not a count of AI-introduced vulnerabilities and not a claim of perfect global recall for all CVE/GHSA records since May 2025. The 12 advisories were a repository-disjoint positive held-out set, public AI attribution is incomplete, and a closed candidate inventory cannot measure cases absent from its upstream census.

First-ever repository origin is not required; causal reimplementation and compositional contribution are allowed.

## Lossless method

1. Freeze the canonical 51,218-unit JSONL and verify its byte and canonical hashes, unique IDs, candidate conservation, and local Git object availability.
2. Record all 51,218 attribution dispositions. Lack of a public AI signal remains `unobserved`, never `human` and never a hard negative.
3. Send all 4,168 publicly AI-bound units to `deepseek-v4-flash` through `http://127.0.0.1:8317/v1`. HIGH/MEDIUM/LOW is ranking only; no label deletes a unit.
4. Before opening control labels, freeze a lossless deep-review policy: all 4,168 publicly AI-bound units advance to patch review; ranking and structural signals annotate priority but never control membership.
5. For all 4,168, extract actual candidate-patch excerpts with fix-overlap paths first, then compare them with advisory text and the known fix patch. SUPPORTED remains a model review recommendation unless independent evidence confirms it.
6. Freeze all generated inputs and results, then join the separately frozen, independently reviewed 16-edge control ledger and build one final row per source unit.

## Processing coverage

| Layer | Completed | Total | Remaining |
|---|---|---|---|
| Attribution ledger | 51218 | 51218 | 0 |
| Public-AI DeepSeek triage | 4168 | 4168 | 0 |
| Patch-evidence deep review | 4168 | 4168 | 0 |
| Final exact-ID ledger | 51218 | 51218 | 0 |

DeepSeek triage labels: HIGH=54, MEDIUM=90, LOW=4024. Patch-review recommendations: SUPPORTED=39, INCONCLUSIVE=32, NOT_SUPPORTED=4097.

## Held-out candidate coverage and model sensitivity

| Candidate budget | Gold edges covered | Gold-edge coverage | Cases covered | Case coverage |
|---|---|---|---|---|
| 25 | 14/16 | 87.50% | 11/12 | 91.67% |
| 100 | 15/16 | 93.75% | 12/12 | 100.00% |
| full 51,218 | 16/16 | 100.00% | 12/12 | 100.00% |

Full-inventory 16/16 is candidate coverage after unblinding, not 100% model recall.

DeepSeek's `SUPPORTED` sensitivity on the 16 controls was 15/16 (93.75%); one control was `INCONCLUSIVE`.

| Advisory | Candidate | Rank | Triage | Patch review | Final |
|---|---|---|---|---|---|
| CVE-2026-21882 | 0fc1b4f70117 | 3 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| GHSA-fmfg-9g7c-3vq7 | aae7acba91dc | 9 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-27627 | e193701defac | 4 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2025-69288 | 40331e610075 | 1 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-33331 | 3e17621325a7 | 29 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2025-13120 | cf8faed585e1 | 4 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-22171 | 2267d58afcc7 | 2 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-32890 | 403ccf079be0 | 1 | HIGH | INCONCLUSIVE | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-2376 | a6d759cd016b | 7 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-2376 | 24d6083f5a43 | 11 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-2376 | bb7c06aec08a | 301 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| GHSA-8g98-m4j9-qww5 | c139c021f68a | 1 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-27203 | 4c9c826c6fc8 | 5 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-27203 | 8c1989e36ad2 | 9 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-27695 | e17c29d93319 | 7 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |
| CVE-2026-27695 | 3902c8c22868 | 11 | HIGH | SUPPORTED | CONFIRMED_TRUE_POSITIVE_CONTROL |

## Per-advisory accounting

| Advisory | Repository | All units | Public AI | Deep review | Confirmed edges | Model-supported unconfirmed |
|---|---|---|---|---|---|---|
| CVE-2025-13120 | github.com/mruby/mruby | 17883 | 539 | 539 | 1 | 0 |
| CVE-2025-69288 | github.com/kromitgmbh/titra | 558 | 40 | 40 | 1 | 2 |
| CVE-2026-21882 | github.com/asfhtgkdavid/theshit | 78 | 2 | 2 | 1 | 0 |
| CVE-2026-22171 | github.com/openclaw/openclaw | 12809 | 412 | 412 | 1 | 0 |
| CVE-2026-2376 | github.com/quay/quay | 13126 | 534 | 534 | 3 | 6 |
| CVE-2026-27203 | github.com/yosefhayim/ebay-mcp | 489 | 100 | 100 | 2 | 0 |
| CVE-2026-27627 | github.com/karakeep-app/karakeep | 2117 | 402 | 402 | 1 | 1 |
| CVE-2026-27695 | github.com/zeroae/zae-limiter | 1021 | 948 | 948 | 2 | 8 |
| CVE-2026-32890 | github.com/openvessl/anchorr | 244 | 30 | 30 | 1 | 0 |
| CVE-2026-33331 | github.com/middleapi/orpc | 1340 | 102 | 102 | 1 | 2 |
| GHSA-8g98-m4j9-qww5 | github.com/tailot/taylored | 90 | 47 | 47 | 1 | 0 |
| GHSA-fmfg-9g7c-3vq7 | github.com/homeassistant-ai/ha-mcp | 1463 | 1012 | 1012 | 1 | 5 |

## Final dispositions

| Disposition | Units |
|---|---|
| ANALYZED_ATTRIBUTION_UNOBSERVED | 47007 |
| MODEL_PATCH_REVIEW_NOT_SUPPORTED | 4097 |
| ANALYZED_NO_OBSERVED_AI_BINDING | 43 |
| MODEL_PATCH_REVIEW_INCONCLUSIVE | 31 |
| MODEL_PATCH_REVIEW_SUPPORTED_UNCONFIRMED | 24 |
| CONFIRMED_TRUE_POSITIVE_CONTROL | 16 |

24 model-supported edges remain unconfirmed and are preserved for independent adjudication; they are not silently promoted into the confirmed corpus. No row stopped at `MODEL_TRIAGE_LOW_NO_DEEP_REVIEW`, because all 4,168 publicly AI-bound units proceeded to patch review.

## Additional model-supported review candidates

| Advisory | Candidate | Triage | Confidence | Mechanism chain |
|---|---|---|---|---|
| GHSA-fmfg-9g7c-3vq7 | 39806871c972 | HIGH | HIGH | Candidate lands consent form collecting ha_url and outbound /api/config validation; fix reverses by pinning server-side URL. |
| GHSA-fmfg-9g7c-3vq7 | ff28281fd4a4 | HIGH | HIGH | Candidate embeds user-supplied ha_url in stateless token; fix eliminates ha_url and server-side pins URL |
| GHSA-fmfg-9g7c-3vq7 | 293e6180eb22 | HIGH | HIGH | User-supplied URL -> OAuthProxyClient -> SSRF error oracle |
| GHSA-fmfg-9g7c-3vq7 | ce8593b5513b | HIGH | HIGH | Introduced user-supplied ha_url in OAuth claims -> outbound GET to {ha_url}/api/config -> SSRF; fix eliminates that control. |
| GHSA-fmfg-9g7c-3vq7 | 2af133dac639 | HIGH | HIGH | User-supplied ha_url in consent -> token claim -> used for outbound GET -> SSRF. Candidate activates this flow; fix removes URL from claims. |
| CVE-2026-27627 | 7a10067234b1 | HIGH | HIGH | Introduced vulnerable direct-content path; fix applies DOMPurify to that path |
| CVE-2025-69288 | 67c7b7663219 | HIGH | HIGH | Vulnerable sandbox from PR lacks validation; admin can set timeEntryRule to arbitrary code; fix validates. |
| CVE-2025-69288 | f4017a3e7706 | HIGH | HIGH | Sandbox extended without validation; admin code execution persists; fix adds validation. |
| CVE-2026-33331 | b910bb82f684 | HIGH | HIGH | Candidate implements vulnerable JSON-to-HTML embedding; fix replaces it with escaped JSON serialization. |
| CVE-2026-33331 | 4f28b69506c2 | HIGH | HIGH | Commit introduced vulnerable raw JSON embedding; fix sanitizes JSON for HTML context. |
| CVE-2026-2376 | 3869d001aec3 | HIGH | HIGH | Implements org mirroring network requests following redirects; fix adds SSRF validation to prevent access to private/reserved IPs. |
| CVE-2026-2376 | 92b6f4729a5e | HIGH | HIGH | Accepts unvalidated external_registry_url; fix blocks private/reserved IPs and follows redirects only within allowlist. |
| CVE-2026-2376 | 4ae1b6488650 | HIGH | HIGH | Candidate implemented org mirror endpoints accepting user-supplied external_registry_url without redirect/IP restrictions; fix adds validation to these same code paths. |
| CVE-2026-2376 | 7f07e970be3c | HIGH | HIGH | Candidate introduces org mirroring without SSRF validation; fix adds URL checks against private/reserved IPs and blocked hostnames. |
| CVE-2026-2376 | c6d9345859b2 | HIGH | MEDIUM | Candidate extends org mirroring API with URL-triggering endpoint; omits SSRF validation that fix introduces |
| CVE-2026-2376 | 320934433470 | HIGH | HIGH | Candidate introduced external_registry_url handling; fix adds SSRF validation to that same code path, correcting the vulnerability. |
| CVE-2026-27695 | 0e6b99c185c2 | HIGH | HIGH | Candidate extends vulnerable entity-key bucket access; fix replaces with per-shard partition keys. |
| CVE-2026-27695 | 663b687a3748 | HIGH | HIGH | Candidate store bucket state under entity partition key -> hot partition risk. Fix migrates to per-shard bucket partition keys, correcting vulnerable design. |
| CVE-2026-27695 | f2c3a6fb1889 | HIGH | HIGH | Candidate reimplemented entity-partition bucket keys in sync repository, matching disclosed hot-partition scheme |
| CVE-2026-27695 | f73d39c3ca31 | HIGH | MEDIUM | Candidate extends entity-keyed bucket operations; fix corrects with sharded partition keys. |
| CVE-2026-27695 | f7d4d5e3999f | HIGH | HIGH | Candidate increases reliance on entity partition key for bucket reads; fix introduces per-shard keys. |
| CVE-2026-27695 | 4d0b13ac4f4c | HIGH | HIGH | Candidate extended bucket reads under entity partition key; fix replaces with per-shard bucket keys. |
| CVE-2026-27695 | 2d8cdd8c7c38 | HIGH | HIGH | Candidate implements required per-shard PK scheme; fix applies it to all bucket reads/writes, correcting disclosed issue. |
| CVE-2026-27695 | 626beb70e155 | HIGH | MEDIUM | Candidate implements entity-keyed composite bucket storage; fix migrates to per-shard pk_bucket keys, addressing hot partition. |

## Reproducibility nucleus

- [`inventory-freeze.json`](../research/orchestrator-260809-1424/inventory-freeze.json)
- [`triage-inference-profile.json`](../research/orchestrator-260809-1424/triage-inference-profile.json)
- [`public-candidate-patches.jsonl`](../research/orchestrator-260809-1424/public-candidate-patches.jsonl)
- [`deep-review-policy-v2.json`](../research/orchestrator-260809-1424/deep-review-policy-v2.json)
- [`deep-review-inference-profile.json`](../research/orchestrator-260809-1424/deep-review-inference-profile.json)
- [`model-response-manifest.json`](../research/orchestrator-260809-1424/model-response-manifest.json)
- [`pre-unblind-analysis-freeze.json`](../research/orchestrator-260809-1424/pre-unblind-analysis-freeze.json)
- [`positive-control-scorecard.json`](../research/orchestrator-260809-1424/positive-control-scorecard.json)
- [`full-analysis-ledger.jsonl`](../research/orchestrator-260809-1424/full-analysis-ledger.jsonl)

```sh
python3 research/orchestrator-260809-1424/prepare_full_inventory.py
python3 research/orchestrator-260809-1424/run_deepseek_full_triage.py
python3 research/orchestrator-260809-1424/prepare_public_patches.py
python3 research/orchestrator-260809-1424/build_deep_review_queue.py
python3 research/orchestrator-260809-1424/run_deepseek_deep_review.py
python3 research/orchestrator-260809-1424/build_model_response_manifest.py
python3 research/orchestrator-260809-1424/freeze_pre_unblind.py
python3 research/orchestrator-260809-1424/build_final_ledger.py
python3 research/orchestrator-260809-1424/write_full_report.py
python3 research/orchestrator-260809-1424/verify_full_analysis.py
```

The model endpoint and raw response envelopes are locally frozen; authentication material is not embedded in research artifacts.
