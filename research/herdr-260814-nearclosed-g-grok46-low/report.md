# Near-closed released wave G (fp211 ordinals 22, 24, 34)

TERMINAL. Assigned 3, reviewed 3, PASS_PROPOSAL 0, NARROW 3. Conservation 3=3+0. Canonical88 remains 88 HOLD. Packet delta 0. No causal or publication admission.

Bound to leader CONTRACT.md SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical88 summary SHA-256 `81667a2d2bec79b054e70c2bde9a801c0cf6387310fa0704a8263dab93b1b921`. Ledger SHA-256 `35017e63b30fce7a7e46bf1121d532bc7b40394c17ac87a5a5370a864bb93074`. fp211 public_cases.jsonl SHA-256 `e20d4ba5b7fdf43d338af6f7ecb8e1abfe43cc02396332091eee3689688ed257`. Shared tracked files and canonical ledgers were not edited. No commit, push, or credential output.

Exactly three first-party identities, fp211 ordinals 22, 24, 34: GHSA-42M6-XH7C-6XM4, GHSA-2M67-CXXQ-C3H8, GHSA-Q9J6-XCVX-PX63. Overlay routing is release_gate PASS with two inherited causal NARROW gates. That vector is not truth. All seven contract gates were rebuilt from Git objects, first-party advisories, tags, and public artifacts. Scoped contributor PASSes only when the AI change creates a clearly advisory-covered new transport, TOCTOU seam, or interpolation surface, and the minimum closer reverses that exact delta, including every needed member of a multi-purpose fix. Later human transport and preexisting sibling interpolation are not transferred. Worker PASS is proposal-only; this packet emits none.

## Per case

1. GHSA-42M6-XH7C-6XM4 ordinal 22 NARROW. Unreviewed GHSA-42m6 aliases CVE-2026-49949 and names CodexBar ProviderHTTPClient credentialed redirects before 0.33.0. affected[] is empty. Claude OpenRouter 8348c85c, DeepSeek b6b77b4b, and Kimi c3a03042 are atomic and AI-marked. Their trees use URLSession.shared and lack ProviderHTTPClient.swift. Human f62bb8c8 dated 2026-05-17 adds that transport after all three AI dates. Closer 08c171b6 guards redirects on ProviderHTTPClient.swift and OpenAI cookie import, not the AI fetchers. v0.32.0 peel 1351961f contains candidates plus f62bb8c8 without the closer; v0.33.0 peel 6cf42251 contains 08c171b6. Later human transport is not transferred.

2. GHSA-2M67-CXXQ-C3H8 ordinal 24 NARROW. Reviewed GHSA-2m67 aliases CVE-2026-32232. R2 is validate-then-use on filesystem and file-consuming tools; it does not uniquely name pdf_read. Counted squash 51bc07a0 carries its own Claude Sonnet 4.6 trailer and adds pdf_read.rs. Parent 24386e4b already calls validate_path_in_workspace in filesystem.rs. Member fe70dcd4 is not a tag ancestor; authorship is not transferred. v0.5.0 pdf_read blob 8d9747ec has no revalidate_path. f50c17e1 wires revalidate_path into pdf_read and also hardens path.rs, filesystem.rs, docx_read, and transcribe. GHSA also names bf004a20 and fixed 0.7.6 / last affected <=0.7.5, whose pdf_read blob 21e0bd74 already equals f50c17e1. Whole-advisory minimum fix is f50c17e1 plus bf004a20. Deleting pdf_read leaves parent filesystem TOCTOU.

3. GHSA-Q9J6-XCVX-PX63 ordinal 34 NARROW. Repo GHSA-q9j6 aliases CVE-2026-34599. GetLogs interpolates unlocked $container into docker logs. PoC method is getLogs. Claude member bbb2aa9a adds downloadAllLogs as a second interpolator of the same property. Parent b484c0cc already has getLogs interpolation. Carrier 4d4254b5 is a merge that includes the member and has no Claude trailer. Closer member 48ba4ece locks properties and authorizes both methods; GetLogs.php blob d0121bdc equals v4.0.0-beta.471. Merge f267a28c also carries unrelated model/API hardening from b3256d4d. Preexisting sibling interpolation is not transferred. v4.0.0-beta.470 peel 575b0766 contains the member without 48ba4ece; v4.0.0-beta.471 peel 914d7e0b contains the merge closer.

## Uniqueness

None of the three are in canonical88 strict_released_case_ids (88, including GHSA-8RW6-P7M8-63JP). CVE aliases are stored and not counted.

## Boundary

Worker PASS is proposal-only. This packet proposes none. Canonical strict count remains 88. Publication HOLD. This packet did not edit canonical ledgers, did not commit or push, and did not store durable pages, clones, packages, or caches.
