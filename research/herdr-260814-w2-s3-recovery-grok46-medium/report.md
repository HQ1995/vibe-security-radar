# Wave-2 slice-3 recovery: 0 countable proposals

**Status: not terminal for the 200+ objective. Proposed PASS = 0. Countable PASS = 0. Publication HOLD.**

Worker PASS is a proposal only. This packet proposes no admissions and does not claim more than 200. Canonical strict count remains **84**.

## Claim boundary

The 24 assigned rows are additive-guard recovery identities whose `commit_refs` are the first-party GHSA-referenced fix SHAs. Those closures were inspected for explicit AI markers and for an AI-authored earlier security boundary that the fix later amended. Neither was proved. Missing origin evidence stays UNKNOWN. Heuristic miss is not whole-case causal REJECT and is not GHSA-wide NOT_AI.

AI_INCOMPLETE_REMEDIATION was considered and not counted: the assigned candidate is the named closure, not an explicit earlier AI security attempt that left the residual path later closed.

## Input hashes

- slice `_ag_slice.jsonl`: `c833572d4d2573c3e9b80d770c0dd7b55ec2f3e987e6afd8c4a0d75ef789ff58`
- spec `_ag_spec.md`: `94ba89b0ec0bb6703e7c5fbc33e5b35eb313ca243ec18add357f51685dcc06d1`
- contract `_contract.md`: `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`
- canonical84 `ledger.jsonl`: `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`
- work/gather.json: `d81f32e2c0c7f7ab25ab3ae18997f50be4b3ff9b34966c81e1f1f3227748d8f0`

Canonical84 used only as exclusion and uniqueness reference. Overlap with counted IDs: 0. Ledger not edited.

## Conservation

| Class | N | Meaning |
|---|---:|---|
| Assigned | 24 | Entire `_ag_slice.jsonl` |
| next30 source | 12 | global_order 49-60 |
| final36 source | 12 | global_order 61-72 |
| identity PASS | 24 | First-party reviewed GHSA, not withdrawn |
| uniqueness PASS | 24 | Not in canonical84 counted set |
| UNKNOWN verdict | 24 | Causal gates not closed |
| CONFIRM / NARROW / FALSE_POSITIVE | 0 / 0 / 0 | |
| Countable proposal | 0 | All seven gates not PASS |
| Canonical strict | 84 | Unchanged |

Equations: **24=12+12**. Verdicts **24=0+0+0+24**. Source pool **381=285+96; 96=30+30+36; 96=88+8**. Holds. Did not pad or backfill.

## Stored-label disagreement

- 21 prior `NOT_SELECTED` mining rows: seven-gate adjudication opened identity and uniqueness; remaining gates UNKNOWN.
- 3 prior `BLOCKED` rows (GHSA-8398-GMMX-564H, GHSA-96PC-27RX-PR36, GHSA-WF6X-7X77-MVGW): assigned commits are present. Leftover promisor blame gaps stay UNKNOWN, not BLOCKED.

## Per-row evidence

### GHSA-5H7V-G49C-H887

- Repository: `lf-edge/eve`
- Summary: EVE Doesn't Protect Rootfs
- Aliases: CVE-2023-43636
- Advisory: `advisories/github-reviewed/2026/02/GHSA-5h7v-g49c-h887/GHSA-5h7v-g49c-h887.json` sha256 `ad46d51e57b08a3e961a028d4709c3ddb138a76dd57f4050a6ddff7767b32391`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 5fef4d92e758 `Measure rootfs and CONFIG into PCR 13` by Mikhail Malyshev parents=1 ai_marker=False; aa3501d6c572 `Seal disk decription key to PCR 13` by Mikhail Malyshev parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-5h7v-g49c-h887/GHSA-5h7v-g49c-h887.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lf-edge__eve show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 5fef4d92e75838cc78010edaed5247dfbdae1889`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lf-edge__eve show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' aa3501d6c57206ced222c33aea15a9169d629141`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lf-edge__eve rev-parse --verify 5fef4d92e75838cc78010edaed5247dfbdae1889^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lf-edge__eve show -s --format=fuller 5fef4d92e75838cc78010edaed5247dfbdae1889`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lf-edge__eve cat-file -t 5fef4d92e75838cc78010edaed5247dfbdae1889`

### GHSA-8398-GMMX-564H

- Repository: `n8n-io/n8n`
- Summary: n8n has a Python sandbox escape
- Aliases: CVE-2026-25115
- Advisory: `advisories/github-reviewed/2026/02/GHSA-8398-gmmx-564h/GHSA-8398-gmmx-564h.json` sha256 `b555c4fb76a4216cb0e4a115f08ea7ff417547c2edcd986916b05d857c2b0d43`
- Prior: BLOCKED / UNKNOWN (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 8607d372f78c `refactor(core): Improve Python match extraction handling (#24975)` by Ivan Ovejero parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining BLOCKED. Candidate objects are present in the cache clone. Residual parent-blob lazy-fetch gaps do not restore BLOCKED; they leave ai_hunk_gate UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-8398-gmmx-564h/GHSA-8398-gmmx-564h.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/n8n-io__n8n show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 8607d372f78c388bb3691d9d5b52af7259ec7b1f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/n8n-io__n8n rev-parse --verify 8607d372f78c388bb3691d9d5b52af7259ec7b1f^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/n8n-io__n8n show -s --format=fuller 8607d372f78c388bb3691d9d5b52af7259ec7b1f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/n8n-io__n8n cat-file -t 8607d372f78c388bb3691d9d5b52af7259ec7b1f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/n8n-io__n8n diff --stat d4dffbe3ba0a839afd766b5f2a15ceb4936490bf...8607d372f78c388bb3691d9d5b52af7259ec7b1f`

### GHSA-96PC-27RX-PR36

- Repository: `ImageMagick/ImageMagick`
- Summary: ImageMagick has Possible Heap Information Disclosure in PSD ZIP Decompression
- Aliases: CVE-2026-24481
- Advisory: `advisories/github-reviewed/2026/02/GHSA-96pc-27rx-pr36/GHSA-96pc-27rx-pr36.json` sha256 `047e724e0cc448a55f3845e40b5c01eff895f8e46c6c3f0991cb5717608404a7`
- Prior: BLOCKED / UNKNOWN (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 51c9d33f4770 `Initialize the pixels with empty values to prevent possible heap information disclosure (GHSA-96pc-27rx-pr36)` by Dirk Lemstra parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL. Residual promisor/path blame errors: 1; those gaps stay UNKNOWN.
- Label note: Prior mining BLOCKED. Candidate objects are present in the cache clone. Residual parent-blob lazy-fetch gaps do not restore BLOCKED; they leave ai_hunk_gate UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-96pc-27rx-pr36/GHSA-96pc-27rx-pr36.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/ImageMagick__ImageMagick show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 51c9d33f4770cdcfa1a029199375d570af801c97`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/ImageMagick__ImageMagick rev-parse --verify 51c9d33f4770cdcfa1a029199375d570af801c97^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/ImageMagick__ImageMagick show -s --format=fuller 51c9d33f4770cdcfa1a029199375d570af801c97`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/ImageMagick__ImageMagick cat-file -t 51c9d33f4770cdcfa1a029199375d570af801c97`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/ImageMagick__ImageMagick diff --stat 85dc1a5bf1ba54a2475e140074889724bd49a97c...51c9d33f4770cdcfa1a029199375d570af801c97`

### GHSA-C87C-78RC-VMV2

- Repository: `man-group/dtale`
- Summary: D-Tale affected by Remote Code Execution through the /save-column-filter endpoint
- Aliases: CVE-2026-27194
- Advisory: `advisories/github-reviewed/2026/02/GHSA-c87c-78rc-vmv2/GHSA-c87c-78rc-vmv2.json` sha256 `37395b86d6194cfce6f73e200474a8585d0aa6084e8964a9919b99508a9140dd`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 431c6148d3c7 `Add input validation to guard against code injection via DataFrame.query()` by Andrew Schonfeld (Boston) parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-c87c-78rc-vmv2/GHSA-c87c-78rc-vmv2.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/man-group__dtale show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 431c6148d3c799de20e1dec86c4432f48e3d0746`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/man-group__dtale rev-parse --verify 431c6148d3c799de20e1dec86c4432f48e3d0746^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/man-group__dtale show -s --format=fuller 431c6148d3c799de20e1dec86c4432f48e3d0746`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/man-group__dtale cat-file -t 431c6148d3c799de20e1dec86c4432f48e3d0746`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/man-group__dtale diff --stat 83fce4380848d9ae026b34f5dfd7bd56c52e7b02...431c6148d3c799de20e1dec86c4432f48e3d0746`

### GHSA-M7J5-R2P5-C39R

- Repository: `mmaitre314/picklescan`
- Summary: picklescan vulnerable to arbitrary file create using logging.FileHandler
- Aliases: (none)
- Advisory: `advisories/github-reviewed/2026/02/GHSA-m7j5-r2p5-c39r/GHSA-m7j5-r2p5-c39r.json` sha256 `95db9b9cbd4297cdd6747bb01f4c481420f1edd99e2df3e7853410b515664fcd`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 4d9bc9cd34bc `GHSA-m7j5-r2p5-c39r (#60)` by Matthieu Maitre parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-m7j5-r2p5-c39r/GHSA-m7j5-r2p5-c39r.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 4d9bc9cd34bca8672dad3481cd4556d5ba747156`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan rev-parse --verify 4d9bc9cd34bca8672dad3481cd4556d5ba747156^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan show -s --format=fuller 4d9bc9cd34bca8672dad3481cd4556d5ba747156`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan cat-file -t 4d9bc9cd34bca8672dad3481cd4556d5ba747156`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan diff --stat 173c8f2a869ea9b69b543477525ec70611c3c6f4...4d9bc9cd34bca8672dad3481cd4556d5ba747156`

### GHSA-9M3X-QQW2-H32H

- Repository: `mmaitre314/picklescan`
- Summary: picklescan missing detection by simple obfuscation of a `builtins.eval` call
- Aliases: CVE-2026-53874
- Advisory: `advisories/github-reviewed/2026/02/GHSA-9m3x-qqw2-h32h/GHSA-9m3x-qqw2-h32h.json` sha256 `8b7e25df8a2321a00f63b1c4cf0bb971bff12cea2e2b68f66fac408fd9babe80`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 173c8f2a869e `GHSA-9m3x-qqw2-h32h (#59)` by Matthieu Maitre parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-9m3x-qqw2-h32h/GHSA-9m3x-qqw2-h32h.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 173c8f2a869ea9b69b543477525ec70611c3c6f4`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan rev-parse --verify 173c8f2a869ea9b69b543477525ec70611c3c6f4^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan show -s --format=fuller 173c8f2a869ea9b69b543477525ec70611c3c6f4`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan cat-file -t 173c8f2a869ea9b69b543477525ec70611c3c6f4`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/mmaitre314__picklescan diff --stat 87629cb05c4521d14766eea174de0e1172d8acde...173c8f2a869ea9b69b543477525ec70611c3c6f4`

### GHSA-26GQ-GRMH-6XM6

- Repository: `gogs/gogs`
- Summary: Gogs vulnerable to Stored XSS via Mermaid diagrams
- Aliases: (none)
- Advisory: `advisories/github-reviewed/2026/02/GHSA-26gq-grmh-6xm6/GHSA-26gq-grmh-6xm6.json` sha256 `371a390bbcc747432d931085217bc8e0e4f075c3dc9512340ced956464f2d435`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 71a72a72ad1c `security: patch mermaid package version` by Jakub Domeracki parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL. Residual promisor/path blame errors: 1; those gaps stay UNKNOWN.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/02/GHSA-26gq-grmh-6xm6/GHSA-26gq-grmh-6xm6.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs rev-parse --verify 71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show -s --format=fuller 71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs cat-file -t 71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs diff --stat 4167a4d5685e434c9643e3c038e6e77a7407645a...71a72a72ad1c8cea7940c9d7e4cbdfbc0fc3d401`

### GHSA-JQ8V-RMF6-65JW

- Repository: `gogs/gogs`
- Summary: Gogs has Stored XSS in `.ipynb` Preview
- Aliases: CVE-2026-52798
- Advisory: `advisories/github-reviewed/2026/06/GHSA-jq8v-rmf6-65jw/GHSA-jq8v-rmf6-65jw.json` sha256 `a8e9b4fb0661da9bc5b05a08217f2d9451466031862009431e41db1070d51345`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 17b168b11ca7 `security: upgrade marked.js to 4.3.0 (#8319)` by jc@unknwon.io parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL. Residual promisor/path blame errors: 2; those gaps stay UNKNOWN.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-jq8v-rmf6-65jw/GHSA-jq8v-rmf6-65jw.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 17b168b11ca759a7550e1f4bbd68bbde14db7785`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs rev-parse --verify 17b168b11ca759a7550e1f4bbd68bbde14db7785^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show -s --format=fuller 17b168b11ca759a7550e1f4bbd68bbde14db7785`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs cat-file -t 17b168b11ca759a7550e1f4bbd68bbde14db7785`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs diff --stat 96c9a6626c12035249b3b967bc462c3e409e3b77...17b168b11ca759a7550e1f4bbd68bbde14db7785`

### GHSA-F3C5-6CW8-FG57

- Repository: `grokability/snipe-it`
- Summary: Snipe-IT's selectlist visibility is too permissive
- Aliases: CVE-2026-48492
- Advisory: `advisories/github-reviewed/2026/06/GHSA-f3c5-6cw8-fg57/GHSA-f3c5-6cw8-fg57.json` sha256 `88dd1539b3023922d8d8d73b9d235d6a31f3e88e9abd0d30e6b8c906fbcc2a93`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 4f943d4a7ab8 `Fixed FD-55580 - added selectlist gate and tests` by snipe parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-f3c5-6cw8-fg57/GHSA-f3c5-6cw8-fg57.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 4f943d4a7ab8e53f3d9e32770602d1118bab005f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it rev-parse --verify 4f943d4a7ab8e53f3d9e32770602d1118bab005f^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it show -s --format=fuller 4f943d4a7ab8e53f3d9e32770602d1118bab005f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it cat-file -t 4f943d4a7ab8e53f3d9e32770602d1118bab005f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it diff --stat 37361ef52f3a628bbc6f04538e267ef7a9ba593c...4f943d4a7ab8e53f3d9e32770602d1118bab005f`

### GHSA-VCM5-GVMP-78MP

- Repository: `gogs/gogs`
- Summary: Gogs has DOM-based XSS via Milestone Name on New Issue Page
- Aliases: CVE-2026-52807
- Advisory: `advisories/github-reviewed/2026/06/GHSA-vcm5-gvmp-78mp/GHSA-vcm5-gvmp-78mp.json` sha256 `2d3c0b7f8398103aa20deda4774aa676cbfd05d40dc1a241d67f8aa3d4436b68`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 573eacdc6586 `security: sanitize milestone names in new issue form (#8325)` by jc@unknwon.io parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-vcm5-gvmp-78mp/GHSA-vcm5-gvmp-78mp.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 573eacdc658641487f8ad883da96b29ec8e2852d`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs rev-parse --verify 573eacdc658641487f8ad883da96b29ec8e2852d^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs show -s --format=fuller 573eacdc658641487f8ad883da96b29ec8e2852d`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs cat-file -t 573eacdc658641487f8ad883da96b29ec8e2852d`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs diff --stat a9dbafbfd8e1020bacc626420238c01d75d03364...573eacdc658641487f8ad883da96b29ec8e2852d`

### GHSA-C9CV-MQ2M-PPP3

- Repository: `nuxt/nuxt`
- Summary: Nuxt: URL-handling weaknesses in `navigateTo` and `reloadNuxtApp`: SSR open redirect, client-side script execution via the `open` option, and protocol-relative bypass in `reloadNuxtApp`
- Aliases: CVE-2026-56326
- Advisory: `advisories/github-reviewed/2026/06/GHSA-c9cv-mq2m-ppp3/GHSA-c9cv-mq2m-ppp3.json` sha256 `25f9b63157285519eddf6b67a15ee243d6aa2cd3a05178f279b3e8ebe88bb1c6`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 1f2dd5e78c77 `fix(nuxt): block path-normalization open redirect in `navigateTo`` by Daniel Roe parents=1 ai_marker=False; 2cce6fb02e62 `fix(nuxt): block path-normalization open redirect in `navigateTo`` by Daniel Roe parents=1 ai_marker=False; 3394716d4a91 `fix(nuxt): apply `isScriptProtocol` guard to `navigateTo` open option (#35206)` by Daniel Roe parents=1 ai_marker=False; 62fc32eddf64 `fix(nuxt): apply `isScriptProtocol` guard to `navigateTo` open option (#35206)` by Daniel Roe parents=1 ai_marker=False; 6497d99dd106 `fix(nuxt): reject cross-origin paths in `reloadNuxtApp`` by Daniel Roe parents=1 ai_marker=False; e447a793c477 `fix(nuxt): reject cross-origin paths in `reloadNuxtApp`` by Daniel Roe parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-c9cv-mq2m-ppp3/GHSA-c9cv-mq2m-ppp3.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nuxt__nuxt show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 1f2dd5e78c77576437138e97671965573c232835`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nuxt__nuxt show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 2cce6fb02e621196d56df92e05594e07469b5a6d`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nuxt__nuxt show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 3394716d4a913cba904b028df5338f2aead50032`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nuxt__nuxt show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 62fc32eddf648b00a3890141e0235d2a222b024d`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nuxt__nuxt show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 6497d99dd106254abd089f6a263d7773869a343b`

### GHSA-8G7M-96C8-8WWC

- Repository: `lxc/incus`
- Summary: Incus has a Nil-Pointer Dereference Panic via Instance Backup Import (volume omitted)
- Aliases: CVE-2026-47753
- Advisory: `advisories/github-reviewed/2026/06/GHSA-8g7m-96c8-8wwc/GHSA-8g7m-96c8-8wwc.json` sha256 `e6d7eecd9d2f7a0c24634866503a3f3f725665fa88ee9c6cfa196615ddd8b0e4`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-next30-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 98e64f0a6fcf `incusd/storage: Guard nil fields in createDependentVolumesFromBackup` by Stephane Graber parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-8g7m-96c8-8wwc/GHSA-8g7m-96c8-8wwc.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lxc__incus show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 98e64f0a6fcfdc9676eea0246418d490c53297bf`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lxc__incus rev-parse --verify 98e64f0a6fcfdc9676eea0246418d490c53297bf^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lxc__incus show -s --format=fuller 98e64f0a6fcfdc9676eea0246418d490c53297bf`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lxc__incus cat-file -t 98e64f0a6fcfdc9676eea0246418d490c53297bf`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lxc__incus diff --stat ab6b7dff0c770044875d9d26a6254a7075b4d00b...98e64f0a6fcfdc9676eea0246418d490c53297bf`

### GHSA-PWPJ-P52H-Q484

- Repository: `grokability/snipe-it`
- Summary: Snipe-IT API Vulnerable to Cross-Tenant Accessory Injection
- Aliases: CVE-2026-54329
- Advisory: `advisories/github-reviewed/2026/06/GHSA-pwpj-p52h-q484/GHSA-pwpj-p52h-q484.json` sha256 `1303aa55a6cfd76f681f75c077bf01c944ac07b943b6c1f0eae54bc91f67d299`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: dc8cbf4786bb `Stricter FMCS enforcement in API` by snipe parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/06/GHSA-pwpj-p52h-q484/GHSA-pwpj-p52h-q484.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' dc8cbf4786bb38b260b4ae1723ec9e7f81d82fe5`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it rev-parse --verify dc8cbf4786bb38b260b4ae1723ec9e7f81d82fe5^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it show -s --format=fuller dc8cbf4786bb38b260b4ae1723ec9e7f81d82fe5`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it cat-file -t dc8cbf4786bb38b260b4ae1723ec9e7f81d82fe5`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/grokability__snipe-it diff --stat 5f81a48d8b642971332669aaabba903b9575f5fd...dc8cbf4786bb38b260b4ae1723ec9e7f81d82fe5`

### GHSA-8645-P2V4-73R2

- Repository: `gleam-wisp/wisp`
- Summary: wisp has Allocation of Resources Without Limits or Throttling
- Aliases: CVE-2026-32145
- Advisory: `advisories/github-reviewed/2026/04/GHSA-8645-p2v4-73r2/GHSA-8645-p2v4-73r2.json` sha256 `93393bb966b7a38b838feccff2394417b99f246b04a48f83444c6963f94f44c7`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 7a978748e12a `Fix body limits` by Louis Pilfold parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL. Residual promisor/path blame errors: 1; those gaps stay UNKNOWN.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-8645-p2v4-73r2/GHSA-8645-p2v4-73r2.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 7a978748e12ab29db232c222254465890e1a4a90`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp rev-parse --verify 7a978748e12ab29db232c222254465890e1a4a90^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp show -s --format=fuller 7a978748e12ab29db232c222254465890e1a4a90`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp cat-file -t 7a978748e12ab29db232c222254465890e1a4a90`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp diff --stat 161118c431047f7ef1ff7cabfcc38981877fdd93...7a978748e12ab29db232c222254465890e1a4a90`

### GHSA-2679-6MX9-H9XC

- Repository: `marimo-team/marimo`
- Summary: Marimo: Pre-Auth Remote Code Execution via Terminal WebSocket Authentication Bypass
- Aliases: CVE-2026-39987
- Advisory: `advisories/github-reviewed/2026/04/GHSA-2679-6mx9-h9xc/GHSA-2679-6mx9-h9xc.json` sha256 `73e4f9ef7e8f50260bea1b73ab88c0d28064b4c45e104d1363dc37a8781c3596`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: c24d4806398f `fix: properly authenticate terminal route (#9098)` by Myles Scolnick parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-2679-6mx9-h9xc/GHSA-2679-6mx9-h9xc.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/marimo-team__marimo show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' c24d4806398f30be6b12acd6c60d1d7c68cfd12a`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/marimo-team__marimo rev-parse --verify c24d4806398f30be6b12acd6c60d1d7c68cfd12a^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/marimo-team__marimo show -s --format=fuller c24d4806398f30be6b12acd6c60d1d7c68cfd12a`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/marimo-team__marimo cat-file -t c24d4806398f30be6b12acd6c60d1d7c68cfd12a`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/marimo-team__marimo diff --stat 78489d4621dc4358dc5974af0c727feb0b7331cb...c24d4806398f30be6b12acd6c60d1d7c68cfd12a`

### GHSA-HR2V-4R36-88HR

- Repository: `helm/helm`
- Summary: Helm Chart extraction output directory collapse via `Chart.yaml` name dot-segment
- Aliases: CVE-2026-35206
- Advisory: `advisories/github-reviewed/2026/04/GHSA-hr2v-4r36-88hr/GHSA-hr2v-4r36-88hr.json` sha256 `6fe6b69ceccfbfacb73e8b344dd8721ed58129e1ac2dc79c9ddce10c847ddc20`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 4e7994d44671 `fix: Chart dot-name path bug` by George Jenkins parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-hr2v-4r36-88hr/GHSA-hr2v-4r36-88hr.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 4e7994d4467182f535b6797c94b5b0e994a91436`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm rev-parse --verify 4e7994d4467182f535b6797c94b5b0e994a91436^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm show -s --format=fuller 4e7994d4467182f535b6797c94b5b0e994a91436`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm cat-file -t 4e7994d4467182f535b6797c94b5b0e994a91436`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm diff --stat 25819432bf87ac0b54f0d3fa54982add2cac609e...4e7994d4467182f535b6797c94b5b0e994a91436`

### GHSA-VMX8-MQV2-9GMG

- Repository: `helm/helm`
- Summary: Helm has a path traversal in plugin metadata version enables arbitrary file write outside Helm plugin directory
- Aliases: CVE-2026-35204
- Advisory: `advisories/github-reviewed/2026/04/GHSA-vmx8-mqv2-9gmg/GHSA-vmx8-mqv2-9gmg.json` sha256 `db8c8e56a7a2225afadaff6d93cb95c2dd44f54261c4993d89cfb91dad128cf9`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 36c8539e99bc `fix: Plugin version path traversal` by George Jenkins parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-vmx8-mqv2-9gmg/GHSA-vmx8-mqv2-9gmg.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 36c8539e99bc42d7aef9b87d136254662d04f027`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm rev-parse --verify 36c8539e99bc42d7aef9b87d136254662d04f027^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm show -s --format=fuller 36c8539e99bc42d7aef9b87d136254662d04f027`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm cat-file -t 36c8539e99bc42d7aef9b87d136254662d04f027`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/helm__helm diff --stat c61e0860ec797330a4c26a78dde7020cdc6743b1...36c8539e99bc42d7aef9b87d136254662d04f027`

### GHSA-WRWH-C28M-9JJH

- Repository: `nocobase/nocobase`
- Summary: @nocobase/plugin-collection-sql: SQL Validation Bypass Through Missing `checkSQL` Call
- Aliases: CVE-2026-41641
- Advisory: `advisories/github-reviewed/2026/04/GHSA-wrwh-c28m-9jjh/GHSA-wrwh-c28m-9jjh.json` sha256 `51cd9bd07150ce8bc6b1fa0a9b83bbe57dfca7617ab07fea86926d9f6165011c`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 851aee543efa `fix(collection-sql): validate sql on update (#9134)` by YANG QIA parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-wrwh-c28m-9jjh/GHSA-wrwh-c28m-9jjh.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nocobase__nocobase show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 851aee543efa894142e0f7be03eb55d9cec06a91`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nocobase__nocobase rev-parse --verify 851aee543efa894142e0f7be03eb55d9cec06a91^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nocobase__nocobase show -s --format=fuller 851aee543efa894142e0f7be03eb55d9cec06a91`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nocobase__nocobase cat-file -t 851aee543efa894142e0f7be03eb55d9cec06a91`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/nocobase__nocobase diff --stat 7da6628c995e404796c0b29e8cb8528b097df7ad...851aee543efa894142e0f7be03eb55d9cec06a91`

### GHSA-34R5-6J7W-235F

- Repository: `inspektor-gadget/inspektor-gadget`
- Summary: Inspektor Gadget uses unsanitized ANSI Escape Sequences In `columns` Output Mode
- Aliases: CVE-2026-25996
- Advisory: `advisories/github-reviewed/2026/04/GHSA-34r5-6j7w-235f/GHSA-34r5-6j7w-235f.json` sha256 `37f55cc5b04e42aad0f6eb5a2ff8b0833bd29cf331a19b0d842b186021117c93`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: d59cf72971f9 `pkg: columns: Escape strings before printing them.` by Francis Laniel parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-34r5-6j7w-235f/GHSA-34r5-6j7w-235f.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/inspektor-gadget__inspektor-gadget show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' d59cf72971f9b7110d9c179dc8ae8b7a11dbd6d2`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/inspektor-gadget__inspektor-gadget rev-parse --verify d59cf72971f9b7110d9c179dc8ae8b7a11dbd6d2^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/inspektor-gadget__inspektor-gadget show -s --format=fuller d59cf72971f9b7110d9c179dc8ae8b7a11dbd6d2`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/inspektor-gadget__inspektor-gadget cat-file -t d59cf72971f9b7110d9c179dc8ae8b7a11dbd6d2`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/inspektor-gadget__inspektor-gadget diff --stat e2367c741097b3e967e1abc5046296291d2caa98...d59cf72971f9b7110d9c179dc8ae8b7a11dbd6d2`

### GHSA-26PP-8WGV-HJVM

- Repository: `honojs/hono`
- Summary: Hono missing validation of cookie name on write path in setCookie()
- Aliases: (none)
- Advisory: `advisories/github-reviewed/2026/04/GHSA-26pp-8wgv-hjvm/GHSA-26pp-8wgv-hjvm.json` sha256 `3dea06d748715a5ef4ba5d06f80de855dd981b1d18ad7456e23ea56f6777b91e`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: a586cd72e3f6 `Merge commit from fork` by Yusuke Wada parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL. Residual promisor/path blame errors: 2; those gaps stay UNKNOWN.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/04/GHSA-26pp-8wgv-hjvm/GHSA-26pp-8wgv-hjvm.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/honojs__hono show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' a586cd72e3f6122792e631ecf1817e5cabb803ec`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/honojs__hono rev-parse --verify a586cd72e3f6122792e631ecf1817e5cabb803ec^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/honojs__hono show -s --format=fuller a586cd72e3f6122792e631ecf1817e5cabb803ec`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/honojs__hono cat-file -t a586cd72e3f6122792e631ecf1817e5cabb803ec`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/honojs__hono diff --stat 48fa2233bc092f650119f42df043050737cabf39...a586cd72e3f6122792e631ecf1817e5cabb803ec`

### GHSA-H7CJ-J2VV-QW8R

- Repository: `gleam-wisp/wisp`
- Summary: Wisp Vulnerable to Path Traversal
- Aliases: CVE-2026-28807
- Advisory: `advisories/github-reviewed/2026/03/GHSA-h7cj-j2vv-qw8r/GHSA-h7cj-j2vv-qw8r.json` sha256 `7f7c1eab6784ea667004311d1b19e4acb71f733bf45e3419bf251705e79aad46`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 129dcb1fe10a `Update wisp.gleam` by Jarod1980 parents=1 ai_marker=False; 161118c43104 `v2.2.1` by Louis Pilfold parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/03/GHSA-h7cj-j2vv-qw8r/GHSA-h7cj-j2vv-qw8r.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 129dcb1fe10ab1e676145d91477535e1c90ab550`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 161118c431047f7ef1ff7cabfcc38981877fdd93`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp rev-parse --verify 129dcb1fe10ab1e676145d91477535e1c90ab550^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp show -s --format=fuller 129dcb1fe10ab1e676145d91477535e1c90ab550`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gleam-wisp__wisp cat-file -t 129dcb1fe10ab1e676145d91477535e1c90ab550`

### GHSA-V33R-R6H2-8WR7

- Repository: `kimai/kimai`
- Summary: Kimai's API invoice endpoint missing customer-level access control (IDOR)
- Aliases: CVE-2026-28685
- Advisory: `advisories/github-reviewed/2026/03/GHSA-v33r-r6h2-8wr7/GHSA-v33r-r6h2-8wr7.json` sha256 `779e2bd3ee5c856b75001ea1d523715f1958e49f5d6e85160c1c6581fa5327db`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: a0601c8cb28f `check customer permissions on invoice api access (#5849)` by Kevin Papst parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/03/GHSA-v33r-r6h2-8wr7/GHSA-v33r-r6h2-8wr7.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kimai__kimai show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' a0601c8cb28fed1cca19051a8272425069ab758f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kimai__kimai rev-parse --verify a0601c8cb28fed1cca19051a8272425069ab758f^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kimai__kimai show -s --format=fuller a0601c8cb28fed1cca19051a8272425069ab758f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kimai__kimai cat-file -t a0601c8cb28fed1cca19051a8272425069ab758f`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/kimai__kimai diff --stat 5b320bf2ead19d62c271dfc789bd628d70b68a86...a0601c8cb28fed1cca19051a8272425069ab758f`

### GHSA-VQ4Q-79HH-Q767

- Repository: `go-vikunja/vikunja`
- Summary: Vikunjas Improper Access Control Enables Bypass of Administrator-Imposed Account Disablement
- Aliases: CVE-2026-33316
- Advisory: `advisories/github-reviewed/2026/03/GHSA-vq4q-79hh-q767/GHSA-vq4q-79hh-q767.json` sha256 `6996a897e0f6e2d0319b19a197d8e0fe79a34399edc4b5a4e1775522afc5bd57`
- Prior: NOT_SELECTED / heuristic_no_hard_hit (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 049f4a6be46f `fix: prevent email confirmation from re-enabling admin-disabled accounts` by kolaente parents=1 ai_marker=False; d8570c603da1 `fix: prevent password reset from re-enabling admin-disabled accounts` by kolaente parents=1 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL.
- Label note: Prior mining NOT_SELECTED is not a seven-gate verdict. This packet opened identity_gate and uniqueness_gate. Remaining causal gates stay UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/03/GHSA-vq4q-79hh-q767/GHSA-vq4q-79hh-q767.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 049f4a6be46f9460bd516f489ef9f569574bc70d`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' d8570c603da1f26635ce6048d6af85ede827abfb`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja rev-parse --verify 049f4a6be46f9460bd516f489ef9f569574bc70d^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja show -s --format=fuller 049f4a6be46f9460bd516f489ef9f569574bc70d`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja cat-file -t 049f4a6be46f9460bd516f489ef9f569574bc70d`

### GHSA-WF6X-7X77-MVGW

- Repository: `immutable-js/immutable-js`
- Summary: Immutable is vulnerable to Prototype Pollution
- Aliases: CVE-2026-29063
- Advisory: `advisories/github-reviewed/2026/03/GHSA-wf6x-7x77-mvgw/GHSA-wf6x-7x77-mvgw.json` sha256 `40626506c617c9083a48b57ed9a8d20e134047bb8d64a53bb70076b4f35fcd6f`
- Prior: BLOCKED / UNKNOWN (herdr-260814-ghsa200-additiveguard-final36-grok46-high)
- Verdict: UNKNOWN (identity PASS, uniqueness PASS, other gates UNKNOWN). Countable: no.
- Candidates: 16b3313fdf2c `Merge commit from fork` by Julien Deniau parents=2 ai_marker=False; 6e2cf1cfe613 `Port patch for CVE 2026-29063 onto branch 3.x` by Julien Deniau parents=1 ai_marker=False; 6ed4eb626906 `Merge commit from fork` by Julien Deniau parents=2 ai_marker=False
- AI marker: Assigned commit_refs are the first-party GHSA-referenced fix SHAs. No explicit AI trailer, bot identity, or Generated-with marker on those atomic commits or on inspected merge members. Bounded parent-context blame of added source spans found 0 AI-marked origins. Assigned refs are closures, not an earlier explicit security attempt with a later residual-path amendment. DIRECT_ROOT introducing-history was not searched beyond this additive-fix window; missing origin evidence stays UNKNOWN, not FAIL. Residual promisor/path blame errors: 6; those gaps stay UNKNOWN.
- Label note: Prior mining BLOCKED. Candidate objects are present in the cache clone. Residual parent-blob lazy-fetch gaps do not restore BLOCKED; they leave ai_hunk_gate UNKNOWN.
- Evidence commands:
  - `python3 -c "import json,pathlib; p=pathlib.Path('/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database/advisories/github-reviewed/2026/03/GHSA-wf6x-7x77-mvgw/GHSA-wf6x-7x77-mvgw.json'); print(p.exists(), json.load(open(p))['id'])"`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/immutable-js__immutable-js show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 16b3313fdf2c5f579f10799e22869f6909abf945`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/immutable-js__immutable-js show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 6e2cf1cfe6137e72dfa48fc2cfa8f4d399d113f9`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/immutable-js__immutable-js show -s --format='%H%n%P%n%an <%ae>%n%s%n%b' 6ed4eb626906df788b08019061b292b90bc718cb`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/immutable-js__immutable-js rev-parse --verify 16b3313fdf2c5f579f10799e22869f6909abf945^{commit}`
  - `git -C /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/immutable-js__immutable-js show -s --format=fuller 16b3313fdf2c5f579f10799e22869f6909abf945`

## Residual recall

Open outside this assigned fix window: AI_DIRECT_ROOT on introducing hunks, AI_NEW_SURFACE_CONTRIBUTOR, AI_REINTRODUCTION, and incomplete remediation on an earlier unlisted AI guard.

No fetched clone remained under work/. Cache clones were read-only. No credentials printed.

