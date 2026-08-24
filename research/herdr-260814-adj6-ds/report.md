# Unreviewed-adj slice 6

**Status: TERMINAL.** Worker PASS is a proposal only. This packet emits none. All 25 rows are REJECT; no AI commit introduces the named mechanism. Canonical strict count remains **168**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0.

## Method

Frozen github/advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc`, stream `advisories/unreviewed`. Advisory JSON pulled via `git cat-file` (no GitHub API, no blame/SZZ). Candidate AI commits read from the bare blobless pool `/home/hanqing/.cache/ghsa200-sweep-fetch` (ImageMagick, FFmpeg, open5gs already present) and the remaining five repos were blobless-cloned via git smart-HTTP. Full commit messages and changed files cross-checked against the frozen AI-commit corpus `current-ai-scan/commits.jsonl`. All candidates carry an explicit AI identity (anthropic.com/openai.com/cursor.com), satisfying the AI-marker bar, but none authors the vulnerable hunk.

## Verdicts

### 01 GHSA-3VXG-8VGP-994W REJECT

Unreviewed GHSA aliases CVE-2026-49492 (command injection in external file/link opening). Candidates are the 0.8.28 release bump (dcd80281) that pins crossnote 0.9.29 which SHIPS the fix, and the 0.8.25 feature release (dd996523). The vulnerable mechanism lives in the crossnote dependency, not this repo. reject_class MECHANISM_IN_DEPENDENCY_NOT_ORIGIN. uniqueness_gate PASS versus foundation.jsonl.

### 02 GHSA-J39P-JF99-V5W8 REJECT

Unreviewed GHSA aliases CVE-2026-50733 (WaveDrom eval RCE). Same candidates; dcd80281 ships the WaveDrom eval RCE fix via crossnote 0.9.29, dd996523 is unrelated wikilink/autocomplete feature work. Mechanism lives in crossnote. reject_class MECHANISM_IN_DEPENDENCY_NOT_ORIGIN. uniqueness_gate PASS versus foundation.jsonl.

### 03 GHSA-M5V2-JW65-JH59 REJECT

Unreviewed GHSA aliases CVE-2026-49493 (bitfield interpretjs RCE). Same candidates; neither authors the crossnote interpretjs path. Mechanism lives in crossnote. reject_class MECHANISM_IN_DEPENDENCY_NOT_ORIGIN. uniqueness_gate PASS versus foundation.jsonl.

### 04 GHSA-2G53-8J24-X4MG REJECT

Unreviewed GHSA aliases CVE-2026-11440 (vuldb, low). Candidates: a7094c7a bumps the Windows agent in pom.xml (OD-2801 pause fix); eb2b8232 normalizes reference-type casing in web autocomplete. Neither is a security boundary. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 05 GHSA-Q98J-2QW6-GH6W REJECT

Unreviewed GHSA aliases CVE-2026-11439. Same unrelated candidates (pom.xml agent bump, web autocomplete casing). reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 06 GHSA-V89H-G8W6-9CRX REJECT

Unreviewed GHSA aliases CVE-2026-11441. Same unrelated candidates. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 07 GHSA-W3RP-RGP7-P999 REJECT

Unreviewed GHSA aliases CVE-2026-11438. Same unrelated candidates. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 08 GHSA-FH45-7F3J-R575 REJECT

CVE-2026-8484 is the Jansi native-library loading bug. Candidate 300aa781 is itself the fix ("Fix native library loading failure caused by incorrect buffer comparison", Fixes #317); 1fd379a9 is a pom.xml deployment migration. AI-authored fix, not origin. reject_class AI_ON_FIX. uniqueness_gate PASS versus foundation.jsonl.

### 09 GHSA-JMQV-2MX7-544H REJECT

CVE-2026-56378 is a PCD decoder heap OOB read in coders/pcd.c (first-party GHSA-wgxp-q8xq-wpp9, introduced 0). Candidates 89a9974e (MagickWand/drawing-wand.c) and bd4a469a (coders/svg.c double-free fix) touch neither PCD path. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 10 GHSA-RG39-4FM5-HRP2 REJECT

CVE-2026-56367 is PSB (PSD v2) RLE integer-overflow heap OOB in coders/psd.c (GHSA-273h-m46v-96q4, introduced 0). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 11 GHSA-8G9F-CCMR-VFVG REJECT

CVE-2026-56376 is a meta coder UAF in coders/meta.c (GHSA-2gq3-ww97-wfjm, introduced 0). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 12 GHSA-98GV-6GMJ-CM6M REJECT

CVE-2026-56371 is a coders/txt.c memory leak without freetype (GHSA-3q5f-gmjc-38r8, introduced 0). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 13 GHSA-V772-658Q-978P REJECT

CVE-2026-56379 is SVG-to-MVG command injection in coders/svg.c (GHSA-xpg8-7m6m-jf56, introduced 0). Candidate bd4a469a is a coders/svg.c FIX for a DIFFERENT bug (double-free in gradientTransform/transform parsing, #8582), not the MVG command-injection path. 89a9974e is drawing-wand.c. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus foundation.jsonl.

### 14 GHSA-MJXR-6GQF-W78H REJECT

CVE-2026-58049 is in libavcodec/rasc.c. Candidates dd057bd8 (fate photosensitivity filter test) and b40d91ca (libavformat/avio.c tmp_opts leak fix) touch neither rasc.c nor its codec. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 15 GHSA-4H5W-9GQ6-38F8 REJECT

CVE-2026-56361 is an off-by-one in morphology (GHSA-q8h3-jv9v-57qx, fixed 14.12.0). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 16 GHSA-HQ73-7C65-P9CQ REJECT

CVE-2026-56365 is a PNG encoder leak writing MNG (GHSA-x928-4434-crqj). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 17 GHSA-R8HQ-C3QH-XQ9J REJECT

CVE-2026-56377 is a policy bypass via path validation (GHSA-gm48-c7f2-v67p). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 18 GHSA-VGQJ-4JHR-3WH5 REJECT

CVE-2026-56369 is AES-CTR nonce reuse in PasskeyEncipherImage (GHSA-qv2q-c278-pch5). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 19 GHSA-XGP5-592F-4XCV REJECT

CVE-2026-56363 is division-by-zero in the binomial kernel (GHSA-vf33-6r7x-66xx). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 20 GHSA-RQQ2-JP9P-6M4P REJECT

CVE-2026-15034 (UI:R/I:L) references issue #557; no first-party mechanism text. Candidates: 2eb83fdc adds database retention/pruning (config + database_pruning.py) and 143ce58b drops Python 3.9/3.10 (CI/setup.py). No named mechanism links either to a vulnerable surface. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 21 GHSA-G4X5-MWW6-M42X REJECT

CVE-2026-56374 is a FTXT encoder heap overflow (GHSA-w54j-7wpm-crhj). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 22 GHSA-M366-RHM3-CX89 REJECT

CVE-2026-56362 is a GetPixelIndex heap OOB read (GHSA-gq5v-qf8q-fp77). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

### 23 GHSA-MH32-G5Q6-4X93 REJECT

CVE-2026-15138 references issue #22 (path validation / file access). Candidates cb81dd84 (lint/typecheck fix touching path validation) and deaca46d (P0 security-fixes patch: path validation, secure hash compare, file locking) are themselves security FIXES, not introductions. reject_class AI_ON_FIX. uniqueness_gate PASS versus foundation.jsonl.

### 24 GHSA-7VWM-Q9FW-CFJW REJECT

CVE-2026-15194 references open5gs PFCP advisory GHSA-88pq-hpwv-2vjw. Candidates c42d7b7d (defensive resets of FAR/URR optional fields) and d28e2f7f (find_or_add + idempotent Remove) are defensive PFCP FIXES in lib/pfcp/handler.c, not introductions. reject_class AI_ON_FIX. uniqueness_gate PASS versus foundation.jsonl.

### 25 GHSA-377P-XR9W-8773 REJECT

CVE-2026-56366 is a META reader APP1JPEG leak (GHSA-9r56-3gjq-hqf7). Candidates touch drawing-wand.c and svg.c only. reject_class UNTOUCHED_SIBLING_PATH. uniqueness_gate PASS versus foundation.jsonl.

