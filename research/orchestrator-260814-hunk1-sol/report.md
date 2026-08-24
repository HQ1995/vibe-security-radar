# Exact-hunk adjudication: hunk-slice-1

Verdict first: **0 CONFIRM, 25 FALSE_POSITIVE, 0 UNKNOWN, 0 countable proposals**. Every negative decision has affirmative diff-level counterevidence; no row was rejected merely because a bounded search missed evidence. All supplied candidates are ancestors of their resolved fix edge, but none authors the advisory-named vulnerable hunk.

## Method and claim boundary

- Read the complete acceptance contract at autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md (SHA-256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3).
- Froze all 25 input rows from hunk-slice-1.jsonl (SHA-256 9030d058e9e21732e89dc6ba3a1f90cd9ca2714979b245e4a23ae168775698db).
- Read each local first-party advisory, each supplied candidate diff, and each supplied fix diff. Shared filenames were treated only as routing evidence.
- Checked ancestry with git merge-base --is-ancestor; all 25 supplied candidate-to-fix edges resolve.
- Scanned a bounded 500 overlap-file ancestors per row for strict generative-AI markers. This added three commits to the review: Better Auth 1e30369 (Copilot), SurrealDB 0bf1a51 (Cursor), and pypdf 0276a6f (Cursor). Flowise 42d593f is the only supplied candidate with a strict generative-AI marker.
- Did not use GitHub API, git blame, or SZZ. No canonical ledger was edited. Worker decisions are evidence packets, not leader admissions.

Gate order below is identity / AI-hunk / topology / but-for / fix-reversal / release / uniqueness.

## Row decisions

| # | Case | Verdict | Gates | Exact-hunk finding |
|---:|---|---|---|---|
| 1 | GHSA-7W99-5WM4-3G79 | FALSE_POSITIVE | P/F/P/F/P/U/P | c6918ec fixes refresh-token CAS; extra Copilot 1e30369 changes PKCE. The fix atomically consumes a different authorization-code find/delete primitive. |
| 2 | GHSA-4MXG-3P6V-XGQ3 | FALSE_POSITIVE | P/F/P/F/P/U/P | Dependabot 37ee11e only bumps the release-it dev dependency; 31ead94 processes the exact XML returned by signedReferences. |
| 3 | GHSA-M837-G268-MMV7 | FALSE_POSITIVE | P/F/P/F/P/U/P | Same dependency-only candidate and signed-assertion fix as row 2; no candidate production hunk exists. |
| 4 | GHSA-5662-CV6M-63WH | FALSE_POSITIVE | P/F/P/F/P/U/P | Dependabot 881f41b only bumps cloud storage. The supplied 1b272db is actually the advisory's introducing commit; e29494b is the real 0644 closure. |
| 5 | GHSA-MWH4-6H8G-PG8W | FALSE_POSITIVE | P/F/P/F/P/U/P | db560cf rejects NUL in header fields. 53b35a2 separately applies CR/LF validation to the reason/status line. |
| 6 | GHSA-XH69-987W-HRP8 | FALSE_POSITIVE | P/F/P/F/P/U/P | 7d524df changes UDP/TCP fallback; 4c2f71b adds a 255-octet bound in DNS MessageDecoder.get_labels. |
| 7 | GHSA-8MVJ-3J78-4QMW | FALSE_POSITIVE | P/F/P/F/P/U/P | The candidate is an @babel/runtime manifest bump. The fix replaces the bundled PNG parser with fast-png. |
| 8 | GHSA-FVMW-CJ7J-J39Q | FALSE_POSITIVE | P/F/P/F/P/U/P | 0f75f6b repairs *.domain matching; the pre-existing unconditional data: allowance remains until 9e9c528. |
| 9 | GHSA-FCXQ-V2R3-CC8H | FALSE_POSITIVE | P/F/P/F/P/U/P | de40e8f is a human advisory fix for the SecretStore sibling selector; 39cdba5 fixes the independent Secret selector. It remedies rather than introduces. |
| 10 | GHSA-4J8X-X6V7-W9RQ | FALSE_POSITIVE | P/F/P/F/P/U/P | Gemini-marked 42d593f hardens a validator but never touches the data-URI base64 interpolation in CSVAgent; f4e2794 removes the agent. |
| 11 | GHSA-52FH-8V99-63C2 | FALSE_POSITIVE | P/F/P/F/P/U/P | Gemini-marked 42d593f adds NFKC normalization and exact homoglyph tests, directly removing the named bypass rather than introducing it. |
| 12 | GHSA-5XVG-PMGG-3MXR | FALSE_POSITIVE | P/F/P/F/P/U/P | The AI commit narrows an older denylist boundary; the LLM-output-to-Pyodide execution sink predates it and is deleted by f4e2794. |
| 13 | GHSA-VMV7-4M6C-3CG5 | FALSE_POSITIVE | P/F/P/F/P/U/P | The AI diff changes only the downstream validator, not CSVAgent code construction, customReadCSV interpolation, or runPythonAsync. |
| 14 | GHSA-HJFH-P8F5-24WR | FALSE_POSITIVE | P/F/P/F/P/U/P | 59903c1 only relocates the rate-limiter import in the overlapping endpoint; 2ffd125 adds requester-scope subset checks. |
| 15 | GHSA-RPW8-82V9-3Q87 | FALSE_POSITIVE | P/F/P/F/P/U/P | The same rate-limiter refactor is unrelated to 8daec4f deleting the user's OAuth client after password changes. |
| 16 | GHSA-5QFP-32CF-69JH | FALSE_POSITIVE | P/F/P/F/P/U/P | Human e9dc863 is a dependency update. Extra Cursor 0bf1a51 changes RPC error types, while sessions/attach and the HTTP session map already exist in its parent. |
| 17 | GHSA-HHF6-3XPG-PGGX | FALSE_POSITIVE | P/F/P/F/U/U/P | f60b919 pads odd-length hex strings, outside attachToObject. The cited d966042 diff contains no named legacy attachToObject reversal in the available tree, so reversal stays UNKNOWN. |
| 18 | GHSA-QJ3P-XC97-XW74 | FALSE_POSITIVE | P/F/P/F/P/U/P | 12479be adds analytics/dev dependencies, but runtime debug:^4.3.4 ranges already admitted 4.4.2; removing the candidate leaves exposure intact. |
| 19 | GHSA-8X88-C5MF-7J5W | FALSE_POSITIVE | P/F/P/F/P/U/P | 21a8220 fixes PAX-to-meta application for another GHSA but preserves pre-existing negative sizes; 9e78bf0 adds the first non-negative guards. |
| 20 | GHSA-83C4-FFJP-MXP9 | FALSE_POSITIVE | P/F/P/F/P/U/P | 3bf29d5 changes alg:none signature-provider lookup; b6cd645 adds the missing realm notBefore checks. |
| 21 | GHSA-6PVW-G552-53C5 | FALSE_POSITIVE | P/F/P/F/P/U/P | 4b25800 is pointer-extension test coverage only. Production write/path hardening is in 5c11ffc, d02bd13, and 0cffe93. |
| 22 | GHSA-7G3R-8C6V-HFMR | FALSE_POSITIVE | P/F/P/F/P/U/P | 5259495 changes KV key/path validation while preserving unbounded body copy; 72a358c adds MaxBytesReader for unknown Content-Length. |
| 23 | GHSA-HQ76-6GH2-5G4Q | FALSE_POSITIVE | P/F/P/F/P/U/P | Renovate 23fa3bb is a Kubernetes dependency bump; bb8d2c8 adds detached LUKS headers and validates cryptsetup metadata. |
| 24 | GHSA-HRHF-2VCR-GHCH | FALSE_POSITIVE | P/F/P/F/P/U/P | 2cd5d91 rejects oversized ProposalMessage blocks; be5677c validates Bits/Elems consistency in distinct BitArray-bearing messages. |
| 25 | GHSA-5QJQ-93H5-HRGP | FALSE_POSITIVE | P/F/P/F/P/P/P | Human c11bf57 is a rename; extra Cursor 0276a6f vectorizes a decoded 1-bit lookup. The unbounded _image_from_bytes allocation predates both. |

## Cross-row findings

The filename-overlap heuristic failed in three recurring ways:

1. **Adjacent but different invariant:** aiohttp status line versus header value, Astro data protocol versus hostname wildcard, Consul body size versus key validation, and CometBFT BitArray structure versus proposal size.
2. **Remediation mistaken for origin:** External Secrets de40e8f, node-tar 21a8220, and all four Flowise rows. Flowise is especially decisive: the Gemini commit adds NFKC and denylist hardening; it cannot be the introducing edge for the weakness it removes.
3. **Manifest/test overlap mistaken for causality:** both Node-SAML rows, melange, jsPDF, Git LFS, and Constellation.

The Melange input label is materially wrong: 1b272db introduces the advisory's world-writable SBOM creation by switching to WorkspaceDirFS.Create; advisory-listed e29494b later specifies mode 0644. This correction does not rescue the proposed AI edge because 881f41b is a dependency-only Dependabot commit.

Release containment remains UNKNOWN for 24 rows because those local pools have no tags and advisory version ranges alone are not commit-containment proof. pypdf is the sole closed release gate: tag 6.13.3 contains Cursor 0276a6f and excludes the fix, while 6.14.0 contains c64583b. That containment does not cure the failed AI-hunk and but-for gates.

## Conservation and output status

- Assigned: 25
- Adjudicated: 25
- FALSE_POSITIVE with affirmative counterevidence: 25
- UNKNOWN: 0
- Proposed or countable PASS: 0
- Original-vulnerability blocks required for AI_INCOMPLETE_REMEDIATION: 0; every row records original_vulnerability as null
- Canonical94 public-ID and CVE-alias overlap: 0
