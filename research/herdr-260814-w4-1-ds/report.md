# herdr-260814-w4-1-ds - unreviewed-adj4 adjudication slice-1

**Verdict-first: 25/25 FALSE_POSITIVE. 0 countable, 0 PASS proposals.**

No candidate AI commit introduces the named advisory mechanism. Five rows are fix-only (escargot crash fixes that the advisories themselves name as the fix boundary, and jetkvm security fixes to a different endpoint); the other twenty touch files fully disjoint from the mechanism file (dirsearch, OrchardCore, Amon, PackageKit, seven FreeRDP CVEs, three mastergo-magic-mcp tools, Checkmate, snipe-it, kestra, ruoyi-vue-pro, documenso, bahmni-core). Packet delta = 0; canonical count unchanged; publication HOLD.

## Method

- Advisory mechanisms read from the local advisory-database clone advisories/unreviewed/ (origin/main FETCH_HEAD 8b901fa43d0e3d09e9bece095afb760dd9dff6e8).

- Candidate diffs read from the sweep pool; 8 missing repos fetched via git smart-HTTP blobless clone (dirsearch, jetkvm/kvm, Amon, PackageKit, mastergo-magic-mcp, kestra, documenso, bahmni-core). No GitHub API, no blame/SZZ.

- diff_read rows: escargot commit messages + jetkvm d303b0ea full diff. changed_files rows: git diff-tree --name-only -r <sha> + subject.

## Gates

identity=NARROW (unreviewed; all 25 name the correct repository), ai_hunk=FAIL, topology=NARROW, but_for=FAIL, fix_reversal=UNKNOWN, release=UNKNOWN, uniqueness=PASS (none of the 25 ids/aliases in foundation.jsonl).

## Per-row

| # | GHSA | CVE | repo | mechanism | candidate(s) | class | verdict |
|---|---|---|---|---|---|---|---|
| 1 | GHSA-95XM-4789-HR5F | CVE-2026-58303 | Samsung/escargot | ByteCodeGenerator (fix boundary) | 2dee22f5,5e3b91b0,e7221f42,b30b63fc,60b1202a,0a2fcaaf,09f0a10b,7e2b3292 | FIX_ONLY | FALSE_POSITIVE |
| 2 | GHSA-F5PV-4R42-W7J4 | CVE-2026-58305 | Samsung/escargot | (type-confusion fix) | 2dee22f5,5e3b91b0,e7221f42,b30b63fc,60b1202a,0a2fcaaf,09f0a10b,7e2b3292 | FIX_ONLY | FALSE_POSITIVE |
| 3 | GHSA-Q26J-G249-RWXV | CVE-2026-58306 | Samsung/escargot | (heap-overflow fix) | 2dee22f5,5e3b91b0,e7221f42,b30b63fc,60b1202a,0a2fcaaf,09f0a10b,7e2b3292 | FIX_ONLY | FALSE_POSITIVE |
| 4 | GHSA-3PQC-WF77-H389 | CVE-2021-47901 | maurosoria/dirsearch | lib/reports --csv-report | 68b6646d,b809c936,ccd1ff63,2be979e7 | DISJOINT | FALSE_POSITIVE |
| 5 | GHSA-GCG5-Q479-JH6F | CVE-2020-37019 | OrchardCMS/OrchardCore | MarkdownBodyPart | 9841e0db,e0345cb4,3d21f203,ce9c2aff,fd8d012d,f4a3c340,0c3d07ce | DISJOINT | FALSE_POSITIVE |
| 6 | GHSA-G66J-37WX-VRJ5 | CVE-2026-32295 | jetkvm/kvm | login rate-limit | edb8162b,cde4d74c,d303b0ea,136966a0 | FIX_ONLY | FALSE_POSITIVE |
| 7 | GHSA-VGQ8-MC5M-6W55 | CVE-2026-32294 | jetkvm/kvm | OTA firmware sign | edb8162b,cde4d74c,d303b0ea,136966a0 | DISJOINT | FALSE_POSITIVE |
| 8 | GHSA-7R2J-HGH9-JQQX | CVE-2025-15604 | tokuhirom/Amon | Amon2/Util.pm random_string | 0cf48434 | DISJOINT | FALSE_POSITIVE |
| 9 | GHSA-9M6P-W8RP-5V54 | CVE-2026-10294 | PackageKit/PackageKit | src/pk-transaction.c | 008f1101,01d9a50c,936c5e31,0875abd8,1d80124f | DISJOINT | FALSE_POSITIVE |
| 10 | GHSA-392F-F2J5-97QM | CVE-2026-56297 | FreeRDP/FreeRDP | channels/drdynvc | 8d991639,c4164804 | DISJOINT | FALSE_POSITIVE |
| 11 | GHSA-R83C-HC4J-PVC5 | CVE-2026-15749 | mastergo-design/mastergo-magic-mcp | src/tools/get-c2d.ts | 396523b6,3c2da7cf | DISJOINT | FALSE_POSITIVE |
| 12 | GHSA-5VH4-8356-P89C | CVE-2026-15750 | mastergo-design/mastergo-magic-mcp | src/tools/get-component-link.ts | 396523b6,3c2da7cf | DISJOINT | FALSE_POSITIVE |
| 13 | GHSA-2957-9WVX-X9F4 | CVE-2026-15751 | mastergo-design/mastergo-magic-mcp | component-workflow.md | 396523b6,3c2da7cf | DISJOINT | FALSE_POSITIVE |
| 14 | GHSA-4VXC-GGFG-5366 | CVE-2026-64624 | FreeRDP/FreeRDP | RDP-file parser | 8d991639,c4164804 | DISJOINT | FALSE_POSITIVE |
| 15 | GHSA-3W26-2CXG-PVH3 | CVE-2026-67305 | FreeRDP/FreeRDP | channels/cliprdr | 8d991639,c4164804 | DISJOINT | FALSE_POSITIVE |
| 16 | GHSA-43RQ-PV9M-43RF | CVE-2026-67297 | FreeRDP/FreeRDP | http gateway | 8d991639,c4164804 | DISJOINT | FALSE_POSITIVE |
| 17 | GHSA-XQ3V-XJ62-R99V | CVE-2026-67296 | FreeRDP/FreeRDP | channels/rdpei | 8d991639,c4164804 | DISJOINT | FALSE_POSITIVE |
| 18 | GHSA-MJ63-24H6-P8WQ | CVE-2026-68580 | FreeRDP/FreeRDP | channels/audin | 8d991639,c4164804 | DISJOINT | FALSE_POSITIVE |
| 19 | GHSA-CJR5-M69M-F39C | CVE-2026-72588 | bluewave-labs/Checkmate | auth/recovery/request | 8f3edac2,0f3c81c0,2d58facb | DISJOINT | FALSE_POSITIVE |
| 20 | GHSA-9Q6X-42CW-M8JX | CVE-2026-72745 | FreeRDP/FreeRDP | Kerberos/kerberos.c | 8d991639,c4164804 | DISJOINT | FALSE_POSITIVE |
| 21 | GHSA-9G74-JCX5-95FC | CVE-2026-19579 | snipe/snipe-it | checkout cancellation | 9d40df17,af5e8797,c4c8750b,068e6c0e | DISJOINT | FALSE_POSITIVE |
| 22 | GHSA-9JRQ-5WF3-M9FP | CVE-2026-38428 | kestra-io/kestra | SQL query | 4d44077f,1d153e18,ccf5ed7a,26746659,c0ebddf3 | DISJOINT | FALSE_POSITIVE |
| 23 | GHSA-6Q7H-QG7R-3G9C | CVE-2026-13528 | YunaiV/ruoyi-vue-pro | infra FileServiceImpl | c82e0937 | DISJOINT | FALSE_POSITIVE |
| 24 | GHSA-3HJR-GMH6-W2QR | CVE-2026-13543 | documenso/documenso | oauth callback | 7ea66421,0d65693d,4babe9b1,93137c63 | DISJOINT | FALSE_POSITIVE |
| 25 | GHSA-8G7P-3GHX-XX9X | CVE-2026-15477 | Bahmni/bahmni-core | bahmnicore sql endpoint | 16b50b98,c57e37eb,ddf2d3cf,dc61000a,959bd440 | DISJOINT | FALSE_POSITIVE |

## Detail

- escargot (#1-3): candidates are Fix continue/break at first instruction of env-allocating block, Fix labeled continue targeting a for-of loop, Add missing m_currentLoopLabel and fix Crashes, by Seonghyun Kim with some Claude co-author trailers. Advisory #1 says affected-before b30b63fc63b4, i.e. that candidate is the fix boundary not the introducer; #2/#3 fix boundaries (779f6bed, ef525f33) are not in the candidate set.

- jetkvm (#6/#7): d303b0ea rate-limit /device/setup reuses the password rate limiter on the setup endpoint, not the login endpoint named by CVE-2026-32295; edb8162 sanitizes error strings and cde4d74 adds HTTP security headers. All fixes; none touches firmware-signature verification (CVE-2026-32294).

- FreeRDP (#10,#14-18,#20): candidates 8d991639 (rdpgfx server frame-command fix) and c4164804 (NTLM AUTHENTICATE message free) are disjoint from drdynvc UAF, RDP-file /slash parsing, cliprdr, http gateway, rdpei, audin, and Kerberos kerberos.c.

- mastergo-magic-mcp (#11-13): 396523b6 confines applyDesign output paths (apply-design.ts); the named tools get-c2d.ts, get-component-link.ts, component-workflow.md are not touched.

- remainder (#4,5,8,9,19,21-25): dirsearch CSV writer, OrchardCore MarkdownBodyPart, Amon2 random_string, PackageKit pk-transaction.c, Checkmate auth/recovery, snipe-it checkout cancellation, kestra SQL, ruoyi-vue-pro infra FileServiceImpl, documenso OAuth callback, bahmni-core search endpoint are each in a file no candidate touches (bahmni only sql hit is a test-only SqlQueryHelperTest update).

## Conclusion

This packet admits no countable case. All 25 rows close at ai_hunk/but_for FAIL (fix-only or disjoint edge). Canonical ledger untouched; publication HOLD.
