# CF3 adjacent-20 discovery: canonical87 repo allowlist

Zero PASS_PROPOSAL. Packet delta 0. Canonical87 stays 87.

Mined first-party GHSA identities from the pinned local github/advisory-database HEAD a42c436870111aa3f221257c9d56126a93173ccc only. Allowlist is the 48 repository names on canonical87 STRICT_RELEASED_CASE rows. Excluded canonical87 counted IDs, foundation165, stale/negative controls, and all other cf3 assigned IDs. Eligible pool 772; AI-marker filter 222; freeze 20 strongest with an official fix commit plus an exact recognized AI marker on the fix or in first-parent ancestry. Shared repo/SHA is routing only.

PASS_PROPOSAL requires all seven gates exact PASS plus immutable public vulnerable and fixed artifacts. Prefer 0 PASS over weak inference. Conservation: assigned=20, reviewed=20, unreviewed=0.

## Freeze rule vs origin

The freeze used AI authorship on the cited closer (or a pre-fix AI commit). That is routing, not origin. Parent already held the named hole for 19 of 20. AI-on-closer is NARROW. Unrelated ancestry is REJECT.

## Per identity

1. GHSA-HMQ2-W58F-27JC GitPython. NARROW. GPT 5.6 trailers on closers 4299c990/e4b8e7d0. Parent already accepted invalid submodule names. Clone tag window empty.

2. GHSA-WMGG-3P4H-48X7 fission. NARROW. Claude on 8fa79941/e484df84. e484df84 is a shared SHA with counted fission rows. Routing only.

3. GHSA-CFP9-W5V9-3Q4H openclaw. NARROW. Claude on workspaceOnly closer 14baadda. Sibling prepare/test SHAs are not the image-tool origin.

4. GHSA-CXPW-2G23-2VGW openclaw. NARROW. 8ae2d511 is a docker digest pin. Prompt-size closer ebcf1974 is Aether-marked, still a closer.

5. GHSA-FQRJ-M88P-QF3V openclaw. NARROW. Subject [AI] on closer 7cea7c29 Zalo replay cache.

6. GHSA-22C2-9GWG-MJ59 langroid. NARROW. Copilot/Claude on closer 0d9e4a7b. Distinct from counted PMCH. AI-on-closer.

7. GHSA-248R-7H7Q-CR24 vm2. NARROW. Claude on closer 093494c0. Parent already had the sandbox.

8. GHSA-2C6V-8R3V-GH6P gogs. NARROW. Claude on closer 7b7e38c8. Distinct from counted gogs rows.

9. GHSA-2F96-G7MH-G2HX GitPython. NARROW. GPT closer 56806080 is the same SHA as the V396 hypothesized closer. Shared SHA is routing only.

10. GHSA-2VHW-Q7VH-7XV2 openssl_encrypt. NARROW. Closer 7aa8787f. Same repo as counted 425G. No tags. Distinct GHSA.

11. GHSA-2XWM-4H2Q-GGFX open-webui. NARROW. Closer 17df0264. Same repo as counted FRVJ. No tags.

12. GHSA-33MH-2634-FWR2 faraday. NARROW. SHA a6d3a3a0 is shared with counted GHSA-5RV5. Routing only. Protocol-relative SSRF is not a new proven AI origin.

13. GHSA-3Q42-XMXV-9VFR openclaw. NARROW. Closer e3469473 talk-voice admin scope.

14. GHSA-3R8V-2XMJ-5C39 fission. NARROW. Closer 80e7ba55 is ancestor of WMGG 8fa79941. Sibling GHSA.

15. GHSA-3X3X-H76W-HP98 openclaw. REJECT. Ancestry AI 466a1e1c is clawdock docker-compose helper, not the named safeBins short-option bypass. Unrelated ancestor cannot transfer. not_ai=false.

16. GHSA-49CG-279W-M73X openclaw. NARROW. Subject [AI] on closer 0a105c09 empty-approver list.

17. GHSA-4RH7-JWG9-M28M openssl_encrypt. NARROW. Closer 4b2adb05 after 7aa8787f. No tags.

18. GHSA-66R7-M7XM-V49H openclaw. NARROW. Subject [AI] on closer 604777e4 QQBot media path.

19. GHSA-73X5-H92W-XC2J open-webui. NARROW. Closer a66477b7 channel parent_id. No tags.

20. GHSA-74H3-CXQ7-VC5Q open-webui. NARROW. Closer 386ac958 Socket.IO session_id. No tags.

## Claim boundary

No worker PASS. Leader admission is unchanged. Publication and more-than-200 stay HOLD. This packet does not edit canonical87, web, or scripts. No durable pages, clones, packages, or caches were written.
