# Scale1 twenty-five: zero PASS, eleven REJECT, fourteen UNKNOWN

Timebox terminal of frozen scale1 identities. PASS_proposal=0.
Canonical93 stays 93 HOLD. Publication and greater-than-200 remain unsupported.
Worker PASS is proposal only; this packet emits none.
Conservation 25=25+0. Did not pad. Unclosed gates stay UNKNOWN. Missing evidence was not converted to FAIL.

## Freeze

CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Slice sha256 `eb6bb3de216e426cb3811dd0b74f06ad1d5c137eb5e3c814266840c11d774d0a`.
Spec sha256 `672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750`.
Matcher contract `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.
Shared caches were read-only. No GitHub API. No credentials. No retained clone or page added by this closeout. Existing packet diffs/ were already present.

## Method

Each row was judged from the frozen compact advisory plus local commit stat/diff when present under diffs/. A listed SHA with a readable disjoint file list or a commit message naming a different bug can FAIL ai_hunk and REJECT. A listed SHA with no local commit object, or a mechanism-adjacent commit whose diff blob could not be fetched, stays UNKNOWN. Shared SHAs are not dedupe. CVE aliases are not counting units.

## REJECT (11)

Disjoint docs or sibling bug on an AI-attributed listed SHA:

1. GHSA-HXV8-4J4R-CQGV cilium/cilium - Claude-coauthored Gateway API CRD retry vs L7 same-node NetworkPolicy.
2. GHSA-MW3M-PQR2-QV7C ImageMagick/ImageMagick - Claude Opus SVG gradientTransform double-free vs X11 OOB write.
3. GHSA-8793-7XV6-82CF ImageMagick/ImageMagick - same SVG sibling vs InterpretImageFilename OOB write.
4. GHSA-6P22-Q7W5-33PG ImageMagick/ImageMagick - same SVG sibling vs ASHLAR leak.
5. GHSA-9R56-3GJQ-HQF7 ImageMagick/ImageMagick - same SVG sibling vs META APP1JPEG leak.
6. GHSA-QR99-7898-VR7C traefik/traefik - Copilot docker.md whoami middleware vs BasicAuth headerField spoofing.
7. GHSA-46WH-3698-F2CX traefik/traefik - same docker.md docs vs gRPC deny-rule bypass.
8. GHSA-F8XP-WVCX-P6F4 cloudreve/cloudreve - Copilot OAuth grant-limit planning (no code changes yet) vs weak PRNG ATO.
9. GHSA-MVF2-F6GM-W987 nearform/fast-jwt - Jules README error-handling vs JWT alg confusion.
10. GHSA-HM7R-C7QW-GHP6 nearform/fast-jwt - same README vs unknown crit header.
11. GHSA-GC59-R5JQ-98QW jetty/jetty.project - Copilot OSGi BundleDelegatingClassLoader vs JASPIAuthenticator ThreadLocal.

For these REJECT rows identity_gate is PASS and ai_hunk_gate is FAIL. topology/but_for/fix_reversal/release/uniqueness stay UNKNOWN because those gates were not closed from local evidence.

## UNKNOWN (14)

No local commit object (12): GHSA-HGX2, GHSA-R9W3, GHSA-C38G, GHSA-GMFG, GHSA-4C29, GHSA-4VRQ, GHSA-443W, GHSA-X27P, GHSA-XPH3, GHSA-324Q, GHSA-78H2, GHSA-56P5.

Mechanism-adjacent unread diff (2): GHSA-37FQ and GHSA-5724 share YesWiki SHA eb440b844320. Copilot Autofix for DOM text reinterpreted as HTML is XSS-adjacent. Promisor fetch of the blob failed, so ai_hunk and later gates stay UNKNOWN rather than FAIL.

## Conservation

assigned=25 reviewed=25 unreviewed=0 equation 25=25+0.
PASS=0 REJECT=11 UNKNOWN=14 packet_delta=0 countable_pass=0.
Did not commit, push, edit tracked canonical ledgers, or mutate shared cache.
