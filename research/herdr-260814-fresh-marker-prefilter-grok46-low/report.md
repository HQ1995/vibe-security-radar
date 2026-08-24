# Fresh marker prefilter (recall routing only)

Verdict first: this packet is recall routing for exact AI author or trailer evidence.
It is not causality, not admission, and it does not claim PASS.
No case-count claim is made.
Unclosed gates stay UNKNOWN. This packet does not close identity, topology, but-for, fix-reversal, release, or uniqueness as admission gates.

## Conservation

- Local github-reviewed 2025-2026 JSON files: 12817
- First-party GHSA objects: 9620
- Excluded because present in canonical84 STRICT_RELEASED_CASE records: 69
- Assigned net-new first-party identities: 9551
- candidates.jsonl (exact-marker routing hits, cap 50): 50
- rejected.jsonl (decisive mismatch): 4469
- unknown.jsonl (missing evidence or cap overflow): 5032
- Exact-marker hits before cap: 104
- Equation: 9551=50+4469+5032
- Holds: true
- Did not pad, drop, or invent assigned identities.

## Method

Newest local advisory-database clone was read-only.
Existing repository caches were read-only. GIT_NO_LAZY_FETCH=1. No GitHub REST API.
A candidate requires an exact recognized AI author or trailer on an atomic commit,
or on a mapped atomic member that owns the advisory-relevant hunk.
Generic PR or squash carrier branding without member-to-hunk mapping is not a hit.
Candidates freeze at 50 newest-published exact-marker rows; overflow stays UNKNOWN.

## Input hashes

- advisory-database HEAD: f2c6ab3202aeafb36fbea6e76d892532acfca1a6
- advisory-database path: /home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database
- canonical84 ledger.jsonl sha256: a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06
- canonical84 summary.json sha256: 6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a

## Candidate SHAs (routing only)

1. GHSA-48P8-G2FX-3WWM argoproj/argo-workflows sha=277e9cef0ad1 via=atomic_named_commit
2. GHSA-WVPP-8HX9-P66J gitpython-developers/GitPython sha=96a888f4d782 via=atomic_named_commit
3. GHSA-HMQ2-W58F-27JC gitpython-developers/GitPython sha=4299c990e1ca via=atomic_named_commit
4. GHSA-HH9P-6WH2-4MFC gitpython-developers/GitPython sha=f2550b65bf60 via=atomic_named_commit
5. GHSA-9RJ7-RF2P-W77R gitpython-developers/GitPython sha=d9ddb55bdc66 via=atomic_named_commit
6. GHSA-4GMW-GG2M-W46P gitpython-developers/GitPython sha=9b5dcaf85da5 via=atomic_named_commit
7. GHSA-F6WF-28G6-769X smarty-php/smarty sha=99c048ce7a59 via=atomic_named_commit
8. GHSA-2Q4P-G7HV-5RGV thephpleague/commonmark sha=a6ef6cdc308d via=atomic_named_commit
9. GHSA-29PJ-957V-52MC thephpleague/commonmark sha=493a5aa7d657 via=atomic_named_commit
10. GHSA-P538-C434-8V24 gitpython-developers/GitPython sha=38553b6fddc7 via=atomic_named_commit
11. GHSA-3F7W-8RR8-F37F gitpython-developers/GitPython sha=3af0c2516c5e via=atomic_named_commit
12. GHSA-34RH-WP3J-6CXC pion/stun sha=fa9f074a33a8 via=atomic_named_commit
13. GHSA-XGR6-PQJV-3PF8 alextselegidis/easyappointments sha=40bb0b31b531 via=atomic_named_commit
14. GHSA-FP43-VJ7G-PG92 omnifaces/omnifaces sha=59d6c5188c39 via=atomic_named_commit
15. GHSA-P6PH-3JX2-3337 OpenListTeam/OpenList sha=84ecda35aae2 via=atomic_named_commit
16. GHSA-94P4-4CQ8-9G67 gitpython-developers/GitPython sha=863417457a06 via=atomic_named_commit
17. GHSA-6P8H-3WGX-97GF gitpython-developers/GitPython sha=ffcb5359e876 via=atomic_named_commit
18. GHSA-FJR4-X663-MWXC gitpython-developers/GitPython sha=1d51b891d7f2 via=atomic_named_commit
19. GHSA-7RQJ-J65F-68WH nextauthjs/next-auth sha=19d2feb24359 via=atomic_named_commit
20. GHSA-7488-6R32-C95Q BerriAI/litellm sha=73869f0faf7d via=atomic_named_commit
21. GHSA-V2HH-GCRM-F6HX fastify/fast-uri sha=0542a216860f via=atomic_named_commit
22. GHSA-RWJ8-PGH3-R573 gitpython-developers/GitPython sha=8ac5a30519b6 via=atomic_named_commit
23. GHSA-956X-8GVW-WG5V gitpython-developers/GitPython sha=701ce32fe5ba via=atomic_named_commit
24. GHSA-2F96-G7MH-G2HX gitpython-developers/GitPython sha=56806080c134 via=atomic_named_commit
25. GHSA-PF56-329R-95RW sigstore/sigstore-js sha=85c58380758b via=atomic_named_commit
26. GHSA-H35F-9H28-MQ5C pypa/setuptools sha=dd9f436a3648 via=atomic_named_commit
27. GHSA-XVCM-6775-5M9R immutable-js/immutable-js sha=3dd7e5655012 via=atomic_named_commit
28. GHSA-J92G-9F8W-J867 pgjdbc/pgjdbc sha=77df98e4e66c via=atomic_named_commit
29. GHSA-F4VV-55C2-5789 HKUDS/LightRAG sha=f7819aa3a49a via=atomic_named_commit
30. GHSA-6X6H-QQR7-855W HKUDS/LightRAG sha=09567a4c983f via=atomic_named_commit
31. GHSA-2CF7-HPWF-47H9 czlonkowski/n8n-mcp sha=c1ca1e73697f via=atomic_named_commit
32. GHSA-XW57-23P8-9WC5 asymmetric-effort/specifyjs sha=25d1fb491d99 via=atomic_named_commit
33. GHSA-QCR8-X557-7CP3 asymmetric-effort/specifyjs sha=2ef791bc73ea via=atomic_named_commit
34. GHSA-VH4V-2XQ2-G5CG oras-project/oras-go sha=3c2e884e12ea via=atomic_named_commit
35. GHSA-HVQH-JW65-WCPQ devbridge/jQuery-Autocomplete sha=63ff096ff5b7 via=atomic_named_commit
36. GHSA-47QP-HQVX-6R3F jline/jline3 sha=934f09e6128c via=atomic_named_commit
37. GHSA-2R2C-CX56-8933 jline/jline3 sha=733eb353dca7 via=atomic_named_commit
38. GHSA-GXJX-7M74-HCQ8 filebrowser/filebrowser sha=847d08bdd135 via=atomic_named_commit
39. GHSA-W5FM-68J4-FPC4 filebrowser/filebrowser sha=847d08bdd135 via=atomic_named_commit
40. GHSA-3PV8-6F4R-FFG2 composefs/tar-rs sha=bab14dd84b41 via=atomic_named_commit
41. GHSA-GG2G-P7XC-QQMM oscal-compass/compliance-trestle sha=7d107b3ac53c via=atomic_named_commit
42. GHSA-W76H-Q7C6-JPJP oscal-compass/compliance-trestle sha=5c65c5926fe7 via=atomic_named_commit
43. GHSA-4Q5V-7G7X-J79W oscal-compass/compliance-trestle sha=7d107b3ac53c via=atomic_named_commit
44. GHSA-MJ4X-VF5C-5XG8 oscal-compass/compliance-trestle sha=5c65c5926fe7 via=atomic_named_commit
45. GHSA-M6XR-FVFG-5G64 TomWright/dasel sha=95f8dd3af129 via=atomic_named_commit
46. GHSA-Q5PP-GVJG-H7V4 microsoft/apm sha=f85b9f54ad30 via=atomic_named_commit
47. GHSA-MQ5J-PW29-JCV3 microsoft/apm sha=77d1dda8303c via=atomic_named_commit
48. GHSA-248R-7H7Q-CR24 patriksimek/vm2 sha=093494c0c3ef via=atomic_named_commit
49. GHSA-G29V-Q6H7-76WH electerm/electerm sha=9dd8295e37d5 via=atomic_named_commit
50. GHSA-Q4P8-8J9M-8HXJ electerm/electerm sha=24ce7103e264 via=atomic_named_commit

## Commands

```
python3 /home/hanqing/agents/ai-slop/autoresearch/herdr-260814-fresh-marker-prefilter-grok46-low/work/prefilter.py
```

Owned temporary clones under work/tmp-clones were deleted after emit.

## Claim boundary

- Did not edit the ledger.
- Did not claim PASS.
- Did not claim any canonical or publication case count.
- Started: 2026-08-14T19:44:50.886290+00:00
- Ended: 2026-08-14T19:50:28.842137+00:00
- Clone index size: 8255
- Withdrawn among assigned: 278
