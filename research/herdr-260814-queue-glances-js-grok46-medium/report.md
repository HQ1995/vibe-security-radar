# Queue glances/js five: terminal REJECT

Verdict first: **0 PASS**. Frozen assigned count is **5**. All 5 are **REJECT**. Equation **5=5+0**. packet_delta=0. Canonical93 strict count remains **93**. Publication and more-than-200 remain **HOLD**. Worker PASS is proposal only; this packet emits none.

Admission requires exact PASS on identity, ai_hunk, topology, but_for, fix_reversal, release, and uniqueness. NARROW and UNKNOWN are not PASS. Prefer zero PASS over one false positive.

## Freeze

Source packet `autoresearch/herdr-260814-nextqueue-v2-grok46-low` assignment SHA256 `5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3` cases SHA256 `5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf`. CONTRACT SHA256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical93 ledger SHA256 `6d652a089329eb23108083fb73ca1a8a3aa00583415b235381f3b37da389dc3d`.

Queued identities, in audit order, copied from that assignment and no others:

1. GHSA-7P93-6934-F4Q7 nicolargo/glances CWE-942
2. GHSA-396Q-4VC8-28X9 microsoft/kiota-typescript CWE-178,CWE-200
3. GHSA-8GWM-58G9-J8PW mermaid-js/mermaid CWE-79
4. GHSA-VCV2-Q258-WRG7 nicolargo/glances CWE-78
5. GHSA-VX5F-957P-QPVM nicolargo/glances CWE-346,CWE-522

First-party github-reviewed JSON from local cache HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6`. MATCHER_CONTRACT `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`. Shared clones read-only. No GitHub API. No credentials. Temporary pages were not retained.

## Conservation

5 assigned = 5 reviewed + 0 unreviewed. Did not pad. CVE aliases are not counting units. Overlap with canonical93 strict 93: empty. Shared SHA is not identity dedupe.

## Per identity (all REJECT)

1. GHSA-7P93-6934-F4Q7. REJECT. First-party advisory names XML-RPC `send_my_headers` wildcard CORS in `glances/server.py`. That line is blamed to human `a4d75fedaa37` 2022-01-02. Queued AI commits touch LXD, MCP/restful, or `client.py` logging. Closer is two-parent merge `dcb39c3f12b2` with human side `b90a8f2a169f`. Default CORS remains `*`. identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal NARROW; release PASS on tags v4.5.1 vs v4.5.3; uniqueness PASS.

2. GHSA-396Q-4VC8-28X9. REJECT. Advisory names case-sensitive `delete headers.Authorization` after lower-casing in `@microsoft/kiota-http-fetchlibrary`. Incomplete rem `74886cc4c3dd` is human Adrian with empty matcher. Closer merge `09f8bd9b34d6` / atomic `4dab0e233e11` is human tonghuaroot. Queued Copilot hits are lockfile, release-please workflow, and `console.debug` removal. No local preview.97/102 tag or npm tarball pin. identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL (not an AI guard); release UNKNOWN; uniqueness PASS.

3. GHSA-8GWM-58G9-J8PW. REJECT. Advisory names architecture `iconText` into d3 `html()`, introduced by human `734bde38777c` 2024-05-06, released mermaid@11.1.0. Queued AI: zenuml README and kanban example. Sanitize member `c61a431e2d66` is human Sidharth Vinod under merge `2aa833027951`. Tags mermaid@11.9.0 lack the closer; mermaid@11.10.0 contain it. identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL; release PASS; uniqueness PASS.

4. GHSA-VCV2-Q258-WRG7. REJECT. Advisory names Mustache values split by `secure_popen`. Sink blamed to 2022 human `actions.py`. Queued AI `7b200f00fceb` (MCP) and `a7892c1e292a` (client log) are ancestors of merge `6f4ec53d9674` but do not touch `actions.py`. LXD AI commits are after this closer. Side `5680a5da4afd` adds `_sanitize_mustache_dict`. Tags v4.5.1 vs v4.5.2. identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL; release PASS; uniqueness PASS.

5. GHSA-VX5F-957P-QPVM. REJECT. Advisory names Central Browser `get_uri` using Zeroconf advertised name plus default password. Origin `28ae053e4bdb` human issue 3103 is in v4.5.1. Same two AI SHAs as VCV2: sibling client log redaction and MCP. Closer merge `61d38eec5217` / side `2abe8d8733e3` uses discovered IP and refuses dynamic saved passwords. Shared SHA with VCV2 is not duplication and is not proof. identity PASS; ai_hunk FAIL; topology PASS; but_for FAIL; fix_reversal FAIL; release PASS; uniqueness PASS.

## Claim boundary

No worker proposal changes the canonical count. Current leader HOLD snapshot is canonical strict **93**. This packet does not edit canonical, web, scripts, or other packets and does not support a greater-than-200 claim.
