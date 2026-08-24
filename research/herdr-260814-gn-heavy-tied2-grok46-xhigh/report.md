# G-N heavy tied leftovers (gogs, n8n)

Terminal: 2=2+0. PASS=0. Canonical94 stays 94 HOLD. Worker PASS is proposal-only and this packet emits none. Greater-than-200 remains unsupported.

## Freeze

Exact tied leftovers left UNREVIEWED by `autoresearch/herdr-260814-gn-heavy-deferred-grok46-xhigh` after cap-12 on 14 local atomic human closers. Deferred replay equation 228=12+216. Deferred hashes: assignment `04292fe6c1de79dd0a9dc8b90dad05a9427b4501aaddc76ca3aef59dd4b11183`, cases `4c4be98cf0c5f37273cbe157f2eaebe6a9fb88aa329d75eba2ec39221e3bc8a0`, result `9b443c6b96f17ff83f963a57c7ddbbc8110b74e0ba0b769222a3982b2d0833b4`, report `0d304d14eaad4b6464ba3675179c99e498252185fd382d11a3ba4cccb7d99e1f`, replay `6308c9c5af0d696eff035c8e6c35b6e3db0815eea78d3c6e7a22023b3b3b7d23`. tied_closer_not_in_cap12 = GHSA-RJV5-9PX2-FQW6, GHSA-W96V-GF22-CRWP. Did not pad. Did not inherit the deferred reason.

Source universe: unreviewed G-N subject-only intersections in `autoresearch/herdr-260813-ghsa200-commitfirst-gn` (cases sha256 `47538e731f8c4979651ff36ead7063ea23a1adc05e551a99ae94ceaafd835b2d`; result sha256 `4443df9d098302be1b3fc3b73dbdc0ae7b76471a5f2f67aeed97c98ec1d6c08a`). Heavy remaining after canonical94 and post-CF2 terminals = 228; remaining_ids sha256 `987dcad828bb11ef6935e3d5b47c9dc71125ee58eb500ee1a825c7ac509d7e81`. Reconstructing that 228 with local atomic closer then case_id yields 14 rows; cap 12 by case_id; leftovers are these two.
CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Canonical94 ledger sha256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`. CF2 result sha256 `0f3e056a36daec32658ffd9434def475308b9d9ff452ee5686c7862e46d2ff97`. Matcher `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.

Gates rebuilt from the first-party advisory, atomic closer/parent objects, parent diffs, fix-path history, PR members, pickaxe intro, and formal tags. AI overlap, human closer, shared SHA, same file, carrier trailer, AI-on-fix, and old-bug preservation are not causal proof.

Anonymous smart-HTTP recovered closer/parent/tag blobs. Shared clones were not mutated. No GitHub REST/GraphQL. No credentials.

## Verdicts

### GHSA-RJV5-9PX2-FQW6 REJECT

Identity PASS: first-party github-reviewed GHSA-rjv5-9px2-fqw6, repo gogs/gogs, not withdrawn. Advisory sha256 `7c07296ac9c462716d92690e0974d2c58c0e3d2c53fb3bac51f91901b7b9e25d`.
Mechanism: DELETE /api/v1/repos/:owner/:repo inherits repoAssignment() and omits reqRepoOwner.
Closer `961a79e8f9f2b3190ea804bcf635e4b43b123272` n_parents=1 email jc@unknwon.io subject api: verify owner access to delete repos (#8101). Tree `154432766dc494b7e60cbd12511a670caba6ad6e`. Parent `d568e048315dc9729c8518d8085cab7dbbfac80f` tree `4c9a69a6bf2c669632c39c0533504a136a79b6e4`. source_matcher empty.
PR tip `3ec5b983854429fd82d74cc9f6ceeea3b6097d53` n_parents=1 same human email; api.go blob `6f10bf9cece24b4d565e77da6e5583836068566e` differs from squash closer blob `ae9b2969fdd4937407ffad1f9a8c9ca2ac058f9d`. Authorship is not transferred.
Pickaxe intro `880d0ec19f488001a90b3e370a992eaabac89e70` n_parents=1 u@gogs.io #5980. source_matcher empty.
Semantic: closer inserts reqRepoOwner(); parent blob `79d346fe69a845bcb6403e602cd0c0baaaafe2f9` has m.Delete("/:username/:reponame", repoAssignment(), repo.Delete).
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer and PR tip recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release FAIL (v0.13.3 blob equals parent; v0.13.4 still has reqRepoOwner after later drift; no AI contribution to contain).
Subject-overlap 7b7e38c88007 is a Claude trailer on branch.go, not api.go, and is not an ancestor of the closer.

### GHSA-W96V-GF22-CRWP REJECT

Identity PASS: first-party github-reviewed GHSA-w96v-gf22-crwp, repo n8n-io/n8n, not withdrawn. Advisory sha256 `235e2d0186f5bb6cd62c76fb49cc64bd10e4265490bc1af836f108d8fa2e8948`.
Mechanism: Webhook IP whitelist used substring includes() matching.
Closer `11f8597d4ad69ea3b58941573997fdbc4de1fec5` n_parents=1 email 93014743+mfsiega@users.noreply.github.com subject fix(Webhook Node): Use CIDR matching for IP whitelist check (#23399). Tree `b26751bc7f49b62748b4abb8a7a6973797dd962c`. Parent `6ae4999ef99310d39c43cde611966875787b331b` tree `3f47bf1b60e7d25181856f7137ba24cff09f9cad`. source_matcher empty.
PR 23399 members vs parent: f0dfd62d9cc4 n_parents=1 michael.siega@n8n.io; 87c331ebfc5c merge n_parents=2; 8f1a66efb6e5 n_parents=1 with utils.ts blob equal to the closer. source_matcher empty.
Pickaxe intro `e84c27c0cebd6fba135298ea18844045dcf55b4c` n_parents=1 #8889. source_matcher empty.
Semantic: closer uses BlockList; parent blob `5adea08eb4cc4fc3be11561617b1138c83a03b31` uses includes(address).
ai_hunk FAIL, but_for FAIL. topology PASS (atomic closer and members recorded; authorship not transferred). fix_reversal PASS for the human closer. uniqueness PASS (absent from canonical94). release FAIL (n8n@2.1.4 blob equals parent; n8n@2.2.0 blob equals closer; no AI contribution to contain).
Subject-overlap policy-AI commits have empty path overlap with the closer files.

## Conservation

Assigned exactly GHSA-RJV5-9PX2-FQW6 and GHSA-W96V-GF22-CRWP. 2 = 2 reviewed + 0 unreviewed. Equation 2=2+0 holds. Source freeze 228=12+216 and 14=12+2 remain pinned. Did not pad. PASS_PROPOSAL=0. Canonical94 untouched. Countable remains false.

Stop. No ledger, site, scripts, or other-packet edits. No credentials. No GitHub API.
