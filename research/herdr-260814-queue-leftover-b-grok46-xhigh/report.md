# Queue leftover-b audit (six leftover_ids)

Terminal: 6=6+0 reviewed. PASS=0. Canonical94 stays 94 HOLD. Worker PASS is proposal-only and this packet emits none. Greater-than-200 remains unsupported.

## Freeze

Source packet `autoresearch/herdr-260814-nextqueue-v2-grok46-low` result sha256 `0e9d53f049ba7e42e2e80b964f27b2b0dc2b60a03ad667a8fbc4eb66b099afe1` leftover_ids suffix exactly GHSA-9Q9Q-324X-93R2, GHSA-FRH3-6PV6-RC8J, GHSA-PF94-94M9-536P, GHSA-Q6V9-R226-V65F, GHSA-RF5Q-VWXW-GMRF, GHSA-V56Q-MH7H-F735. Those six are not in queued_ids or source assignment.jsonl. leftover_ids prefix five (GHSA-R54C-2XMF-2CF3, GHSA-V5MV-P594-2X33, GHSA-V95X-XHQ5-4929, GHSA-WVMP-6R4V-J6CV, GHSA-375F-4R2H-F99J) is out of scope. Did not pad. assignment sha256 `5382496f680de8c811d75ca0d3dd6dbdc1b47af0893689e37d36d9dc4a7b93b3` cases sha256 `5edd11a19f8bfb7e598290ee5ce22b72e0e3d51c4186c6e8d656f552a38d4ccf`.
CONTRACT.md sha256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
Canonical94 ledger sha256 `7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096`. Strict count 94.
First-party github-reviewed HEAD `f2c6ab3202aeafb36fbea6e76d892532acfca1a6` tree `3308b2f6c73929d3854bd12908e996787a8bb0c8` committer 2026-08-14T03:33:36+00:00 (read-only cache). Shared caches were not mutated. No temporary clone retained. Matcher `ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4`.

Assigned exactly the six leftover suffix IDs. All six absent from canonical94 strict IDs. Routing, same-repo fix, shared SHA, AI-on-fix, carrier trailer transfer, old-bug preservation, sibling fields, and incomplete hardening that only reduces risk are not causal proof. NA/NARROW/UNKNOWN/BLOCKED is not PASS.

Independent reconstruction of leftover AI hits (not copied from routing prose): each Bandit closer has exactly one source_matcher-positive ancestor, `a330b13588f874fee170e508f75c6ee5037737d9` (Claude Sonnet 4.6 trailer on `.github/workflows/elixir.yml`). Immutable 5.x merge `a1a1ee412dcaa380ab325196283d06594ffe4b84` has exactly one, `93cb6dfb14c2468bccbe5906006f50b2c755f36c` (Claude Opus 4.8 on `src/Operations.js`). Fix-touched file history of every advisory path has 0 matcher hits. Dependabot `1085ad071204ab135cc8ffc4120c2f6656b8548f` (`mix.lock`) is not a matcher hit.

## Verdicts

### GHSA-9Q9Q-324X-93R2 REJECT

Identity PASS: first-party GHSA-9q9q-324x-93r2, repo mtrudel/bandit, CWE-770, Hex bandit. Advisory sha256 `8dcab38c9cbcbc3f87ae7192397137ebce4d7b571c1205983851765ad896e7b6`.
Mechanism: HTTP/1 chunked reader drops `:length` and materializes the whole body.
Closer `ae3520dfdbfab115c638f8c7f6f6b805db34e1ab` Mat Trudel, one parent, no AI marker. Parent blob `84ce94592f5c152280c121c354e4eb7e5beeabd7`, fixed blob `659a498c8728dcb6056daf72932c4b8d807d60ad`. Fixed `do_read_chunked_data!/4` uses `Keyword.get(opts, :length, 8_000_000)` and can return `{:more, ...}`.
Claude `a330b135` is CI yaml. ai_hunk FAIL, but_for FAIL. Local clone has no v1.11.1 tag. release UNKNOWN. uniqueness PASS (distinct from GHSA-RF5Q trailers despite shared closer SHA).

### GHSA-FRH3-6PV6-RC8J REJECT

Identity PASS: first-party GHSA-frh3-6pv6-rc8j. Advisory sha256 `bfdee5cb3299f9d46b1291ea60200a29ffd32abf1d9346dadbd331d1e14c9a11`.
Mechanism: unbounded `:zlib.inflate` on permessage-deflate.
Closer `8156921a51e684a951221da7bc30a70a022f722e` is a one-parent merge-from-fork, Mat Trudel, no AI marker. Parent blob `dbb2bfc0b5d4d85811dd2a24bfe8c685da3d3c4f` inflates then `IO.iodata_to_binary`. Fixed blob `e5677719dd5d49574664b6a923154bb6983bc0c3` adds `safeInflate` plus `max_inflate_ratio`.
a330b135 does not touch websocket sources. ai_hunk FAIL. No v1.11.0 tag. release UNKNOWN.

### GHSA-PF94-94M9-536P REJECT

Identity PASS: first-party GHSA-pf94-94m9-536p. Advisory sha256 `0cfe9da2adaa56154b1b6ff200e219e31c11a5221d414fbbc49c82df5bba0734`.
Mechanism: unbounded WebSocket continuation reassembly.
Closer `21612c7c7b1ce43eccd36d3af3a2299d23513667` Mat Trudel, one parent (the FRH3 closer), no AI marker. Parent connection.ex blob `0494aba148159552048adcfc2a818489481a6d0a` appends `fragment_frame.data` with no `oversize_message?/2`. Fixed blob `02cf00834959c0602d656e8c9a6abd614ffc5f52`.
Parent of this closer is not an authorship transfer. a330b135 is CI. ai_hunk FAIL. No v1.11.0 tag. release UNKNOWN. uniqueness PASS vs FRH3 (inflate vs fragments).

### GHSA-Q6V9-R226-V65F REJECT

Identity PASS: first-party GHSA-q6v9-r226-v65f. Advisory sha256 `9cabac1b81c00919800c12d57e989d7ccb6cfc78b6b7e434b36ed7d45dec943d`.
Mechanism: HTTP/2 `deserialize/2` requires `payload::binary-size(length)` before `max_frame_size`.
Closer `1e8e55966da9129016b73d32f0e1df4630e3b463` Mat Trudel, one parent `45feea20dea8af7ffd7245271107b695c040e667`, no AI marker. Parent blob `076fb85a4cdf90c9f9ad0c8a397d1f0754d3dd97`. Fixed blob `74da60f9eeb2f5277d6b3b129924f6b0626df50c` rejects on the 9-byte header.
a330b135 is CI. ai_hunk FAIL. No v1.11.0 tag. release UNKNOWN.

### GHSA-RF5Q-VWXW-GMRF REJECT

Identity PASS: first-party GHSA-rf5q-vwxw-gmrf, CWE-835. Advisory sha256 `768e0d019581e5fff91805990efde80ca744bf9570216d0229c53b935b9748f9`.
Mechanism: chunked last-chunk terminator does not consume RFC 9112 trailers, then recurses with an unchanged buffer.
Advisory names intro `e73e379ab59840e8561b5730878f16e29ab06217` (Handle pipelined requests #437) Mat Trudel 2024-12-06, no matcher hit. Same closer `ae3520df` as GHSA-9Q9Q. Parent blob still has comment `We should be reading (and ignoring) trailers here`.
Claude a330b135 is CI. ai_hunk FAIL. Shared SHA is not dedupe. No v1.11.1 tag. release UNKNOWN.

### GHSA-V56Q-MH7H-F735 REJECT

Identity PASS: first-party GHSA-v56q-mh7h-f735, repo immutable-js/immutable-js, npm immutable. Advisory sha256 `f2171a7ab5d7a27fd4406e65db06adad6544274a49d46f146b7d20d14a508792`.
Mechanism: `setListBounds` `1 << (newLevel + SHIFT)` wrap for sizes in `[2**30, 2**31)`.
Claude `93cb6dfb14c2468bccbe5906006f50b2c755f36c` is reverseFactory `__iterator` in `src/Operations.js` plus IndexedSeq tests. Not `src/List.js`.
5.x peel `f4c94e276678161632a6ed4bfc3019558d796435` (Julien Deniau, no AI marker) is the second parent of merge `a1a1ee412dcaa380ab325196283d06594ffe4b84`. Carrier merge is recorded; authorship is not transferred. 4.x `f0bc997d8eb9886aff2236635aa210a95a04304a` is a one-parent human cherry-pick; 93cb6dfb is not its ancestor. Parent List.js blob `e512bb90db8a29b905e2cce007a67f3b27a32a92` already has the wrapping shift loop.
93cb6dfb is absent from `v5.1.5` peel `b37b85568632227751ddc8a16034cacc0f42b652` and `v4.3.8` peel `485cbe0edf3ca7bb4b9c4a80ac55ba937a291da0`. Local clone has no v4.3.9 or v5.1.8. release UNKNOWN. ai_hunk FAIL, but_for FAIL.

## Conservation

assigned 6 = reviewed 6 + unreviewed 0. Equation 6=6+0. Holds. Did not pad. PASS_PROPOSAL=0. Canonical94 untouched. Countable remains false.

Stop. No ledger, site, scripts, or other-packet edits. No credentials. No GitHub API.
