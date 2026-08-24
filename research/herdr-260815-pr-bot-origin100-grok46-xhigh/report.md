# PR-bot origin100 over commit-first remainder

Routing only. This packet does not call a PASS. Canonical94 stays 94 HOLD.
Publication and greater-than-200 remain unsupported. Worker PASS is proposal only; this packet emits none.

## Verdict

Inspected prefix 100 of the frozen 611 remaining commit-first identities: ROUTE 0, PASS 0, REJECT_ROUTING 100, UNKNOWN 0.
ROUTE IDs: none.
No seven-gate row is free of FAIL. Identity is first-party PLAUSIBLE on all 100. AI-hunk, but-for, fix-reversal, and release fail on all 100.

## Freeze

Authority: canonical94 HOLD at autoresearch/orchestrator-260814-ghsa200-canonical94.
CONTRACT SHA256 cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3 from autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md.
canonical94 ledger SHA256 7dc5e3bc00ed0c11554bdada539ef7947228f03024de6cfce384d1ca11258096.
summary SHA256 c2f7ca777c400ca4069e29a67313d8a4c5acb278f239fb36c4a2019451cf503b. status HOLD, strict 94.
Candidate identities reconstructed unique-first-seen from AF/GJ/GN/KN/OZ artifacts in that shard order.
Reconstructed pool 5980 matches remainder20 work/candidate-pool.jsonl. Pool ID SHA256 0c5ec3f753e27e6bcf78d1edcb77496fce7406ab510034dacd43fd1f5703581a.
Pinned shard files:
AF review-queue.jsonl fef5b3b2d175b57fd9ec043644dd0def5cc314a4574e675a2900bde071c9cdea (559).
AF ai-commits.jsonl 9659e93e82df4428df361507c6728ac83988211b0282ffbc3c12e3aba529d6d0 (80473).
GJ origin-rank.jsonl 4ed1d2c6683593916536d2ada5c961f5c2120f00582da895a2f78bfdaa9534b3 (94).
GN ai-ghsa-intersections.jsonl c58444221e9cc00555ba251da75f518281bacd660a438f6cc8a5df3ac5cf331e (733).
GN ai-commit-scans.jsonl a6d7ca1584dbeb1596c57643092df0178001925efe0de60ca3eee5f72182481a (580).
KN ranking.jsonl 26570a27d1474f220ae8cac5f01805d37019b67cec401a3bf90610588951cd37 (1451).
OZ shard_novel.jsonl bad0e50986cce173f3e1f440c041bdd937576b4ecec2a10caa3f01556983b543 (3623).
OZ ai_mine.jsonl 047bbb068b09194a59a934117fec1448563e073147bf2e005d53f427bdc8c18a (743).
First-party github-reviewed tree HEAD f2c6ab3202aeafb36fbea6e76d892532acfca1a6 committer 2026-08-14T03:33:36+00:00 tree 3308b2f6c73929d3854bd12908e996787a8bb0c8 from read-only cache /home/hanqing/.cache/ghsa200-worker-clones/fresh-delta20-grok46-low/advisory-database.
Matcher contract ai-authorship-source-v3:policy-0b995a85424fa8c604f9568f76ca502bb270caf53bbe6ff53bb3f47457df72f1:author_identity-v2,coauthor_trailer-v4,explicit_attribution-v4.
Existing authenticated gh was used only to confirm PR authors and peel PR commit lists. Credentials were not printed or persisted. Replay strips token-like environment variables. Shared caches were read-only. No clone was retained. No commit or push.

## Exclusion and conservation

Canonical94 strict 94. Overlap with the 5980 pool: 17. Explicit terminal identities harvested from herdr/orchestrator 260813-260815 top-level cases, assignment, adjudication, and result artifacts, skipping work/notes/pages/snapshot/clones/cache/tmp/node_modules and this lane: union 12470. Terminals in pool excluding the 17 canonical IDs: 5352.
5980 = 17 canonical94-in-pool + 5352 terminals-in-pool-excluding-canonical + 611 remaining. Holds.
Remaining ID SHA256 91095c0b6e9e9453a5f8dcf54031ac92eb7a7648601f5c785e9c9773428514d4.
Remaining shards: KN 327 + GN 284 = 611. AF/GJ/OZ remaining 0. Did not pad. Did not substitute.
Negative-control identities GHSA-2MHJ-FHVG-V428 (squash/bot-carrier authorship transfer) and GHSA-HHJV sit outside remaining. This packet does not transfer bot-PR or squash-carrier authorship onto human members.
611 = 100 inspected + 511 unreviewed remainder. Holds.
100 = 100 REJECT_ROUTING + 0 ROUTE + 0 UNKNOWN. Equation 100=100+0 assigned=reviewed+unreviewed. Holds.
PASS=0. ROUTE=0. Canonical94 strict count remains 94.

## Rank

Remaining 611 scored after local clone bot-author scan and gh PR confirmation: confirmed registered autonomous PR author first, then atomic overlap, ancestor of recovered closer, vulnerable tag, closer present, bot-hit count, first-party repo advisory, pool ordinal, case_id. Prefix 100. 90 of 100 have a confirmed exact registered bot PR author (copilot or cursor or devin-ai-integration) with earliest-date hold. 10 do not.
Registered logins searched: copilot, copilot-swe-agent, claude, anthropic-code-agent, cursor, devin-ai-integration, gemini-code-assist, google-labs-jules, labs-code-app, chatgpt-codex-connector, openai-code-agent, codex, openhands-agent, qoderai, roomote, oz-by-warp. Security-autofix logins github-advanced-security and github-code-quality were not used.

## Why zero ROUTE

The 611 leftover commit-first rows are almost all subject_only (GN 284) or no_real_fix_path (KN 326) plus one keras advisory-commit row that has no confirmed bot PR (rank 231, not in this prefix).
Recovered closers on the inspected 100 are version anchors: ecosystem_fixed_tag 96, release_tag 4. None is a GIT advisory commit, compare right-hand SHA, or GHSA grep closer. Version bumps that touch package.json, Cargo.toml, pyproject.toml, VERSION, or csproj are not a minimum first-party fix, so fix-reversal FAIL.
Reject reasons: no_atomic_autonomous_member_on_mechanism 77, manifest_overlap_not_mechanism 13, no_registered_bot_introducing_pr 10.
Thirteen rows had an atomic autonomous member that was an ancestor of the version-anchor closer, but the overlap was only a manifest (package.json, Cargo.toml, pyproject.toml, csproj). That is nearby packaging, not the named IDOR, SSRF, credential-leak, or argument-injection mechanism. ai_hunk FAIL. Examples: Vikunja Copilot PR 1806 (tiptap downgrade) overlaps frontend/package.json; microsoft/apm Copilot PR 407 (CI pipeline) overlaps pyproject.toml; gitoxide chatgpt-codex-connector overlaps Cargo.toml; lightdash Devin PR 12917 (e2e tests) overlaps packages/e2e/package.json; mcp-searxng Copilot Release 0.9.0 overlaps package.json.
Confirmed bot PRs on the other 77 are unrelated later or sibling work (PraisonAI cursor[bot] PRs against Docker/version files, Gitea Copilot WIP-timeline PR 36518, motioneye Copilot findfiles merge, LangChain Copilot Qwen streaming, Home Assistant Copilot ZHA/awair). Members were peeled. Human members were not credited with bot authorship.
Closest miss, still not ROUTE: GHSA-RPM5-65CW-6HJ4 gitpython-developers/GitPython Copilot PR 2125 (harden commit trailer subprocess handling). Atomic Copilot members are ancestors of the release-tag closer, but the closer blob is VERSION only and the GHSA mechanism is not those trailer IO commits. Overlap empty. REJECT_ROUTING no_atomic_autonomous_member_on_mechanism.
Fiber GHSA-QJV7-627W-8QJV Copilot commits overlap app.go (code) but are not ancestors of the ecosystem-tag closer. Topology of an introducing PR on the exact closer fails.

## Seven gates

identity_gate PLAUSIBLE: github-reviewed first-party repo advisory URL for the same GHSA, not withdrawn.
ai_hunk_gate FAIL: no AI-authored atomic member on a non-manifest mechanism path.
topology_gate PLAUSIBLE on 90 confirmed bot PRs after peeling members; FAIL on 10 without a registered bot introducing PR. No authorship transfer.
but_for_gate FAIL: removing the AI member does not shrink the named advisory mechanism.
fix_reversal_gate FAIL: recovered closer is a version anchor, not a minimum fix that reverses the same invariant.
release_gate FAIL: version-tag containment of a packaging commit is not a vulnerable-release proof of the mechanism.
uniqueness_gate PLAUSIBLE: none of the 100 is in canonical94. Shared SHA or shared repository is not identity dedupe.
ROUTE requires all seven PLAUSIBLE and no FAIL. Never PASS.

## Inspected prefix (100)

Order is the deterministic rank. Verdict is REJECT_ROUTING.

001. GHSA-XHRW-5QXX-JPWR repo=microsoft/apm REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=407 closer_src=ecosystem_fixed_tag np=1 member=-
002. GHSA-2PV8-4C52-MF8J repo=go-vikunja/vikunja REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=1806 closer_src=ecosystem_fixed_tag np=1 member=-
003. GHSA-564F-WX8X-878H repo=go-vikunja/vikunja REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=1806 closer_src=ecosystem_fixed_tag np=1 member=-
004. GHSA-7C2G-P23P-4JG3 repo=go-vikunja/vikunja REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=1806 closer_src=ecosystem_fixed_tag np=1 member=-
005. GHSA-F95F-77JX-FCJC repo=go-vikunja/vikunja REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=1806 closer_src=ecosystem_fixed_tag np=1 member=-
006. GHSA-JFMM-MJCP-8WQ2 repo=go-vikunja/vikunja REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=1806 closer_src=ecosystem_fixed_tag np=1 member=-
007. GHSA-9857-6MW7-FQ2M repo=GitoxideLabs/gitoxide REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=2437 closer_src=ecosystem_fixed_tag np=1 member=-
008. GHSA-FR8X-3VFX-F45H repo=GitoxideLabs/gitoxide REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=2437 closer_src=ecosystem_fixed_tag np=1 member=-
009. GHSA-PG4W-G64P-QWHJ repo=GitoxideLabs/gitoxide REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=2437 closer_src=ecosystem_fixed_tag np=1 member=-
010. GHSA-2HX3-VP6R-MG3F repo=microsoft/kiota REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=7330 closer_src=ecosystem_fixed_tag np=1 member=-
011. GHSA-3HFP-GQGH-XC5G repo=lightdash/lightdash REJECT_ROUTING manifest_overlap_not_mechanism bot=devin-ai-integration[bot] pr=12917 closer_src=ecosystem_fixed_tag np=1 member=-
012. GHSA-MRVX-JMJW-VGGC repo=ihor-sokoliuk/mcp-searxng REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=49 closer_src=ecosystem_fixed_tag np=1 member=-
013. GHSA-XCQX-9JF5-W339 repo=ihor-sokoliuk/mcp-searxng REJECT_ROUTING manifest_overlap_not_mechanism bot=Copilot pr=49 closer_src=ecosystem_fixed_tag np=1 member=-
014. GHSA-22CJ-M4WF-FV2C repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
015. GHSA-4869-X4PR-Q22X repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
016. GHSA-5QW8-F2G9-FF29 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
017. GHSA-63V4-W882-G4X2 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
018. GHSA-F44V-7QGW-9GH9 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
019. GHSA-FQ2M-6WQH-X44G repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
020. GHSA-GCQ3-MFVH-3X25 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
021. GHSA-GV83-GQW6-9J2C repo=gofiber/fiber REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=4379 closer_src=ecosystem_fixed_tag np=1 member=-
022. GHSA-J4HJ-7HFH-G2F4 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
023. GHSA-J7QX-P75M-WP7G repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
024. GHSA-P4PJ-VH7H-6CQH repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
025. GHSA-P75F-6FP4-P57W repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
026. GHSA-PM96-6XPR-978X repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=2004 closer_src=ecosystem_fixed_tag np=1 member=-
027. GHSA-QJV7-627W-8QJV repo=gofiber/fiber REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=4372 closer_src=ecosystem_fixed_tag np=1 member=-
028. GHSA-QVPF-J64C-JMHR repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
029. GHSA-V847-HXXW-3PXG repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
030. GHSA-W6H2-FR4Q-XVXV repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
031. GHSA-X462-JJPC-Q4Q4 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=2004 closer_src=release_tag np=1 member=-
032. GHSA-X92V-RPX6-P6CW repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
033. GHSA-8579-RGG5-PH2M repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
034. GHSA-FC26-M9PF-V56Q repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
035. GHSA-VMF9-XX9W-86WX repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
036. GHSA-MQ77-RV97-285M repo=home-assistant/core REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=149748 closer_src=ecosystem_fixed_tag np=2 member=-
037. GHSA-X84V-G949-293W repo=home-assistant/core REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=153521 closer_src=ecosystem_fixed_tag np=2 member=-
038. GHSA-C2JP-C369-7PVX repo=jlowin/fastmcp REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=2295 closer_src=ecosystem_fixed_tag np=1 member=-
039. GHSA-RCFX-77HG-W2WV repo=jlowin/fastmcp REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=2295 closer_src=ecosystem_fixed_tag np=1 member=-
040. GHSA-RJ5C-58RQ-J5G5 repo=jlowin/fastmcp REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=2295 closer_src=ecosystem_fixed_tag np=1 member=-
041. GHSA-3FWP-P5RJ-2PXF repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=ecosystem_fixed_tag np=1 member=-
042. GHSA-5GGR-2F2H-JMVM repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=ecosystem_fixed_tag np=1 member=-
043. GHSA-9R5X-WG6M-X2RC repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=ecosystem_fixed_tag np=1 member=-
044. GHSA-CC8W-R4QH-3V65 repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=ecosystem_fixed_tag np=1 member=-
045. GHSA-CR4G-F395-H25H repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=ecosystem_fixed_tag np=1 member=-
046. GHSA-J5R2-4C8J-XC3M repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=ecosystem_fixed_tag np=1 member=-
047. GHSA-MM7C-RHG6-QR4R repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=ecosystem_fixed_tag np=1 member=-
048. GHSA-XV9X-FJ9G-VJ6H repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=release_tag np=1 member=-
049. GHSA-XXJV-752H-3VP2 repo=go-gitea/gitea REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=36518 closer_src=release_tag np=1 member=-
050. GHSA-G9FX-5R4H-PCW3 repo=motioneye-project/motioneye REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=3219 closer_src=ecosystem_fixed_tag np=2 member=-
051. GHSA-J67X-Q29F-QCVV repo=motioneye-project/motioneye REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=3219 closer_src=ecosystem_fixed_tag np=2 member=-
052. GHSA-PHV5-334H-MXCW repo=motioneye-project/motioneye REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=3219 closer_src=ecosystem_fixed_tag np=2 member=-
053. GHSA-R3CW-C95M-WFH9 repo=motioneye-project/motioneye REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=3219 closer_src=ecosystem_fixed_tag np=2 member=-
054. GHSA-RW9Q-97R9-8GVH repo=motioneye-project/motioneye REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=3219 closer_src=ecosystem_fixed_tag np=2 member=-
055. GHSA-QXVG-H7Q2-HCXH repo=motioneye-project/motioneye REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=3219 closer_src=ecosystem_fixed_tag np=2 member=-
056. GHSA-RHGP-6WQ6-9J67 repo=motioneye-project/motioneye REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=3219 closer_src=ecosystem_fixed_tag np=2 member=-
057. GHSA-FV5P-P927-QMXR repo=langchain-ai/langchain REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=32160 closer_src=ecosystem_fixed_tag np=1 member=-
058. GHSA-PJWX-R37V-7724 repo=langchain-ai/langchain REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=32160 closer_src=ecosystem_fixed_tag np=1 member=-
059. GHSA-R7W7-9XR2-QQ2R repo=langchain-ai/langchain REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=32160 closer_src=ecosystem_fixed_tag np=1 member=-
060. GHSA-QPFV-44F3-QQX6 repo=mikro-orm/mikro-orm REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=7282 closer_src=ecosystem_fixed_tag np=1 member=-
061. GHSA-RPM5-65CW-6HJ4 repo=gitpython-developers/GitPython REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=2125 closer_src=release_tag np=1 member=-
062. GHSA-GWHV-J974-6FXM repo=mikro-orm/mikro-orm REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=7282 closer_src=ecosystem_fixed_tag np=1 member=-
063. GHSA-P68W-RGMG-3C2V repo=grokability/snipe-it REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=18745 closer_src=ecosystem_fixed_tag np=1 member=-
064. GHSA-9CQF-439C-J96R repo=kedro-org/kedro REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=Copilot pr=5187 closer_src=ecosystem_fixed_tag np=1 member=-
065. GHSA-27P4-PJQV-WHGJ repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
066. GHSA-2FJJ-QQG8-FG7X repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
067. GHSA-6H6V-6M7W-7VXX repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
068. GHSA-7P8G-6C6G-H9W7 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
069. GHSA-8G2P-PQM3-FCFH repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
070. GHSA-943M-6WX2-RC2J repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
071. GHSA-98F9-FQG5-HVQ5 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
072. GHSA-9CQ8-3V94-434G repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
073. GHSA-C2M8-4GCG-V22G repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
074. GHSA-CFH6-VR3J-QC3G repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
075. GHSA-CP4F-5M9R-5JC2 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
076. GHSA-CWJ8-7GP2-GGCW repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
077. GHSA-G8RR-7RJ2-F627 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
078. GHSA-GV23-XRM3-8C62 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
079. GHSA-H37G-4H4P-9X97 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
080. GHSA-H8Q5-CP56-RR65 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
081. GHSA-R4F2-3M54-PP7Q repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
082. GHSA-RCMC-Q9RJ-4WMQ repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
083. GHSA-RH39-9C67-59MH repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
084. GHSA-W388-2392-PX73 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
085. GHSA-XWQ8-FRCG-77Q8 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
086. GHSA-3QG8-5G3R-79V5 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
087. GHSA-4X6R-9V57-3GQW repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
088. GHSA-5JX9-W35F-VP65 repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=2 member=-
089. GHSA-8W9J-HC3G-3G7F repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
090. GHSA-X6M9-GXVR-7JPV repo=MervinPraison/PraisonAI REJECT_ROUTING no_atomic_autonomous_member_on_mechanism bot=cursor[bot] pr=1892 closer_src=ecosystem_fixed_tag np=1 member=-
091. GHSA-9XWC-HFWC-8W59 repo=modelcontextprotocol/servers REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
092. GHSA-J22H-9J4X-23W5 repo=modelcontextprotocol/servers REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
093. GHSA-P3HW-MV63-RF9W repo=GitoxideLabs/gitoxide REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
094. GHSA-3643-7V76-5CJ2 repo=MervinPraison/PraisonAI REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
095. GHSA-5CXW-77WG-JRF3 repo=MervinPraison/PraisonAI REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
096. GHSA-6RMH-7XCM-CPXJ repo=MervinPraison/PraisonAI REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
097. GHSA-78R8-WWQV-R299 repo=MervinPraison/PraisonAI REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
098. GHSA-8444-4FHQ-FXPQ repo=MervinPraison/PraisonAI REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
099. GHSA-86QC-R5V2-V6X6 repo=MervinPraison/PraisonAI REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-
100. GHSA-9MQQ-JQXF-GRVW repo=MervinPraison/PraisonAI REJECT_ROUTING no_registered_bot_introducing_pr bot=- pr=- closer_src=ecosystem_fixed_tag np=1 member=-

## Replay

replay.zsh reconstructs the 5980 IDs from the pinned AF/GJ/GN/KN/OZ files, checks remainder20 equality, canonical94 overlap 17, remaining 611 hash, prefix 100, never PASS, and the git parent/author facts above. Run twice.
