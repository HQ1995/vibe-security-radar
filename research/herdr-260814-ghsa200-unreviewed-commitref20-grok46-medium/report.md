# Unreviewed commit-ref 20

**Status: TERMINAL.** Worker PASS is a proposal only. This packet emits none. Canonical strict count remains **82**. Publication and a more-than-200 claim remain **HOLD**. packet_delta=0.

## Freeze

Frozen github/advisory-database HEAD `a42c436870111aa3f221257c9d56126a93173ccc`. Stream `advisories/unreviewed` (github-unreviewed). Files seen 323296. First-party commit-ref identities 9337. Excluded canonical82 strict 82 plus existing herdr-260814-ghsa200-*/selected.jsonl plus GHSA-425G-FJHQ-5H92 and GHSA-HC8V-WWC9-VGXM. Probe used local clones only. First 20 unique qualifying IDs frozen. No padding.

Conservation: assigned 20 = reviewed 20 + unreviewed 0.

## Verdicts

All 20 rows are REJECT. Unreviewed listing is routing. No row has a first-party repo advisory GHSA object, so identity_gate FAIL. Release containment therefore cannot close. OSV introduced fields were not used. AI-on-fix was not treated as origin.

### 01 GHSA-5GMG-XG53-5783 REJECT

Unreviewed GHSA names GET apps/dbagent/src/app/api/evals/route.ts. Nearby Copilot commit e18a0cb5 adds LiteLLM chat routes, not the evals GET handler. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 02 GHSA-PFCX-HCR4-FW85 REJECT

Unreviewed GHSA names AuthMiddleware API authentication bypass. Copilot trailer is on the security update that precedes the merge fix, not an origin hunk. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 03 GHSA-J383-Q79V-268X REJECT

Unreviewed GHSA names sort_cmp use-after-free in src/array.c. Referenced commit eb398971 is the later length-check fix with a Claude trailer. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 04 GHSA-Q269-XQWW-45MM REJECT

Unreviewed GHSA names ary_fill_exec in array.c. Referenced commit is on fork makesoftwaresafe/mruby, Claude-marked validation fix. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 05 GHSA-CP89-J668-CMF6 REJECT

Unreviewed GHSA names createTool workspace-domain handling in packages/sdk/src/mcp/teams/api.ts. Nearby Cursor/Claude commits add project rename and theme tools, not the later auto-join fix. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 06 GHSA-7R5X-3969-58XR REJECT

Unreviewed GHSA names embedding_config.py IP-address handling. Referenced commit da853fdd is a Claude-marked follow-up fix of an SSRF guard. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 07 GHSA-PC25-PWR8-GPP2 REJECT

Unreviewed GHSA names processmp4 use-after-free in mp4.c. Referenced commit fd7271ba is a Claude-marked bounds-check patch covering mp4 and MPEG-TS parsers. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 08 GHSA-W24P-5M2C-JVFH REJECT

Unreviewed GHSA names parse_PAT/parse_PMT in ts_tables.c. Same referenced Claude-marked fix fd7271ba as GHSA-PC25. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 09 GHSA-688C-H9C2-FFWG REJECT

Unreviewed GHSA names BGPHeader.DecodeFromBytes in bgp.go. Nearby Copilot commits are tiny Update bgp.go edits, not the later marker-field validation fix. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 10 GHSA-M763-9MQF-95RQ REJECT

Unreviewed GHSA names CapSoftwareVersion.DecodeFromBytes in bgp.go. Same Copilot filename overlap as the other GoBGP rows. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 11 GHSA-VJ73-H4QP-97X2 REJECT

Unreviewed GHSA names BGP OPEN DecodeFromBytes in bgp.go. Same Copilot filename overlap. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 12 GHSA-8X9F-C335-83WQ REJECT

Unreviewed GHSA names CSRF on upload.php. Referenced commit 2c0d2582 is a Claude-marked CSRF fix. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 13 GHSA-5JVQ-55XJ-6QFF REJECT

Unreviewed GHSA names PathAttributeAigp.DecodeFromBytes in bgp.go. Same Copilot filename overlap. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 14 GHSA-JCWF-QRR5-XWQ3 REJECT

Unreviewed GHSA names base60 buffer underflow in perl_syck.h. Referenced commit 208a4d3b is a Claude-marked fix. reject_class AI_ON_FIX. uniqueness_gate PASS versus canonical82.

### 15 GHSA-34J3-4JPJ-GX6Q REJECT

Unreviewed GHSA names session-export authorization bypass in api/routes.py. Nearby Claude/Cursor commits touch routes.py for TTS voices, truncation watermarks, and i18n, not the later profile-scope security release. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 16 GHSA-4PQR-V6C3-X77J REJECT

Unreviewed GHSA names _isTrackedConversation in ChannelBridge.ts. Nearby Claude v0.4.0 feature dump is the parent of the later human channel-scoped tracking fix. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 17 GHSA-7CPF-FRP7-PM75 REJECT

Unreviewed GHSA names JSONP callback reflection in weed/server/common.go. Nearby gemini-code-assist commit is an SSE-KMS feature, not the JSONP helper origin. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 18 GHSA-MWQ6-FG78-P6CQ REJECT

Unreviewed GHSA names Brotli decompression-bomb bypass in response.py. Nearby Claude commit only fixes a readinto type hint. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 19 GHSA-3397-VR69-3M3W REJECT

Unreviewed GHSA names _build_handoff_toolset in astr_agent_tool_exec.py. Nearby Copilot commit applies max_agent_step to subagents; referenced fix is a later human persona-tool boundary change. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

### 20 GHSA-74W5-9874-X8HW REJECT

Unreviewed GHSA names missing authorization on BankAccountListController. Nearby Claude commit removes unused Request parameters and adds delete-request classes; it is not the list-endpoint authorization origin or the later first-party closure. reject_class NEARBY_FILE_OVERLAP_NOT_MECHANISM. uniqueness_gate PASS versus canonical82.

## Claim boundary

PASS is a proposal only. This packet admits nothing. Canonical ledger was not edited. Publication stays HOLD. Greater-than-200 remains unsupported.

## Replay

`zsh autoresearch/herdr-260814-ghsa200-unreviewed-commitref20-grok46-medium/replay.zsh`

Two consecutive runs must be byte-identical.
