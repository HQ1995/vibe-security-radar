# herdr-260814-w3-6-ds - slice 6 (unr-adj3) adjudication

**Verdict first: 25/25 FALSE_POSITIVE, 0 countable.** For every row the candidate
AI commits do not author the vulnerable hunk of the named mechanism; they are
unrelated fixes/refactors, and 14 rows name a mechanism in a different
repository than the row's repo. `ai_hunk_gate` and `but_for_gate` FAIL, so no
row closes the seven gates.

## Result

- assigned 25, reviewed 25, FALSE_POSITIVE 25, CONFIRM 0, NARROW 0, UNKNOWN 0
- terminal=true on all rows; zero proposed acceptances

## Per-repository evidence

### getgrav/grav - 16 rows
Candidates are the same five GPM/Installer/media/Twig3 commits as the adj2
slice: upgrade gating (`2c517b01`), media blueprint (`e3ff054d`), two Copilot
Twig3 one-liners (`2dcf9179`, `bf7dd2e6`), and a Twig3 regex fix (`50865058`).
Only three rows name a core-Grav mechanism (blueprint `isSafeDynamicCall`
static-call denylist, Flex Objects ZIP upload RCE, email-action SSTI); the
candidates do not touch those areas. The other 13 rows name mechanisms in
grav-plugin-login (profile-update privilege fields, Remember-Me token expiry),
grav-plugin-form (open redirect, radio/toggle XSS), or grav-plugin-api
(9 API-key scope-cap bypasses) - different repositories than `getgrav/grav`.

### jenkinsci/jenkins - 1 row
CVE-2026-19429 is a `FilePath.untarFrom()` symlink-target bypass. The five
Copilot candidates are UI changes (sidebar navigation, header actions,
badgeClass) plus a `HudsonPrivateSecurityRealm` admin-account race fix; none
touch `FilePath.untarFrom()` tar extraction.

### Zie619/n8n-workflows - 1 row
CVE-2025-55526 is a directory traversal in `api_server.py::download_workflow`.
The Claude candidates are devcontainer, docs, a documentation generator, and
workflow JSON renames; none edit `api_server.py` source.

### rustdesk/hbb_common - 1 row
CVE-2026-30793 is a CSRF/privilege-escalation in the rustdesk-client Flutter URI
handler + FFI bridge (`flutter/lib/common.dart`, `src/flutter_ffi.rs`) - the
`rustdesk/rustdesk` repo, not `hbb_common`. The six Copilot candidates edit
webrtc signaling/examples only.

### rrweb-io/rrweb - 1 row
CVE-2025-45806 is an XSS in rrweb-snapshot serialization (<2.0.0-alpha.18). The
Copilot candidates are a vite migration, a stylesheet replace/replaceSync fix,
and a vitest config fix; none alters snapshot serialization/rebuild.

### jsonpickle/jsonpickle - 1 row
CVE-2021-47952 is the longstanding py/repr deserialization RCE of jsonpickle
2.0.0 (2021). The 2026 GPT/Claude candidates are numpy/pandas, defaultdict,
`__reduce_ex__`, and `types` importable-name changes; none introduces py/repr.

### hestiacp/hestiacp - 1 row
CVE-2026-12196 is a broken access control on the panel cronjob feature. The
candidates are four Copilot XSS/proxy-header hardening commits plus the human
`1.9.5 beta` release (no AI marker); none introduces the cronjob access-control.

### openwrt/luci - 3 rows
CVE-2026-59260 (samba4 `file.exec` ACL), CVE-2026-61876 (DHCPv6 lease hostname
XSS), CVE-2026-61875 (upnp AddPortMapping stored XSS). The five Claude
candidates are DHCPv4 client-id option, two wireless.js additions, a
`cbi.js String.format` extension, and an ocserv status fix; none touches
luci-app-samba4, DHCPv6 lease rendering, or luci-app-upnp.

## Gate summary

identity_gate=PASS (first-party unreviewed advisory names mechanism + CVE);
ai_hunk_gate=FAIL (AI-marked commits do not author the vulnerable hunk);
topology_gate=FAIL; but_for_gate=FAIL; fix_reversal_gate=FAIL;
release_gate=FAIL; uniqueness_gate=PASS.

## Disagreements with stored labels

Upstream triage marked these KEEP on commit-subject overlap. Deep adjudication
of the actual diffs overturns every KEEP: the overlaps are superficial and no
candidate introduces the named mechanism.
