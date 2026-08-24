# herdr-260814-w2-9-ds - unreviewed-adjudication unr-adj2-slice-9

**Verdict-first: 25/25 FALSE_POSITIVE. 0 countable, 0 PASS proposals.**

No candidate AI commit introduces the named advisory mechanism. Every candidate
touches files disjoint from the mechanism file/component, or (where the diff was
read) is a fix/refactor that does not author the vulnerable hunk. Packet delta = 0;
the canonical count is unchanged and publication stays HOLD.

## Method

- Mechanisms read from the local advisory-database clone (advisories/unreviewed/...) for
  the 14 in-window advisories; the 11 August-2026 advisories are absent from the frozen
  DB (tree ends at 2026/07) and osv.dev returns 404, so their mechanisms/CVEs were read
  from the first-party github.com/advisories page title plus the NVD CVE description.
- Candidate diffs: disjoint rows resolved from the slice changed-file lists; four
  overlapping/near-overlapping commits were fetched via git smart-HTTP (depth-1 +
  --deepen=1) into work/ and their diffs read. No GitHub API, no blame/SZZ.
- Gates: identity=NARROW (unreviewed GHSA), ai_hunk=FAIL, topology=NARROW, but_for=FAIL,
  fix_reversal=UNKNOWN (no first-party fix ref in slice), release=UNKNOWN,
  uniqueness=PASS (none of the 25 ids/aliases are in foundation.jsonl).

## Per-row

| # | GHSA | CVE | repo | mechanism | candidate | evidence | verdict |
|---|---|---|---|---|---|---|---|
| 1 | GHSA-997V-R4V7-9F3G | CVE-2026-15529 | yzhao062/pyod | pyod/utils/persistence.py | 7b0b7b516d63 | changed_files | FALSE_POSITIVE |
| 2 | GHSA-VG36-RRRG-4WQV | CVE-2026-15538 | Mantle-UI/mantle-ui | ObjectUtils.mutateFieldData (prototype pollution; advisory names primefaces primereact) | 8398e1162a34 | diff_read | FALSE_POSITIVE |
| 3 | GHSA-HVV2-8JPJ-GR8H | CVE-2026-63771 | vrana/adminer | cookie/Set-Cookie path via X-Forwarded-Prefix header | 87cb0781b617 | changed_files | FALSE_POSITIVE |
| 4 | GHSA-HWWM-2GQ7-F4RR | CVE-2025-15686 | open5gs/open5gs | fd_msg_sess_get (HSS Service) | 8c37b4b785e0 | changed_files | FALSE_POSITIVE |
| 5 | GHSA-VXM6-3HJQ-R228 | CVE-2025-15685 | open5gs/open5gs | freeDiameter component | 8c37b4b785e0 | changed_files | FALSE_POSITIVE |
| 6 | GHSA-F8M3-93XM-637C | CVE-2026-2069 | ggml-org/llama.cpp | src/llama-grammar.cpp (llama_grammar_advance_stack) | 0dfcd3b60755 | changed_files | FALSE_POSITIVE |
| 7 | GHSA-C56H-J8GW-3V54 | CVE-2026-3288 | kubernetes/kubernetes | ingress-nginx rewrite-target annotation (separate repo) | cc483208aa30 | changed_files | FALSE_POSITIVE |
| 8 | GHSA-JPJ3-M5Q9-54RF | CVE-2026-40028 | Yamato-Security/hayabusa | HTML report output (Computer field) | f18d86f89f37 | diff_read | FALSE_POSITIVE |
| 9 | GHSA-572J-C8JF-P9VV | CVE-2026-38570 | bacnet-stack/bacnet-stack | bacnet_tag_number_decode | 0ebe5fd8dc71 | changed_files | FALSE_POSITIVE |
| 10 | GHSA-WWV2-C3P6-CPR5 | CVE-2026-19000 | jeecgboot/JeecgBoot | /airag/chat/send (Anonymous Chat Attachment Parser) | 24338e562cdb | changed_files | FALSE_POSITIVE |
| 11 | GHSA-98J2-6V39-78W8 | CVE-2026-13505 | bcgit/bc-java | BC-FJA Object.finalize zeroisation (FIPS product) | 436a9078cd5a | changed_files | FALSE_POSITIVE |
| 12 | GHSA-V6W3-QRH8-QCCC | CVE-2026-8798 | bcgit/bc-java | BC-FJA native entropy source (RDSEED/RDRAND) | 436a9078cd5a | changed_files | FALSE_POSITIVE |
| 13 | GHSA-497M-753J-QCPH | CVE-2025-43880 | weseek/growi | regex (ReDoS) | 1d02b1fbb0f8 | changed_files | FALSE_POSITIVE |
| 14 | GHSA-QGG6-HJ2R-3X43 | CVE-2025-56225 | FluidSynth/fluidsynth | src/synth/fluid_synth_monopoly.c | 962b9946b5cb | changed_files | FALSE_POSITIVE |
| 15 | GHSA-54VC-PH3H-X39X | CVE-2026-44029 | NixOS/nix | nix-prefetch-url --unpack / prefetch-file (directory traversal) | db505658529d | changed_files | FALSE_POSITIVE |
| 16 | GHSA-JGGJ-J5FQ-X969 | CVE-2026-44028 | NixOS/nix | NAR parser (unbounded recursion) | db505658529d | changed_files | FALSE_POSITIVE |
| 17 | GHSA-9HPQ-F88H-GMV3 | CVE-2018-25356 | SIPp/sipp | sipp.cpp (-3pcc/-i/-log_file strcpy) | bbbb03416abc | changed_files | FALSE_POSITIVE |
| 18 | GHSA-M2C6-QHF9-2XM8 | CVE-2026-2299 | mattermost/mattermost-plugin-google-drive | file creation endpoint (channel membership validation) | 2fe647c1bc42 | diff_read | FALSE_POSITIVE |
| 19 | GHSA-F3MC-X4VF-JRW2 | CVE-2026-13323 | eclipse-openvsx/openvsx | /vscode/unpkg/ endpoint (text/html, no CSP) | e7075d23d854 | changed_files | FALSE_POSITIVE |
| 20 | GHSA-8GGV-VMGF-36WQ | CVE-2026-67352 | openwrt/luci | luci-app-https-dns-proxy (resolver_url) | 4a78eccd90dc | changed_files | FALSE_POSITIVE |
| 21 | GHSA-VH6J-2JXW-848C | CVE-2026-68583 | openwrt/luci | luci-app-adblock-fast (blocklist name) | 4a78eccd90dc | changed_files | FALSE_POSITIVE |
| 22 | GHSA-4Q7Q-8M76-5RV8 | CVE-2026-69095 | openwrt/luci | luci-app-bmx7 bmx7-info CGI (path traversal) | 4a78eccd90dc | changed_files | FALSE_POSITIVE |
| 23 | GHSA-6VFC-74MF-QRMJ | CVE-2026-72840 | openwrt/luci | luci-mod-system-mounts ACL (/etc/crontabs/root) | 4a78eccd90dc | changed_files | FALSE_POSITIVE |
| 24 | GHSA-X5WV-6F33-PH3P | CVE-2026-72841 | openwrt/luci | luci-app-openvpn (instance_name2 path traversal) | 4a78eccd90dc | changed_files | FALSE_POSITIVE |
| 25 | GHSA-Q7C4-GHWQ-63XH | CVE-2026-72842 | openwrt/luci | luci-app-lxc (ACL inconsistency) | 4a78eccd90dc | changed_files | FALSE_POSITIVE |

## Diff-read rows

- mantle-ui 7ea4f0a7 (row 2): Copilot Autofix adds a 7-line
  __proto__/prototype/constructor blocklist to ObjectUtils.mutateFieldData. It is a
  mitigation, not an introduction; the advisory names primefaces primereact, a different repo.
- hayabusa a9e0ae81 (row 8): afterfact.rs val.is_empty() -> val.trim().is_empty() in
  output_json_str (1 line). No HTML escaping of the Computer field is touched.
- mattermost 797f8903 / 7ec381c6 (row 18): api.go changes are telemetry removal and a
  deferClose body-close refactor in handleFileUpload/handleAllFilesUpload; no channel
  membership validation is added or removed.

## Conclusion

This packet admits no countable case. All 25 rows close at ai_hunk/but_for FAIL
(wrong edge). Identity stays NARROW on unreviewed advisories; fix_reversal/release stay
UNKNOWN. Canonical ledger untouched; publication HOLD.
