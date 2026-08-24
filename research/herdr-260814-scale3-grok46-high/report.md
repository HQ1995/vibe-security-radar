# herdr-260814-scale3-grok46-high

Timebox-closed review of fwd-slice-7 (25 first-party GHSA rows).
Unclosed gates remain UNKNOWN. Missing evidence was not converted into FAIL.
No PASS proposals. Conservation 25=25+0.

## Counts

- assigned: 25
- UNKNOWN: 25
- PASS/REJECT/NARROW/BLOCKED: 0

## Per-row decisions

| row | ghsa | repo | identity | ai_hunk | verdict | candidate_sha |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | GHSA-39H7-PWV7-RC3X | excalidraw/excalidraw | PASS | UNKNOWN | UNKNOWN | bfd4af23673df9904a37b9f194c1823cd6e831b7 |
| 2 | GHSA-GJ49-89WH-H4GJ | cilium/cilium | PASS | FAIL | UNKNOWN | 2c59ba7dfaa5065e3b71814b97be7d217e07cda3 |
| 3 | GHSA-2WPX-QPW2-G5H5 | coredns/coredns | PASS | UNKNOWN | UNKNOWN | 12d9457e71461c6864eb4be5ed3e94de32c9aa9c |
| 4 | GHSA-63CW-R7XF-JMWR | coredns/coredns | PASS | UNKNOWN | UNKNOWN | 12d9457e71461c6864eb4be5ed3e94de32c9aa9c |
| 5 | GHSA-H8MM-C463-WJQ3 | coredns/coredns | PASS | UNKNOWN | UNKNOWN | 12d9457e71461c6864eb4be5ed3e94de32c9aa9c |
| 6 | GHSA-QHMP-Q7XH-99RH | coredns/coredns | PASS | UNKNOWN | UNKNOWN | 12d9457e71461c6864eb4be5ed3e94de32c9aa9c |
| 7 | GHSA-VP29-5652-4FW9 | coredns/coredns | PASS | UNKNOWN | UNKNOWN | 12d9457e71461c6864eb4be5ed3e94de32c9aa9c |
| 8 | GHSA-P6HG-QH38-555R | traefik/traefik | PASS | UNKNOWN | UNKNOWN | 8ac8473554d758459ae4e99dab4be7dcbb167a07 |
| 9 | GHSA-R35X-V8P8-XVHW | befeleme/pyp2spec | PASS | UNKNOWN | UNKNOWN | 04d9f499d38c7dfb981a55d6e1c0d3ec1094945f |
| 10 | GHSA-CCXC-X975-4HH9 | pyload/pyload | PASS | UNKNOWN | UNKNOWN | 23c48a5c3cddc37d16b9265d0d44e554eaea3918 |
| 11 | GHSA-PG67-9WJV-MR85 | pyload/pyload | PASS | UNKNOWN | UNKNOWN | 23c48a5c3cddc37d16b9265d0d44e554eaea3918 |
| 12 | GHSA-FJ4G-2P96-Q6M3 | Jovancoding/Network-AI | PASS | UNKNOWN | UNKNOWN | 27b549f4d3a16c2a54a382d58b8ad01530f20b5d |
| 13 | GHSA-J4RJ-2JR5-M439 | felippe-regazio/ssrfcheck | PASS | UNKNOWN | UNKNOWN | 43c9680baf6a712ff93e584c32acfdedd02bec7f |
| 14 | GHSA-33GV-FC78-QGF5 | YAFNET/YAFNET | PASS | UNKNOWN | UNKNOWN | d2b474be09ac6e1a917668be379e07539e96f2a8 |
| 15 | GHSA-8RQ5-WWPP-FMJ2 | YAFNET/YAFNET | PASS | UNKNOWN | UNKNOWN | d2b474be09ac6e1a917668be379e07539e96f2a8 |
| 16 | GHSA-97R3-5W84-R4Q8 | pyload/pyload | PASS | UNKNOWN | UNKNOWN | 23c48a5c3cddc37d16b9265d0d44e554eaea3918 |
| 17 | GHSA-838G-GR43-QQG9 | pyload/pyload | PASS | UNKNOWN | UNKNOWN | 23c48a5c3cddc37d16b9265d0d44e554eaea3918 |
| 18 | GHSA-7GMJ-67G7-PHM9 | tauri-apps/tauri | PASS | UNKNOWN | UNKNOWN | 001c8fe3d288802de9a8c29cfd2f46f9220d97c5 |
| 19 | GHSA-C3GC-9PF2-84GG | pyload/pyload | PASS | UNKNOWN | UNKNOWN | 23c48a5c3cddc37d16b9265d0d44e554eaea3918 |
| 20 | GHSA-8P33-Q827-GHJ5 | HackingRepo/dssrf-js | PASS | UNKNOWN | UNKNOWN | 817c900ac2e080b8580a6688647c486bdddfc2f5 |
| 21 | GHSA-C4RQ-3M3G-8WGX | sparklemotion/nokogiri | PASS | UNKNOWN | UNKNOWN | 3b4896953188a76a0da728d64027164c52be48ef |
| 22 | GHSA-V2FC-QM4H-8HQV | sparklemotion/nokogiri | PASS | UNKNOWN | UNKNOWN | 3b4896953188a76a0da728d64027164c52be48ef |
| 23 | GHSA-PGGP-6C3X-2XMX | brantburnett/Snappier | PASS | UNKNOWN | UNKNOWN | 96b68fd6f46c5693c5670fda97334ab50d752ced |
| 24 | GHSA-GMVF-9V4P-V8JC | nearform/fast-jwt | PASS | UNKNOWN | UNKNOWN | 2181bf1e218088a8b174b1f32902ebcb1ae5e335 |
| 25 | GHSA-J72X-XFWG-783F | shellhub-io/shellhub | PASS | UNKNOWN | UNKNOWN | 43bed23b24370ec787e838403cd6ae5e5e9f1603 |

## Notes

Identity PASS is from frozen reviewed GHSA JSON in the local advisory-database cache.
GHSA-GJ49-89WH-H4GJ has a evidenced AI-hunk mismatch (gateway-api cell vs bugtool/WireGuard), so ai_hunk_gate is FAIL; remaining gates stay UNKNOWN and the case verdict stays UNKNOWN.
Other rows keep ai_hunk_gate UNKNOWN because diffs were not closed against the advisory sink before timebox.
Topology, but-for, fix-reversal, release, and uniqueness were not closed for any row.

