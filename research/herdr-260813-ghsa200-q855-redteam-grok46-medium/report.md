# Red-team: GHSA-Q855-8RH5-JFGQ

**Status: `REDTEAM_COMPLETE`.** Hostile hypothesis: the direct-root mining proposal is not countable. Independent first-party identity, first-parent hunk, topology, patch reversal, release, and uniqueness replay against `/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/homeassistant-ai__ha-mcp` plus frozen GitHub/PyPI snapshots.

**Verdict: `KEEP` (proposal only).** All seven gates `PASS`. Countable admission remains **false**. Publication remains **HOLD**.

Leader contract frozen at SHA-256 `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`. Source proposal: `autoresearch/herdr-260813-ghsa200-directroot-mining-grok46-xhigh` (`GHSA-Q855-8RH5-JFGQ` only).

## Attacks

| Attack | Result |
|--------|--------|
| Advisory `first_patched` 7.10.0 vs git/PyPI 7.7.0 | Does not stick. 7.7.0 closes every named root route. |
| Later blob inequality | Does not stick. v7.5.0 mount lines still blame `9783f346`. |
| Ingress trust (Supervisor IP) | Does not stick. That is the first-party reversal. |
| Secret-prefix vs bare-root | Does not stick. Secret path is out of GHSA scope. |
| Topology / authorship transfer | Does not stick. Counted squash has its own Claude trailer. |
| Uniqueness vs canonical72 and sibling ha-mcp GHSAs | Does not stick. Distinct identity and sink. |
| v7.5.0 missing policy/features/backups | Does not stick. PoC routes exist at origin; extras reuse the same root mount and die with `9f5b085a`. |

## Identity — PASS

Reviewed global GHSA-q855-8rh5-jfgq (`type=reviewed`, `github_reviewed_at=2026-07-07T23:41:21Z`, `withdrawn_at` null, no CVE alias). `source_code_location` is `https://github.com/homeassistant-ai/ha-mcp`. Repository advisory is published, not withdrawn, CWE-306/CWE-352. Summary: add-on settings and policy routes reachable without authentication at the bare root of `:9583`.

Version-range split is real and was the primary attack:

- Repo advisory: `ha-mcp` `<= 7.6.0`, `patched_versions` empty.
- Global advisory / frozen advisory-database JSON: `introduced:0`, `fixed` / `first_patched_version` `7.10.0`, range `< 7.10.0`.
- Advisory body: “v7.6.0 and earlier”; PoC is unauthenticated `GET/POST /api/settings/tools` and `POST /api/settings/restart`. Named extras: features, backups, policy.

Identity names repository, mechanism, and public GHSA. The range split is a release-gate question, not an identity failure.

## AI hunk / topology / but-for — PASS

`9783f346795be919bffda8a6475ae716a9e3580c` is a single-parent squash (`8ba80aee`). The squash carries `Co-authored-by: Claude Opus 4.6`. First-parent adds `src/ha_mcp/settings_ui.py` (862 lines). Parent tree has no that path. Under `is_addon` it registers unauthenticated `mcp.custom_route("/", ...)` plus `/api/settings/tools` and `/api/settings/restart`. Secret-prefix mounts are a separate, authenticated path.

The squash is an ancestor of `v7.5.0`, `v7.6.0`, `v7.7.0`, `v7.10.0`, and of fix `9f5b085a`. No member-to-carrier authorship transfer.

Removing that first-parent file removes the bare-root settings surface. Later commits add features/backups/policy onto the same unauthenticated root table; they are not a pre-existing sibling path.

## Fix reversal — PASS

Minimum same-invariant fix is `9f5b085ad4a7b38b067c9da0dc5b45462c4d796e` (first `_ingress_only` commit; PR #1508). It wraps add-on root mounts so only Supervisor transport peer `172.30.32.2` is admitted, using `request.client.host`, never `X-Forwarded-For`. Secret-prefix mounts stay unguarded by design. That matches the GHSA patch text.

## Release — PASS (count 7.7.0; 7.10.0 also closed)

Exact mapping:

| Artifact | settings blob | `_ingress_only` | Named extras | Root mount blame |
|----------|---------------|-----------------|--------------|------------------|
| AI `9783f346` | `7e829d74` | no | tools/restart only | origin |
| PyPI/git **7.5.0** | `46d32362` (wheel = tag) | no | tools/restart only | **`9783f346` L968–L973** |
| PyPI/git **7.6.0** | `47286cb4` | no | tools, features, backups, policy | `6c3c0ac4` (later rewrite) |
| Fix `9f5b085a` | `4275a831` | yes | full table `_mount("", guard=True)` | fix |
| PyPI/git **7.7.0** | `36479aaa` | yes | full table guarded | `9f5b085a` for `SUPERVISOR_INGRESS_IP` |
| PyPI/git **7.10.0** | `905311e7` at `settings_ui/__init__.py` | yes | full table guarded | `9f5b085a` after package split |

GitHub Releases `v7.5.0`, `v7.6.0`, `v7.7.0`, `v7.10.0` are all `prerelease=false`.

**7.7.0 truly closes every advisory-named root route**, not a subset. `v7.7.0` / wheel `ha_mcp-7.7.0` contain `/api/settings/tools`, `/api/settings/features`, `/api/settings/backups`, `/api/settings/backup-config`, `/api/settings/restart`, `/api/policy/config|approve|deny`, and `_mount("", guard=True)`. Global `first_patched 7.10.0` is a later Advisory Database ecosystem mapping (reviewed 2026-07-07, after the 2026-07-06 `settings_ui` package split). 7.10.0 still contains the same `9f5b085a` guard. Repo range `<= 7.6.0` matches git: `v7.6.0` unguarded, `v7.7.0` guarded.

Vulnerable containment uses **7.5.0** because that is the released non-prerelease wheel whose exact `custom_route("/")` lines still blame the origin squash. 7.6.0 has the full named surface but those lines blame later Claude-marked squash `6c3c0ac4` (stdio settings UI). `6c3c0ac4` is not counted as origin.

Blob inequality is expected and recorded: origin blob ≠ 7.5.0 blob; fix blob ≠ 7.7.0 blob. Line identity, not whole-file equality, is the gate.

## Uniqueness — PASS

`GHSA-Q855-8RH5-JFGQ` is absent from frozen canonical72 (72 ids), fp211 `public_cases.jsonl`, and live `scripts/publication_adjudications.json`. Canonical72 ha-mcp siblings `GHSA-FMFG-9G7C-3VQ7` (OAuth `ha_url` SSRF), `GHSA-G39V-CVJH-8FPF` (`www/yaml_backups` local read), and `GHSA-PF93-J98V-25PV` (consent-form XSS) are different sinks. Shared repository is not duplication.

## Claim boundary

This packet does not rebuild the 48-case strict-released lower bound and does not support a more-than-200 claim. Worker KEEP is a proposal. Leader admission is required before the row is countable.
