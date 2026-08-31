# Duplicate cases — independent second review

Date: 2026-08-31  
Scope: the two proposed merges only. No ledger, database, publisher, or generated-data mutation was performed. Review follows [`docs/AUDIT-PROTOCOL.md`](../../docs/AUDIT-PROTOCOL.md) and compares public identity, repository, source-to-sink mechanism, BIC/fix patches, and release artifacts rather than matching titles alone.

## Answer

| Proposed merge | Verdict | Canonical class_id to retain | Public IDs in the merged class | Site count |
|---|---|---|---|---|
| GHSA-723W-CRW6-P9HX ↔ GHSA-8H88-GXP3-J7PG / CVE-2026-74876 | **AGREE** | `alias-0a97ba3bb4787b9352f519d1` | `GHSA-8H88-GXP3-J7PG`, `GHSA-723W-CRW6-P9HX`, `CVE-2026-74876` | `-1` |
| GHSA-J48Q-4C78-RHF9 ↔ GHSA-CCP9-5G7C-PJ86 / CVE-2026-74872 | **AGREE** | `alias-0ae1e9b85f4a9eebb8ee56b3` | `GHSA-J48Q-4C78-RHF9`, `GHSA-CCP9-5G7C-PJ86`, `CVE-2026-74872` | `-1` |

Total: current snapshot `254` cases becomes **`252`**, a net **`-2`**. If the two retained canonical records stay confirmed, the snapshot buckets become `confirmed=125`, `qualified=86`, `provisional=41`.

## Pair 1: 723W versus 8H88 / CVE-2026-74876

**Verdict: AGREE — exact duplicate, not merely a similar weakness.**

| Dimension | Independent comparison |
|---|---|
| Advisory identity | The reviewed [vendor advisory GHSA-8H88-GXP3-J7PG](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-8h88-gxp3-j7pg) is the source named by the official [CVE-2026-74876 record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/74xxx/CVE-2026-74876.json). The unreviewed GHSA-723W record also directly references that same vendor advisory. Its later GHSA/CVE IDs are aliases, not a second vendor finding. |
| Repository | Both records resolve to `jahlives/openssl_encrypt`. |
| Mechanism | Identical path and impact: untrusted data enters `PublicKeyBundle.from_dict()` without self-signature verification; `to_identity()` accepts the resulting bundle; encryption can consequently target attacker-controlled public keys. Both identify CWE-347. Different severity scores do not create a different vulnerability. |
| BIC | Both site records use [`fafdfeed1b279cfe61e86cd8adc132b206eef8d4`](https://github.com/jahlives/openssl_encrypt/commit/fafdfeed1b279cfe61e86cd8adc132b206eef8d4), parent `4c7ae852c784c9986d087c5956a77fa563a05a35`. The parent lacks `key_bundle.py`; the BIC creates the vulnerable API and has a Claude Sonnet 4.5 co-author marker. Both records publish candidate patch hash `301c66ad900d9b5a2591f71192abc97b788e7cfee070386582d2f3361dcc34d3`. |
| Fix | Both use [`f4a1ba660063cd9e17883829e5272a248525a16b`](https://github.com/jahlives/openssl_encrypt/commit/f4a1ba660063cd9e17883829e5272a248525a16b), which adds default `verify=True` and calls `verify_signature()` before returning. Both publish fix patch hash `ec479da1229a4e27b1f1667c9c07eef0b775aa36fdcb571d01d9decdc34fa15c`. |
| Release | Both advisories state `<1.4.0`, fixed `1.4.0`. The primary [PyPI 1.4.0b8 artifact](https://pypi.org/project/openssl-encrypt/1.4.0b8/) contains the unverified method; the [PyPI 1.4.0 artifact](https://pypi.org/project/openssl-encrypt/1.4.0/) contains the default verification. Git tag `v1.4.0` contains both BIC and fix, so the published beta wheel—not that stable tag alone—is the vulnerable-release witness. |

### Merge instruction

- Retain internal class `alias-0a97ba3bb4787b9352f519d1` and canonical public case ID `GHSA-8H88-GXP3-J7PG`: it is the earlier vendor-originated, GitHub-reviewed record and already carries the closed causal dossier.
- Merge `GHSA-723W-CRW6-P9HX` and `CVE-2026-74876` into its public aliases.
- Retire `alias-7a67e4c2cdfe7bc6ade411ee` as a non-publishing duplicate.
- Net site change for this pair: `-1` (`254 -> 253` if performed alone).

Primary local sources:

- `.ai-slop/state/repos/jahlives_openssl_encrypt`
- `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/04/GHSA-8h88-gxp3-j7pg/GHSA-8h88-gxp3-j7pg.json`
- `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/unreviewed/2026/08/GHSA-723w-crw6-p9hx/GHSA-723w-crw6-p9hx.json`

## Pair 2: J48Q versus CCP9 / CVE-2026-74872

**Verdict: AGREE on the merge. DISAGREE with treating `963d0d1` and release `1.4.0` as a closed fix boundary.**

| Dimension | Independent comparison |
|---|---|
| Advisory identity | The official [CVE-2026-74872 record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/74xxx/CVE-2026-74872.json) names the reviewed [vendor advisory GHSA-J48Q-4C78-RHF9](https://github.com/jahlives/openssl_encrypt/security/advisories/GHSA-j48q-4c78-rhf9) as its vendor advisory. The unreviewed GHSA-CCP9 record in turn describes the same Whirlpool loader and references J48Q. This is an explicit public identity edge. |
| Repository | Both records resolve to `jahlives/openssl_encrypt`. |
| Mechanism | Both concern attacker-planted native Whirlpool modules selected by broad `whirlpool*.so` / `whirlpool*py313*.so` globs and imported without authenticating their contents, producing native-code execution. CWE-427 versus CWE-426 is taxonomy variation around the same loader, not a separate source-to-sink path. |
| BIC | Both current site records already select [`cb07e5f88a98f4459a5f828142e740c024810692`](https://github.com/jahlives/openssl_encrypt/commit/cb07e5f88a98f4459a5f828142e740c024810692) and publish the identical candidate patch hash `aba231af9b8a4b5d629bbf3171359c01cbccb86c3e9089f0c3fbc5bbf459c73e`. It first introduces the product-wide unauthenticated glob/select/link-or-copy/import mechanism. AI-marked `f6770c1e774ff46a591257c1e62063f39a6f568b` later duplicates the direct loader in the advisory-quoted `hash_registry.py`; it is a later path/carrier within the same finding, not a second advisory identity. |
| Fix patches | J48Q's claimed [`963d0d1278b722ea134272f9df65fddcd3e6ab47`](https://github.com/jahlives/openssl_encrypt/commit/963d0d1278b722ea134272f9df65fddcd3e6ab47) changes only `setup_whirlpool.py`. It neither removes nor validates the advisory-quoted loaders in `crypt_core.py` and `registry/hash_registry.py`, and still accepts a malicious module already inside site-packages. CCP9's [`fdb5d72999914f5604a419225949db669d4be3f2`](https://github.com/jahlives/openssl_encrypt/commit/fdb5d72999914f5604a419225949db669d4be3f2) removes Whirlpool support from both direct-loader files and deletes `setup_whirlpool.py`; this is the first observed full reversal. The differing fix SHAs reflect partial versus complete remediation, not different vulnerabilities. |
| Release | The vendor advisory/CVE claim `1.4.0` fixed, but the exact [PyPI 1.4.0 wheel](https://pypi.org/project/openssl-encrypt/1.4.0/) still contains all three vulnerable loader families. Local tags `v1.4.0` and `v1.4.9` contain `cb07e5f8` and `963d0d1`, retain the direct loaders, and do not contain `fdb5d729`; no tag contains `fdb5d729`. The merged class must therefore be modeled as unpatched through at least `v1.4.9`, with `fdb5d729` only an unreleased potential-fix reference. |

### Merge instruction

- Retain internal class `alias-0ae1e9b85f4a9eebb8ee56b3`, because it holds the fuller product-wide origin/closure analysis. Use `GHSA-J48Q-4C78-RHF9` as the canonical public case/advisory URL because it is the reviewed first-party advisory.
- Merge `GHSA-CCP9-5G7C-PJ86` and `CVE-2026-74872` into the public aliases.
- Retire `alias-bf499d08da8dae005eecbbc0` as a non-publishing duplicate.
- Do not carry `963d0d1` as `minimum_fix_set` or `1.4.0` as a fixed-release witness. Record `f6770c1e…` as a later duplicate/carrier and represent `fdb5d729…` as an unreleased potential fix until a containing release exists.
- Net site change for this pair: `-1` (`254 -> 253` if performed alone).

Primary local sources:

- `.ai-slop/state/repos/jahlives_openssl_encrypt`
- `web/src/generated/research-data.json`
- `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/github-reviewed/2026/03/GHSA-j48q-4c78-rhf9/GHSA-j48q-4c78-rhf9.json`
- `/home/hanqing/.cache/cve-analyzer/advisory-database/advisories/unreviewed/2026/08/GHSA-ccp9-5g7c-pj86/GHSA-ccp9-5g7c-pj86.json`

## Exact count delta

Current generated snapshot (`2026-08-31T01:16:40Z`): `case_count=254`, `confirmed=125`, `qualified=86`, `provisional=43`.

The two duplicate classes to stop publishing are:

1. `alias-7a67e4c2cdfe7bc6ade411ee` (GHSA-723W / CVE-2026-74876)
2. `alias-bf499d08da8dae005eecbbc0` (GHSA-J48Q standalone row)

The two canonical classes remain. Therefore the exact net change is **`254 - 2 = 252`** cases. This conclusion is independent of any later decision to adjust the retained Whirlpool class's publication status while correcting its false fixed-release field.
