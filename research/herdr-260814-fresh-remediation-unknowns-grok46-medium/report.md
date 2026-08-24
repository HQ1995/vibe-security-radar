# Fresh incomplete-remediation UNKNOWN/BLOCKED close

Verdict first: **0 PASS**. Assigned **14** (9 UNKNOWN + 5 BLOCKED from the source screen packet). Fully closed **13 REJECT**. Remaining **1 UNKNOWN**. AI prior-attempt hits **0**. Packet delta **0**. Canonical84 stays **84**. Publication and more-than-200 remain **HOLD**. Worker PASS is a proposal only and is not issued.

This lane requires an AI-authored commit that explicitly attempted a security guard, a vulnerable release that contained that attempt, and a later exact closer of the same residual bypass. Ordinary vulnerable feature origins are out of lane. Fully closed source-packet REJECT rows were not reopened.

## Sources (read-only)

- Canonical84 ledger sha256 `a9b23a7ca39104f851b684a4089fa58f43887bb895379b68f6306c47d969ec06`
- Canonical84 summary sha256 `6dd6386e1fc8f15638ee7fac9bc6c934ac8677351b74d5205fbd9f87ad05879a`
- Canonical84 manifest sha256 `a4b930757e97a3ecaa76fde28a0ee37ebd851717bc0eb214d42fb6292fc00bec`
- Source candidates.jsonl sha256 `8d63832351b4e1c32a575516230bc8a4088460b65dda3f64946df1bee08d6d54`
- Advisory cache `/home/hanqing/.cache/cve-analyzer/advisory-database` git HEAD `39d8887723797efc1804585dd06585c9fd751226` (read-only).
- Temporary blobless clones under owned `work/clones/` used `--reference` caches where present, then removed before finish.
- GitHub REST was not used. Canonical ledger was not edited.

## Conservation

14 assigned = 13 REJECT + 1 UNKNOWN + 0 BLOCKED + 0 PASS. Equation `14=13+1+0+0`. Did not pad. Did not backfill. Did not reopen the source fully-closed 10.

## Seven gates

identity, exact AI hunk authorship of the prior security attempt, topology/atomic member, but-for, exact minimum-fix reversal, vulnerable+fixed release containment, uniqueness versus canonical84.

## Closed REJECT

| ID | Repository | Prior (human) | Closer | Release gate |
|---|---|---|---|---|
| GHSA-JR45-52CW-69H5 | nl-portal/nl-portal-backend-libraries | `32e0ebdf173f` | `6e738a876ff9` | UNKNOWN |
| GHSA-F48W-9M4C-M7F5 | withastro/astro | `add3df10fdaf` | `5240e26c9dd9` | UNKNOWN |
| GHSA-QCM7-3VPR-HJ5H | adonisjs/bodyparser | `2515698a5389` | `8a85eb0c2061` | PASS |
| GHSA-3775-99MW-8RP4 | argoproj/argo-workflows | `4cac12c75de7` | `2727f3f70167` | PASS |
| GHSA-CG7W-RG45-PC59 | pydantic/pydantic-ai | `e64d2bf82839` | `1add06179ba4` | PASS |
| GHSA-J3FJ-QPPJ-FMMC | axllent/mailpit | `1679a0aba592` | `04c779994bb0` | PASS |
| GHSA-J6FM-9RFM-J5HX | froxlor/froxlor | `b34829262dc3` | `3dceec4650e0` | PASS |
| GHSA-X6QJ-4H56-5RJ5 | nuxt/nuxt | `9c5d0e457fc6` | `77187ee4015e` | PASS |
| GHSA-6QVR-WJMV-V8MM | koel/koel | `8708f077efd7` | `5f6ce2cefd08` | PASS |
| GHSA-7V6W-C3F4-9WPQ | openremote/openremote | `45a728ab45ea` | `c28d3c60ebc2` | UNKNOWN |
| GHSA-FXJ4-P9XP-37V5 | hapifhir/org.hl7.fhir.core | `e4aa38e4680a` | `56376f798622` | PASS |
| GHSA-HCJJ-CHVW-FMW9 | admidio/admidio | `f6b7a966abe4` | `d39915697e6e` | PASS |
| GHSA-VG6X-6PG9-6QWG | ArcadeData/arcadedb | `04110c06315d` | `2ee76fe442b9` | UNKNOWN |

### GHSA-JR45-52CW-69H5 REJECT

Document GraphQL content query residual after human auth-parameter attempt 32e0ebdf.

Original vulnerability: `CVE-2026-49463` / `GHSA-QPM9-H556-MWXM`. Prior attempt `32e0ebdf173f9684b2d48785aac0580104f93f0e` by Tom Bokma <tom.bokma@ritense.com>. AI marker: none. Advisory sha256 `32009702b1160917edfd8ca9d207bd3d204e2d632b05401f2fd50708427b496a`.

Local clone has no git tags containing prior 32e0ebdf or closer 6e738a876ff9. GitHub Releases were not queried.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 32e0ebdf173f author Tom Bokma <tom.bokma@ritense.com> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer removes the insecure GraphQL document-content query on the same DocumentContentQuery.kt path. Secondary closer e326e6db862f changes upload/download handling.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/nl-portal/nl-portal-backend-libraries.git work/clones/nl-portal__nl-portal-backend-libraries`
- `git -C work/clones/nl-portal__nl-portal-backend-libraries log -1 --format=%H%n%an%n%s%n%B 32e0ebdf173f9684b2d48785aac0580104f93f0e`
- `git -C work/clones/nl-portal__nl-portal-backend-libraries merge-base --is-ancestor 32e0ebdf173f9684b2d48785aac0580104f93f0e 6e738a876ff9f581991b5b070706100b5516e183`
- `git -C work/clones/nl-portal__nl-portal-backend-libraries tag --contains 32e0ebdf173f9684b2d48785aac0580104f93f0e`

### GHSA-F48W-9M4C-M7F5 REJECT

Custom-element SSR attribute-name XSS residual after human addAttribute harden add3df10fdaf.

Original vulnerability: `CVE-2026-54298` / `GHSA-JRPJ-WCV7-9FH9`. Prior attempt `add3df10fdaff469ae0228f09d99290de170029a` by Matthew Phillips <matthewphillips@cloudflare.com>. AI marker: none. Advisory sha256 `cafe284c22d66062b15622c11bc29d725c00fef14f59bcc72de08e5b0a75ce8b`.

Tag astro@6.4.6 contains prior add3df10fdaf and not closer 5240e26c9dd9. Closer has no containing tags in this clone.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt add3df10fdaf author Matthew Phillips <matthewphillips@cloudflare.com> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer validates attribute names on custom HTML elements during SSR on the same addAttribute/spread path.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/withastro/astro.git work/clones/withastro__astro`
- `git -C work/clones/withastro__astro log -1 --format=%H%n%an%n%s  add3df10fdaff469ae0228f09d99290de170029a`
- `git -C work/clones/withastro__astro merge-base --is-ancestor add3df10fdaff469ae0228f09d99290de170029a 5240e26c9dd91f9bc7140dcfacdb48d5a132830d`
- `git -C work/clones/withastro__astro tag --contains add3df10fdaff469ae0228f09d99290de170029a`

### GHSA-QCM7-3VPR-HJ5H REJECT

Nested multipart prototype-pollution residual after human field-name guard 2515698a5389 on the 10.1.x line.

Original vulnerability: `CVE-2026-25754` / `GHSA-F5X2-VJ4H-VG4C`. Prior attempt `2515698a53899b8c761d43ac342d6a6271c852ad` by Romain Lanz <romain.lanz@pm.me>. AI marker: none. Advisory sha256 `e8c562f5e709e89ff5af805a08876078edb56afead29200c2c0ab582fc6aafaa`.

Tags v10.1.3 and v10.1.4 contain prior 2515698a5389 and not closer 8a85eb0c2061. Closer is in v10.1.5. Advisory-named 40e1c71f958c is the v11 counterpart and is not an ancestor of 8a85eb0c2061.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 2515698a5389 author Romain Lanz <romain.lanz@pm.me> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer blocks nested __proto__ segments after a non-dangerous prefix on the same multipart FormFields path.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/adonisjs/bodyparser.git work/clones/adonisjs__bodyparser`
- `git -C work/clones/adonisjs__bodyparser fetch --filter=blob:none origin refs/tags/v10.1.3:refs/tags/v10.1.3 refs/tags/v10.1.5:refs/tags/v10.1.5`
- `git -C work/clones/adonisjs__bodyparser merge-base --is-ancestor 2515698a53899b8c761d43ac342d6a6271c852ad 8a85eb0c2061b0caca10faedbfc2cf24b56cf9f6`
- `git -C work/clones/adonisjs__bodyparser merge-base --is-ancestor 40e1c71f958cffb74f6b91bed6630dca979062ed 8a85eb0c2061b0caca10faedbfc2cf24b56cf9f6`

### GHSA-3775-99MW-8RP4 REJECT

WorkflowSpec field allow-list residual after human podSpecPatch deny 4cac12c75de7.

Original vulnerability: `CVE-2026-31892` / `GHSA-3WF5-G532-RCRR`. Prior attempt `4cac12c75de720889ad2cae8a6cc63c566b1d8d8` by Alan Clucas <alan@clucas.org>. AI marker: none. Advisory sha256 `9ed5fc9882606564899f98f80ba000ca2279397618536ef6ef877c3b7eaf8177`.

Tag v4.0.2 contains prior 4cac12c75de7 and not closer 2727f3f70167. Closer is in v4.0.5. Closer atomic message carries Co-authored-by Claude Opus 4.6; the prior attempt does not.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 4cac12c75de7 author Alan Clucas <alan@clucas.org> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer replaces the single podSpecPatch deny-check with allow-list validation. AI trailer is on the closer, not the prior security attempt. Incomplete-remediation eligibility requires AI authorship of the prior attempt. Closer 2727f3f70167 carries Co-authored-by Claude Opus 4.6 <noreply@anthropic.com>. That is the residual closer, not the prior security attempt.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/argoproj/argo-workflows.git work/clones/argoproj__argo-workflows`
- `git -C work/clones/argoproj__argo-workflows log -1 --format=%B 4cac12c75de720889ad2cae8a6cc63c566b1d8d8`
- `git -C work/clones/argoproj__argo-workflows log -1 --format=%B 2727f3f701677d467dfb5e053c57237cbc752c3c`
- `git -C work/clones/argoproj__argo-workflows merge-base --is-ancestor 4cac12c75de720889ad2cae8a6cc63c566b1d8d8 2727f3f701677d467dfb5e053c57237cbc752c3c`

### GHSA-CG7W-RG45-PC59 REJECT

Expanded IPv6 transition-form SSRF residual after human normalize commit e64d2bf82839.

Original vulnerability: `CVE-2026-46678` / `GHSA-CQP8-FCVH-X7R3`. Prior attempt `e64d2bf82839a02d4fad98736ff9a87fdb5bf1ca` by Douwe Maan <douwe@pydantic.dev>. AI marker: none. Advisory sha256 `13876e09bd7eb995224a4c39f7846ed3e3c69ba3ccf84249400953a634ab876d`.

Tag v1.99.0 contains prior e64d2bf82839 and not closer 1add06179ba4. Closer is in v1.102.0. Immediate prior is the GHSA-cqp8 IPv6-normalize attempt, not the older GHSA-2jrp origin.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt e64d2bf82839 author Douwe Maan <douwe@pydantic.dev> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer expands IPv6 transition-form handling on the same URL validation blocklist.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/pydantic/pydantic-ai.git work/clones/pydantic__pydantic-ai`
- `git -C work/clones/pydantic__pydantic-ai merge-base --is-ancestor e64d2bf82839a02d4fad98736ff9a87fdb5bf1ca 1add06179ba4de259f7ab977620b697b7209f7e4`
- `git -C work/clones/pydantic__pydantic-ai tag --contains e64d2bf82839a02d4fad98736ff9a87fdb5bf1ca`
- `git -C work/clones/pydantic__pydantic-ai tag --contains 1add06179ba4de259f7ab977620b697b7209f7e4`

### GHSA-J3FJ-QPPJ-FMMC REJECT

HTML-check SSRF to private/loopback/IMDS residual after human GHSA-6jxm commit 1679a0aba592.

Original vulnerability: `CVE-2026-23845` / `GHSA-6JXM-FV7W-RW5J`. Prior attempt `1679a0aba592ebc8487a996d37fea8318c984dfe` by Ralph Slooten <axllent@gmail.com>. AI marker: none. Advisory sha256 `04a80f7b34f65a0d2952b192325249306e68b633bc8a6ab051cfbb26fcbf5f34`.

Tag v1.28.3 contains prior 1679a0aba592 and not closer 04c779994bb0. Closer is in v1.30.0.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 1679a0aba592 author Ralph Slooten <axllent@gmail.com> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer adds an internal-IP blocking dialer on the same HTML-check download path.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/axllent/mailpit.git work/clones/axllent__mailpit`
- `git -C work/clones/axllent__mailpit merge-base --is-ancestor 1679a0aba592ebc8487a996d37fea8318c984dfe 04c779994bb0168350fd246cb6a6b901b85db7af`
- `git -C work/clones/axllent__mailpit tag --contains 1679a0aba592ebc8487a996d37fea8318c984dfe`

### GHSA-J6FM-9RFM-J5HX REJECT

DNS LOC regex / control-character residual after human DomainZones content validation b34829262dc3.

Original vulnerability: `CVE-2026-30932` / `GHSA-X6W6-2XWP-3JH6`. Prior attempt `b34829262dc32818b37f6a1eabb426d0b277a86b` by Michael Kaufmann <d00p@froxlor.org>. AI marker: none. Advisory sha256 `a81e52f9608c23c8ee53c6d7d46bf06c289c9e88a2f07cabcf3222309897a896`.

Tag 2.3.5 contains prior b34829262dc3 and not closer 3dceec4650e0. Closer is in 2.3.7. Advisory listed b34829262dc3 as the current fix SHA; that SHA is the prior attempt, not the residual closer.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt b34829262dc3 author Michael Kaufmann <d00p@froxlor.org> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer tightens LOC regex and strips control characters on the same DNS content-field path.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/froxlor/Froxlor.git work/clones/froxlor__froxlor`
- `git -C work/clones/froxlor__froxlor merge-base --is-ancestor b34829262dc32818b37f6a1eabb426d0b277a86b 3dceec4650e071b86e068b8cdfd1de74cc73d368`
- `git -C work/clones/froxlor__froxlor tag --contains b34829262dc32818b37f6a1eabb426d0b277a86b`

### GHSA-X6QJ-4H56-5RJ5 REJECT

Missing same-origin header loopback residual after human #35051 extract 9c5d0e457fc6 on the 3.21 line.

Original vulnerability: `CVE-2026-45670` / `GHSA-6M52-M754-PW2G`. Prior attempt `9c5d0e457fc6bb10dec7eb3648a5f614f76580f2` by Daniel Roe <daniel@roe.dev>. AI marker: none. Advisory sha256 `238fc99875afafa7a92066fabb86b1711f3e7d162eb54655cfde7106e0c829fe`.

Tag v3.21.6 contains prior 9c5d0e457fc6 and not closer 77187ee4015e. Closer is in v3.21.7. Main-line SHA e763cc34592a (#35051) is not an ancestor of 77187ee4015e.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 9c5d0e457fc6 author Daniel Roe <daniel@roe.dev> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer requires a loopback host when same-origin signals are missing on the same webpack/rspack dev middleware.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/nuxt/nuxt.git work/clones/nuxt__nuxt`
- `git -C work/clones/nuxt__nuxt fetch --filter=blob:none origin refs/tags/v3.21.6:refs/tags/v3.21.6 refs/tags/v3.21.7:refs/tags/v3.21.7`
- `git -C work/clones/nuxt__nuxt merge-base --is-ancestor 9c5d0e457fc6bb10dec7eb3648a5f614f76580f2 77187ee4015e9267fb464951542a3e09e8b5fa05`

### GHSA-6QVR-WJMV-V8MM REJECT

DNS-rebinding / IPv6-transition SSRF residual after human GHSA-7j2f URL validation 8708f077efd7.

Original vulnerability: `CVE-2026-47260` / `GHSA-7J2F-6H2R-6CQC`. Prior attempt `8708f077efd7d8a332b32e954d65bc837f3a413a` by Phan An <me@phanan.net>. AI marker: none. Advisory sha256 `920f623fc9327569b46ba2a21b809ea773677936617d72b0c3570b85911ba6bd`.

Tag v9.3.5 contains prior 8708f077efd7 and not closer 5f6ce2cefd08. Closer is in v9.7.1.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 8708f077efd7 author Phan An <me@phanan.net> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer names remaining SSRF advisories on the same URL-validation surface.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/koel/koel.git work/clones/koel__koel`
- `git -C work/clones/koel__koel fetch --filter=blob:none origin refs/tags/v9.3.5:refs/tags/v9.3.5 refs/tags/v9.7.1:refs/tags/v9.7.1`
- `git -C work/clones/koel__koel merge-base --is-ancestor 8708f077efd7d8a332b32e954d65bc837f3a413a 5f6ce2cefd08f437a269236b677ad971517ccbb6`

### GHSA-7V6W-C3F4-9WPQ REJECT

KNX asset-import XXE residual after human Velbus createSecureDocumentBuilderFactory attempt 45a728ab45ea.

Original vulnerability: `CVE-2026-40882` / `GHSA-G24F-MGC3-JWWC`. Prior attempt `45a728ab45eac2e78004603748d7398e4c63544f` by Eric Bariaux <375613+ebariaux@users.noreply.github.com>. AI marker: none. Advisory sha256 `56541bf231d9443c7a1b5d15e7a33f3cc5580df9f2954ddc3306070b90166cef`.

Tag 1.22.0 contains prior 45a728ab45ea (Velbus XXE harden) and not closer c28d3c60ebc2. Closer has no containing tags in this clone.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 45a728ab45ea author Eric Bariaux <375613+ebariaux@users.noreply.github.com> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Advisory states the Velbus handler was patched and KNXProtocol retained unprotected XMLInputFactory. Closer hardens KNX import. Both atomic messages are human merge-from-fork with no AI trailer.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/openremote/openremote.git work/clones/openremote__openremote`
- `git -C work/clones/openremote__openremote diff-tree --no-commit-id --name-only -r 45a728ab45eac2e78004603748d7398e4c63544f`
- `git -C work/clones/openremote__openremote diff-tree --no-commit-id --name-only -r c28d3c60ebc2da68d9b6c4a6d7a5ad875a255ee9`
- `git -C work/clones/openremote__openremote merge-base --is-ancestor 45a728ab45eac2e78004603748d7398e4c63544f c28d3c60ebc2da68d9b6c4a6d7a5ad875a255ee9`

### GHSA-FXJ4-P9XP-37V5 REJECT

dstu2 funcMatches ReDoS residual after human RegexTimeout wiring e4aa38e4680a.

Original vulnerability: `CVE-2026-45367` / `GHSA-3653-68V6-RQ57`. Prior attempt `e4aa38e4680a176e4c0c48ff32c1aadbd06641ed` by dotasek <david.otasek@smilecdr.com>. AI marker: none. Advisory sha256 `d401da086685d0ac2a55e5eac70b762c7cf9521c9534a478a295c004a87688bd`.

Tag 6.9.7 contains prior e4aa38e4680a and not closer 56376f798622. Closer is in 6.9.10.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt e4aa38e4680a author dotasek <david.otasek@smilecdr.com> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer adds RegexTimeout to dstu2 funcMatches on the same FHIRPathEngine regex path.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/hapifhir/org.hl7.fhir.core.git work/clones/hapifhir__org.hl7.fhir.core`
- `git -C work/clones/hapifhir__org.hl7.fhir.core merge-base --is-ancestor e4aa38e4680a176e4c0c48ff32c1aadbd06641ed 56376f7986222626af061ca7fc27ee1ab030e590`
- `git -C work/clones/hapifhir__org.hl7.fhir.core tag --contains e4aa38e4680a176e4c0c48ff32c1aadbd06641ed`

### GHSA-HCJJ-CHVW-FMW9 REJECT

SSO metadata fetch host-bind SSRF residual after human HTTPS/cURL restrict f6b7a966abe4.

Original vulnerability: `CVE-2026-32812` / `GHSA-6J68-GCC3-MQ73`. Prior attempt `f6b7a966abe4d75e9f707d665d7b4b5570e3185a` by Markus Fassbender <markus.fassbender@gmail.com>. AI marker: none. Advisory sha256 `ba4c56d882f9f7e69bd06b473f92f28ee7d537c0eac792db0250ed5d7af7df8f`.

Tag v5.0.7 contains prior f6b7a966abe4 and not closer d39915697e6e. Closer is in v5.0.9. Both touch modules/sso/fetch_metadata.php.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release PASS; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt f6b7a966abe4 author Markus Fassbender <markus.fassbender@gmail.com> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer binds the fetch host to a resolved IP on the same fetch_metadata.php endpoint. Author name ASCII-folded from the git header.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/Admidio/admidio.git work/clones/Admidio__admidio`
- `git -C work/clones/Admidio__admidio log -1 --format=%B f6b7a966abe4d75e9f707d665d7b4b5570e3185a`
- `git -C work/clones/Admidio__admidio merge-base --is-ancestor f6b7a966abe4d75e9f707d665d7b4b5570e3185a d39915697e6e0be04d02d55a46c631f53013aea6`
- `git -C work/clones/Admidio__admidio diff-tree --no-commit-id --name-only -r f6b7a966abe4d75e9f707d665d7b4b5570e3185a`

### GHSA-VG6X-6PG9-6QWG REJECT

Schema-mutator permission residual after human HTTP per-database access attempt 04110c06315d.

Original vulnerability: `CVE-2026-44221` / `GHSA-FXC7-FM93-6Q77`. Prior attempt `04110c06315da55604ac107f71fe7182f3a3deb8` by Luca Garulli <lvca@users.noreply.github.com>. AI marker: none. Advisory sha256 `0cc4da0fed8ab947a4c35e31baa16d8bb6644cdf0ccfccc255f71b3ae4523a66`.

Tag 26.6.1 contains both prior 04110c06315d and closer 2ee76fe442b9. No residual tag interval was proved.

Gates: identity PASS; ai_hunk FAIL; topology PASS; but_for UNKNOWN; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS; patch-delta UNKNOWN.

Counterevidence: Prior attempt 04110c06315d author Luca Garulli <lvca@users.noreply.github.com> has no AI trailer. But-for, exact-reversal, and patch-delta were not closed in this packet and stay UNKNOWN. Closer requires UPDATE_SCHEMA on schema mutators after the HTTP access-map attempt. First file-log chore d5463d51 was not used as the closer.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/ArcadeData/arcadedb.git work/clones/ArcadeData__arcadedb`
- `git -C work/clones/ArcadeData__arcadedb merge-base --is-ancestor 04110c06315da55604ac107f71fe7182f3a3deb8 2ee76fe442b974b2482f1e9eddd1ab429bcac614`
- `git -C work/clones/ArcadeData__arcadedb tag --contains 04110c06315da55604ac107f71fe7182f3a3deb8`
- `git -C work/clones/ArcadeData__arcadedb tag --contains 2ee76fe442b974b2482f1e9eddd1ab429bcac614`

## Remaining UNKNOWN

### GHSA-8Q5W-MMXF-48JG UNKNOWN

XSS residual after GHSA-4663; distinct prior-versus-closer pair not recovered.

Advisory closer SHA b382f50e1880 names GHSA-v3mg, not this residual. Distinct first-party closer for GHSA-8q5w was not recovered. Tag v3.6.4 fetch failed on missing promisor objects.

Gates: identity PASS; ai_hunk UNKNOWN; topology UNKNOWN; but_for UNKNOWN; fix_reversal UNKNOWN; release UNKNOWN; uniqueness PASS; patch-delta UNKNOWN.

Commands:

- `git clone --filter=blob:none --no-tags https://github.com/siyuan-note/siyuan.git work/clones/siyuan-note__siyuan`
- `git -C work/clones/siyuan-note__siyuan log -1 --format=%H%n%s%n%B b382f50e1880ed996364509de5a10a72d7409428`
- `git -C work/clones/siyuan-note__siyuan fetch --filter=blob:none origin refs/tags/v3.6.4:refs/tags/v3.6.4`

## Count boundary

Assigned 14 = 13 REJECT + 1 UNKNOWN. No PASS proposals. Canonical ledger was not edited. Owned temporary clones were removed.
