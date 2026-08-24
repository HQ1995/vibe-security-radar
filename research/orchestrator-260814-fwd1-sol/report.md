# Forward-map adjudication: slice 1

## Verdict

All 25 assigned rows are terminal `FALSE_POSITIVE` findings with class
`no_ai_origin`. No candidate AI commit creates, removes a guard from, copies,
or materially contributes to its assigned advisory mechanism. There are zero
`CONFIRM`, zero verdict-level `UNKNOWN`, and zero countable proposals.

The conclusion comes from reading the nine unique candidate diffs, not from
filename-only screening. Seven GeoServer rows share one 20-file WPS OpenAI
module diff, and eleven Dragonfly rows share one two-file documentation and
ignore-rule diff. Those shared candidates were read once in full and compared
separately with every advisory invariant.

## Gate disposition

For 24 rows the first-party advisory establishes repository, public identity,
and mechanism, so `identity_gate=PASS`. `GHSA-3J63-5H8P-GF7C` names the affected
x402 SDK packages and fixed versions but withholds the vulnerable behavior, so
its identity gate remains `UNKNOWN` under the fail-closed rule.

Every row has `ai_hunk_gate=FAIL` and `but_for_gate=FAIL`: the candidate's own
diff affirmatively contains no relevant vulnerable hunk, and deleting it leaves
the exact advisory mechanism unchanged. `topology_gate`, `fix_reversal_gate`,
`release_gate`, and `uniqueness_gate` remain `UNKNOWN`. The slice provides no
fix refs, and once the proposed causal edge is disproved, version-only metadata
is not used to invent fix ancestry or semantic uniqueness. These unknown
downstream gates do not make a false-positive verdict nonterminal.

| Gate | PASS | FAIL | UNKNOWN |
|---|---:|---:|---:|
| identity | 24 | 0 | 1 |
| AI hunk | 0 | 25 | 0 |
| topology | 0 | 0 | 25 |
| but-for | 0 | 25 | 0 |
| fix reversal | 0 | 0 | 25 |
| release | 0 | 0 | 25 |
| uniqueness | 0 | 0 | 25 |

## Candidate diff inventory

| Repository | AI candidate | AI evidence | Diff actually read | Assigned rows |
|---|---|---|---|---:|
| `strapi/strapi` | `a95ebca1` | Copilot SWE agent author | Empty commit; zero files and empty patch | 1 |
| `denoland/deno` | `9b2b1c41` | Copilot co-author trailer | Six files implementing cgroup-aware V8 heap limits | 1 |
| `geoserver/geoserver` | `c460d349` | Copilot co-author trailer | Twenty files creating the separate WPS OpenAI community module | 7 |
| `Anipaleja/nginx-defender` | `fbf7c826` | Copilot Autofix trailer | One JavaScript notification hunk replacing `innerHTML` with safe DOM construction | 1 |
| `coinbase/x402` | `efa7a7ff` | Cursor Agent trailer | Partner-site metadata, a logo, and a newline-only lockfile change | 1 |
| `runatlantis/atlantis` | `0fb41570` | Copilot co-author trailer | Pre-workflow-hook failure comments and tests | 1 |
| `angular/angular` | `b24fec72` | Gemini Code Assist trailer | Experimental forms proxy/types/validation documentation and tests | 1 |
| `igniterealtime/Openfire` | `b752bc2c` | Copilot co-author trailer | One Javadoc markup correction in `LocalSession.java` | 1 |
| `dragonflyoss/dragonfly` | `9aa047b9` | Copilot author and bot trailer | `.github/copilot-instructions.md` plus `bin/` in `.gitignore`; no Go source | 11 |

The frozen patch hashes are recorded in `result.json`. The Strapi patch hash is
the SHA-256 of an empty byte stream, corroborating the zero-file commit. The two
objects absent from their preexisting pools (nginx-defender and x402) were read
after exact-SHA Git smart-HTTP fetches into temporary repositories inside the
owned output directory. No GitHub API was used.

## Per-row adjudication

| # | Advisory mechanism | Diff comparison | Verdict |
|---:|---|---|---|
| 1 | `GHSA-V8WJ-F5C7-PVXF`: Strapi webhook URLs can target localhost/internal services. | `a95ebca1` has no diff at all. | `FALSE_POSITIVE / no_ai_origin` |
| 2 | `GHSA-JV4X-JV3H-QFF5`: static imports bypass Deno's network permission. | `9b2b1c41` only detects cgroup memory limits and configures V8 heap size. It never edits module loading or permissions. | `FALSE_POSITIVE / no_ai_origin` |
| 3 | `GHSA-5GW5-JCCF-6HXW`: unauthenticated `TestWfsPost` SSRF. | `c460d349` adds WPS OpenAI; it never touches the demo servlet, Proxy Base URL, or its outbound request path. | `FALSE_POSITIVE / no_ai_origin` |
| 4 | `GHSA-MC43-4FQR-C965`: permissive XML entity URI validation. | The new module registers an XStream settings type but never changes `PreventLocalEntityResolver`, `ENTITY_RESOLUTION_ALLOWLIST`, URI regexes, or schema resolution. | `FALSE_POSITIVE / no_ai_origin` |
| 5 | `GHSA-JM79-7XHW-6F6F`: public GWC home page leaks version, revision, paths, and runtime information. | The diff does not touch `GeoWebCacheDispatcher.handleFrontPage` or GWC output. Its new page is an admin settings page for a different module. | `FALSE_POSITIVE / no_ai_origin` |
| 6 | `GHSA-R4HF-R8GJ-JGW2`: Coverage REST URL upload omits `URLCheckers.confirm`. | No `RESTUtils`, Coverage REST, file URL, upload, or URL-checker hunk exists. | `FALSE_POSITIVE / no_ai_origin` |
| 7 | `GHSA-H86G-X8MM-78M5`: `/rest.html` bypasses REST index authorization. | No REST index handler, URL mapping, `security/config.xml`, or `/rest.*` filter is changed. | `FALSE_POSITIVE / no_ai_origin` |
| 8 | `GHSA-GR67-PWCV-76GF`: unbounded Jiffle loops cause DoS through WMS/WPS. | The OpenAI WPS process contains no Jiffle interpreter, loop construct, rendering transformation, or iteration limit. Sharing only the WPS umbrella is not causality. | `FALSE_POSITIVE / no_ai_origin` |
| 9 | `GHSA-68CF-J696-WVV9`: a specific-target `TestWfsPost` SSRF follow-on. | No `TestWfsPost` or request-target validation hunk exists. The separate OpenAI API client is not the named servlet surface. | `FALSE_POSITIVE / no_ai_origin` |
| 10 | `GHSA-PR72-8FXW-XX22`: deployment examples ship known default credentials. | `fbf7c826` fixes client-side XSS in `dashboard.js`; neither `config.yaml` nor `docker-compose.yml` changes. | `FALSE_POSITIVE / no_ai_origin` |
| 11 | `GHSA-3J63-5H8P-GF7C`: undisclosed x402 resource-server SDK flaw. | The advisory does not reveal the mechanism, but `efa7a7ff` changes only website partner metadata/logo plus a final newline. It cannot alter any named affected SDK runtime package. | `FALSE_POSITIVE / no_ai_origin`; identity `UNKNOWN` |
| 12 | `GHSA-XH7V-965R-23F7`: unauthenticated Atlantis `/status` exposes version/build data. | `0fb41570` comments pre-workflow-hook failures on pull requests and never touches `/status`, health output, versions, or authentication. | `FALSE_POSITIVE / no_ai_origin` |
| 13 | `GHSA-68X2-MX4Q-78M7`: Angular SSR global platform injector races across requests. | `b24fec72` is confined to experimental forms; it never changes platform-server, SSR, bootstrap context, or injector lifetime. | `FALSE_POSITIVE / no_ai_origin` |
| 14 | `GHSA-W252-645G-87MP`: regex parsing of an unescaped certificate DN permits CN spoofing. | `b752bc2c` changes one Javadoc tag in `LocalSession.java`; `CNCertificateIdentityMapping` and all certificate parsing are untouched. | `FALSE_POSITIVE / no_ai_origin` |
| 15 | `GHSA-89VC-VF32-CH59`: Manager job/preheat endpoints lack authentication. | `9aa047b9` has no Go source and cannot change API middleware or handlers. | `FALSE_POSITIVE / no_ai_origin` |
| 16 | `GHSA-G2RQ-JV54-WCPR`: Manager, peer-source, and redirect SSRF paths. | The documentation/ignore diff contains no URL parsing, client, redirect, preheat, or `DownloadSource` logic. | `FALSE_POSITIVE / no_ai_origin` |
| 17 | `GHSA-98X5-JW98-6C97`: Manager HTTP clients disable TLS verification. | No `tls.Config`, `InsecureSkipVerify`, Manager client, or HTTP transport changes. | `FALSE_POSITIVE / no_ai_origin` |
| 18 | `GHSA-2QGR-GFVJ-QPCR`: stale `n` guard prevents `usedTraffic` accounting. | No task processing, `result.Size`, `n`, `AddTraffic`, or rate-limit hunk exists. | `FALSE_POSITIVE / no_ai_origin` |
| 19 | `GHSA-8425-8R2F-MRV6`: `os.MkdirAll` trusts permissions on preexisting directories. | No runtime directory creation or permission validation changes; the `.gitignore` addition is unrelated. | `FALSE_POSITIVE / no_ai_origin` |
| 20 | `GHSA-C2FC-9Q9C-5486`: Proxy basic-auth uses timing-sensitive string equality. | No authentication or comparison source changes. | `FALSE_POSITIVE / no_ai_origin` |
| 21 | `GHSA-4MHV-8RH3-4GHW`: error branches dereference a possibly nil return value. | No Go error path, request constructor, or dereference changes. | `FALSE_POSITIVE / no_ai_origin` |
| 22 | `GHSA-79HX-3FP8-HJ66`: peer APIs enable arbitrary-path file read/write. | No peer server, path, `DataFilePath`, `os.OpenFile`, `Seek`, or `io.Copy` hunk exists. | `FALSE_POSITIVE / no_ai_origin` |
| 23 | `GHSA-255V-QV84-29P5`: Manager signs CSR IPs not bound to the requesting peer. | No certificate service, CSR, IP, peer address, or mTLS code changes. | `FALSE_POSITIVE / no_ai_origin` |
| 24 | `GHSA-HX2H-VJW2-8R54`: MD5-derived piece integrity lacks collision resistance. | No digest, MD5, `PieceMd5Sign`, piece metadata, or integrity check changes. | `FALSE_POSITIVE / no_ai_origin` |
| 25 | `GHSA-MCVP-RPGG-9273`: tiny-file downloads hard-code plaintext HTTP. | No `DownloadTinyFile`, URL construction, HTTP scheme, peer request, or transport-security hunk exists. | `FALSE_POSITIVE / no_ai_origin` |

## Detailed shared-candidate checks

### GeoServer

The complete `c460d349` diff contains 20 paths, not merely the eight paths
summarized in the input row. It creates `src/community/wps-openai`, its POM,
settings persistence, encrypted API-key UI, Caffeine session cache,
`OpenAIProcess`, Spring beans, documentation, images, and tests. The process
sends prompts to OpenAI, converts generated ECQL to GeoJSON, and optionally
returns features. None of those hunks creates any of the seven assigned legacy
mechanisms. In particular:

- an XStream settings initializer is not XML external-entity resolution;
- an admin Wicket page is not the public GWC or REST index;
- a new OpenAI WPS process is not the Jiffle interpreter;
- an outbound OpenAI API call is not either `TestWfsPost` or Coverage REST URL
  upload.

This is an exact-boundary decision. The candidate may warrant separate review
for its own surfaces, but unrelated potential issues cannot be substituted for
the assigned advisories.

### Dragonfly

The entire `9aa047b9` patch is a new 178-line contributor-instruction document
and two `.gitignore` lines excluding `bin/`. There is no Go source delta. This
single observation is independently dispositive for all eleven assigned
runtime mechanisms: removing the candidate changes none of their request
handlers, clients, task accounting, filesystem operations, authentication,
certificate issuance, digests, or peer download transports.

## Evidence commands

All Git commands were bounded to 30 seconds. These commands read commit objects
and diffs only; no blame, SZZ, or GitHub API command was used.

```sh
timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/strapi__strapi \
  show --format=fuller --stat a95ebca14760790323d0a09bf601a30c8560b8ac
timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/strapi__strapi \
  show --format= --no-ext-diff --no-color a95ebca14760790323d0a09bf601a30c8560b8ac

timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/denoland__deno \
  show --format= --no-ext-diff --no-color 9b2b1c41f53faeff8c8707bec3ed23d02661601c

timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/geoserver__geoserver \
  show --format= --no-ext-diff --no-color c460d3498f75fed31a5130baa117a3a9b571e855

timeout 30s git -C autoresearch/orchestrator-260814-fwd1-sol/.replay-nginx init --bare
timeout 30s git -C autoresearch/orchestrator-260814-fwd1-sol/.replay-nginx \
  fetch --filter=blob:none --depth=2 https://github.com/Anipaleja/nginx-defender.git \
  fbf7c826abdbd9b8aed63a710dc0a40d47b61509
timeout 30s git -C autoresearch/orchestrator-260814-fwd1-sol/.replay-nginx \
  show --format= --no-ext-diff --no-color fbf7c826abdbd9b8aed63a710dc0a40d47b61509

timeout 30s git -C autoresearch/orchestrator-260814-fwd1-sol/.replay-x402 init --bare
timeout 30s git -C autoresearch/orchestrator-260814-fwd1-sol/.replay-x402 \
  fetch --filter=blob:none --depth=2 https://github.com/coinbase/x402.git \
  efa7a7ff3b3cac929f39bb403c14a15afb773a86
timeout 30s git -C autoresearch/orchestrator-260814-fwd1-sol/.replay-x402 \
  show --format= --no-ext-diff --no-color efa7a7ff3b3cac929f39bb403c14a15afb773a86

timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/runatlantis__atlantis \
  show --format= --no-ext-diff --no-color 0fb41570b5b0acfb41109dbf6e0fd3d1a2ef1daf
timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/angular__angular \
  show --format= --no-ext-diff --no-color b24fec7215f82eec0870ed8e3a4747195d60b382
timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/igniterealtime__Openfire \
  show --format= --no-ext-diff --no-color b752bc2caeaaad151e18fe0e3cf463b75c13380b
timeout 30s git -C /home/hanqing/.cache/ghsa200-sweep-fetch/dragonflyoss__dragonfly \
  show --format= --no-ext-diff --no-color 9aa047b994f74afb9a35b9eea77a709a90403eb5
```

The first-party advisory objects are the 25 exact paths recorded in
`cases.jsonl`; each object was read in full from the local `commit-gn`
advisory-database clone at `a42c436870111aa3f221257c9d56126a93173ccc`.

## Controls and limitations

- `FWD-SPEC.md` SHA-256: `672c45d1f98054a597ce12aa0879daa00b884d9207884e9a10e23c0fdc2d5750`.
- Input SHA-256: `203bd9f8b852a7c27b09ab5a381e9a89af07259abb69a22db9b38f8f5bde3ff7`.
- `CONTRACT.md` SHA-256: `cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3`.
- Candidate AI identities were verified from commit author/trailer metadata;
  authorship was not transferred across commits.
- No fix SHA was guessed from an affected/fixed version range. Consequently,
  unresolved downstream gates remain `UNKNOWN`, not `FAIL`.
- The frozen canonical ledger has no exact public-ID match for these 25 rows,
  but exact-ID absence is not semantic uniqueness proof, so uniqueness remains
  `UNKNOWN`.
- No ledger, web, script, tracked source file, or other worker directory was
  edited. No commit or push was performed.
