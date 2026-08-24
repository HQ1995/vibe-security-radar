# SoK: AI-Contributed Vulnerabilities with CVE/GHSA IDs

- **Research freeze:** 2026-08-09
- **Study window:** 2025-05-01 through 2026-08-09
- **Status:** COMPLETE UNDER THE FROZEN PROTOCOL
- **Population unit:** CVE/GHSA alias class
- **Corpus:** 40 verified alias classes (35 with a CVE, 32 with a GHSA)
- **Corpus SHA-256:** `cb94d06a9d4073f6a18b3e48151951ad2b56141477260c10d2970355297859da`

## Abstract

This Systematization of Knowledge (SoK) studies publicly disclosed vulnerabilities for which a real CVE or GHSA identifier and public evidence connect an AI coding system to code that contributed to the vulnerability. We union five complementary retrieval lanes: an official-advisory census, advisory-to-history tracing, reverse AI-commit-to-advisory linkage, public-web and literature snowballing, and searches over known AI-tool identities. The frozen official universe contains 84,798 CVE/GHSA alias classes and 159,714 eligible source records; 5,789 records without usable dates remain explicitly blocked rather than silently discarded. Case-level causal adjudication yields a strict lower-bound corpus of 40 verified classes, including 36 grade-A and 4 grade-B cases. Access-control and injection failures account for 25/40 (62.5%), while missing guards and unsafe interpolation account for 21/40 (52.5%). The corpus is evidence of disclosed, publicly attributable cases—not an estimate of AI-code vulnerability prevalence or a claim that every real-world case is observable.

## Scope and research questions

We define an **AI-contributed vulnerability** as a numbered vulnerability in which public evidence shows that an AI coding tool authored, co-authored, autonomously generated, or causally extended code needed for the vulnerable behavior. AI-assisted vulnerability discovery, an AI product merely being vulnerable, runtime generation of attacker-controlled content, AI-written fixes, translations, and release-carrier commits do not satisfy this definition.

The study asks:

1. **RQ1—Observed corpus:** Which CVE/GHSA alias classes published in the study window have public AI-attribution plus case-level causal evidence?
2. **RQ2—Contribution:** How did AI participate: direct generation, assistant co-authorship, autonomous generation, indirect causal extension, or mixed/squashed work?
3. **RQ3—Failure structure:** Which vulnerability families and AI-specific implementation failures recur?
4. **RQ4—Observability:** Which evidence sources recover cases, and which blind spots prevent a perfect-recall claim?

### Inclusion contract

Every included alias class satisfies all four conditions:

1. publication date is between 2025-05-01 and 2026-08-09 inclusive;
2. at least one identifier is a CVE or GHSA;
3. public evidence binds a named AI coding system to a relevant change or generated component; and
4. case-level evidence shows how that AI-attributed contribution participates in the vulnerable behavior.

OSV-only, RUSTSEC-only, vendor-only, unnumbered bug reports, AI-assisted discoveries, and speculative authorship are excluded. Aliases are collapsed before counting, so a CVE and its GHSA count once.

## Systematic-search protocol

### Sources and normalization

We froze [CVE List V5](https://github.com/CVEProject/cvelistV5), the [GitHub Advisory Database](https://github.com/github/advisory-database), [NVD](https://nvd.nist.gov/vuln), and [OSV](https://osv.dev/) inputs. CVE/GHSA identifiers, references, repository identities, publication dates, and aliases were normalized into 84,798 alias classes. The 5,789 source records lacking a usable date are retained as `BLOCKED`; they are not treated as screened negatives.

### Recall-oriented union of retrieval lanes

No single signal is sufficient. Advisory text rarely records code authorship, commit trailers disappear under squash merges, AI identities vary, and closed generators may have no inspectable Git history. We therefore take the union of five differently biased lanes and adjudicate the union:

| Lane | Frozen input | Result | Local evidence |
|---|---|---|---|
| Official Advisory Census | CVE List V5 plus GitHub Advisory Database | 84798 alias classes; 5789 date-missing records retained as BLOCKED | [summary.json](../research/orchestrator-260809-0539/current-official-census/summary.json) |
| Advisory To Repository History | 111855 public fix references and 37390 full-SHA roots | 10850 local fix roots; 515461 conserved AI-attributed ancestry edges; missing history remains BLOCKED or DEFER | [summary.json](../research/orchestrator-260809-0539/current-advisory-candidates/summary.json) |
| Ai Commit To Advisory Reverse Linkage | 434422 public AI-attributed repository commits | 28 exact OSV introduced-SHA intersections screened by deepseek-v4-flash: 2 HIGH, 2 MEDIUM, 24 LOW; Ciguard/Mail-MCP/Mysti included, Termix carrier excluded, no unresolved HIGH | [deepseek-osv-introduced-screen.json](../research/orchestrator-260809-1127/deepseek-osv-introduced-screen.json) |
| Public Web And Literature Snowballing | six frozen query families over public CVE/GHSA, tool-attribution and AI-generated-code language | CVE-2025-48757/GHSA-773X-PXJG-GXGX added at evidence grade B; supplier dispute preserved | [web-literature-adjudications.json](../research/orchestrator-260809-1127/web-literature-adjudications.json) |
| Known Project And Tool Identity Search | CVE List, GHSA, NVD and OSV term scan for Claude Code, Copilot, Cursor, Jules, Rovo, Devin, Codex and vibe-coding phrases | 289 source hits collapsed to 104 alias packets; deepseek screen yielded 66 AI_PRODUCT, 31 AMBIGUOUS, 4 GENERIC_RISK, 3 apparent ORIGIN_EVIDENCE; manual scope review excluded all three because they concern discovery assistance or runtime-generated content | [deepseek-official-term-screen.json](../research/orchestrator-260809-1127/deepseek-official-term-screen.json) |

The forward lane starts from all official numbered advisories and walks public fix references and repository ancestry. The reverse lane starts from public commits carrying known AI identities/trailers and intersects their exact SHAs with OSV introduced ranges and numbered aliases. The public-web lane catches closed-platform and prose-only attribution. The identity lane searches official descriptions and references for Claude Code, GitHub Copilot, Cursor, Google Jules, Atlassian Rovo, Devin, OpenAI Codex, and vibe-coding terms.

The term scan produced 289 source hits, collapsed to 104 alias packets. Model-assisted screening labeled 66 as AI products, 31 ambiguous, four generic AI-risk mentions, and three apparent origin-evidence packets. Manual scope review excluded the three apparent positives: one described runtime AI-generated content and two described AI-assisted vulnerability discovery. The exact introduced-SHA reverse screen yielded 28 packets: two high-priority, two medium-priority, and 24 low-priority. All high/medium packets were manually resolved; the frozen ledger has `pending_high_priority_count=0`.

### Model use and adjudication boundary

The requested local `deepseek-v4-flash` endpoint (`http://127.0.0.1:8317/v1`) made 19 successful structured-triage calls consuming 189,428 recorded tokens. It ranked exact-SHA intersections, classified term hits, and proposed a descriptive taxonomy. It did **not** decide inclusion. Inclusion remained a deterministic contract over public identifiers, public attribution, and case-level causal evidence, followed by manual review of high-priority candidates. Request and response digests are preserved in the [model receipt](../research/orchestrator-260809-1127/deepseek-v4-flash-receipt.json).

### Recall stopping rule

The protocol stops at a reproducible queue state rather than asserting unknowable global completeness: all five frozen lanes are complete, every high-priority candidate is resolved, and the independent verifier reports zero remaining units. Newly published records, previously private repositories, missing dates, deleted history, unattributed AI use, and later CVE/GHSA aliases remain refresh obligations.

## Evidence and inclusion rubric

### Evidence grades

- **Grade A:** public numbered advisory plus repository-level attribution and causal evidence at a relevant revision or conserved causal chain. Atomic authorship is preferred but not required when a mixed/squashed change has a documented causal witness.
- **Grade B:** the inclusion contract is still satisfied, but attribution or causal localization is non-atomic, qualified, or contested. Grade B is not a weaker vulnerability; it is a more limited attribution record.

This freeze contains 36 grade-A (90.0%) and 4 grade-B (10.0%) cases. CVE-2025-48757/GHSA-773X-PXJG-GXGX is retained as grade B because public CVE evidence names generated code and row-level-security policy while the supplier disputes platform responsibility.

### Contribution modes

- **Direct code generation:** a public AI-attributed change directly adds the vulnerable implementation.
- **Assistant co-authorship:** a participant explicitly credits an AI assistant on a relevant feature change.
- **Autonomous agent:** an agent or hosted generator produces the affected component as a delegated task.
- **Indirect causal extension:** AI-authored code extends an existing flaw into the disclosed vulnerable behavior or reachable surface.
- **Mixed or squash contribution:** a non-atomic change contains attributable AI participation and case-level causal evidence, but per-line authorship is not preserved.

### Negative controls and common false positives

We reject (1) vulnerable AI products without code-origin evidence, (2) AI-assisted discovery, (3) runtime AI payloads processed by human-written vulnerable code, (4) release/version-bump carriers, (5) AI-authored fixes, (6) Copilot translation metadata, and (7) semantic similarity without public attribution. These controls prevent a recall-oriented search from turning every mention of “AI,” “Claude,” or “Copilot” into an origin claim.

## Corpus results

### Overall distributions

The strict corpus contains 40/84,798 frozen alias classes (0.0472%). This is an **observability-bound lower bound**, not an incidence or prevalence rate: the denominator contains all numbered vulnerabilities, while the numerator requires unusually visible AI attribution and public causal evidence.

**Severity**

| Category | Cases | Share |
|---|---:|---:|
| High | 13 | 32.5% |
| Critical | 10 | 25.0% |
| Medium | 10 | 25.0% |
| Unknown | 4 | 10.0% |
| Low | 3 | 7.5% |

**Publication month**

| Month | Cases | Share |
|---|---:|---:|
| 2025-05 | 1 | 2.5% |
| 2025-06 | 2 | 5.0% |
| 2025-08 | 1 | 2.5% |
| 2025-09 | 2 | 5.0% |
| 2025-10 | 1 | 2.5% |
| 2025-11 | 1 | 2.5% |
| 2025-12 | 1 | 2.5% |
| 2026-02 | 9 | 22.5% |
| 2026-03 | 18 | 45.0% |
| 2026-04 | 1 | 2.5% |
| 2026-05 | 1 | 2.5% |
| 2026-06 | 2 | 5.0% |

March 2026 contributes 18/40 (45.0%). This concentration may reflect disclosure timing, source coverage, and clustered project audits; it should not be read as a time-series increase in underlying AI-code risk.

**AI tool mentions (multi-label)**

| Tool | Classes | Share of corpus |
|---|---:|---:|
| Claude Code | 32 | 80.0% |
| Github Copilot | 7 | 17.5% |
| Google Jules | 2 | 5.0% |
| Cursor | 2 | 5.0% |
| Lovable | 1 | 2.5% |
| Atlassian Rovo | 1 | 2.5% |

5 classes mention more than one tool. Claude Code appears in 32/40 classes (80.0%), but public trailer conventions, tool popularity, and the starting corpus make cross-tool safety comparisons invalid.

### Case catalogue

Each row is one alias class; linked IDs point to the official CVE or GitHub Advisory record. “Public” links expose a representative attribution/causal source, while “audit” links point to the frozen local adjudication.

| # | CVE/GHSA aliases | Published | Project | AI tool(s) | Severity | Contribution | Vulnerability / AI failure | Evidence |
|---:|---|---|---|---|---|---|---|---|
| 1 | [CVE-2025-48757](https://www.cve.org/CVERecord?id=CVE-2025-48757)<br>[GHSA-773X-PXJG-GXGX](https://github.com/advisories/GHSA-773X-PXJG-GXGX) | 2025-05-30 | hosted-service/lovable/lovable | Lovable | HIGH | Autonomous Agent | Access Control<br>Unsafe Default | B: [public](https://gist.github.com/lhchavez/625ee42a6c408a850d35e50f8e649de9), [audit](../research/orchestrator-260809-1127/web-literature-adjudications.json)<br>Supplier Disputed Hosted Service |
| 2 | [GHSA-8G98-M4J9-QWW5](https://github.com/advisories/GHSA-8G98-M4J9-QWW5) | 2025-06-18 | [tailot/taylored](https://github.com/tailot/taylored) | Google Jules | CRITICAL | Autonomous Agent | Data Validation<br>Incomplete Validation | A: [public](https://github.com/tailot/taylored/commit/57b7634391959dbbdb39b387ac4dc68157cd58a1), [audit](../scripts/audit_adjudications.json) |
| 3 | [GHSA-VH5J-5FHQ-9XWG](https://github.com/advisories/GHSA-VH5J-5FHQ-9XWG) | 2025-06-27 | [tailot/taylored](https://github.com/tailot/taylored) | Google Jules | LOW | Autonomous Agent | Access Control<br>State Or Context Confusion | A: [public](https://github.com/tailot/taylored/commit/45b69f6becd298e7bb7a15b5c57a7de007771d7b), [audit](../scripts/audit_adjudications.json) |
| 4 | [CVE-2025-55526](https://www.cve.org/CVERecord?id=CVE-2025-55526)<br>[GHSA-C7RR-QHWX-6Q49](https://github.com/advisories/GHSA-C7RR-QHWX-6Q49) | 2025-08-26 | [zie619/n8n-workflows](https://github.com/zie619/n8n-workflows) | Claude Code | CRITICAL | Direct Code Generation | Path Or File<br>Incomplete Validation | A: [public](https://github.com/Zie619/n8n-workflows/commit/64f9f86f87c23705fda6faa9947a947bf48b12c2), [audit](../scripts/audit_adjudications.json) |
| 5 | [CVE-2025-59163](https://www.cve.org/CVERecord?id=CVE-2025-59163)<br>[GHSA-6Q9C-M9FR-865M](https://github.com/advisories/GHSA-6Q9C-M9FR-865M) | 2025-09-29 | [safedep/vet](https://github.com/safedep/vet) | Claude Code, Github Copilot | LOW | Direct Code Generation | Network Trust<br>Missing Guard | A: [public](https://github.com/safedep/vet/commit/0ae3560ba11846375812377299fe078d45cc3d48), [audit](../scripts/audit_adjudications.json) |
| 6 | [GHSA-PWF7-47C3-MFHX](https://github.com/advisories/GHSA-PWF7-47C3-MFHX) | 2025-09-29 | [j178/prek-action](https://github.com/j178/prek-action) | Github Copilot | CRITICAL | Mixed Or Squash Contribution | Injection<br>Unsafe Interpolation | A: [public](https://github.com/j178/prek-action/commit/070aae8e5398e8a01806912ed2833f8b0fc8197a), [audit](../scripts/audit_adjudications.json) |
| 7 | [CVE-2025-59829](https://www.cve.org/CVERecord?id=CVE-2025-59829)<br>[GHSA-66M2-GX93-V996](https://github.com/advisories/GHSA-66M2-GX93-V996) | 2025-10-03 | [anthropics/claude-code](https://github.com/anthropics/claude-code) | Claude Code | LOW | Direct Code Generation | Access Control<br>Missing Guard | B: [public](https://github.com/anthropics/claude-code/commit/59372c0921b0170e81f9c63777962d02347411d5), [audit](../scripts/audit_adjudications.json) |
| 8 | [CVE-2025-13120](https://www.cve.org/CVERecord?id=CVE-2025-13120)<br>[GHSA-J383-Q79V-268X](https://github.com/advisories/GHSA-J383-Q79V-268X) | 2025-11-13 | [mruby/mruby](https://github.com/mruby/mruby) | Atlassian Rovo, Claude Code | MEDIUM | Direct Code Generation | Memory Safety<br>Memory Contract Error | A: [public](https://github.com/mruby/mruby/commit/2735340702ac767a7fe91ac353f7c4b2ff005e27), [audit](../scripts/audit_adjudications.json) |
| 9 | [CVE-2025-69288](https://www.cve.org/CVERecord?id=CVE-2025-69288) | 2025-12-31 | [kromitgmbh/titra](https://github.com/kromitgmbh/titra) | Github Copilot | CRITICAL | Direct Code Generation | Injection<br>Missing Guard | A: [public](https://github.com/kromitgmbh/titra/commit/2e2ac5cbeed47a76720b21c7fde0214a242e065e), [audit](../scripts/audit_adjudications.json) |
| 10 | [CVE-2026-25505](https://www.cve.org/CVERecord?id=CVE-2026-25505)<br>[GHSA-GC24-PX2R-5QMF](https://github.com/advisories/GHSA-GC24-PX2R-5QMF) | 2026-02-02 | [maziggy/bambuddy](https://github.com/maziggy/bambuddy) | Claude Code, Github Copilot | CRITICAL | Assistant Coauthorship | Access Control<br>Missing Guard | B: [public](https://github.com/maziggy/bambuddy/blob/a9bb8ed8239602bf08a9914f85a09eeb2bf13d15/backend/app/core/auth.py#L28), [audit](../scripts/audit_adjudications.json) |
| 11 | [CVE-2026-1979](https://www.cve.org/CVERecord?id=CVE-2026-1979)<br>[GHSA-GXGQ-RPMR-R8XR](https://github.com/advisories/GHSA-GXGQ-RPMR-R8XR) | 2026-02-06 | [sysfce2/mruby](https://github.com/sysfce2/mruby) | Claude Code | MEDIUM | Direct Code Generation | Memory Safety<br>Memory Contract Error | A: [public](https://github.com/sysfce2/mruby/commit/1de6340f1bc81564274890660f66444e48d660b0), [audit](../scripts/audit_adjudications.json) |
| 12 | [CVE-2026-28472](https://www.cve.org/CVERecord?id=CVE-2026-28472)<br>[GHSA-RV39-79C4-7459](https://github.com/advisories/GHSA-RV39-79C4-7459) | 2026-02-17 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | CRITICAL | Direct Code Generation | Access Control<br>Incomplete Validation | A: [public](https://github.com/openclaw/openclaw/commit/079af0d0b02ca2c722f90b6c4e38e27ba16227b4), [audit](../scripts/audit_adjudications.json) |
| 13 | [CVE-2026-28391](https://www.cve.org/CVERecord?id=CVE-2026-28391)<br>[GHSA-QJ77-C3C8-9C3Q](https://github.com/advisories/GHSA-QJ77-C3C8-9C3Q) | 2026-02-17 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | CRITICAL | Mixed Or Squash Contribution | Injection<br>Incomplete Validation | A: [public](https://github.com/openclaw/openclaw/commit/78d08fc574af8742c674cd6b986cd61a46d811e6), [audit](../scripts/audit_adjudications.json) |
| 14 | [CVE-2026-28478](https://www.cve.org/CVERecord?id=CVE-2026-28478)<br>[GHSA-Q447-RJ3R-2CGH](https://github.com/advisories/GHSA-Q447-RJ3R-2CGH) | 2026-02-18 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | HIGH | Mixed Or Squash Contribution | Resource Exhaustion<br>Missing Guard | A: [public](https://github.com/openclaw/openclaw/commit/2267d58afcc70fe19408b8f0dce108c340f3426d), [audit](../scripts/audit_adjudications.json) |
| 15 | [CVE-2026-28451](https://www.cve.org/CVERecord?id=CVE-2026-28451)<br>[GHSA-X22M-J5QQ-J49M](https://github.com/advisories/GHSA-X22M-J5QQ-J49M) | 2026-02-18 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | CRITICAL | Indirect Causal Extension | Network Trust<br>Incomplete Validation | A: [public](https://github.com/openclaw/openclaw/commit/2267d58afcc70fe19408b8f0dce108c340f3426d), [audit](../scripts/audit_adjudications.json) |
| 16 | [CVE-2026-27203](https://www.cve.org/CVERecord?id=CVE-2026-27203)<br>[GHSA-97RM-XJ73-33JH](https://github.com/advisories/GHSA-97RM-XJ73-33JH) | 2026-02-19 | [yosefhayim/ebay-mcp](https://github.com/yosefhayim/ebay-mcp) | Claude Code | HIGH | Direct Code Generation | Injection<br>Unsafe Interpolation | A: [public](https://github.com/yosefhayim/ebay-mcp/commit/4c9c826c6fc8b64a20e948cb46fefdda42d5244d), [audit](../scripts/audit_adjudications.json) |
| 17 | [CVE-2026-27627](https://www.cve.org/CVERecord?id=CVE-2026-27627) | 2026-02-25 | [karakeep-app/karakeep](https://github.com/karakeep-app/karakeep) | Claude Code | HIGH | Mixed Or Squash Contribution | Injection<br>Unsafe Interpolation | A: [public](https://github.com/karakeep-app/karakeep/commit/ba3db953c0d8675e2e3ecc29113a332b570b2cb9), [audit](../scripts/audit_adjudications.json) |
| 18 | [CVE-2026-27695](https://www.cve.org/CVERecord?id=CVE-2026-27695)<br>[GHSA-76RV-2R9V-C5M6](https://github.com/advisories/GHSA-76RV-2R9V-C5M6) | 2026-02-25 | [zeroae/zae-limiter](https://github.com/zeroae/zae-limiter) | Claude Code | MEDIUM | Direct Code Generation | Resource Exhaustion<br>Missing Guard | A: [public](https://github.com/zeroae/zae-limiter/commit/0e6b99c185c2d5de000bc08fe354ffcd06ddab39), [audit](../scripts/audit_adjudications.json) |
| 19 | [CVE-2026-21882](https://www.cve.org/CVERecord?id=CVE-2026-21882)<br>[GHSA-2J3P-GQW5-G59J](https://github.com/advisories/GHSA-2J3P-GQW5-G59J) | 2026-03-02 | [asfhtgkdavid/theshit](https://github.com/asfhtgkdavid/theshit) | Github Copilot | HIGH | Direct Code Generation | Access Control<br>Missing Guard | A: [public](https://github.com/asfhtgkdavid/theshit/commit/0fc1b4f701171346848fd4f3b3faa967442108fb), [audit](../scripts/audit_adjudications.json) |
| 20 | [CVE-2026-22178](https://www.cve.org/CVERecord?id=CVE-2026-22178)<br>[GHSA-C6HR-W26Q-C636](https://github.com/advisories/GHSA-C6HR-W26Q-C636) | 2026-03-02 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | MEDIUM | Indirect Causal Extension | Injection<br>Unsafe Interpolation | A: [public](https://github.com/openclaw/openclaw/commit/74268489137510b6f6349919d1e197b17290d92c), [audit](../scripts/audit_adjudications.json) |
| 21 | [CVE-2026-22171](https://www.cve.org/CVERecord?id=CVE-2026-22171)<br>[GHSA-VJ3G-5PX3-GR46](https://github.com/advisories/GHSA-VJ3G-5PX3-GR46) | 2026-03-03 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | HIGH | Direct Code Generation | Path Or File<br>Unsafe Interpolation | A: [public](https://github.com/openclaw/openclaw/commit/2267d58afcc70fe19408b8f0dce108c340f3426d), [audit](../scripts/audit_adjudications.json) |
| 22 | [CVE-2026-32021](https://www.cve.org/CVERecord?id=CVE-2026-32021)<br>[GHSA-J4XF-96QF-RX69](https://github.com/advisories/GHSA-J4XF-96QF-RX69) | 2026-03-03 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | MEDIUM | Indirect Causal Extension | Access Control<br>Trust Boundary Expansion | A: [public](https://github.com/openclaw/openclaw/commit/2267d58afcc70fe19408b8f0dce108c340f3426d), [audit](../scripts/audit_adjudications.json) |
| 23 | [CVE-2026-32057](https://www.cve.org/CVERecord?id=CVE-2026-32057)<br>[GHSA-VVGP-4C28-M3JM](https://github.com/advisories/GHSA-VVGP-4C28-M3JM) | 2026-03-03 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Cursor | MEDIUM | Direct Code Generation | Access Control<br>Missing Guard | A: [public](https://github.com/openclaw/openclaw/commit/ec45c317f5d0631a3d333b236da58c4749ede2a3), [audit](../scripts/audit_adjudications.json) |
| 24 | [CVE-2026-31998](https://www.cve.org/CVERecord?id=CVE-2026-31998)<br>[GHSA-GW85-XP4Q-5GP9](https://github.com/advisories/GHSA-GW85-XP4Q-5GP9) | 2026-03-03 | [openclaw/openclaw](https://github.com/openclaw/openclaw) | Claude Code | HIGH | Mixed Or Squash Contribution | Access Control<br>Unsafe Default | A: [public](https://github.com/openclaw/openclaw/commit/0ee30361b8f6ef3f110f3a7b001da6dd3df96bb5), [audit](../scripts/audit_adjudications.json) |
| 25 | [GHSA-5WP8-Q9MX-8JX8](https://github.com/advisories/GHSA-5WP8-Q9MX-8JX8) | 2026-03-05 | [qhkm/zeptoclaw](https://github.com/qhkm/zeptoclaw) | Claude Code | CRITICAL | Direct Code Generation | Injection<br>Incomplete Validation | A: [public](https://github.com/qhkm/zeptoclaw/blob/fe2ef07cfec5bb46b42cdd65f52b9230c03e9270/src/security/shell.rs#L218-L243), [audit](../scripts/audit_adjudications.json) |
| 26 | [CVE-2026-32111](https://www.cve.org/CVERecord?id=CVE-2026-32111)<br>[GHSA-FMFG-9G7C-3VQ7](https://github.com/advisories/GHSA-FMFG-9G7C-3VQ7) | 2026-03-11 | [homeassistant-ai/ha-mcp](https://github.com/homeassistant-ai/ha-mcp) | Claude Code | MEDIUM | Mixed Or Squash Contribution | Network Trust<br>Trust Boundary Expansion | A: [public](https://github.com/homeassistant-ai/ha-mcp/commit/1f2bbbc74e81933a39e9c63998d1408f0c198309), [audit](../scripts/audit_adjudications.json) |
| 27 | [CVE-2026-32231](https://www.cve.org/CVERecord?id=CVE-2026-32231)<br>[GHSA-46Q5-G3J9-WX5C](https://github.com/advisories/GHSA-46Q5-G3J9-WX5C) | 2026-03-12 | [qhkm/zeptoclaw](https://github.com/qhkm/zeptoclaw) | Claude Code | HIGH | Direct Code Generation | Access Control<br>Trust Boundary Expansion | A: [public](https://github.com/qhkm/zeptoclaw/commit/0325464647135e6bab5bd407eacd8691f5c8191f), [audit](../scripts/audit_adjudications.json) |
| 28 | [CVE-2026-32232](https://www.cve.org/CVERecord?id=CVE-2026-32232)<br>[GHSA-2M67-CXXQ-C3H8](https://github.com/advisories/GHSA-2M67-CXXQ-C3H8) | 2026-03-12 | [qhkm/zeptoclaw](https://github.com/qhkm/zeptoclaw) | Claude Code | HIGH | Direct Code Generation | Path Or File<br>State Or Context Confusion | A: [public](https://github.com/qhkm/zeptoclaw/commit/061066f761ebe337c0b480a24560e5f1b9126280), [audit](../scripts/audit_adjudications.json) |
| 29 | [GHSA-4CM8-XPFV-JV6F](https://github.com/advisories/GHSA-4CM8-XPFV-JV6F) | 2026-03-12 | [qhkm/zeptoclaw](https://github.com/qhkm/zeptoclaw) | Claude Code | MEDIUM | Indirect Causal Extension | Access Control<br>Trust Boundary Expansion | A: [public](https://github.com/qhkm/zeptoclaw/commit/0325464647135e6bab5bd407eacd8691f5c8191f), [audit](../scripts/audit_adjudications.json) |
| 30 | [CVE-2026-32247](https://www.cve.org/CVERecord?id=CVE-2026-32247)<br>[GHSA-GG5M-55JJ-8M5G](https://github.com/advisories/GHSA-GG5M-55JJ-8M5G) | 2026-03-12 | [getzep/graphiti](https://github.com/getzep/graphiti) | Claude Code | HIGH | Direct Code Generation | Injection<br>Unsafe Interpolation | B: [public](https://github.com/getzep/graphiti/commit/14146dc46fb87d5d6c16ea31795534c662c4058d), [audit](../scripts/audit_adjudications.json) |
| 31 | [CVE-2026-2376](https://www.cve.org/CVERecord?id=CVE-2026-2376)<br>[GHSA-9W78-X9JW-9C7M](https://github.com/advisories/GHSA-9W78-X9JW-9C7M) | 2026-03-12 | [quay/quay](https://github.com/quay/quay) | Claude Code | MEDIUM | Mixed Or Squash Contribution | Network Trust<br>Missing Guard | A: [public](https://github.com/quay/quay/commit/4ae1b6488650ea07f1caa4759d282bd2c9968bb9), [audit](../scripts/audit_adjudications.json) |
| 32 | [CVE-2026-32890](https://www.cve.org/CVERecord?id=CVE-2026-32890) | 2026-03-20 | [openvessl/anchorr](https://github.com/openvessl/anchorr) | Claude Code | CRITICAL | Direct Code Generation | Injection<br>Unsafe Interpolation | A: [public](https://github.com/openvessl/anchorr/commit/403ccf079be0ee5e6660f0ed2fa64174d76eff2f), [audit](../scripts/audit_adjudications.json) |
| 33 | [CVE-2026-33331](https://www.cve.org/CVERecord?id=CVE-2026-33331)<br>[GHSA-7F6V-3GX7-27Q8](https://github.com/advisories/GHSA-7F6V-3GX7-27Q8) | 2026-03-20 | [middleapi/orpc](https://github.com/middleapi/orpc) | Github Copilot | HIGH | Mixed Or Squash Contribution | Injection<br>Unsafe Interpolation | A: [public](https://github.com/middleapi/orpc/commit/0997c10e96ea1d6a8aab9fa65ab1a956350d2ea5), [audit](../scripts/audit_adjudications.json) |
| 34 | [CVE-2026-33632](https://www.cve.org/CVERecord?id=CVE-2026-33632) | 2026-03-26 | [craigjbass/clearancekit](https://github.com/craigjbass/clearancekit) | Claude Code | HIGH | Direct Code Generation | Access Control<br>Missing Guard | A: [public](https://github.com/craigjbass/clearancekit/commit/56cf8aabd3d6f33e39749e27b135106878cbb7fc), [audit](../scripts/audit_adjudications.json) |
| 35 | [CVE-2026-33890](https://www.cve.org/CVERecord?id=CVE-2026-33890) | 2026-03-27 | [franklioxygen/mytube](https://github.com/franklioxygen/mytube) | Claude Code, Cursor | HIGH | Direct Code Generation | Access Control<br>Missing Guard | A: [public](https://github.com/franklioxygen/mytube/commit/941035909ee3f96a6f80f38acf70cbc3e66b5098), [audit](../scripts/audit_adjudications.json) |
| 36 | [CVE-2026-34218](https://www.cve.org/CVERecord?id=CVE-2026-34218) | 2026-03-31 | [craigjbass/clearancekit](https://github.com/craigjbass/clearancekit) | Claude Code, Github Copilot | MEDIUM | Direct Code Generation | Access Control<br>State Or Context Confusion | A: [public](https://github.com/craigjbass/clearancekit/commit/31c617c8286a0707e1c7e65ec6469013d40b3ff1), [audit](../scripts/audit_adjudications.json) |
| 37 | [CVE-2026-7386](https://www.cve.org/CVERecord?id=CVE-2026-7386) | 2026-04-29 | [fatbobman/mail-mcp-bridge](https://github.com/fatbobman/mail-mcp-bridge) | Claude Code | UNKNOWN | Direct Code Generation | Path Or File<br>Incomplete Validation | A: [public](https://github.com/fatbobman/mail-mcp-bridge/commit/26be5ccbf17501852e98f7699d77ec4f63128ece), [audit](../research/orchestrator-260809-0539/current-mail-mcp-witness/adjudication.json) |
| 38 | [CVE-2026-44219](https://www.cve.org/CVERecord?id=CVE-2026-44219)<br>[GHSA-XW8C-RRVX-F7XQ](https://github.com/advisories/GHSA-XW8C-RRVX-F7XQ) | 2026-05-05 | [jo-jo98/ciguard](https://github.com/jo-jo98/ciguard) | Claude Code | UNKNOWN | Direct Code Generation | Resource Exhaustion<br>Missing Guard | A: [public](https://github.com/jo-jo98/ciguard/commit/17a119fe43dd956ef463c1c575a463ffd9a8d95b), [audit](../research/orchestrator-260809-0539/current-ciguard-witness/adjudication.json) |
| 39 | [CVE-2026-10281](https://www.cve.org/CVERecord?id=CVE-2026-10281)<br>[GHSA-Q6QC-XP4Q-RJQ5](https://github.com/advisories/GHSA-Q6QC-XP4Q-RJQ5) | 2026-06-01 | [enderfga/claw-orchestrator](https://github.com/enderfga/claw-orchestrator) | Claude Code | UNKNOWN | Assistant Coauthorship | Access Control<br>Missing Guard | A: [public](https://github.com/enderfga/claw-orchestrator/commit/d0b02a800aa0689d9428cc4cc170e0b6589fb2c3), [audit](../research/orchestrator-260809-0539/current-claw-orchestrator-witness/adjudication.json) |
| 40 | [CVE-2026-13591](https://www.cve.org/CVERecord?id=CVE-2026-13591) | 2026-06-29 | [deepmyst/mysti](https://github.com/deepmyst/mysti) | Claude Code | UNKNOWN | Assistant Coauthorship | Data Validation<br>State Or Context Confusion | A: [public](https://github.com/deepmyst/mysti/commit/94e14d9d30e2b9bf0b9d67ae6d459dbf263b9d99), [audit](../research/orchestrator-260809-0539/current-mysti-witness/adjudication.json) |

## Taxonomy

### Vulnerability family

| Category | Cases | Share |
|---|---:|---:|
| Access Control | 15 | 37.5% |
| Injection | 10 | 25.0% |
| Path Or File | 4 | 10.0% |
| Network Trust | 4 | 10.0% |
| Resource Exhaustion | 3 | 7.5% |
| Data Validation | 2 | 5.0% |
| Memory Safety | 2 | 5.0% |

Access-control (15) and injection (10) together account for 25/40 cases (62.5%). The recurring boundary is not “incorrect syntax”; it is failure to preserve authentication, authorization, quoting, path, host/origin, and trust invariants across generated features.

### AI implementation-failure mode

| Category | Cases | Share |
|---|---:|---:|
| Missing Guard | 13 | 32.5% |
| Unsafe Interpolation | 8 | 20.0% |
| Incomplete Validation | 7 | 17.5% |
| State Or Context Confusion | 4 | 10.0% |
| Trust Boundary Expansion | 4 | 10.0% |
| Unsafe Default | 2 | 5.0% |
| Memory Contract Error | 2 | 5.0% |

Missing guards (13) and unsafe interpolation (8) account for 21/40 (52.5%). Incomplete validation is the next largest class. These modes suggest evaluation should test negative security obligations—what the generated feature must reject—not only functional happy paths.

### Contribution mode

| Category | Cases | Share |
|---|---:|---:|
| Direct Code Generation | 22 | 55.0% |
| Mixed Or Squash Contribution | 8 | 20.0% |
| Indirect Causal Extension | 4 | 10.0% |
| Autonomous Agent | 3 | 7.5% |
| Assistant Coauthorship | 3 | 7.5% |

Direct generation is visible in 22/40 cases. Mixed/squashed and indirect causal contributions total 12/40 (30.0%), demonstrating why atomic-line blame alone cannot achieve high recall. The Lovable case demonstrates the complementary blind spot: platform-generated code may be publicly documented without a retrievable origin commit.

### Synthesis

The evidence supports four SoK-level conclusions:

1. **Security obligations are omitted more often than implementations are syntactically broken.** Missing authorization, validation, size bounds, quoting, and trust-boundary checks dominate the verified set.
2. **AI contribution is compositional.** A generated feature can make a pre-existing weakness reachable or material even when the root defect predates the AI change.
3. **Metadata visibility drives what can be measured.** Tool frequencies reflect public trailers, bot identities, repository availability, and search seeds as much as real deployment volume.
4. **High recall requires bidirectional and off-repository search.** Advisory-first history, AI-commit-first intersections, and web/literature search each recover cases the others miss.

## Related empirical literature

Adjacent work studies agent-generated software, AI-code prevalence, benchmarks, or vulnerability rates rather than this study's numbered-disclosure and causal-attribution unit. Relevant primary papers include [AgentPack](https://arxiv.org/abs/2509.21891), [Agentic Much?](https://arxiv.org/abs/2601.18341), [AI Code in the Wild](https://arxiv.org/abs/2512.18567), [Understanding the (In)Security of Vibe-Coded Applications](https://arxiv.org/abs/2606.23130), [Security Vulnerabilities in AI-Generated Code](https://arxiv.org/abs/2510.26103), [Human-Written vs. AI-Generated Code](https://arxiv.org/abs/2508.21634), [A.S.E](https://arxiv.org/abs/2508.18106), and [When Correct Is Not Safe](https://arxiv.org/abs/2510.17862). This corpus complements those studies with claim-auditable CVE/GHSA cases and explicit evidence boundaries; it does not convert benchmark defect rates into ecosystem prevalence.

## Threats to validity

- **Unobservable use and construct validity.** Developers may omit AI attribution, and public trailers may overstate or understate actual contribution. The corpus measures disclosed and evidenced contribution, not latent use.
- **Selection and source bias.** Public Git history favors open repositories and tools with recognizable identities. Closed generators and squash merges are under-observed; the web lane mitigates but cannot eliminate this bias.
- **Disclosure and temporal lag.** Vulnerabilities may receive identifiers months after introduction. A frozen end date therefore right-censors recent code, and future aliases can move records into scope.
- **Missing and mutable data.** 5,789 date-missing records remain blocked. Repositories, references, NVD enrichment, CVE aliases, and advisory text can change after the freeze.
- **Causal-chain judgment.** Indirect contribution requires reasoning about reachability and security obligations. The audit records preserve witnesses and grades, but reasonable reviewers can disagree at the boundary.
- **Model-assisted triage.** DeepSeek may mis-rank candidates or propose unstable labels. Manual adjudication and deterministic inclusion checks reduce this risk; they do not prove that low-ranked candidates contain no hidden cases.
- **Taxonomy subjectivity.** Each case receives one primary vulnerability family and one primary AI failure mode even when several apply. The labels summarize the corpus rather than replace CWE or advisory descriptions.
- **No prevalence inference.** 40/84,798 is a discovery yield under an attribution-heavy protocol. It is not the fraction of AI-written code that is vulnerable, nor the fraction of all vulnerabilities caused by AI.

## Reproducibility

The frozen run is `research/orchestrator-260809-1127/`. Its machine-readable nucleus is:

- [`goal_contract.json`](../research/orchestrator-260809-1127/goal_contract.json): scope, inclusion contract, lanes, and success predicate;
- [`corpus.json`](../research/orchestrator-260809-1127/corpus.json): all 40 alias classes and case-level sources;
- [`screening-ledger.json`](../research/orchestrator-260809-1127/screening-ledger.json): lane inputs, outputs, and queue state;
- [`official-ai-term-hits.json`](../research/orchestrator-260809-1127/official-ai-term-hits.json): frozen official-source term hits;
- [`deepseek-osv-introduced-screen.json`](../research/orchestrator-260809-1127/deepseek-osv-introduced-screen.json) and [`deepseek-official-term-screen.json`](../research/orchestrator-260809-1127/deepseek-official-term-screen.json): structured model triage;
- [`web-literature-adjudications.json`](../research/orchestrator-260809-1127/web-literature-adjudications.json): inclusions and manual exclusions from prose search;
- [`deepseek-v4-flash-receipt.json`](../research/orchestrator-260809-1127/deepseek-v4-flash-receipt.json): model, endpoint, request/response digests, and token accounting.

From repository root, the deterministic final build and verification are:

```sh
python3 research/orchestrator-260809-1127/build_sok_corpus.py
python3 research/orchestrator-260809-1127/write_sok_manuscript.py
python3 research/orchestrator-260809-1127/verify_sok.py
```

The last command succeeds only when all cases meet the identifier/evidence schema, all five lanes are complete, no high-priority candidate is pending, the requested model receipt is valid, the manuscript contains all required sections, and the embedded corpus SHA-256 matches the live corpus. Re-running network acquisition can produce a later snapshot; reproducing this paper means retaining the frozen artifacts and hashes above.
