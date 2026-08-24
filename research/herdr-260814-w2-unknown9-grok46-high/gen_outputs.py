#!/usr/bin/env python3
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/home/hanqing/agents/ai-slop")
OWNED = ROOT / "autoresearch/herdr-260814-w2-unknown9-grok46-high"
SLICE = ROOT / "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-01.jsonl"
ADV_ROOT = Path("/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")
CONTRACT = ROOT / "autoresearch/orchestrator-260813-ghsa200-leader/CONTRACT.md"

started = datetime.now(timezone.utc)
slice_bytes = SLICE.read_bytes()
slice_sha = hashlib.sha256(slice_bytes).hexdigest()
contract_sha = hashlib.sha256(CONTRACT.read_bytes()).hexdigest()
rows_in = [json.loads(l) for l in SLICE.read_text().splitlines() if l.strip()]

GATES = ["identity_gate","ai_hunk_gate","topology_gate","but_for_gate","fix_reversal_gate","release_gate","uniqueness_gate"]

def adv_path(ghsa):
    slug = ghsa.lower()
    for year in ("2025","2026"):
        for month in [f"{m:02d}" for m in range(1,13)]:
            p = ADV_ROOT / "advisories/github-reviewed" / year / month / slug / f"{slug}.json"
            if p.exists():
                return str(p)
    return None

def load_adv(ghsa):
    p = adv_path(ghsa)
    if not p:
        return {}, None
    o = json.loads(Path(p).read_text())
    aliases = o.get("aliases") or []
    refs = []
    for r in o.get("references") or []:
        u = r.get("url") if isinstance(r, dict) else None
        if u:
            refs.append(u)
    pkgs = []
    for a in o.get("affected") or []:
        pkg = a.get("package") or {}
        pkgs.append({"ecosystem": pkg.get("ecosystem"), "name": pkg.get("name")})
    return {
        "aliases": aliases,
        "summary": o.get("summary"),
        "withdrawn": o.get("withdrawn"),
        "refs": refs[:12],
        "pkgs": pkgs,
    }, p

# Per-row judgments. Missing evidence stays UNKNOWN. Affirmative disproof only for FP.
# clone paths from evidence collection.
CLONES = {
    "coder/coder": "/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/coder__coder",
    "anthropic-experimental/sandbox-runtime": "/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/anthropic-experimental__sandbox-runtime",
    "babylonlabs-io/babylon": "/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/babylonlabs-io__babylon",
    "quic-go/quic-go": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/quic-go__quic-go",
    "shopware/shopware": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/shopware__shopware",
    "silverbucket/webfinger.js": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/silverbucket__webfinger.js",
    "modelcontextprotocol/python-sdk": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__python-sdk",
    "psd-tools/psd-tools": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/psd-tools__psd-tools",
    "OpenListTeam/OpenList": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/OpenListTeam__OpenList",
    "zitadel/zitadel": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/zitadel__zitadel",
    "rustfs/rustfs": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/rustfs__rustfs",
    "modelcontextprotocol/go-sdk": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/modelcontextprotocol__go-sdk",
    "gogs/gogs": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gogs__gogs",
    "Basekick-Labs/arc": "/home/hanqing/.cache/ghsa200-worker-clones/commit-af/repos/Basekick-Labs__arc",
    "gofiber/fiber": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/gofiber__fiber",
    "lobehub/lobehub": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/lobehub__lobehub",
    "MontFerret/ferret": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/MontFerret__ferret",
    "OpenC3/cosmos": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/OpenC3__cosmos",
    "go-vikunja/vikunja": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/go-vikunja__vikunja",
    "jahlives/openssl_encrypt": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/jahlives__openssl_encrypt",
    "locutusjs/locutus": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/locutusjs__locutus",
    "stellar/rs-soroban-sdk": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/stellar__rs-soroban-sdk",
    "google/clasp": "/home/hanqing/.cache/ghsa200-worker-clones/commit-gn/clones/google__clasp",
    "withastro/astro": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/withastro__astro",
    "vercel/workflow": "/home/hanqing/.cache/ghsa200-worker-clones/commit-oz/repos/vercel__workflow",
}

# Compact judgment table keyed by ghsa.
J = {
"GHSA-J6XF-JWRJ-V5QP": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on chore cherry-pick batch #18674 (115 files, many human co-authors). Not hunk-level proof that Copilot authored the prebuilds/dbauthz privilege-escalation sink.",
    note="Candidate is a v2.24 cherry-pick carrier. Fix 20d67d7d expires prebuild tokens. File overlap on dbauthz exists, but authorship cannot be transferred from the batch trailer. Release containment not independently tagged this session.",
    ce=["Cherry-pick / multi-PR carrier cannot close topology or ai_hunk.","Copilot is one of many co-authors; not relevant-hunk proof."]),
"GHSA-9GQJ-5W7C-VX47": dict(v="UNKNOWN", c="MEDIUM", cc="AI_INCOMPLETE_REMEDIATION", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-Authored-By: Claude on 23e9e226 (BPF/seccomp unix-socket blocking). Fix bea2930 is also Claude (empty allowedDomains).",
    note="Same-author Claude pair on network sandboxing. Patch-delta incomplete-remediation is plausible but not closed: BPF/unix-socket work may be a sibling of the empty-allowedDomains residual. Missing hunk-level proof that 23e9e226 authored the empty-allowedDomains guard. Not converted to CONFIRM.",
    ce=["Fix-side Claude trailer is not origin.","Empty allowedDomains vs unix-socket BPF may be sibling surfaces."],
    ov=dict(original_advisory_ids=["GHSA-9GQJ-5W7C-VX47","CVE-2025-66479"], original_mechanism="Network sandboxing documented to block when allowedDomains is empty, but implementation still allowed traffic.", original_sink="src/sandbox/linux-sandbox-utils.ts / sandbox-manager.ts", original_introducing_commit=None, attempted_remediation="23e9e226 added BPF/seccomp unix-socket blocking; residual empty-allowedDomains behavior not proved as the same boundary.", residual_bypass="Empty allowedDomains fails to block network as documented.", final_closure="bea2930cc1db9c73a1b15acf6dc19c5261aec1f3")),
"GHSA-4RMQ-MC2C-R495": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on 249-file costaking backport #1755 with many human co-authors.",
    note="Backport carrier of #1707. Phantom-stake accounting hunk authorship not isolated. Fix e65c3a55 is a later security-advisory backport.",
    ce=["Backport/cherry-pick trailer is not hunk proof."]),
"GHSA-G754-HX8W-X2G6": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on b7886d5c 'update qpack to v0.6.0'.",
    note="HTTP/3 QPACK header-expansion DoS. Candidate updates qpack and touches http3 headers/conn/stream. Copilot trailer on a dependency bump is not hunk-level proof of missing decompressed-header limits. Fix 5b2d2129 adds the limit.",
    ce=["Dependency-bump Copilot trailer is not origin of the missing limit."]),
"GHSA-3CPP-FV95-MPR5": dict(v="FALSE_POSITIVE", c="HIGH", cc=None, fp="UNRELATED_AI_COMMIT_TESTS_ONLY", term=True,
    g=dict(identity_gate="PASS", ai_hunk_gate="FAIL", topology_gate="FAIL", but_for_gate="FAIL", fix_reversal_gate="FAIL", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on 543eb637 'test: add snapshot tests for documents'.",
    note="Affirmative disproof: candidate files are snapshot tests / SnapshotTesting.php only. Production SSRF sink lives in document twig templates touched by fix f32737b, which are absent from the candidate tree. Removing tests does not remove invoice SSRF.",
    ce=["AI candidate does not author production document-renderer sink.","Test overlap with the later fix is not origin."]),
"GHSA-8XQ3-W9FX-74RV": dict(v="FALSE_POSITIVE", c="HIGH", cc=None, fp="UNRELATED_AI_COMMIT_TESTS_ONLY", term=True,
    g=dict(identity_gate="PASS", ai_hunk_gate="FAIL", topology_gate="FAIL", but_for_gate="FAIL", fix_reversal_gate="FAIL", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Claude trailers on ff1abb86 'Enhance testing infrastructure'.",
    note="Affirmative disproof: candidate files are tests/README/tooling. Production Blind-SSRF sink src/webfinger.ts is in the fix (b5f2f2c) and not in the candidate file list.",
    ce=["Claude authored tests, not webfinger.ts fetch logic."]),
"GHSA-J975-95F5-7WQH": dict(v="UNKNOWN", c="LOW", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="No explicit AI trailer. Slice 'anthropic' hit is a substring, not Co-Authored-By/bot identity.",
    note="7901552e authors session.py error-on-close. Fix 7b420656 handles uncaught exception in streamable HTTP. Missing explicit AI marker stays UNKNOWN, not FAIL.",
    ce=["Substring 'anthropic' is not an explicit AI marker."]),
"GHSA-3QHF-M339-9G5V": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-authored-by: Claude on 568cbd1a moving incoming message stream into ServerSession.",
    note="Blame hits src/mcp/shared/session.py (2 lines) and fix 29c69e6a touches the same file for FastMCP validation-error DoS. Claude trailer is explicit, but those two blamed lines were not shown to be the validation-error mechanism. ai_hunk therefore stays UNKNOWN (relevant-hunk not proved).",
    ce=["File overlap plus Claude trailer is not by itself the FastMCP validation-error hunk."]),
"GHSA-24P2-J2JR-386W": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-Authored-By: Claude on f871f527 docs/docstring commit. Fix 6c0a78f is also Claude.",
    note="Candidate subject is documentation. Overlap includes compression/rle.py, which could be docstring-only. Docstring-vs-code was not disproved from a full hunk dump, so this stays UNKNOWN rather than tests-only FP.",
    ce=["Fix-side Claude is not origin.","Docs subject is not by itself FAIL."]),
"GHSA-WF93-3GHH-H389": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on 016ed90e stream cache feature that also lists TLS config files.",
    note="Insecure TLS default is fixed by e3c664f8. Candidate/fix overlap on internal/conf/config.go. Copilot trailer on a stream-buffer feature is not hunk proof of the TLS default.",
    ce=["Config-file overlap is not TLS-default authorship."]),
"GHSA-282G-FHMX-XF54": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on 88-file user-API feature #9794.",
    note="Self-verify email/phone residual is fixed in user_v2_human.go. Large feature PR; Copilot trailer does not isolate the self-verify hunk.",
    ce=["Large multi-file feature carrier."]),
"GHSA-FC6G-2GCP-2QRQ": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="dependabot[bot] author plus Copilot trailer on s3s rc bump #1046.",
    note="SourceIp/XFF bypass is fixed in admin policy evaluation. A dependency bump that lists admin handlers is not hunk proof. Not converted to FP because regenerated handler code was not inspected line-by-line.",
    ce=["Dependabot bump is weak origin evidence; missing hunk stays UNKNOWN."]),
"GHSA-WVJ2-96WP-FQ3F": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-authored-by: Claude on 3cf9f990 sampling-with-tools.",
    note="Blame 3 lines in mcp/content.go; fix 7b8d81c switches to case-sensitive JSON. Sampling feature vs case-sensitivity mechanism not tied at hunk level.",
    ce=["Claude sampling commit is not proved to author case-insensitive unmarshal."]),
"GHSA-89MR-XQFV-758M": dict(v="FALSE_POSITIVE", c="HIGH", cc=None, fp="RENAME_OR_MOVE_ONLY", term=True,
    g=dict(identity_gate="PASS", ai_hunk_gate="FAIL", topology_gate="PASS", but_for_gate="FAIL", fix_reversal_gate="FAIL", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-authored-by: Claude on 36d56d55 'rename packages ending with util to end with x' (212 files).",
    note="Affirmative: candidate is a repo-wide util→x rename. Overlap on repo_editor.go is the rename touching the later symlink-walk sink. Merely moving/preserving an old bug fails but_for. Fix 04cb8afb walks upload paths for parent symlinks.",
    ce=["Rename/move is not origin of committed-parent symlink escape."]),
"GHSA-P2J4-C4G6-RPF5": dict(v="UNKNOWN", c="MEDIUM", cc="AI_INCOMPLETE_REMEDIATION", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Substring 'gemini' on c069b351 denylist/storage_root SQL wiring. Not a verified Co-Authored-By Gemini trailer in the collected log.",
    note="Strong incomplete-rem story: denylist of DuckDB I/O, later enable_external_access=false. Explicit AI marker not closed, so ai_hunk stays UNKNOWN. Residual GHSA is authenticated local-file read via DuckDB I/O bypassing RBAC.",
    ce=["'gemini' substring is not enough for ai_hunk PASS."],
    ov=dict(original_advisory_ids=["GHSA-P2J4-C4G6-RPF5","CVE-2026-47735"], original_mechanism="Authenticated DuckDB I/O functions read local files and bypass RBAC table checks.", original_sink="internal/database/duckdb.go", original_introducing_commit=None, attempted_remediation="c069b351 wired storage_root plus denylist arc_partition_agg in user SQL.", residual_bypass="DuckDB I/O functions still read arbitrary local files despite table-level denylist.", final_closure="91bdc29d1a02178ccf8c66375eccf85203108dfb enable_external_access=false + allowed_directories")),
"GHSA-268J-37XF-PP52": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-authored-by: Claude on a1fa62b2 'decouple API types from go-gogs-client SDK' (90 files).",
    note="Blame 3 lines in internal/route/api/v1/api.go; fix 62834621 requires admin for repo settings API. Large SDK decoupling may only have moved types. Hunk not dumped; stays UNKNOWN rather than rename-FP.",
    ce=["API-type decoupling is not proved as the collaborator-settings permission hole."]),
"GHSA-WV27-2VQP-J7G5": dict(v="FALSE_POSITIVE", c="HIGH", cc=None, fp="RENAME_OR_MOVE_ONLY", term=True,
    g=dict(identity_gate="PASS", ai_hunk_gate="FAIL", topology_gate="PASS", but_for_gate="FAIL", fix_reversal_gate="FAIL", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Same Claude rename commit 36d56d55 as GHSA-89MR.",
    note="Shared SHA does not duplicate uniqueness: different mechanism (mirror local-repo import). Candidate remains a util→x rename overlapping form/repo.go and setting.go. Fix 11e19f28 validates remote mirror addresses. Move/rename fails but_for.",
    ce=["Rename commit is not origin of mirror local-import."]),
"GHSA-3W28-36P9-W929": dict(v="UNKNOWN", c="HIGH", cc="AI_INCOMPLETE_REMEDIATION", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-authored-by: Claude on 441c64d7 'markup: restrict data URI scheme to safe image MIME types' (sanitizer.go + test only).",
    note="Strong incomplete-rem candidate: Claude added a data-URI allowlist; GHSA residual is ipynb sanitizer still allowing arbitrary data: URIs; fix dd1bd983 tightens ipynb in sanitizer.go. Patch-delta not closed because ipynb may be an untouched sibling path (fix also touches internal/app/api.go). Release tags not independently shown. Not CONFIRM.",
    ce=["Sibling ipynb path vs general sanitizer allowlist not disambiguated from hunks.","Missing release tags stay UNKNOWN."],
    ov=dict(original_advisory_ids=["GHSA-3W28-36P9-W929","CVE-2026-52816"], original_mechanism="Markup sanitizer allowed arbitrary data: URIs leading to XSS.", original_sink="internal/markup/sanitizer.go", original_introducing_commit=None, attempted_remediation="441c64d7 restricted data URI scheme to safe image MIME types in the general sanitizer.", residual_bypass="Unauthenticated Jupyter Notebook (ipynb) sanitizer still allowed arbitrary data: URIs.", final_closure="dd1bd9837aa196b3ed3a8ee21e5727b5d7a986a3")),
"GHSA-C39W-43GM-34H5": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Same Claude API-decouple commit a1fa62b2 as GHSA-268J.",
    note="Org-name path traversal / Git-hook RCE. Overlap internal/route/api/v1/org.go. Different mechanism from GHSA-268J so uniqueness PASS. Hunk not shown to introduce traversal.",
    ce=["SDK decoupling overlap on org.go is not path-traversal origin proof."]),
"GHSA-35HP-HQMV-8QG8": dict(v="UNKNOWN", c="HIGH", cc="AI_INCOMPLETE_REMEDIATION", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Author copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com> on 27d359e8 cache middleware review-feedback (cache.go/config/tests).",
    note="Explicit bot identity authors the cache-key files later hardened by 9a0d12c0 (restore Methods, include query string). Parent was already a cache security fix. Patch-delta / but_for not closed: Copilot may have restored Methods while leaving query-string out, or may not have introduced that omission. Release 3.2.0 not independently tagged this session.",
    ce=["Parent already claimed to fix cache delimiter/DoS; Copilot review follow-up needs hunk-level residual proof."],
    ov=dict(original_advisory_ids=["GHSA-35HP-HQMV-8QG8","CVE-2026-30246"], original_mechanism="Cache middleware default key generator ignored query string, mixing responses across distinct queries.", original_sink="middleware/cache/cache.go", original_introducing_commit=None, attempted_remediation="27d359e8 Copilot-bot addressed cache middleware review feedback after a prior security patch.", residual_bypass="Default cache key still ignored query string.", final_closure="9a0d12c07ed895b84c72987f9288b04137afe5de")),
"GHSA-5MWJ-V5JW-5C97": dict(v="FALSE_POSITIVE", c="HIGH", cc=None, fp="UNRELATED_AI_COMMIT_WRONG_SURFACE", term=True,
    g=dict(identity_gate="PASS", ai_hunk_gate="FAIL", topology_gate="FAIL", but_for_gate="FAIL", fix_reversal_gate="FAIL", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Claude trailers on e67bcb25 CLI generate-command feature.",
    note="Affirmative: candidate files are apps/cli generate/http. GHSA is unauthenticated webapi auth bypass via X-lobe-chat-auth. Fix 3327b293 removes apiKey fallback in backend auth and xor helpers, files absent from the candidate tree.",
    ce=["CLI generate command is not the webapi auth header bypass."]),
"GHSA-J6V5-G24H-VG4J": dict(v="UNKNOWN", c="LOW", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on a252ad8e Feat/modules.",
    note="Alleged fix 160ebad6 is Feat/fs (131 files) while the advisory is IO::FS::WRITE path traversal. Candidate overlap is engine.go lifecycle, not an FS write sink. Pairing not proved; missing evidence stays UNKNOWN.",
    ce=["Feature-PR pairing is not a first-party closer without hunk proof."]),
"GHSA-4JVX-93H3-F45H": dict(v="UNKNOWN", c="HIGH", cc="AI_INCOMPLETE_REMEDIATION", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS", but_for_gate="PASS", fix_reversal_gate="PASS", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-Authored-By: Claude on 9957a9fa 'Prevent path traversal in tool config names' (exact tool_config_model.rb/.py + SaveConfigDialog.vue + spec).",
    note="Patch-delta closed locally: Claude denylist attempt, same four files, later Claude allowlist e6efccbd amends that boundary. Residual is denylist bypass of path-traversed config filenames. git tag --contains and name-rev returned no tags for either SHA (commits dated 2026-03-03/04; advisory names 7.0.0.pre.rc1 -> 7.0.0-rc3). Missing tags stay UNKNOWN, not unreleased-FP. Not CONFIRM.",
    ce=["No local tag names contained the candidate or closer."],
    ov=dict(original_advisory_ids=["GHSA-4JVX-93H3-F45H","CVE-2026-42085"], original_mechanism="Tool config filenames could path-traverse into the plugins directory.", original_sink="openc3/lib/openc3/models/tool_config_model.rb and python equivalent / SaveConfigDialog.vue", original_introducing_commit=None, attempted_remediation="9957a9fa added a denylist for path traversal in tool config names.", residual_bypass="Denylist bypass still allowed path-traversed config filenames to write the plugins directory.", final_closure="e6efccbd148ba0e3361c5891027f2373aa140d42 allowlist validation")),
"GHSA-45Q4-X4R9-8FQJ": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="PASS", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Author Copilot <198982749+Copilot@users.noreply.github.com> on 5f795bb5 self-assignment notification wording.",
    note="Blame 3 lines in pkg/models/notifications.go. GHSA is HTML injection via task titles in overdue emails; closer 0f3730d0 escapes markdown. Copilot wording change may have added an unescaped interpolation, but the 3 lines were not dumped. Stays UNKNOWN.",
    ce=["Bot-authored notification wording is not yet proved as the HTML/markdown sink."]),
"GHSA-VFGX-5Q85-58Q3": dict(v="FALSE_POSITIVE", c="HIGH", cc=None, fp="RENAME_OR_MOVE_ONLY", term=True,
    g=dict(identity_gate="PASS", ai_hunk_gate="FAIL", topology_gate="PASS", but_for_gate="FAIL", fix_reversal_gate="FAIL", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-Authored-By: Claude on 990c09c4 'Extract steganography module into plugin architecture' (42 files, modules/ -> plugins/).",
    note="Affirmative move/refactor carrying the pre-existing non-crypto PRNG. Not an explicit security-guard attempt, so not incomplete-remediation. Closer 09e96e09 replaces random.seed/shuffle with HMAC-SHA256 CSPRNG in the moved plugin files.",
    ce=["Plugin extraction preserves the old PRNG; moving code fails but_for."]),
"GHSA-4MPH-V827-F877": dict(v="FALSE_POSITIVE", c="HIGH", cc=None, fp="SIBLING_SINK_NOT_ADVISORY_MECHANISM", term=True,
    g=dict(identity_gate="PASS", ai_hunk_gate="FAIL", topology_gate="PASS", but_for_gate="FAIL", fix_reversal_gate="FAIL", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Claude trailers on 042af9ca hardening parse_str against includes() bypass.",
    note="Affirmative sibling-sink: advisory mechanism is unserialize() __proto__ injection. Candidate files are parse_str.js plus parse_str tests; unserialize.ts appears only in closer 345a6211. A parse_str guard plus a later unserialize fix is not incomplete-remediation causality.",
    ce=["parse_str is surface A; unserialize is pre-existing surface B."]),
"GHSA-X2HW-PX52-WP4M": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Copilot trailer on 183-file bn254/poseidon feature #1667.",
    note="Fr constructed without reducing mod r is a plausible origin in bn254.rs, but Copilot is not isolated as the Fr From<U256>/PartialEq author. Fix 082424b applies rem_euclid(r).",
    ce=["Large crypto feature carrier; Copilot trailer is not Fr-hunk proof."]),
"GHSA-HQJG-PWW4-PCGQ": dict(v="UNKNOWN", c="LOW", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="No Co-Authored-By. Body mentions Jules could not finish a docs task on 9c141469.",
    note="Docs commit overlapping src/core/files.ts with path-traversal closer ba6bd666. Jules note is not relevant-hunk AI proof. Missing marker stays UNKNOWN.",
    ce=["Jules timeout note is not files.ts path-traversal authorship."]),
"GHSA-3RMJ-9M5H-8FPV": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="UNKNOWN", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Co-authored-by: Claude among many humans/bots on 336b0033 'Merge main into next' (49 files, n_parents=1 squash).",
    note="Server Islands missing body limit. Squash/merge carrier transfers authorship. Fix f9ee8685 adds security.serverIslandBodySizeLimit.",
    ce=["Squash of merge main-into-next cannot close topology or ai_hunk."]),
"GHSA-9R75-G2CR-3H76": dict(v="UNKNOWN", c="MEDIUM", cc="UNRESOLVED", fp=None, term=False,
    g=dict(identity_gate="PASS", ai_hunk_gate="UNKNOWN", topology_gate="PASS", but_for_gate="UNKNOWN", fix_reversal_gate="UNKNOWN", release_gate="UNKNOWN", uniqueness_gate="PASS"),
    marker="Claude trailers on 02681dce hook.dispose(). Fix 30e24d44 is also Claude (reject deterministic createWebhook tokens).",
    note="create-hook.ts overlap exists, but dispose() is not proved as the user-specified webhook-token option. Fix-side Claude is not origin. Stays UNKNOWN.",
    ce=["dispose() vs createWebhook token may be sibling surfaces in the same file."]),
}

def open_fail(g):
    open_g = [k for k in GATES if g[k] in ("UNKNOWN","NARROW")]
    fail_g = [k for k in GATES if g[k] == "FAIL"]
    return open_g, fail_g

gate_matrix = []
cases = []
reviewed_ids = []
counts = dict(CONFIRM=0, NARROW=0, FALSE_POSITIVE=0, UNKNOWN=0, terminal_true=0, terminal_false=0, countable_pass=0, proposed_acceptances=0)

for i, raw in enumerate(rows_in):
    b = raw.get("best") or {}
    ghsa = raw["ghsa_id"]
    repo = raw["repository"]
    j = J[ghsa]
    adv, apath = load_adv(ghsa)
    g = j["g"]
    open_g, fail_g = open_fail(g)
    v = j["v"]
    term = j["term"]
    counts[v] += 1
    counts["terminal_true" if term else "terminal_false"] += 1
    reviewed_ids.append(ghsa)
    gm = {
        "ord": i+1,
        "case_id": ghsa,
        "repository": repo,
        "verdict": v,
        "confidence": j["c"],
        "contribution_class": j["cc"],
        "fp_class": j["fp"],
        "terminal": term,
        "failing_gates": fail_g,
        "open_gates": open_g,
        **g,
    }
    gate_matrix.append(gm)
    first_party = []
    if apath:
        first_party.append(apath)
    first_party.extend(adv.get("refs") or [])
    case = {
        "schema_version": "wave2-slice01-kind1-v1",
        "row_kind": "directroot_kind1",
        "assigned_order": i+1,
        "case_id": ghsa,
        "aliases": adv.get("aliases") or [],
        "packages": adv.get("pkgs") or [],
        "repository": repo,
        "summary": raw.get("summary") or adv.get("summary"),
        "candidate_set": [b.get("ai_sha")] if b.get("ai_sha") else [],
        "carrier_set": [],
        "minimum_fix_set": [b.get("fix")] if b.get("fix") else [],
        "parent": b.get("parent"),
        "n_parents": b.get("n_parents"),
        "atomic_first_parent": b.get("atomic_first_parent"),
        "history_files": b.get("history_files") or [],
        "blame_files": b.get("blame_files") or [],
        "blame_lines": b.get("blame_lines") or 0,
        "commit_refs": raw.get("commit_refs") or [],
        "mechanism_key": None,
        "scope_statement": j["note"],
        "contribution_class": j["cc"],
        "false_positive_class": j["fp"],
        "verdict": v,
        "confidence": j["c"],
        "terminal": term,
        "countable": False,
        "countable_proposal": False,
        "causal_admission": False,
        "gates": g,
        **g,
        "failing_gates": fail_g,
        "open_gates": open_g,
        "ai_marker_evidence": j["marker"],
        "first_party_sources": first_party,
        "clone_path": CLONES.get(repo),
        "advisory_path": apath,
        "notes": [j["note"]],
        "counterevidence": j["ce"],
        "english_only": True,
        "worker_pass_is_proposal_only": True,
        "did_not_use_github_api": True,
        "lane": "herdr-260814-w2-unknown9-grok46-high",
        "original_vulnerability": j.get("ov"),
        "replay_commands": [
            f"git -C {CLONES.get(repo)} show -s --format=%H%n%P%n%an%n%ae%n%s {b.get('ai_sha')}",
            f"git -C {CLONES.get(repo)} diff-tree --no-commit-id --name-only -r {b.get('ai_sha')}",
            f"git -C {CLONES.get(repo)} show -s --format=%H%n%P%n%an%n%ae%n%s {b.get('fix')}",
            f"git -C {CLONES.get(repo)} diff-tree --no-commit-id --name-only -r {b.get('fix')}",
        ],
        "baseline_overlap_disposition": "Not in canonical84 ledger.jsonl (0/30 overlap). Proposal only.",
        "disagreement_with_stored_labels": "None; slice-01 rows have no stored seven-gate labels.",
        "slice_sha256": slice_sha,
        "withdrawn": adv.get("withdrawn"),
    }
    cases.append(case)

ended = datetime.now(timezone.utc)
n = len(rows_in)
result = {
    "schema_version": "wave2-slice01-kind1-v1",
    "artifact_kind": "ghsa200_wave2_slice01_kind1",
    "owned_directory": "autoresearch/herdr-260814-w2-unknown9-grok46-high",
    "worker": "grok46-high",
    "language": "en",
    "english_only": True,
    "lane": "herdr-260814-w2-unknown9-grok46-high",
    "started_at": started.isoformat(),
    "ended_at": ended.isoformat(),
    "terminal": counts["terminal_false"] == 0,
    "status": "NONTERMINAL" if counts["terminal_false"] else "TERMINAL",
    "did_not_edit_ledger": True,
    "did_not_use_github_api": True,
    "did_not_expand": True,
    "did_not_invent_evidence": True,
    "did_not_commit_or_push": True,
    "did_not_edit_outside_owned_dir": True,
    "ledger_gates_treated_as_non_evidence": True,
    "assigned": n,
    "reviewed": n,
    "assigned_slice": "autoresearch/orchestrator-260814-ghsa200-canvas/wave2/slice-01.jsonl",
    "kind": "directroot_kind1",
    "counts": {
        "assigned": n,
        "reviewed": n,
        **counts,
        "ai_hunk_unknown": sum(1 for r in gate_matrix if r["ai_hunk_gate"]=="UNKNOWN"),
        "identity_fail": sum(1 for r in gate_matrix if r["identity_gate"]=="FAIL"),
    },
    "conservation": {
        "assigned": n,
        "reviewed": n,
        "unreviewed": 0,
        "did_not_pad": True,
        "equation": f"{n}={n}+0",
        "holds": True,
        "reviewed_case_ids": reviewed_ids,
    },
    "claim_boundary": {
        "worker_PASS": "proposal only; this packet has zero CONFIRM and zero countable PASS unless listed",
        "canonical_ledger_edited": False,
        "more_than_200_claim_supported_by_this_review": False,
        "publication_status": "HOLD",
    },
    "gate_matrix": gate_matrix,
    "input_hashes": {
        "slice_sha256": slice_sha,
        "contract_sha256": contract_sha,
    },
    "blockers": [
        "Release tags were not independently named for any proposed incomplete-remediation row; missing tags were not converted into FAIL or unreleased-FP.",
        "Several Copilot/Claude trailers sit on large cherry-pick, rename, or feature carriers; those stay UNKNOWN or FALSE_POSITIVE from file-list disproof, never from absent blobs.",
    ],
    "causal_admission": False,
}

lines = []
lines.append("# Wave-2 slice-01 kind-1 adjudication (grok-4.6 high)")
lines.append("")
lines.append("Owner: autoresearch/herdr-260814-w2-unknown9-grok46-high/. Proposal only. Assigned slice-01.jsonl, 30 kind-1 directroot rows. No expansion. No GitHub API. Missing evidence stays UNKNOWN. Canonical ledger was not edited. Publication and greater-than-200 stay HOLD.")
lines.append("")
lines.append("## Verdict-first")
lines.append("")
lines.append(f"Reviewed {n}/{n}. CONFIRM 0, NARROW 0, FALSE_POSITIVE {counts['FALSE_POSITIVE']}, UNKNOWN {counts['UNKNOWN']}. terminal_true={counts['terminal_true']} terminal_false={counts['terminal_false']}. countable_proposal=0.")
lines.append("")
lines.append("| # | Case | Repo | Verdict | Open / failed gates | Notes |")
lines.append("| ---: | --- | --- | --- | --- | --- |")
for gm, case in zip(gate_matrix, cases):
    gates = ",".join((gm["failing_gates"] or []) + (gm["open_gates"] or [])) or "none"
    note = case["ai_marker_evidence"].replace("|","/")
    if len(note) > 140:
        note = note[:137] + "..."
    lines.append(f"| {gm['ord']} | {gm['case_id']} | {gm['repository']} | {gm['verdict']} | {gates} | {note} |")
lines.append("")
lines.append("## Method")
lines.append("")
lines.append("Kind-1 rows with best.ai_sha + fix. Local clones under /home/hanqing/.cache/ghsa200-worker-clones/, first-party GHSA JSON from commit-gn/advisory-database, git show / diff-tree file lists, and commit trailers. No gh api. Uniqueness checked against orchestrator-260814-ghsa200-canonical84/ledger.jsonl (zero slice IDs present). Worker PASS/CONFIRM is proposal only.")
lines.append("")
lines.append("## What closed")
lines.append("")
lines.append("Identity PASS on all 30 from frozen GHSA objects (none withdrawn). Uniqueness PASS on all 30; shared Gogs SHAs 36d56d55 and a1fa62b2 are different mechanisms. ai_hunk PASS only where an explicit Claude trailer or Copilot bot author sits on an atomic commit whose file set is the advisory sink (OpenC3 denylist, Gogs data-URI sanitizer, Fiber cache bot, Vikunja Copilot notification author). OpenC3 also closes topology, patch-delta but_for, and fix_reversal on the denylist→allowlist pair. Seven FALSE_POSITIVE rows are affirmative file-list disproof, not missing blobs.")
lines.append("")
lines.append("## What stayed open")
lines.append("")
lines.append("Release stays UNKNOWN on every row: local tag --contains / name-rev did not name a vulnerable-then-fixed pair for the strongest incomplete-remediation candidate (OpenC3 9957a9fa / e6efccbd). Large cherry-pick and feature carriers (Coder, Babylon, ZITADEL, Soroban, Astro squash) keep ai_hunk/topology UNKNOWN. Claude/Copilot trailers on tests, docs, or sibling files were not treated as origin.")
lines.append("")
lines.append("## Per-gate failures")
lines.append("")
for gm, case in zip(gate_matrix, cases):
    if gm["verdict"] == "FALSE_POSITIVE" or gm["failing_gates"]:
        lines.append(f"- {gm['case_id']} {gm['repository']}: {gm['verdict']} failing={gm['failing_gates'] or 'none'}; {case['notes'][0]}")
lines.append("")
lines.append("No gate was failed from absent blobs, DNS errors, or missing tags.")
lines.append("")
lines.append("## Disagreement with stored labels")
lines.append("")
lines.append("None. Slice-01 has no stored seven-gate labels. Not in canonical84. OpenC3 is not proposed as CONFIRM because release_gate is open.")
lines.append("")
lines.append("## Evidence paths")
lines.append("")
lines.append(f"- slice: {SLICE} sha256={slice_sha}")
lines.append(f"- contract: {CONTRACT}")
lines.append("- advisory root: /home/hanqing/.cache/ghsa200-worker-clones/commit-gn/advisory-database")
lines.append("- clones: commit-af/repos, commit-oz/repos, commit-gn/clones as recorded per row")
lines.append("")

(OWNED / "result.json").write_text(json.dumps(result, indent=2) + "\n")
(OWNED / "cases.jsonl").write_text("\n".join(json.dumps(c, ensure_ascii=True) for c in cases) + "\n")
(OWNED / "report.md").write_text("\n".join(lines) + "\n")
print("wrote", n, "CONFIRM", counts["CONFIRM"], "FP", counts["FALSE_POSITIVE"], "UNK", counts["UNKNOWN"])
