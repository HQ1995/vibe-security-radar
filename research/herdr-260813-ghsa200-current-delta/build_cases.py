#!/usr/bin/env python3
"""Phase 7: assemble cases.jsonl and result.json for the current-delta worker.

cases.jsonl rows:
  - one row per ODD-partition ID (338): deep-adjudicated rows carry full
    seven-gate evidence; the rest are UNKNOWN with routing/queue data.
  - one row per modified github-reviewed advisory with identity/alias/range
    changes (72): separate review, never counted as new IDs.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_delta import OWN, sha256_file, sha256_bytes  # noqa: E402

QA_ADDED = Path("/home/hanqing/agents/ai-slop/autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/github_reviewed_window_added_ids.txt")

GATES = ["identity_gate", "ai_hunk_gate", "topology_gate", "but_for_gate",
         "fix_reversal_gate", "release_gate", "uniqueness_gate"]


def nibble(gid: str) -> int:
    return int(hashlib.sha256(gid.upper().encode()).hexdigest()[-1], 16)


def rej(case_id, repository, mechanism_key, summary, aliases, fix_shas, introduced,
        ai_marker_evidence, counterevidence, extra=None):
    """Template for a REJECT row: vulnerable hunk not AI-authored."""
    r = {
        "status": "REJECT",
        "case_id": case_id,
        "aliases": aliases,
        "repository": repository,
        "mechanism_key": mechanism_key,
        "scope_statement": summary,
        "contribution_class": None,
        "candidate_set": fix_shas,
        "carrier_set": introduced,
        "minimum_fix_set": fix_shas,
        "identity_gate": "PASS",
        "ai_hunk_gate": "FAIL",
        "topology_gate": "PASS",
        "but_for_gate": "FAIL",
        "fix_reversal_gate": "PASS",
        "release_gate": "PASS",
        "uniqueness_gate": "PASS",
        "ai_marker_evidence": ai_marker_evidence,
        "counterevidence": counterevidence,
        "baseline_overlap": "none",
        "first_party_sources": "github/advisory-database (frozen 39d8887723..current 6e8a7ca9f3), vulnerable-repo git history",
        "partition": "ODD",
    }
    if extra:
        r.update(extra)
    return r


def main() -> int:
    qa_ids = sorted({l.strip().upper() for l in QA_ADDED.read_text().splitlines() if l.strip()})
    odd = [g for g in qa_ids if nibble(g) % 2 == 1]
    reviewed = {json.loads(l)["ghsa"]: json.loads(l) for l in (OWN / "reviewed-delta.jsonl").open()}
    sweep = json.loads((OWN / "recall-sweep.json").read_text())
    sweep_flags = {f["ghsa"]: f for f in sweep["flagged"]}

    ADJ = []
    # ---------------- deep-adjudicated rows ----------------
    ADJ.append(rej(
        "GHSA-2V37-7H3G-55P8", "ai/nanoid",
        "nanoid.custom-generator.zero-size.infinite-loop",
        "nanoid: custom generators can loop indefinitely when size is zero (CVE-2026-67213)",
        ["CVE-2026-67213"],
        ["cb3626d0f3342fdf179cd425fd9c4fbb92c7d0e7", "e10f8d40ce9d1ab47f66d65a16b48086432730d0", "f9d13f150847d117877adee3460a46eceb0cf49b"],
        ["d643045f40 (Fix pool pollution, infinite loop #510)", "a83734e28f (ESM/CJS dual package) - all by Andrey Sitnik, human"],
        "none on vulnerable hunks",
        "all introducing/fix commits authored by maintainer Andrey Sitnik (andrey@sitnik.ru); no AI trailers on any touched commit; fixes cb3626d0/f9d13f15 by same maintainer."))
    ADJ.append(rej(
        "GHSA-3CCP-42PG-HGV6", "traefik/traefik",
        "traefik.connect.pool.response-poisoning",
        "Traefik: cross-user response poisoning via proxied CONNECT on shared backend keep-alive pool",
        [], ["04d36f28e4", "0807b6d5dd", "94a7508817"],
        ["94a7508817 (Defer the CONNECT payload, Simon Delicata, human)"],
        "none on vulnerable hunks",
        "CONNECT pooling code authored by Traefik maintainers Simon Delicata and Kevin Pollet; fixes by same humans."))
    ADJ.append(rej(
        "GHSA-3WHF-VGF2-9W6G", "zingolabs/zaino",
        "zaino-state.non-finalized-reorg.no-cycle-detection",
        "zaino-state: non-finalized state reorg without cycle detection or depth limit",
        [], ["428822509b"],
        ["32c7fdb5 (start reimplementing handle reorg, Hazel OHearn, Dec 2025, human)"],
        "none on vulnerable hunks",
        "reorg loop introduced by zingolabs maintainer Hazel OHearn; fix 'add bound to reorg loop' by same author."))
    ADJ.append(rej(
        "GHSA-6V4J-43GG-VJ32", "yt-dlp/yt-dlp",
        "yt-dlp.write-link.unescaped-value.code-injection",
        "yt-dlp: --write-link output not escaped (code injection via crafted link values)",
        [], ["b6590aaa1e"],
        ["9c393e3f62 / e59c82a74c (Authored-by: pomtnp / seproDev trailers, human contributors)"],
        "none on vulnerable hunks",
        "vulnerable --write-link path authored by human contributors (bashonly, seproDev, pomtnp per 'Authored by:' trailers); fix by bashonly (human)."))
    ADJ.append(rej(
        "GHSA-8XCM-R25X-G524", "nodejs/undici",
        "undici.retry-interceptor.content-length.desync",
        "undici: downstream response desynchronization via retry interceptor stale Content-Length",
        [], ["1b5a5312c3", "2b3f749336", "4a9dafb16f", "4fd5a0c61e", "cba3a52ac2", "e11a68ed4f"],
        ["d0399c40f1 (retry-handler.js creation, Carlos Fuentes, Jul 2025, human)"],
        "commit 01122dafab carries 'Assisted-by: openai:gpt-5.5' trailer (Trivikram Kamat, May 2026)",
        "gpt-5.5-assisted commit changed only rangeHeaderRegex in lib/core/util.js (parse 'bytes X-Y/*' for test fixtures) - not the retry/Content-Length mechanism; retry-handler authored by Carlos Fuentes; fixes by Matteo Collina/Ulises Gascon (humans)."))
    ADJ.append(rej(
        "GHSA-MHVJ-JHPQ-885V", "http4s/blaze",
        "blaze.http1-parser.request-smuggling.primitives",
        "blaze: multiple HTTP/1.1 request-smuggling primitives in the Java wire parser",
        [], ["3f7c022e30", "4eec200780", "927b67753a", "a54bc9cd31", "c47d9675f8", "e871ebb1d2"],
        ["7304f64362 / 64f8dea5ba (wire parser history, blaze team, human)"],
        "none on vulnerable hunks",
        "parser authored by http4s/blaze maintainers (Ross A. Baker, ERobertGII); fixes by same humans."))
    ADJ.append(rej(
        "GHSA-PM5P-7W5H-JM5Q", "alextselegidis/easyappointments",
        "easyappointments.caldav.connection-test.ssrf",
        "Easy!Appointments: SSRF in CalDAV connection test exposes internal network",
        [], ["2da2baed18", "4abb10545d", "6b34b78c47", "6eb9336a91"],
        ["de63955341 (Integrate CalDAV Protocol #209, Alex Tselegidis, May 2024, human)", "f398d18bbc (Jun 2024, human)"],
        "commit a1b005161d carries 'Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>' (David Pinkerton, Apr 2026)",
        "Claude-co-authored commit changed only CalDAV XML namespace-URI parsing and try/catch error handling; get_http_client URL fetch (SSRF source) introduced by Alex Tselegidis in 2024 before any AI involvement; fixes by same maintainer."))
    ADJ.append(rej(
        "GHSA-RM67-G9CH-VXFF", "poweradmin/poweradmin",
        "poweradmin.dnsrecord.edit.zone-idor",
        "Poweradmin: IDOR - zone owner can modify DNS records in zones they do not own",
        [], ["12651facf4", "88f443d0bd", "e021067157"],
        ["98a4d6a3e4 (Edmondas Girkantas, Dec 2024, human)"],
        "none on vulnerable hunks",
        "record-edit path authored by maintainer Edmondas Girkantas; fixes by same author."))
    ADJ.append(rej(
        "GHSA-WFP6-F47H-HXC3", "aws/aws-cli",
        "awscli.output-files.permissive-permissions",
        "AWS CLI: overly permissive file permissions for credential/bootstrap outputs",
        [], ["68811b5ad5", "84f0ec6afd", "0799fde3c"],
        ["27bc82da09 (iamvirtmfa.py creation, AWS maintainers, human)"],
        "none on vulnerable hunks",
        "permission modes authored by AWS CLI maintainers (Manthan Jamdagni, aahallal, FiveSlashNine fixes are human)."))
    ADJ.append(rej(
        "GHSA-X83G-979R-F5FH", "Sylius/MolliePlugin",
        "sylius-mollie.webhook.idor.order-token-pii",
        "Sylius Mollie Plugin: unauthenticated IDOR leaks order token and customer PII",
        [], ["01316b3ad3", "153c754486", "d1f7753e92"],
        ["plugin webhook code authored by Sylius maintainers (Kamil Grygierzec, human)"],
        "none on vulnerable hunks",
        "fixes by Kamil Grygierzec (Sylius core maintainer); no AI markers in plugin history."))
    ADJ.append(rej(
        "GHSA-XR9X-R78C-5HRM", "rails/rails",
        "rails.active-storage.vips-variant.arbitrary-file-read-rce",
        "Active Storage: arbitrary file read and RCE in vips variant processing",
        [], ["1c01bb5872", "349e7a5d5b", "d79b7f4aa1"],
        ["ac296a1b27 / 684e7609a7 (vips analyzer, Rails core, human)"],
        "none on vulnerable hunks",
        "libvips loader configuration authored by Rails maintainers (Mike Dalessio authored the fixes); introduced pre-AI era."))
    ADJ.append(rej(
        "GHSA-2Q4P-G7HV-5RGV", "thephpleague/commonmark",
        "commonmark.multibyte-parsing.quadratic-dos",
        "league/commonmark: quadratic-time DoS when parsing crafted Markdown",
        [], ["a6ef6cdc30", "a70979ea0d", "c97b02e5e6"],
        ["2780470a88 / 3067b93862 (Cursor/UrlAutolinkParser history, Colin O'Dell et al., human)"],
        "copilot-swe-agent[bot] authored 629da942ca 'Fix AutolinkExtension to anchor regex'; fixes carry 'Co-Authored-By: Claude Opus 4.8' and 'Claude-Session:' trailers",
        "copilot-swe-agent commit ADDED the '^' regex anchor (a mitigation of the quadratic path, not its introduction); vulnerable multibyte cursor scanning predates (introduced 0.6.0-era); AI trailers sit on the fixes by Colin O'Dell/Graham Campbell - vulnerable hunk itself human-authored."))
    ADJ.append(rej(
        "GHSA-4J8X-X6V7-W9RQ", "FlowiseAI/Flowise",
        "flowise.csvagent.csvfile-data-uri.python-rce",
        "Flowise: RCE via CSVAgent csvFile data URI base64 interpolated into Python source",
        [], ["f4e2794f6a"],
        ["366d38b861 / 0c6924bb08 (squash-carriers of CSVAgent.ts; constituent authors Henry Heng et al., human)"],
        "commit 1449e80d34 carries 'Co-authored-by: gemini-code-assist[bot]' (Ankit5467, May 2026)",
        "gemini-code-assist commit extended the AWS Bedrock node (unrelated files); CSVAgent Python-code generation authored by Flowise maintainer Henry Heng; remediation deletes the node entirely (fix f4e2794f6a by yau-wd, human)."))
    ADJ.append(rej(
        "GHSA-4JWF-M4WG-8P66", "microsoft/kiota",
        "kiota.plugin-manifest.static-template-file.path-url-injection",
        "Microsoft Kiota: path/URL injection into generated Copilot plugin manifest via x-ai-* extensions",
        [], ["9a185994a4"],
        ["ee538eae (feat: support x-ai-capabilities in plugin manifest, Samwel K., Apr 2025, human)"],
        "commit dee8b673dc carries 'Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>' (Sebastien Levert, Jul 2026)",
        "Copilot-co-authored commit added only isNonConsequential confirmation mapping; the vulnerable static_template raw passthrough (WriteRaw) was authored by Samwel K. (Apr 2025, human, Co-authored-by: Vincent Biret); fix 9a185994a4 by Jingjing Jia (human)."))
    ADJ.append(rej(
        "GHSA-52FH-8V99-63C2", "FlowiseAI/Flowise",
        "flowise.pyodide-validator.unicode-homoglyph.rce-bypass",
        "Flowise: Pyodide validator Unicode homoglyph bypass leads to RCE",
        [], ["f4e2794f6a"],
        ["a24acac5 (Sanitize Code Ran in Pyodide #5701) and 0c8236ac (#5836), christopherholland-workday, human"],
        "none on vulnerable hunks",
        "Pyodide sanitizer and its bypass surface authored by Workday security engineers (humans); fix by yau-wd (human)."))
    ADJ.append({
        "status": "BLOCKED", "case_id": "GHSA-7835-87Q9-RGVV",
        "aliases": ["CVE-2026-55607"], "repository": "anthropics/claude-code",
        "mechanism_key": "claude-code.sandbox.git-worktree-path-confusion.escape",
        "scope_statement": "Claude Code: sandbox escape via git worktree path confusion allows unsandboxed code execution",
        "contribution_class": None, "candidate_set": [], "carrier_set": [],
        "minimum_fix_set": [], "identity_gate": "PASS",
        "ai_hunk_gate": "UNKNOWN", "topology_gate": "UNKNOWN", "but_for_gate": "UNKNOWN",
        "fix_reversal_gate": "UNKNOWN", "release_gate": "PASS",
        "uniqueness_gate": "PASS",
        "ai_marker_evidence": "none retrievable",
        "counterevidence": "",
        "baseline_overlap": "none",
        "blocked_reason": ("advisory references no fix commits (only release tag v2.1.163 and security-advisory URL); "
                           "public anthropics/claude-code tag history exposes only CHANGELOG/feed deltas between "
                           "v2.1.162 and v2.1.163; the vulnerable-hunk introducing commit is not reachable from "
                           "first-party sources. Fixed released artifact v2.1.163 exists (release_gate PASS for the fixed side)."),
        "first_party_sources": "github/advisory-database (frozen..current), anthropics/claude-code public repo tags",
        "partition": "ODD",
    })
    ADJ.append(rej(
        "GHSA-C5PX-58J2-7FQP", "eLyiN/gemini-bridge",
        "gemini-bridge.consult-gemini-with-files.inline.path-traversal",
        "gemini-bridge: arbitrary local file read via consult_gemini_with_files inline mode",
        [], ["8f3b85afd0"],
        ["c0ac13b4 (initial release v1.0.0, Adrian Arribas Lopera, Aug 2025, human)"],
        "none on vulnerable hunks (product description mentions Claude Code/Gemini; no authorship trailers)",
        "consult_gemini_with_files introduced by maintainer Adrian Arribas in initial release; fix 8f3b85afd0 by same author."))
    ADJ.append(rej(
        "GHSA-GMFW-G93R-VG53", "open-webui/open-webui",
        "open-webui.ydoc-websocket.unauthenticated-handlers",
        "Open WebUI: unauthenticated WebSocket access to collaborative document handlers",
        ["CVE-2026-59715"], ["22f2fe1ffb"],
        ["e8e9141 (refac, Timothy Jaeryang Baek, May 2026, human)"],
        "none on vulnerable hunks",
        "ydoc awareness/document handlers authored by open-webui founder Timothy Baek; fix by Classic298 (human)."))
    ADJ.append(rej(
        "GHSA-HC4M-Q9JH-XW4J", "nolabs-ai/nono",
        "nono.registry-pack-verification.fail-open-missing-provenance",
        "nono-cli: registry pack verification fails open when provenance metadata is absent",
        [], ["db07375031"],
        ["088bdad (feat(profile): introduce packs and command_args, Luke Hinds, Apr 2026, human); 0b05508 (May 2026, human)"],
        "commit 0ced085a6f carries 'Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>' (Leonardo Zanivan, May 2026)",
        "Claude-co-authored commit touched only line 18 (PreparedProfile struct) of profile_runtime.rs - not the verify_profile_packs fail-open logic; verification introduced by maintainer Luke Hinds; fix db07375031 (fork merge) by Luke Hinds."))
    ADJ.append(rej(
        "GHSA-HFHX-W8P8-4HC7", "Budibase/budibase",
        "budibase.uploadurl.bare-fetch.ssrf-ai-table-generation",
        "Budibase: SSRF via bare fetch() in uploadUrl during AI table generation",
        [], ["72e602d68d"],
        ["c8fc01fa0c (Extract utils from controller, Adria Navarro, Apr 2025, human)"],
        "fix PR #18866 branch 'codex/fix-vulns-73-ssrf-uploadurl' is Codex-authored",
        "Codex authored the FIX (fetch -> utils.fetchWithBlacklist); the vulnerable bare fetch in uploadUrl was introduced by maintainer Adria Navarro (Apr 2025); AI-table-generation rows.ts authored by Sam Rose (human, Mar 2025). Vulnerable hunk human-authored."))
    ADJ.append(rej(
        "GHSA-HR7P-WG7R-HG9M", "flytohub/flyto-core",
        "flyto-core.env-interpolation.denylist-bypass",
        "Flyto2 Core: ${env.VAR} interpolation reads any env secret despite env.get denylist",
        ["CVE-2026-67427"], ["d5f89d7130"],
        ["42b15c6 (feat(verify): dynamic Spec-as-Test framework, Chester, Feb 2026, human)"],
        "none on vulnerable hunks",
        "env interpolation authored by maintainer ChesterHsu; fix by same author."))
    ADJ.append(rej(
        "GHSA-PGWH-4JJ4-QM8V", "flytohub/flyto-core",
        "flyto-core.http-modules.ssrf-guard-missing",
        "Flyto2 Core: HTTP-family modules fetch client-controlled URLs without SSRF guard",
        ["CVE-2026-67428"], ["0a0a528520"],
        ["b835e45 / 42b15c6 (Chester, Feb 2026, human)"],
        "none on vulnerable hunks",
        "HTTP modules authored by maintainer ChesterHsu; fix by same author."))
    ADJ.append(rej(
        "GHSA-VQFP-P66C-XRP9", "ether/etherpad",
        "etherpad.token-transfer.endpoint.replayable",
        "ep_etherpad-lite: author-token transfer endpoint is replayable and never expires",
        [], ["a6de73c"],
        ["fd2f3ba (tokenTransfer.ts introduction, SamTV12345, May 2026, human)"],
        "none on vulnerable hunks",
        "token-transfer endpoint authored by community contributor SamTV12345; fix a6de73c by John McLear (human)."))
    ADJ.append(rej(
        "GHSA-WG86-R78F-74MP", "FlowiseAI/Flowise",
        "flowise.pyodide-sandbox.escape.rce",
        "Flowise: sandbox escape to RCE",
        [], ["3f257bdc81"],
        ["0c6924bb08 / 366d38b861 (squash-carriers; constituent authors Henry Heng et al., human)"],
        "commit 1449e80d34 carries 'Co-authored-by: gemini-code-assist[bot]' (unrelated AWS Bedrock node)",
        "sandbox/Pyodide surface authored by Flowise maintainers; fix 3f257bdc81 (FLOWISE-400/543/551) by Ilango (human)."))
    ADJ.append(rej(
        "GHSA-XRMJ-5G4G-8987", "dynatrace-oss/dynatrace-mcp",
        "dynatrace-mcp.create-workflow-template.injection",
        "@dynatrace-oss/dynatrace-mcp-server: workflow template injection via create_workflow_for_notification",
        [], ["64dfcb1095"],
        ["10eb041 (feature: Added implementation for Dynatrace-MCP, Christian Kreuzberger, Apr 2025, human)"],
        "Copilot authored removal commit 8f975d6f 'feat!: remove create_workflow_for_notification' (Co-authored-by: copilot-swe-agent[bot])",
        "Copilot authored the REMOVAL (fix closure); the vulnerable tool was introduced by maintainer Christian Kreuzberger (Apr 2025, human)."))
    ADJ.append(rej(
        "GHSA-W6P7-2FXX-4F44", "pocket-id/pocket-id",
        "pocket-id.oidc.refresh-token.missing-authorization-checks",
        "Pocket ID: OIDC refresh token flow bypasses authorization revocation, account disabling, group removal",
        [], ["978ac87deffe"],
        ["8c96381 (fix: hash the refresh token in the DB #379, Alessandro Segala, Mar 2025, human); core OIDC by Elias Schneider (human)"],
        "commit 59fe481a (#1299) carries 'Co-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>' and 'Co-authored-by: Claude Opus 4.6 (1M context) <noreply@anthropic.com>'",
        "AI-co-authored #1299 added only prompt-error redirect handling in the authorize controller; the vulnerable createTokenFromRefreshToken (missing disabled-user/client/group checks) predates it and is human-authored; fix 978ac87deffe by Elias Schneider (human)."))
    ADJ.append(rej(
        "GHSA-33QV-C5QM-799V", "NousResearch/hermes-agent",
        "hermes-agent.injection.unspecified",
        "hermes-agent has an injection issue",
        [], ["0dee92df22"],
        ["mechanism introduced at 0 (pre-AI era, Teknium et al., human)"],
        "commit carrying 'Co-Authored-By: Claude Opus 4.7' is 'chore(models): drop retired grok-4-1-fast' (ronhi, May 2026)",
        "flagged AI-trailered commit is an unrelated model-metadata chore; fix 'promptware defense' by Teknium (human)."))
    ADJ.append(rej(
        "GHSA-WQQC-JJCQ-VFXM", "sigstore/sigstore-go",
        "sigstore-go.managed-key.verification.missing-timestamp-check",
        "sigstore-go fails to check signature timestamps against signing key validity",
        [], ["4594ab4c77"],
        ["managed-key verification authored by sigstore-go maintainers (human)"],
        "commit 4594ab4c77 'Fix conformance test failures' carries 'Co-authored-by: Claude Opus 4.6' (Cody Soyland, Jun 2026)",
        "flagged AI-trailered commit is test/conformance-only; the vulnerable verification logic predates it; fix 'Check signature time against public key validity window (#642)' by Hayden (human)."))
    ADJ.append(rej(
        "GHSA-HP74-GM6M-2QM5", "pocket-id/pocket-id",
        "pocket-id.onetime-token.reauthentication-bypass",
        "Pocket ID: reauthentication bypass via one-time access token login",
        [], ["978ac87deffe"],
        ["introduced 0; core OIDC authored by Elias Schneider (human)"],
        "see GHSA-W6P7-2FXX-4F44 AI-marker notes (Copilot/Claude on #1299 controller hunk only)",
        "same fix as W6P7; vulnerable reauthentication path human-authored; AI-co-authored #1299 touched a different hunk."))
    ADJ.append(rej(
        "GHSA-XMF8-CVQR-RFGJ", "nextauthjs/next-auth",
        "next-auth.getToken.malformed-bearer.uncaught-exception",
        "Auth.js: getToken() throws uncaught exception on malformed Bearer authorization",
        [], ["5bca2399a7", "e707770f00"],
        ["introduced 0.1.0 (2021-era Auth.js core, human)"],
        "commit e707770f00 carries 'Co-Authored-By: Claude Opus 4.8' (Bereket Engida, Jun 2026)",
        "flagged AI-trailered commit is a dependabot pnpm-overrides chore; getToken parsing predates; fix #13469 by Gustavo Valverde (human)."))
    ADJ.append(rej(
        "GHSA-W4HW-QCX7-56PR", "ericcornelissen/shescape",
        "shescape.windows-cmd.unescaped-parentheses.shell-injection",
        "Shescape: shell injection via unescaped parentheses on Windows with CMD",
        [], ["43d70b59d0", "b4b34c394e"],
        ["introduced 0 (Windows CMD escaping authored by Eric Cornelissen, human)"],
        "fixes #2649/#2651 carry 'Assisted-by: Claude Mythos' trailers (Eric Cornelissen, Jul 2026)",
        "AI-assist sits on the FIX commits ('Improve overall escaping'); vulnerable escaping logic predates and is human-authored."))
    ADJ.append(rej(
        "GHSA-WMG3-H8MF-WGVR", "Flux159/mcp-server-kubernetes",
        "mcp-server-kubernetes.kubectl-tools.argument-injection",
        "mcp-server-kubernetes: argument injection in kubectl/helm tools exposes cluster",
        [], ["d7890f50a4"],
        ["tool argv construction authored by Flux159 (human, 2025)"],
        "fix d7890f50a4 carries 'Co-Authored-By: Claude Opus 4.7' (Suyog Sonwalkar, May 2026)",
        "AI-co-authored commit is the FIX ('Block flag injection through positional argv slots'); vulnerable argv passing human-authored."))
    ADJ.append(rej(
        "GHSA-WVPP-8HX9-P66J", "gitpython-developers/GitPython",
        "gitpython.split-single-char-option.guard-bypass",
        "GitPython: unsafe git option guard bypass via split_single_char_option",
        [], ["96a888f4d7"],
        ["f67029c (merge of PR #2205, Sebastian Thiel/Byron, human)"],
        "fix commits 96a888f4d7 carry 'Co-authored-by: GPT 5.6 <codex@openai.com>' (Byron, Aug 2026)",
        "AI-co-authored commits are the FIXES ('Check joined short-option values', 'Reject syntax-bearing option names'); the vulnerable option-parsing code predates and is human-authored."))
    ADJ.append(rej(
        "GHSA-X445-F3H2-J279", "nextauthjs/next-auth",
        "next-auth.oauth-check-cookies.unbound",
        "Auth.js: OAuth state, nonce, PKCE check cookies not bound to the provider",
        [], ["5bca2399a7", "9f7a97fade"],
        ["introduced 0 (core OAuth flow, human-era Auth.js)"],
        "fix merge 9f7a97fade carries 'Co-authored-by: Claude Opus 4.8' (Bereket Engida, Jun 2026)",
        "AI-co-authored commit is the FIX merge ('Merge commit from fork' touching send-token.ts); vulnerable cookie flow predates and is human-authored."))
    # patch-delta (AI_INCOMPLETE_REMEDIATION) audit per revised contract cbd04ef2:
    # the only AI-authored security-adjacent attempt among adjudicated rows is commonmark
    # 629da942ca (copilot-swe-agent, added '^' regex anchor). Its boundary change REDUCED the
    # quadratic path; the later fixes linearize Cursor multibyte scanning, a pre-existing
    # sibling surface the AI patch never touched. Per the patch-delta rule that is not
    # incomplete-remediation causality; row stays REJECT on ai_hunk_gate for AI_DIRECT_ROOT.
    for _r in ADJ:
        if _r["case_id"] == "GHSA-2Q4P-G7HV-5RGV":
            _r["patch_delta_rule_check"] = (
                "AI security-adjacent attempt 629da942ca (anchor regex) does not qualify as "
                "AI_INCOMPLETE_REMEDIATION under contract cbd04ef2: the residual quadratic paths "
                "closed by the advisory fix are pre-existing sibling surfaces the AI patch never "
                "touched; the AI boundary change itself reduced exposure.")

    adj_by_id = {r["case_id"]: r for r in ADJ}

    # ---------------- assemble cases.jsonl ----------------
    out_rows = []
    for gid in odd:
        r = reviewed[gid]
        n = r["new"]
        base = {
            "case_id": gid,
            "aliases": n.get("aliases") or [],
            "repository": (n.get("ref_repos") or [None])[0],
            "ecosystems": n.get("ecosystems") or [],
            "packages": n.get("packages") or [],
            "published": n.get("published"),
            "summary": n.get("summary"),
            "partition_proof": {
                "sha256_hex": hashlib.sha256(gid.encode()).hexdigest(),
                "last_nibble": f"{nibble(gid):x}",
                "owner": "current-delta",
            },
            "collisions": r["collisions"],
            "recall_sweep_flag": bool(sweep_flags.get(gid)),
        }
        if gid in adj_by_id:
            row = dict(adj_by_id[gid])
            row.update({k: base[k] for k in ("partition_proof", "collisions") if k in base})
            row["status_detail"] = "deep-reviewed"
            row["replay_commands"] = adj_by_id[gid].get("replay_commands", [
                f"python3 autoresearch/herdr-260813-ghsa200-current-delta/deep_collect.py {gid}",
                f"git -C /home/hanqing/.cache/ghsa200-worker-clones/current-delta/repos/<repo> log/show/blame (see evidence JSON)",
            ])
            out_rows.append(row)
        else:
            row = dict(base)
            row.update({
                "status": "REJECT" if any(c.startswith("baseline") for c in r["collisions"]) else "UNKNOWN",
                "mechanism_key": None,
                "scope_statement": n.get("summary"),
                "contribution_class": None,
                "candidate_set": n.get("ref_commit_shas") or [],
                "carrier_set": None,
                "minimum_fix_set": None,
                "identity_gate": "PASS" if (n.get("ref_repos") and n.get("summary")) else "UNKNOWN",
                "ai_hunk_gate": "UNKNOWN", "topology_gate": "UNKNOWN", "but_for_gate": "UNKNOWN",
                "fix_reversal_gate": "UNKNOWN", "release_gate": "UNKNOWN", "uniqueness_gate": "UNKNOWN",
                "ai_marker_evidence": (sweep_flags.get(gid) or {}).get("flags") or [],
                "counterevidence": "",
                "baseline_overlap": "baseline-declared" if any(c.startswith("baseline") for c in r["collisions"]) else "none",
                "first_party_sources": "github/advisory-database (frozen..current)",
                "status_detail": "queue-only-not-adjudicated" if not any(c.startswith("baseline") for c in r["collisions"]) else "baseline-collision-routed",
                "replay_commands": [f"python3 autoresearch/herdr-260813-ghsa200-current-delta/deep_collect.py {gid}"],
            })
            out_rows.append(row)

    # modified-148 identity/alias/range change rows (separate review)
    for line in (OWN / "modified-148-review.jsonl").open():
        c = json.loads(line)
        if c["row_kind"] == "modified_reviewed_review" and (
                c["alias_added"] or c["alias_removed"] or c["range_changed"] or c["withdrawn"]):
            out_rows.append({
                "row_kind": "modified_reviewed_review",
                "case_id": c["ghsa"],
                "status": "NOTE",
                "counted_as_new_id": False,
                "review_scope": "identity/alias/range change note only",
                "alias_added": c["alias_added"],
                "alias_removed": c["alias_removed"],
                "range_changed": c["range_changed"],
                "old_ranges": c["old_ranges"],
                "new_ranges": c["new_ranges"],
                "withdrawn": c["withdrawn"],
                "old_modified": c["old_modified"],
                "new_modified": c["new_modified"],
            })

    cases_path = OWN / "cases.jsonl"
    with open(cases_path, "w") as f:
        for row in out_rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    # ---------------- result.json ----------------
    api_manifest = json.loads((OWN / "api-manifest.json").read_text())
    delta_summary = json.loads((OWN / "delta-summary.json").read_text())
    statuses = {}
    for row in out_rows:
        if row.get("row_kind") == "modified_reviewed_review":
            continue
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    result = {
        "schema_version": 1,
        "status": "PARTIAL",
        "status_explanation": ("Deterministic 731-ID manifest and routing queue complete; bounded deep reviews "
                               "completed for 34 odd-partition cases (33 REJECT, 1 BLOCKED, 0 PASS, 0 NARROW); "
                               "remaining odd-partition cases are queue-only UNKNOWN. No completeness claim beyond "
                               "the source enumeration itself."),
        "lane": "current-delta-odd-partition",
        "started_at": delta_summary.get("generated_at_utc"),
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "worker_pass_is_proposal_only": True,
        "pass_rows_emitted": 0,
        "source_denominator": {
            "official_repo": "https://github.com/github/advisory-database.git",
            "frozen_commit": "39d8887723797efc1804585dd06585c9fd751226",
            "frozen_tree": delta_summary["pagination_completeness"]["frozen_tree"],
            "current_commit": "6e8a7ca9f3d8463dc037f2308b57f6cf72b55e86",
            "current_tree": delta_summary["pagination_completeness"]["current_tree"],
            "current_head_date_utc": "2026-08-13T18:29:41+00:00",
            "github_reviewed_delta": {"added": 731, "modified": 148, "deleted": 0},
            "qa_manifest_agreement": "my independently recomputed reviewed-delta set equals the freshness-qa 731-ID manifest exactly",
            "qa_manifest": "autoresearch/herdr-260813-ghsa200-freshness-qa/manifests/github_reviewed_window_added_ids.txt",
        },
        "partition": {
            "rule": "last hex nibble of SHA256(uppercase GHSA ID) is odd -> current-delta; even -> grok lane",
            "odd": 338, "even": 393, "union": 731, "disjoint": True,
            "partition_files": ["autoresearch/herdr-260813-ghsa200-current-delta/partition-odd.txt",
                                "autoresearch/herdr-260813-ghsa200-current-delta/partition-even.txt"],
        },
        "counts": {
            "case_rows": {k: v for k, v in sorted(statuses.items())},
            "deep_reviewed": 34,
            "queue_only_unknown": statuses.get("UNKNOWN", 0),
            "baseline_collision_routed": statuses.get("REJECT", 0) - 33,
            "modified_reviewed_with_changes": 72,
            "modified_reviewed_total": 148,
        },
        "pagination_completeness": {
            "git_method": "full clone of official advisory-database (alternates against frozen local cache, read-only); tree-to-tree diff is complete by construction; no cursors involved",
            "graphql_method": "securityAdvisories publishedSince 2026-07-23T00:00:00Z and updatedSince 2026-07-23T12:34:36Z, 100 nodes/page, orderBy PUBLISHED_AT/UPDATED_AT ASC",
            "graphql_published": {"pages": api_manifest["passes"]["published_since"]["pages"],
                                  "nodes": api_manifest["passes"]["published_since"]["total_nodes"],
                                  "cursor_conservation": api_manifest["passes"]["published_since"]["cursor_conservation"]},
            "graphql_updated": {"pages": api_manifest["passes"]["updated_since"]["pages"],
                                "nodes": api_manifest["passes"]["updated_since"]["total_nodes"],
                                "cursor_conservation": api_manifest["passes"]["updated_since"]["cursor_conservation"]},
            "page_response_sha256_manifest": "autoresearch/herdr-260813-ghsa200-current-delta/api-manifest.json",
            "raw_api_pages_stored_only_under": "/tmp/ghsa200-worker-clones/current-delta/raw/",
        },
        "query_hashes": {
            "query_published_since": sha256_bytes(json.dumps({"publishedSince": "2026-07-23T00:00:00Z", "first": 100, "orderBy": "PUBLISHED_AT ASC"}).encode()),
            "query_updated_since": sha256_bytes(json.dumps({"updatedSince": "2026-07-23T12:34:36Z", "first": 100, "orderBy": "UPDATED_AT ASC"}).encode()),
        },
        "revision_hashes": {
            "frozen_tree": delta_summary["pagination_completeness"]["frozen_tree"],
            "current_tree": delta_summary["pagination_completeness"]["current_tree"],
        },
        "input_hashes": {
            "contract_sha256": "cbd04ef2770d7b93e59032ec92dde3566e1d64df3b1e003dfbcfbea558f90ed3",
            "contract_note": "leader CONTRACT.md revised 2026-08-13 (AI_INCOMPLETE_REMEDIATION patch-delta rule); no incomplete-remediation rows in this worker; direct/contributor but-for unchanged",
            "baseline_sha256": "0939c995b14b419128dc47e4ad767fb136f714bd6f71e028b2528cc4afa8d6d2",
            "qa_added_manifest_sha256": sha256_file(QA_ADDED),
            "exclusion_freeze_sha256": sha256_file(OWN / "exclusion-freeze.json"),
        },
        "output_hashes": {
            "routing_queue": sha256_file(OWN / "routing-queue.jsonl"),
            "reviewed_delta": sha256_file(OWN / "reviewed-delta.jsonl"),
            "modified_148_review": sha256_file(OWN / "modified-148-review.jsonl"),
            "recall_sweep": sha256_file(OWN / "recall-sweep.json"),
            "cases": sha256_file(cases_path),
        },
        "mixed_paths": {
            "policy": "existing current-delta data kept in /tmp; NEW clones/large objects under /home/hanqing/.cache/ghsa200-worker-clones/current-delta",
            "existing_evidence": "/tmp/ghsa200-worker-clones/current-delta/evidence (12 first-batch cases)",
            "new_clones_and_evidence": "/home/hanqing/.cache/ghsa200-worker-clones/current-delta/{repos,evidence}",
            "raw_api_pages": "/tmp/ghsa200-worker-clones/current-delta/raw/",
        },
        "blockers": [
            "0 PASS rows: every deep-reviewed odd-partition case fails ai_hunk_gate - the vulnerable hunk is human-authored; explicit AI markers sit on fixes or unrelated hunks (documented per row).",
            "GHSA-7835-87Q9-RGVV BLOCKED: advisory carries no fix commits; public claude-code tag history exposes only changelog deltas.",
            "304 odd-partition cases remain queue-only UNKNOWN; not causally adjudicated (bounded deep reviews per leader instruction).",
            "Do not read sibling-lane conclusions as evidence; partition ownership (odd/even) is the routing rule.",
        ],
    }
    (OWN / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"cases.jsonl rows: {len(out_rows)}; sha256={result['output_hashes']['cases']}")
    print(json.dumps(result["counts"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
