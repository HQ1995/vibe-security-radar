#!/usr/bin/env python3
"""Bounded first-party identity QA for post-strict-baseline rows."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any


OUT = Path(__file__).resolve().parent
REPO_ROOT = OUT.parents[1]
UA = "ai-slop-alias-qa/2026-08-12"
ID_RE = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})", re.I)
COMMIT_RE = re.compile(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})(?:\b|/)", re.I)
REPO_RE = re.compile(r"https://github\.com/([^/]+/[^/#?]+)", re.I)

SOURCE_FILES = [
    "docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-MAIN-2026-08-12.md",
    "docs/RESEARCH-ALIASFREE-NEW-COMPONENTS-BATCH-A-2026-08-12.md",
    "docs/RESEARCH-OPENCLAW-FRONTIER-12-CLOSURE-2026-08-12.md",
    "docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-B-2026-08-12.md",
    "docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-C-2026-08-12.md",
    "docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-D-2026-08-12.md",
    "docs/RESEARCH-POST135-INCOMPLETE-REMEDIATION-BATCH-E-2026-08-12.md",
    "autoresearch/orchestrator-260811-atomic150/strict-200-v3/ledger.jsonl",
]


def row(
    row_id: str,
    ids: str,
    repo: str,
    fixes: str,
    mechanism: str,
    tier: str,
    source: str,
    *,
    instance: str = "canonical",
) -> dict[str, Any]:
    return {
        "row_id": row_id,
        "instance": instance,
        "ids": ids.upper().split(),
        "repo": repo,
        "proposed_fixes": fixes.lower().split() if fixes else [],
        "mechanism": mechanism,
        "tier": tier,
        "source": source,
    }


ROWS = [
    # Strict additions after strict-200-v3.
    row("bsv-arc-status", "CVE-2026-40069 GHSA-9HFR-GW99-8RHX", "sgbett/bsv-ruby-sdk", "db97de475518eef752ed52b25f49f09cbe24c187", "ARC failure states accepted as success", "STRICT_RELEASED", "Batch-A:15"),
    row("bsv-certificate-signature", "CVE-2026-40070 GHSA-HC36-C89J-5F4J", "sgbett/bsv-ruby-sdk", "db97de475518eef752ed52b25f49f09cbe24c187", "unverified certificate signature persisted", "STRICT_RELEASED", "Batch-A:16"),
    row("claude-cache-statusline-injection", "CVE-2026-45136 GHSA-G3XQ-3GMV-QQ8G", "cnighswonger/claude-code-cache-fix", "0a3e3c130e1ec803a2107fe83775d97f5f8f6dde", "statusline JSON inserted into Python source", "STRICT_RELEASED", "Batch-A:17"),
    row("hermes-first-user-takeover", "CVE-2026-49973 GHSA-P52P-4VMG-4VQ3", "nesquena/hermes-webui", "f2ef2851d389cf7a41308dcf0180d7cfbe446379", "remote first-user password takeover", "STRICT_RELEASED", "Main:63"),
    row("hermes-profile-search", "CVE-2026-49956 GHSA-MGXW-V6RH-WCV6", "nesquena/hermes-webui", "8d8ae89d27a4547b2edc388a986ef0d55549f7d4", "cross-profile session search", "STRICT_RELEASED", "Main:64"),
    row("coolify-trust-host-cache", "CVE-2026-34198", "coollabsio/coolify", "e1d4b4682efc898ba5aa3751b2da2072f89c7e24", "trusted-host negative cache enables forwarded-host poisoning", "STRICT_RELEASED", "Main:65"),
    row("openclaw-minimax-redirect", "CVE-2026-44992 GHSA-H2VW-PH2C-JVWF", "openclaw/openclaw", "2f06696579a1ab0cb5bbbbb6a900414a6b2e3cd1", "MiniMax dotenv redirect leaks bearer credential", "STRICT_RELEASED", "OpenClaw:57"),
    row("openclaw-gateway-url", "CVE-2026-25253 GHSA-G8P2-7WF7-98MQ", "openclaw/openclaw", "a7534dc22382c42465f3676724536a014ce0cbf7", "gatewayUrl token exfiltration and RCE", "STRICT_RELEASED", "OpenClaw:58"),
    row("openclaw-prompt-image", "GHSA-9F72-QCPW-2HXC", "openclaw/openclaw", "370d1155", "prompt image bypasses workspaceOnly", "STRICT_RELEASED", "OpenClaw:59"),
    row("openclaw-browserbase-dns", "CVE-2026-43582 GHSA-XQ94-R468-QWGJ", "openclaw/openclaw", "121c452d666d4749744dc2089287d0227aae2ed3", "remote CDP DNS rebinding", "STRICT_RELEASED", "OpenClaw:60"),
    row("openclaw-sips-pixel", "CVE-2026-41334 GHSA-W85G-3H6X-4XH2", "openclaw/openclaw", "0ed4f8a72bb140045962e97ab01c94c076b758a4", "sips pixel and decompression DoS", "STRICT_RELEASED", "OpenClaw:61"),
    row("openclaw-synology-rate-limit", "CVE-2026-35646 GHSA-MF5G-6R6F-GHHM", "openclaw/openclaw", "0b4d07337467f4d40a0cc1ced83d45ceaec0863c", "pre-auth Synology token guessing lacks rate limit", "STRICT_RELEASED", "OpenClaw:62"),
    row("openclaw-workspace-shadow", "CVE-2026-41295 GHSA-2QRV-RC5X-2G2H CVE-2026-43571 GHSA-82QX-6VJ7-P8M2", "openclaw/openclaw", "53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0 1fede43b948df40ca8674511d4bd08d39f6c5837", "workspace channel shadow and residual", "STRICT_RELEASED", "OpenClaw:63"),
    row("openclaw-feishu-webhook", "CVE-2026-32974 GHSA-G353-MGV3-8PCJ CVE-2026-44109 GHSA-XH72-V6V9-MWHC", "openclaw/openclaw", "7844bc89a1612800810617c823eb0c76ef945804 c8003f1b33ed2924be5f62131bd28742c5a41aae", "Feishu webhook missing encryptKey fail-open", "STRICT_RELEASED", "OpenClaw:65"),
    row("openclaw-feishu-tool-gate", "CVE-2026-62187 GHSA-2Q7J-2VHX-56G8 CVE-2026-62188 GHSA-W8WF-3QVJ-6XQF", "openclaw/openclaw", "d4f11d3005a56abc709ebc8e715972593ebed96e", "per-account Feishu tool-family gate", "STRICT_RELEASED", "OpenClaw:66"),

    # Earlier incomplete-remediation rows summarized by the main report.
    row("zeptoclaw-shell-filter", "GHSA-5WP8-Q9MX-8JX8", "qhkm/zeptoclaw", "68916c3e4f3af107f11940b27854fc7ef517058b", "shell allowlist bypass family", "INCOMPLETE_RELEASED", "Main:107"),
    row("praisonai-ssrf", "CVE-2026-47390 GHSA-5C6W-WWFQ-7QQM", "MervinPraison/PraisonAI", "179cab02dbec0c1e9b601507a65908e079876004", "SSRF alternate loopback encodings", "INCOMPLETE_RELEASED", "Main:108"),
    row("praisonai-python-exec", "CVE-2026-47392 GHSA-4MR5-G6F9-CFRH", "MervinPraison/PraisonAI", "179cab02dbec0c1e9b601507a65908e079876004", "Python object-graph sandbox escape", "INCOMPLETE_RELEASED", "Main:109"),
    row("argo-artifactgc-podspec", "CVE-2026-54526", "argoproj/argo-workflows", "358cc3968c8f06f1be0967e41df191088db0b662 277e9cef0ad16d7eaaab253573d0695951a65dbd", "ArtifactGC PodSpecPatch template-reference bypass", "INCOMPLETE_RELEASED", "Main:110"),
    row("fission-capabilities", "CVE-2026-50570 GHSA-QF5V-M7P4-95RP", "fission/fission", "2569b42bfadbcb7d78b55a00a60f77937e522699", "capability denylist omits SYS_TIME", "INCOMPLETE_RELEASED", "Main:111"),
    row("mcp-registry-ssrf", "CVE-2026-44430 GHSA-R48C-V28R-PF6V", "modelcontextprotocol/registry", "f5f40bd98084466eaf18fe48ea62a0d534caa774", "safeDialContext misses IPv6 ranges", "INCOMPLETE_RELEASED", "Main:112"),
    row("fission-standalone-container", "CVE-2026-50566 GHSA-M63V-2G9W-2W6V", "fission/fission", "695d3e97e3a20463ab7c8c081843e69e65e952e5", "standalone Runtime and Builder container validation", "INCOMPLETE_COMMIT_ONLY", "Main:113"),
    row("fission-path-prefix", "CVE-2026-50568 GHSA-R5JH-Q2MW-GCX4", "fission/fission", "8298e33ea7457702f893eae11077987cf905edb4", "lexical sibling-prefix path escape", "INCOMPLETE_RELEASED", "Main:114"),
    row("clearancekit-auth-clone", "CVE-2026-33632 GHSA-WPXJ-VHFP-HHVM", "craigjbass/clearancekit", "6181c4a22eccbeca973c77f4bd023eb795c13786", "missing AUTH_EXCHANGEDATA and AUTH_CLONE events", "INCOMPLETE_RELEASED", "Main:115"),
    row("fireshare-checksum-path", "CVE-2026-34745 GHSA-FVVP-RJ8G-C7GC", "ShaneIsrael/fireshare", "70b5b35aadd55c7936a25effd6f3e9ee4c124879", "public checksum enters temporary path", "INCOMPLETE_RELEASED", "Main:116"),
    row("filebrowser-scoped-fs", "CVE-2026-54094 GHSA-239W-M3H6-CH8V", "filebrowser/filebrowser", "64511ce45e3be379e965f7f4fb0929a068d5bb81", "incomplete symlink-scope repair chain", "INCOMPLETE_RELEASED", "Main:117"),
    row("kiota-path-decoding", "GHSA-P5RM-JG5C-8C77", "microsoft/kiota", "430008e9d700b3fe80f206c672415cfbd8e830e7", "bounded percent decode fails open", "INCOMPLETE_COMMIT_ONLY", "Main:118"),
    row("vm2-nesting-require", "CVE-2026-47137 GHSA-M4WX-M65X-GHRR", "patriksimek/vm2", "86ab819f202c3a8dad88cef5705f2e416c5188d7", "nesting require-policy type confusion", "INCOMPLETE_RELEASED", "Main:119"),
    row("gitpython-kwarg-option", "GHSA-R9MR-M37C-5FR3", "gitpython-developers/GitPython", "e8d0fbf774d1f6baa3b481adfe48bd262e43b453", "kwarg value becomes option token", "INCOMPLETE_RELEASED", "Main:131"),
    row("gitpython-url-env", "GHSA-94P4-4CQ8-9G67", "gitpython-developers/GitPython", "863417457a0633db7ea5aed4fd01e0b291a41162", "URL environment expansion siblings", "INCOMPLETE_RELEASED", "Main:132"),
    row("gitpython-clone-template", "GHSA-6P8H-3WGX-97GF", "gitpython-developers/GitPython", "ffcb5359e87619f4fe4a70a4aff5f08c5580ba97", "clone template hook option", "INCOMPLETE_RELEASED", "Main:133"),
    row("gitpython-config-section", "GHSA-3RP5-JJMW-4WV2", "gitpython-developers/GitPython", "1ed1b924f4e2d2ee7bab296df77b978af21853f1", "config section delimiter injection", "INCOMPLETE_RELEASED", "Main:134"),
    row("gitpython-archive-options", "GHSA-539M-9XH6-Q6RR", "gitpython-developers/GitPython", "7a4f5dcb7bf3cbcbf6e438017efcdfe0bc0d36ca", "archive add-file and bundle options", "INCOMPLETE_RELEASED", "Main:135"),
    row("gitpython-revlist-output", "GHSA-P538-C434-8V24", "gitpython-developers/GitPython", "38553b6fddc7f6a667cdb45a6762343a08fc72b2", "Commit.count output option", "INCOMPLETE_RELEASED", "Main:136"),
    row("gitpython-checkout-tag-options", "GHSA-3F7W-8RR8-F37F", "gitpython-developers/GitPython", "3af0c2516c5e18c829da30338614688f6b69b49c", "checkout and tag file options", "INCOMPLETE_RELEASED", "Main:137"),
    row("coolify-shell-grammar", "CVE-2026-42204 GHSA-CHG4-63HM-XV9X", "coollabsio/coolify", "817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1", "bare ampersand accepted by shell validator", "INCOMPLETE_RELEASED", "Main:149", instance="main"),
    row("coolify-activity-scope", "CVE-2026-34167 GHSA-962V-GXMW-56HC", "coollabsio/coolify", "3e0d48faeaab950bfd063dfca908f1d140316ede", "ActivityMonitor scope fails open without team", "INCOMPLETE_COMMIT_ONLY", "Main:159", instance="main"),

    # Batch B.
    row("n8n-mcp-ipv6-ssrf", "CVE-2026-42449 GHSA-56C3-VFP2-5QQJ", "czlonkowski/n8n-mcp", "9639f757853149f0cb16663cc8b6b6468f27a25f", "sync SSRF validator misses IPv6 families", "INCOMPLETE_RELEASED", "Batch-B:13"),
    row("prospero-permission-save", "CVE-2026-59233", "Roskus/prospero-flow-crm", "86a7d6557bd111518a221f4575ad6e36087e19d3", "authenticated permission save lacks authorization", "INCOMPLETE_RELEASED", "Batch-B:27"),
    row("prospero-calendar-delete", "CVE-2026-59234", "Roskus/prospero-flow-crm", "8c26eed4d80544c30e55448e12a8e999af6d2b70", "calendar deletion lacks ownership", "INCOMPLETE_RELEASED", "Batch-B:40"),
    row("prospero-notification-delete", "CVE-2026-59240", "Roskus/prospero-flow-crm", "eaee2ae018701d116164976cbfa37fa9294ab4cc", "notification deletion lacks ownership", "INCOMPLETE_RELEASED", "Batch-B:50"),
    row("dynatrace-mcp-auth", "GHSA-P7W7-4929-VPJ5", "dynatrace-oss/dynatrace-mcp", "8f12972481e9165e8bd24d63b0a9e71976f85a43", "explicit external bind remains unauthenticated", "INCOMPLETE_COMMIT_ONLY", "Batch-B:64"),
    row("wacrm-automation-tenant", "CVE-2026-49141", "ArnasDon/wacrm", "b4f18537bbf6787d18a9abafce53c557ac36f475", "automation contact operations cross tenant", "INCOMPLETE_COMMIT_ONLY", "Batch-B:72"),
    row("misp-mass-assignment", "CVE-2026-56422", "MISP/MISP", "025f711506850aadb69cde1b57e5e5d57628c87f", "mass assignment and object re-ownership fix set", "INCOMPLETE_COMMIT_ONLY", "Batch-B:81"),
    row("omnifaces-combined-resource", "GHSA-FP43-VJ7G-PG92", "omnifaces/omnifaces", "a52b92461cf39d983f51ce8724fe7e6b944073e4", "combined-resource and source-map cache boundaries", "INCOMPLETE_COMMIT_ONLY", "Batch-B:90"),
    row("prospero-order-idor", "CVE-2026-59237", "Roskus/prospero-flow-crm", "9a859c4de3d49674916773d346c60d89ad7febe0", "Order and OrderItem cross-tenant IDOR", "STRICT_COMMIT_ONLY", "Batch-B:99"),

    # Batch C.
    row("langroid-pandas-eval", "CVE-2026-25481 GHSA-X34R-63HX-W57F", "langroid/langroid", "30abbc1a854dee22fbd2f8b2f575dfdabdb603ea", "dunder attribute bypass reaches pandas eval", "INCOMPLETE_RELEASED", "Batch-C:15"),
    row("vitest-cdp-gate", "CVE-2026-53633 GHSA-G8MR-85JM-7XHM", "vitest-dev/vitest", "385a1aefd4c2bfa5e7d58bf7c6834c929969f2c7", "raw CDP bypasses write and exec gates", "INCOMPLETE_COMMIT_ONLY", "Batch-C:34"),
    row("mistune-percent-scheme", "CVE-2026-59923 GHSA-8C25-4J27-2RV3", "lepture/mistune", "c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc", "percent-encoded harmful URL scheme", "INCOMPLETE_COMMIT_ONLY", "Batch-C:48"),
    row("mistune-legacy-scheme", "CVE-2026-59929 GHSA-QFRW-5RXM-MHH2", "lepture/mistune", "c7101fcbb6e8790e8e39157c5ca2238fc6dd6cbc", "legacy and chained harmful URL schemes", "INCOMPLETE_COMMIT_ONLY", "Batch-C:59"),

    # Batch D.
    row("fast-uri-authority", "CVE-2026-18446 GHSA-7P8R-X3MC-P8W7", "fastify/fast-uri", "f3c6c905f47831007490f466c5945012e905cc52", "backslash and whitespace authority confusion", "INCOMPLETE_RELEASED", "Batch-D:9"),
    row("locutus-prototype-pollution", "CVE-2026-33994 GHSA-VC8F-X9PP-WF5P", "locutusjs/locutus", "345a6211e1e6f939f96a7090bfeff642c9fcf9e4", "overwritable prototype guard", "INCOMPLETE_RELEASED", "Batch-D:10"),
    row("gitea-draft-attachment", "CVE-2026-58432 GHSA-Q9PG-JJ6X-J9P6", "go-gitea/gitea", "f7fd51022495737cf960b8c4053a27d69148f664", "UUID attachment download misses write gate", "INCOMPLETE_RELEASED", "Batch-D:11"),
    row("scriban-array-multiply", "GHSA-Q6RR-FM2G-G5X8", "scriban/scriban", "205ca6a7c2349d3d388bd5f1f7729ee198c0d5e5", "array multiplication misses loop limit", "INCOMPLETE_RELEASED", "Batch-D:12"),
    row("faraday-uri-authority", "CVE-2026-33637 GHSA-5RV5-XJ5J-3484", "lostisland/faraday", "3f1280c69e93297d574e85a2d462d05ebadf1d09", "URI object overrides base host", "INCOMPLETE_RELEASED", "Batch-D:13"),
    row("filebrowser-delete-scope", "CVE-2026-55667 GHSA-FMM7-X4GX-8JHR", "filebrowser/filebrowser", "64511ce45e3be379e965f7f4fb0929a068d5bb81", "symlink escape delete and permission bypass", "INCOMPLETE_RELEASED", "Batch-D:14"),
    row("filebrowser-dangling-write", "CVE-2026-55668 GHSA-8WC8-HF36-MJH9", "filebrowser/filebrowser", "64511ce45e3be379e965f7f4fb0929a068d5bb81", "dangling symlink write outside scope", "INCOMPLETE_RELEASED", "Batch-D:15"),

    # Batch E. Two Coolify instances intentionally preserve duplicate inputs.
    row("scriban-parser-depth", "GHSA-6Q7J-XR26-3H2C", "scriban/scriban", "8fdbd687bbe8f00085c4c4c5b2b3b8d529933949", "parser depth records error but continues recursion", "INCOMPLETE_RELEASED", "Batch-E:31"),
    row("gitea-oauth-reactivation", "CVE-2026-55987 GHSA-VRHC-JJFC-M3M3", "go-gitea/gitea", "fce961b44aa9631f8e9f5d6b3168d16d9a6728af", "OAuth callback reactivates disabled user", "INCOMPLETE_RELEASED", "Batch-E:32"),
    row("praisonai-jwt-default", "CVE-2026-57148 GHSA-F38V-77QJ-H4JQ", "MervinPraison/PraisonAI", "e0fb8e7dd1ee6759c18ed07f436c21dbd9c20747", "unset production environment uses default JWT secret", "INCOMPLETE_RELEASED", "Batch-E:33"),
    row("coolify-shell-grammar", "CVE-2026-42204 GHSA-CHG4-63HM-XV9X", "coollabsio/coolify", "817128c5affa02c1a8f0f1f9a8df54b9dd80bcc1", "bare ampersand accepted by shell validator", "INCOMPLETE_RELEASED", "Batch-E:34", instance="batch-e"),
    row("gitpython-joined-short-option", "GHSA-V396-V7Q4-X2QJ", "gitpython-developers/GitPython", "56806080c1348749b07daa4a2024ce47b3cad285", "joined short clone option value", "INCOMPLETE_RELEASED", "Batch-E:35"),
    row("gitpython-section-newline", "GHSA-MV93-W799-CJ2W", "gitpython-developers/GitPython", "54538428f79b0c91ba52cda5229856a6edf7ac06", "config section name newline", "INCOMPLETE_RELEASED", "Batch-E:36"),
    row("gitpython-diff-output", "GHSA-FJR4-X663-MWXC", "gitpython-developers/GitPython", "1d51b891d7f236044a6aa17498ec682b63dad6e6", "Diffable.diff output option", "INCOMPLETE_RELEASED", "Batch-E:37"),
    row("gitpython-pathspec-file", "GHSA-HH9P-6WH2-4MFC", "gitpython-developers/GitPython", "f2550b65bf60ca087190981e2c7b6865e201f40c", "pathspec-from-file siblings", "INCOMPLETE_RELEASED", "Batch-E:38"),
    row("gitpython-init-template", "GHSA-9RJ7-RF2P-W77R", "gitpython-developers/GitPython", "d9ddb55bdc66ffe8c9932fe460e6b8c8211e47c7", "Repo.init template option", "INCOMPLETE_RELEASED", "Batch-E:39"),
    row("gitpython-read-tree-index", "GHSA-4GMW-GG2M-W46P", "gitpython-developers/GitPython", "9b5dcaf85da5946dbf69dcd53f9edba08f760b32", "read-tree attacker-selected index", "INCOMPLETE_RELEASED", "Batch-E:40"),
    row("gitpython-split-mode", "GHSA-WVPP-8HX9-P66J", "gitpython-developers/GitPython", "96a888f4d782cb2f80452148e48e60ce4af6d541", "disabled split mode misses joined option value", "INCOMPLETE_RELEASED", "Batch-E:41"),
    row("gitpython-option-name", "GHSA-JM78-9FVV-MHGR", "gitpython-developers/GitPython", "a495ccd3b547ccd60b2187215823b72a9c0188bf", "config option name directive injection", "INCOMPLETE_RELEASED", "Batch-E:42"),
    row("gitpython-config-reserialize", "GHSA-284H-M62Q-GF8W", "gitpython-developers/GitPython", "4b4e47fc1224e23b0c8ee7220a7192818f2e4abb", "dormant multiline config reserialization", "INCOMPLETE_RELEASED", "Batch-E:43"),
    row("gitpython-separate-git-dir", "GHSA-8MCC-HRX5-HVXC", "gitpython-developers/GitPython", "b68afff45af0f49e79a3e2d2162018986b37ad5d", "clone separate-git-dir option", "INCOMPLETE_RELEASED", "Batch-E:44"),
    row("gitpython-blame-contents", "GHSA-5XXX-QHH7-9287", "gitpython-developers/GitPython", "1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6", "Repo.blame contents reads arbitrary file", "INCOMPLETE_RELEASED", "Batch-E:45"),
    row("gitpython-tag-positional-file", "GHSA-3WXW-XV34-2FRG", "gitpython-developers/GitPython", "1b0d2d9b91575f7db44ef4ff58ac37fc9335e5f6", "TagReference positional file option", "INCOMPLETE_RELEASED", "Batch-E:46"),
    row("scriban-lazy-range", "GHSA-89CF-6HMV-8RXM", "scriban/scriban", "973edd1f1c10fae7d3a8650ac0d309d52072102c", "lazy range multiplication misses loop accounting", "INCOMPLETE_RELEASED", "Batch-E:47"),
    row("gitea-private-org-members", "CVE-2026-58427 GHSA-PRR9-9MP4-5GP2", "go-gitea/gitea", "44ea3a8d24638ca4a395d641d39f476ae1dc421d", "private organization members endpoint visibility", "INCOMPLETE_COMMIT_ONLY", "Batch-E:48"),
    row("coolify-activity-scope", "CVE-2026-34167 GHSA-962V-GXMW-56HC", "coollabsio/coolify", "3e0d48faeaab950bfd063dfca908f1d140316ede", "ActivityMonitor scope fails open without team", "INCOMPLETE_COMMIT_ONLY", "Batch-E:49", instance="batch-e"),
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    tmp.replace(path)


def cache_path(kind: str, key: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", key)
    path = OUT / "api-cache" / kind / f"{safe}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


REQUESTS: list[dict[str, Any]] = []


def github(endpoint: str, kind: str, key: str) -> dict[str, Any]:
    path = cache_path(kind, key)
    if path.exists():
        value = json.loads(path.read_text())
        REQUESTS.append({"source": "cache", "command": f"gh api {endpoint}", "status": value.get("_http_status", 200)})
        return value
    proc = subprocess.run(
        ["gh", "api", endpoint, "-H", "Accept: application/vnd.github+json"],
        text=True,
        capture_output=True,
        check=False,
    )
    status = 200 if proc.returncode == 0 else 404 if "HTTP 404" in proc.stderr else 0
    if proc.returncode == 0:
        value = json.loads(proc.stdout)
    else:
        value = {"_error": proc.stderr.strip(), "_http_status": status}
    atomic_json(path, value)
    REQUESTS.append({"source": "live", "command": f"gh api {endpoint}", "status": status})
    return value


def cve_record(cve_id: str) -> dict[str, Any]:
    path = cache_path("cve", cve_id)
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    if path.exists():
        value = json.loads(path.read_text())
        REQUESTS.append({"source": "cache", "url": url, "status": value.get("_http_status", 200)})
        return value
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            value = json.load(response)
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        value = {"_error": str(exc), "_http_status": status}
    except (urllib.error.URLError, TimeoutError) as exc:
        status = 0
        value = {"_error": str(exc), "_http_status": status}
    atomic_json(path, value)
    REQUESTS.append({"source": "live", "url": url, "status": status})
    return value


def walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)


def mentioned_ids(value: Any) -> set[str]:
    return {match.group(0).upper() for text in walk_strings(value) for match in ID_RE.finditer(text)}


def declared_ghsa_ids(value: dict[str, Any]) -> set[str]:
    """Only use first-class identifier fields, never prose or generic references."""
    result = set()
    for field in ("ghsa_id", "cve_id"):
        item = value.get(field)
        if isinstance(item, str) and ID_RE.fullmatch(item):
            result.add(item.upper())
    for item in value.get("identifiers") or []:
        identifier = item.get("value") if isinstance(item, dict) else None
        if isinstance(identifier, str) and ID_RE.fullmatch(identifier):
            result.add(identifier.upper())
    return result


def cve_reference_ghsas(value: dict[str, Any]) -> set[str]:
    """A CNA/ADP link to a concrete GitHub advisory is identity evidence."""
    result = set()
    containers = value.get("containers", {})
    provider_records = [containers.get("cna", {}), *(containers.get("adp") or [])]
    for record in provider_records:
        for reference in record.get("references") or []:
            url = reference.get("url", "") if isinstance(reference, dict) else ""
            if "/security/advisories/GHSA-" not in url and "github.com/advisories/GHSA-" not in url:
                continue
            result.update(match.group(0).upper() for match in ID_RE.finditer(url) if match.group(0).upper().startswith("GHSA-"))
    return result


def commit_refs(value: Any) -> list[dict[str, str]]:
    found: dict[tuple[str, str], dict[str, str]] = {}
    for text in walk_strings(value):
        for match in COMMIT_RE.finditer(text):
            repo, commit = match.group(1), match.group(2).lower()
            found[(repo.lower(), commit)] = {
                "repo": repo,
                "sha": commit,
                "url": f"https://github.com/{repo}/commit/{commit}",
            }
    return sorted(found.values(), key=lambda item: (item["repo"].lower(), item["sha"]))


def repo_refs(value: Any) -> set[str]:
    refs = set()
    for text in walk_strings(value):
        for match in REPO_RE.finditer(text):
            repo = match.group(1).removesuffix(".git")
            if repo.lower() not in {"advisories/ghsa", "cveproject/cvelistv5"}:
                refs.add(repo.lower())
    return refs


def cve_summary(value: dict[str, Any], requested_id: str) -> dict[str, Any]:
    metadata = value.get("cveMetadata", {})
    cna = value.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    cve_id = metadata.get("cveId")
    declared = {cve_id.upper()} if isinstance(cve_id, str) else set()
    reference_ghsas = cve_reference_ghsas(value)
    return {
        "state": metadata.get("state"),
        "date_published": metadata.get("datePublished"),
        "title": cna.get("title"),
        "description": next((item.get("value") for item in descriptions if item.get("lang") == "en"), None),
        "affected": cna.get("affected", []),
        "official_ids": sorted(declared),
        "reference_ghsas": sorted(reference_ghsas),
        "related_ids": sorted(mentioned_ids(value) - declared),
        "commit_refs": commit_refs(value),
        "repo_refs": sorted(repo_refs(value)),
        "url": f"https://cveawg.mitre.org/api/cve/{metadata.get('cveId', requested_id)}",
    }


def ghsa_summary(global_obj: dict[str, Any], repo_obj: dict[str, Any], ghsa_id: str, repo: str) -> dict[str, Any]:
    combined = [global_obj, repo_obj]
    global_ids = declared_ghsa_ids(global_obj)
    repo_ids = declared_ghsa_ids(repo_obj)
    preferred_ids = global_ids | repo_ids
    repo_cves = {item for item in repo_ids if item.startswith("CVE-")}
    global_cves = {item for item in global_ids if item.startswith("CVE-")}
    conflicting_global_ids = (global_cves - repo_cves) if repo_cves else set()
    conflicting_global_ids.update(item for item in global_ids - repo_ids if item.startswith("GHSA-") and item != ghsa_id.upper())
    return {
        "global_status": global_obj.get("_http_status", 200 if "ghsa_id" in global_obj else 0),
        "repo_status": repo_obj.get("_http_status", 200 if "ghsa_id" in repo_obj else 0),
        "global_type": global_obj.get("type"),
        "repo_state": repo_obj.get("state"),
        "published_at": repo_obj.get("published_at") or global_obj.get("published_at"),
        "withdrawn_at": repo_obj.get("withdrawn_at") or global_obj.get("withdrawn_at"),
        "cve_id": repo_obj.get("cve_id") or global_obj.get("cve_id"),
        "summary": repo_obj.get("summary") or global_obj.get("summary"),
        "description": repo_obj.get("description") or global_obj.get("description"),
        "official_ids": sorted(preferred_ids),
        "global_ids": sorted(global_ids),
        "repo_ids": sorted(repo_ids),
        "global_identifier_extras": sorted(conflicting_global_ids),
        "related_ids": sorted(mentioned_ids(combined) - global_ids - repo_ids),
        "commit_refs": commit_refs(combined),
        "repo_refs": sorted(repo_refs(combined)),
        "global_url": f"https://api.github.com/advisories/{ghsa_id}",
        "repo_url": f"https://api.github.com/repos/{repo}/security-advisories/{ghsa_id}",
    }


def main() -> int:
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    snapshots = []
    for rel in SOURCE_FILES:
        path = REPO_ROOT / rel
        snapshots.append({
            "path": rel,
            "sha256": sha256(path),
            "size": path.stat().st_size,
            "mtime_ns": path.stat().st_mtime_ns,
        })

    baseline_ids = set()
    baseline_path = REPO_ROOT / SOURCE_FILES[-1]
    for line in baseline_path.read_text().splitlines():
        if line.strip():
            baseline_ids.update(item.upper() for item in json.loads(line)["public_ids"])

    row_keys = [f"{item['row_id']}@{item['instance']}" for item in ROWS]
    initial_map: dict[str, list[str]] = defaultdict(list)
    for key, item in zip(row_keys, ROWS):
        for public_id in item["ids"]:
            initial_map[public_id].append(key)

    ghsa_records: dict[tuple[str, str], dict[str, Any]] = {}
    cve_records: dict[str, dict[str, Any]] = {}
    discovered_ids: dict[str, set[str]] = {}

    for key, item in zip(row_keys, ROWS):
        closure = set(item["ids"])
        for _ in range(3):
            before = set(closure)
            for public_id in sorted(closure):
                if public_id.startswith("GHSA-"):
                    record_key = (item["repo"].lower(), public_id)
                    if record_key not in ghsa_records:
                        global_obj = github(f"advisories/{public_id}", "ghsa-global", public_id)
                        repo_obj = github(
                            f"repos/{item['repo']}/security-advisories/{public_id}",
                            "ghsa-repo",
                            f"{item['repo']}__{public_id}",
                        )
                        ghsa_records[record_key] = ghsa_summary(global_obj, repo_obj, public_id, item["repo"])
                    closure.update(ghsa_records[record_key]["official_ids"])
                else:
                    if public_id not in cve_records:
                        cve_records[public_id] = cve_summary(cve_record(public_id), public_id)
                    closure.update(cve_records[public_id]["official_ids"])
                    for ghsa_id in cve_records[public_id].get("reference_ghsas", []):
                        record_key = (item["repo"].lower(), ghsa_id)
                        if record_key not in ghsa_records:
                            global_obj = github(f"advisories/{ghsa_id}", "ghsa-global", ghsa_id)
                            repo_obj = github(
                                f"repos/{item['repo']}/security-advisories/{ghsa_id}",
                                "ghsa-repo",
                                f"{item['repo']}__{ghsa_id}",
                            )
                            ghsa_records[record_key] = ghsa_summary(global_obj, repo_obj, ghsa_id, item["repo"])
                        # A generic predecessor/follow-up link is not an alias.
                        if public_id in ghsa_records[record_key]["official_ids"]:
                            closure.add(ghsa_id)
            if closure == before:
                break
        discovered_ids[key] = closure

    # Resolve proposed atomic fix identities via exact repository commit API.
    resolved_fixes: dict[tuple[str, str], dict[str, Any]] = {}
    for item in ROWS:
        for fix in item["proposed_fixes"]:
            fix_key = (item["repo"].lower(), fix)
            if fix_key in resolved_fixes:
                continue
            obj = github(
                f"repos/{item['repo']}/commits/{fix}",
                "commit",
                f"{item['repo']}__{fix}",
            )
            resolved_fixes[fix_key] = {
                "requested": fix,
                "sha": obj.get("sha"),
                "url": obj.get("html_url"),
                "status": obj.get("_http_status", 200 if obj.get("sha") else 0),
                "parents": [parent.get("sha") for parent in obj.get("parents", [])],
            }

    closure_map: dict[str, list[str]] = defaultdict(list)
    for key in row_keys:
        for public_id in discovered_ids[key]:
            closure_map[public_id].append(key)

    instances_by_row: dict[str, list[str]] = defaultdict(list)
    for key, item in zip(row_keys, ROWS):
        instances_by_row[item["row_id"]].append(key)

    ledger = []
    for key, item in zip(row_keys, ROWS):
        closure = discovered_ids[key]
        additions = sorted(closure - set(item["ids"]))
        missing = []
        withdrawn = []
        rejected = []
        repo_mismatch = []
        identifier_conflicts = []
        related_cross_links: dict[str, list[str]] = {}
        summaries = []
        official_commits: dict[tuple[str, str], dict[str, str]] = {}
        official_urls = []

        for public_id in sorted(closure):
            if public_id.startswith("CVE-"):
                record = cve_records.get(public_id)
                if not record:
                    missing.append(public_id)
                    continue
                summaries.append({"id": public_id, **record})
                related = sorted(set(record.get("related_ids", [])) - closure)
                if related:
                    related_cross_links[public_id] = related
                official_urls.append(record["url"])
                if record["state"] == "REJECTED":
                    rejected.append(public_id)
                if record["state"] not in {"PUBLISHED", "REJECTED"}:
                    missing.append(public_id)
                for ref in record["commit_refs"]:
                    official_commits[(ref["repo"].lower(), ref["sha"])] = ref
                explicit_repos = {
                    affected.get("repo", "").removeprefix("https://github.com/").removesuffix(".git").lower()
                    for affected in record.get("affected", [])
                    if affected.get("repo", "").startswith("https://github.com/")
                }
                if explicit_repos and item["repo"].lower() not in explicit_repos:
                    repo_mismatch.append({"id": public_id, "official_repos": sorted(explicit_repos)})
            else:
                record = ghsa_records.get((item["repo"].lower(), public_id))
                if not record:
                    missing.append(public_id)
                    continue
                summaries.append({"id": public_id, **record})
                related = sorted(set(record.get("related_ids", [])) - closure)
                if related:
                    related_cross_links[public_id] = related
                if record.get("global_identifier_extras"):
                    identifier_conflicts.append({
                        "id": public_id,
                        "global_extras_excluded": record["global_identifier_extras"],
                        "repo_ids_preferred": record["repo_ids"],
                    })
                official_urls.extend([record["global_url"], record["repo_url"]])
                if record["global_status"] != 200 and record["repo_status"] != 200:
                    missing.append(public_id)
                if record["repo_state"] not in {None, "published"}:
                    missing.append(public_id)
                if record["withdrawn_at"]:
                    withdrawn.append(public_id)
                for ref in record["commit_refs"]:
                    official_commits[(ref["repo"].lower(), ref["sha"])] = ref

        resolved = [resolved_fixes[(item["repo"].lower(), fix)] for fix in item["proposed_fixes"]]
        unresolved = [fix for fix in resolved if fix["status"] != 200 or not fix["sha"]]
        different_row_collisions = {
            public_id: sorted({other.split("@", 1)[0] for other in owners} - {item["row_id"]})
            for public_id, owners in closure_map.items()
            if key in owners and ({other.split("@", 1)[0] for other in owners} - {item["row_id"]})
        }
        duplicate_instances = instances_by_row[item["row_id"]]
        baseline_overlap = sorted(closure & baseline_ids)
        polluted_input_ids = sorted(
            set(item["ids"]) & {
                extra
                for conflict in identifier_conflicts
                for extra in conflict["global_extras_excluded"]
            }
        )

        if len(duplicate_instances) > 1 and item["instance"] != "main":
            action = "REMOVE_ID"
            reasons = [f"exact duplicate instance of {duplicate_instances[0]}"]
        elif polluted_input_ids:
            action = "REMOVE_ID"
            reasons = [f"repository object excludes polluted global identifiers {polluted_input_ids}"]
        elif rejected or withdrawn:
            action = "REMOVE_ID"
            reasons = [f"rejected={rejected}", f"withdrawn={withdrawn}"]
        elif item["row_id"] == "openclaw-feishu-webhook":
            action = "SPLIT"
            reasons = ["GHSA-XH72-V6V9-MWHC also contains a distinct blank card-action-token mechanism; retain only its webhook-scoped evidence"]
        elif different_row_collisions or repo_mismatch or baseline_overlap:
            action = "SPLIT"
            reasons = [f"cross-row collisions={different_row_collisions}", f"repo mismatch={repo_mismatch}", f"baseline overlap={baseline_overlap}"]
        elif item["row_id"] in {"misp-mass-assignment", "omnifaces-combined-resource"}:
            action = "UNKNOWN"
            reasons = ["first-party advisory is a multi-mechanism, multi-fix set; exact AI-partial-to-complete-fix subset is not closed by the row"]
        elif missing or unresolved:
            action = "UNKNOWN"
            reasons = [f"missing official records={missing}", f"unresolved fixes={[fix['requested'] for fix in unresolved]}"]
        elif additions:
            action = "ADD_ALIAS"
            reasons = [f"official closure adds {additions}"]
        else:
            action = "KEEP"
            reasons = ["published first-party identity and exact fix object resolved"]

        ledger.append({
            **item,
            "key": key,
            "action": action,
            "reasons": reasons,
            "official_ids": sorted(closure),
            "add_aliases": additions,
            "baseline_overlap": baseline_overlap,
            "same_id_different_rows": different_row_collisions,
            "repo_mismatch": repo_mismatch,
            "identifier_conflicts": identifier_conflicts,
            "related_cross_links": related_cross_links,
            "official_urls": sorted(set(official_urls)),
            "official_commit_refs": sorted(official_commits.values(), key=lambda ref: (ref["repo"].lower(), ref["sha"])),
            "resolved_fixes": resolved,
            "records": summaries,
        })

    with (OUT / "ledger.jsonl").open("w") as handle:
        for item in ledger:
            handle.write(json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n")

    end_snapshots = []
    for snapshot in snapshots:
        path = REPO_ROOT / snapshot["path"]
        end_snapshots.append({
            "path": snapshot["path"],
            "sha256": sha256(path),
            "size": path.stat().st_size,
            "mtime_ns": path.stat().st_mtime_ns,
        })
    input_changed = snapshots != end_snapshots
    summary = {
        "started_at": started,
        "ended_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "row_instances": len(ROWS),
        "semantic_rows": len({item["row_id"] for item in ROWS}),
        "initial_public_ids": len(initial_map),
        "official_public_ids": len(closure_map),
        "baseline_ids": len(baseline_ids),
        "actions": {action: sum(item["action"] == action for item in ledger) for action in ["KEEP", "ADD_ALIAS", "SPLIT", "REMOVE_ID", "UNKNOWN"]},
        "tiers": {tier: sum(item["tier"] == tier for item in ledger) for tier in sorted({item["tier"] for item in ROWS})},
        "duplicate_row_ids": {row_id: keys for row_id, keys in instances_by_row.items() if len(keys) > 1},
        "input_changed_during_run": input_changed,
        "input_snapshots_start": snapshots,
        "input_snapshots_end": end_snapshots,
        "requests": len(REQUESTS),
        "live_requests": sum(item["source"] == "live" for item in REQUESTS),
        "request_failures": [item for item in REQUESTS if item["status"] != 200],
    }
    atomic_json(OUT / "input_snapshot.json", {"rows": ROWS, "baseline_ids": sorted(baseline_ids), "sources": snapshots})
    atomic_json(OUT / "requests.json", REQUESTS)
    atomic_json(OUT / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
