#!/usr/bin/env python3
"""Land the accepted 33-case disagreement re-review into canonical primaries."""
from __future__ import annotations

import json
from pathlib import Path

LANE = Path(__file__).resolve().parent
PRIMARY = LANE / "primary"

SCOPES = {
    "CORRECTION_REQUIRED": "w002 w006 w007 w008 w010 w011 w019 w115 w124 w133 w136 w139 w167 w180 w206 w207 w312 w395".split(),
    "CONFIRMED": "w078 w123 w166 w227 w252 w387".split(),
    "FIELD_ERRATUM": "w029 w088 w153 w165 w277 w326 w358".split(),
    "EVIDENCE_GAP": "w122 w289".split(),
}

SET = {
    "w002": {
        "flaw_origin": "8a5ed7e62417441ed98b39481ac1a47510c1a9ef first added plugin validation plus normal module execution. Later import/AST guards were incomplete remediation, not the BIC.",
        "introducer_sha": "8a5ed7e62417441ed98b39481ac1a47510c1a9ef",
        "introducer_parent": "649f737a9f04645508d079c0c772a8a2b4c7457a",
        "introducer_parent_absent": True,
        "ai_marker": "Generated with Claude Code; Co-Authored-By: Claude <noreply@anthropic.com>",
    },
    "w006": {
        "bug_semantics": "Path traversal reaches dynamic require. CNA metadata says 2.0.0, but Git containment first proves the unsafe loader carrier in n8n@2.9.0 and the advisory-specific MCP source-to-sink in n8n@2.25.1; n8n@2.33.3 and n8n@2.34.0 are verified affected endpoints.",
        "reasoning": "AI_ROOT_CAUSE remains closed on the BIC. Treat 2.0.0 as contradicted CNA metadata, not a code-proven lower bound; n8n@2.33.4 and n8n@2.34.1 are verified fixed endpoints.",
    },
    "w007": {
        "bug_semantics": "FALSE_POSITIVE: permissive CORS exists, but protected operations require explicit bearer tokens sent by native clients rather than browser-ambient credentials. No source-to-sink lets an attacker origin act with a visitor's authority.",
        "flaw_origin": None, "introducer_sha": None, "introducer_parent": None,
        "ai_marker": None, "verdict": "FALSE_POSITIVE", "fix_sha": None,
        "direct_fix_sha": None,
        "reasoning": "False positive: the telemetry server permits GET and POST while the key-server copy uses wildcard methods. Public endpoints were already unauthenticated, protected routes require caller-supplied bearer headers, and v1.3.6 lacks the named server paths. The cited commits are lineage/hardening evidence, not a vulnerability lifecycle.",
    },
    "w008": {
        "verdict": "FALSE_POSITIVE",
        "bug_semantics": "The claimed AES-GCM-to-AES-CTR authentication bypass cannot return plaintext: every initialized nonce reaching fallback is 12 bytes, nonce[:16] remains 12 bytes, AES-CTR requires 16 bytes, and the caught constructor failure makes decryption fail closed.",
        "introducer_sha": None, "introducer_parent": None, "introducer_parent_absent": False,
        "squash_decomposed": False, "decomposed_shas": [], "ai_marker": None,
        "fix_sha": None, "direct_fix_sha": None,
    },
    "w010": {
        "flaw_origin": "The vendor PoC's Repo.clone_from path is first written by b425301ad16f265157abdaf47f7af1c1ea879068. Sibling path BICs are 00c5497f190172765cc7a53ff9d8852a26b91676 for non-bare Repo.clone and ba5717549b32f6b5cee304fdff87cb26b3be688a for caller-controlled Submodule clone options.",
        "introducer_sha": "b425301ad16f265157abdaf47f7af1c1ea879068",
        "introducer_parent": "ca288d443f4fc9d790eecb6e1cdf82b6cdd8dc0d",
        "introducer_parent_absent": True,
        "ai_marker": "Absent on all three path BICs; named human author/committer identities Sebastian Thiel and Igor Lakhtenkov, with no AI, bot, generator, or co-author marker.",
    },
    "w011": {
        "bug_semantics": "The Bearer dependency accepted any non-empty token, enabling unauthenticated upload of an otherwise-valid self-signed attacker-controlled bundle. Search was intentionally public, and revocation still required a valid ownership signature.",
        "reasoning": "AI_ROOT_CAUSE remains closed on fafdfeed1b279cfe61e86cd8adc132b206eef8d4. The public Git line shows a vulnerable development interval, but v1.3.6 lacks the subsystem and v1.4.0 contains both BIC and fix; describe <1.4.0 only as vendor metadata.",
    },
    "w019": {
        "flaw_origin": "b47fa1c75d890cd080e3f6699bbfca8cd8d4b939 is the atomic BIC only for the RequireScopes session-token early-return constituent. The advisory also joins independently introduced missing-handler and middleware-free sink defects, including user-list BIC f85756b51d5aa4f8629d4e247eaffdfc5f62a66b.",
        "introducer_parent_absent": True, "fix_sha": None, "direct_fix_sha": None,
        "remaining_gap": "No complete direct-fix commit or fixed release is verified for all advisory-named sinks. 1b8c64d0da2f3df167502af72e95417a1c4578db is only a partial user-list fix; dashboard and WebSocket bypasses remain.",
        "unpatched": {"confirmed": True, "reason": "The aggregate advisory remains partially unpatched.", "potential_fix": {"approach": "Apply authentication and scope checks to every remaining dashboard and WebSocket sink.", "rationale": "The existing commit repairs only the user-list constituent."}},
    },
    "w029": {"introducer_parent_absent": True},
    "w088": {
        "introducer_parent_absent": True,
        "flaw_origin": "Update-path BIC 8b14f8c1f097480d2013a0f78fb198e008d9bf5a (parent 0db96193a3529ffc3801b94520f8d924c09bbd6c) and create-path BIC 781fdb661d9c66f4c2a2ba2b5cd39cefff257cc5 (parent cc4e183e6584fa4d748ee979810eb5e9d65f49d9) independently first write the two vulnerable endpoints.",
        "ai_marker": "Absent on both atomic BICs; each names Thorsten Rinne as author/committer and has no AI, bot, generator, or co-author marker.",
    },
    "w115": {
        "flaw_origin": "This scalar row judges ZDRES-233: Apache SVN r349422 first writes ByteBuffer object deserialization and r349421 lacks it. ZDRES-232 separately has branch BICs 691a9df5a0aff0dddeedc5181f6e5832ee90dcea, cdb59eb6131696a440870ab89ad0e20804eb5ca7, and 834396355766e0c8f6bbf0493d4588b3fa9d347d.",
        "introducer_sha": None, "introducer_parent": None, "introducer_parent_absent": True,
        "ai_marker": "Apache SVN r349422 names ASF account trustin, mapped by Apache to Trustin Lee, with no AI, bot, generator, or co-author marker; the three ZDRES-232 Git BICs name Emmanuel Lecharny and likewise have no such marker.",
        "fix_sha": "409171daa076f4bb5ab2e2e54b312bdcafd8c235",
        "direct_fix_sha": "409171daa076f4bb5ab2e2e54b312bdcafd8c235",
        "remaining_gap": "Scalar fields select the 2.2.x ZDRES-233 mechanism. Other direct fixes are ZDRES-232 850592195d92acbce1d8be9b341e487b4361512c; 2.1.x f2d110bccb7ace38701e44c122832e085f9c455b and 3166d262de1e7027a360ebb85732dbf861b1eea7; 2.0.x d0456f6390b3a275e5e528b405ab3725ad8c8394 and 833f3db173526e3d25f053cf81e37053b0466f2a. Fully fixed releases are 2.2.8, 2.1.15, and 2.0.31.",
    },
    "w122": {
        "verdict": "EVIDENCE_GAP", "introducer_parent_absent": True,
        "ai_marker": "Conditional only: 1b8236afe67fa961d4517e326ca278cb3daf406c has a named human and no AI marker, but no first-party source binds this local mechanism uniquely to CVE-2025-49549.",
        "remaining_gap": "Resolve the identity conflict between the public allCustomerGroups lifecycle in 2.4.8 and the authoritative advisory's older high-privilege release lines before attributing the CVE.",
    },
    "w124": {
        "flaw_origin": "Apache SVN r349422 first adds ByteBuffer.getObject()/ObjectInputStream.readObject(); exact predecessor r349421 lacks the path. Later Git imports and 2024 allowlist work are not the BIC.",
        "introducer_sha": None, "introducer_parent": None, "introducer_parent_absent": True,
        "ai_marker": "Apache SVN r349422 names ASF account trustin, mapped to Trustin Lee, and contains no AI, bot, generator, or co-author marker.",
        "fix_sha": "cca24d646c898adf7e01a765ebf6d677cc02b696",
        "direct_fix_sha": "cca24d646c898adf7e01a765ebf6d677cc02b696",
        "remaining_gap": "Scalar fix fields select the 2.2.x direct fix; 2.1.x is fixed by ba8c355d82a010d677455df43b49725d21dbd07a. First fixed tags are 2.2.7 and 2.1.12.",
    },
    "w133": {"introducer_parent_absent": True},
    "w136": {
        "flaw_origin": "Apache SVN r349422 first adds the unfiltered buffer-to-ObjectInputStream.readObject() path; r349421 lacks it. Git import/move and later allowlist mutations are excluded.",
        "introducer_sha": None, "introducer_parent": None, "introducer_parent_absent": True,
        "ai_marker": "Apache SVN r349422 names ASF account trustin, mapped to Trustin Lee, with no AI, bot, generator, or co-author marker.",
        "fix_sha": "cca24d646c898adf7e01a765ebf6d677cc02b696",
        "direct_fix_sha": "cca24d646c898adf7e01a765ebf6d677cc02b696",
        "remaining_gap": "Scalar fix fields select 2.2.x; the 2.1.x direct fix is ba8c355d82a010d677455df43b49725d21dbd07a.",
    },
    "w139": {
        "flaw_origin": "Two atomic BICs exist: 8011c3bac314ce951abb9de13024626da1ae052b first writes the bulk-clone path, while cdf7678453a21548fda36a6b7105b1b475e2c145 independently first writes the republish-overwrite path.",
        "introducer_parent_absent": True,
        "ai_marker": "Absent on both BICs; named human writers lopo and Andrea Fercia, with no AI, bot, generator, or co-author marker.",
    },
    "w153": {"introducer_parent_absent": True},
    "w165": {},
    "w167": {
        "flaw_origin": "LZ4 36104610053f34bbe033fad50263ce33cd4e9bcc first writes the unbounded decoder loop; downstream lz4net ports, dependency adoption, and MessagePack vendoring bf5f2dd91bad2948063668de3703259f7562cf73 are excluded copies.",
        "introducer_sha": "36104610053f34bbe033fad50263ce33cd4e9bcc",
        "introducer_parent": "409f2436903951a16feebc3e2cf3facf0fd50fbe",
        "introducer_parent_absent": True,
        "ai_marker": "Absent on the LZ4 BIC; author/committer yann.collet.73@gmail.com and source copyright Yann Collet, with no AI, bot, generator, or co-author marker.",
    },
    "w180": {
        "bug_semantics": "Stored HTML bypasses the historical input denylist, but no reachable unsanitized v5.13.0 portal/PDF sink is established: both advisory-named render paths already call Purify::clean().",
        "introducer_sha": None, "introducer_parent": None, "introducer_parent_absent": None,
        "squash_decomposed": False, "ai_marker": None, "verdict": "EVIDENCE_GAP",
        "fix_sha": "b81a3fc302573fc4a53d61e8537dd19154ce1091", "direct_fix_sha": None,
        "remaining_gap": "Identify an affected-release source-to-sink that bypasses the existing Purify calls, or reconcile the published advisory with the inspected v5.13.0 trees.",
    },
    "w206": {
        "bug_semantics": "The route is authenticated and IMAGE-gated, but when keepUploadFileName=true a crafted valid image/polyglot filename can escape uploadPath and cause an arbitrary-path file write.",
        "flaw_origin": "1405b8b1fe76842514d915f360c731db14b80324 first writes the raw original-filename destination under uploadPath; its parent lacks the upload implementation. Later random naming remains bypassable through keepUploadFileName.",
        "introducer_sha": "1405b8b1fe76842514d915f360c731db14b80324",
        "introducer_parent": "539a56a29cb22f871bafce3ff64572a276d505ec",
        "introducer_parent_absent": True, "squash_decomposed": False, "decomposed_shas": [],
        "ai_marker": "Absent on the 2019 BIC; named human author/committer and no AI, bot, generator, or co-author marker.",
        "verdict": "NOT_AI", "fix_sha": "58ed8631700f82c2d079e969b4ecbc2279eb2fde",
        "direct_fix_sha": "58ed8631700f82c2d079e969b4ecbc2279eb2fde",
    },
    "w207": {
        "flaw_origin": "PR #112 member 68ec1b65143352bc11dfd82bba5af56c6c2023c8 first writes the public D-Bus Dispatch surface without sender authorization; 7b21c524177431243b3bb1c53e4aba6d88cfe866 is the identical-tree squash landing.",
        "introducer_sha": "68ec1b65143352bc11dfd82bba5af56c6c2023c8",
        "introducer_parent": "00126d42871358d9204835a7cfa41024ab910913",
        "squash_decomposed": True,
        "decomposed_shas": ["29ca5c50feeb0ba59e0c9324f2fa75c8772e41e3", "745e5b2d0bc311e7e228c7117f2910bd7321de37", "00126d42871358d9204835a7cfa41024ab910913", "68ec1b65143352bc11dfd82bba5af56c6c2023c8"],
        "ai_marker": "Absent; atomic BIC author/committer Link Dupont, with only a matching Signed-off-by and no AI, bot, generator, or co-author marker.",
    },
    "w277": {
        "introducer_parent_absent": True,
        "ai_marker": "Absent; BIC author and committer are the named non-bot account onfranciis <onukwuf@gmail.com>, with no AI, bot, generator, co-author, or signature marker.",
    },
    "w289": {
        "verdict": "EVIDENCE_GAP",
        "ai_marker": "No visible AI marker; causal human authorship is unproven because the BIC is an unsigned, parentless 70,762-line initial snapshot.",
    },
    "w312": {
        "verdict": "EVIDENCE_GAP",
        "ai_marker": "No AI marker is present on ef52453de9523f6a010652847b61cb340ed5daa5, but its unsigned placeholder identity Your Name <you@example.com> maps to invalid-email-address rather than the PR submitter and does not prove named human authorship.",
        "remaining_gap": "Obtain admissible BIC-only evidence tying the placeholder identity to a named human causal writer.",
    },
    "w326": {
        "remaining_gap": "Unpatched: no merged fix SHA. No public tag or release substantiates the advisory's v.1.0 label; the atomic PR member is a loose object established by the first-party PR list and direct object inspection, not current git log --all reachability.",
    },
    "w358": {
        "remaining_gap": "Exact source/ancestry membership for vendor-only enterprise builds 4.0.3.1, 3.2.10.1, 3.1.15/3.1.16, and 2.4.18 is not publicly replayable; this does not alter the public BIC, direct fix, or attribution.",
    },
    "w395": {
        "flaw_origin": "Upstream Gradio PR #2256 member 500bcca42f406dc8ac30c601208828af81fc12c1 first adds the URL redirect branch. PDFMathTranslate mounts the dependency route and remains unpatched while pinning a Gradio range that excludes fixed 6.20.0.",
        "introducer_sha": "500bcca42f406dc8ac30c601208828af81fc12c1",
        "introducer_parent": "b643ae77bfb465960af2f41f66351ef2a1b84d03",
        "introducer_parent_absent": True, "squash_decomposed": True,
        "decomposed_shas": ["500bcca42f406dc8ac30c601208828af81fc12c1", "28e52031933eef35eb0dfef228d24b8609de5278", "d6e6e934f5ad5b15795ecc9d089aeb993c74b16e", "d6676be415dc569c191d8d848dc228f9e5352e46", "bab500af2b2997cba3303554432c8a121f55a16f", "269d80deb33bd10211845665cb9dc09eeb924e23", "90f7345c9f90103a724f33fe0414e164da4f8788"],
        "ai_marker": "Absent on atomic BIC; named human author/committer Abubakar Abid, with no AI, bot, generator, or co-author marker.",
        "verdict": "NOT_AI", "fix_sha": None, "direct_fix_sha": None,
        "remaining_gap": "PDFMathTranslate has no direct-fix commit or fixed release. Upstream Gradio direct fix 1c5c53842df9c2750552d85c19a92e7e732cff3f ships in 6.20.0.",
        "unpatched": {"confirmed": True, "reason": "The consumer still mounts the vulnerable dependency route and excludes the fixed upstream release.", "potential_fix": {"approach": "Upgrade the Gradio dependency to 6.20.0 or later and verify the mounted file route.", "rationale": "Upstream 1c5c53842df9c2750552d85c19a92e7e732cff3f replaces the arbitrary redirect with a secure streamed response.", "reference_commit": "1c5c53842df9c2750552d85c19a92e7e732cff3f", "reference_url": "https://github.com/gradio-app/gradio/commit/1c5c53842df9c2750552d85c19a92e7e732cff3f"}},
    },
}

APPEND = {
    "w029": "Rereview also verifies affected v0.9.0, v1.0.0-BETA-1, v1.0.0-BETA-2, and v1.0.0-RC1 through equivalent squash landing d2333551cd5907b56cfcdd2a244e095ab72512e4.",
    "w133": "For CVE-2026-41635, parent absence refers to the incomplete acceptMatchers/null-clazz pairing, not the older unrestricted deserialization sink. Repository tags first contain fixes in 2.1.12 and 2.2.7.",
    "w153": "First-party PR #234 exposes two members; 5f98c26b86f7e6bc049131441dd3a6aa5c2f0670 remains the atomic BIC, so this is not a squash decomposition.",
    "w165": "Repository-verified affected membership begins at 0.20.0, not version 0; 1.0.3 is last vulnerable and 1.1.0 first fixed.",
    "w277": "Historical BIC paths are app.js, routes/coreRoutes/coreDownloadRouter.js, and handlers/downloadHandler/downloadPdf.js; backend/src paths apply only to later trees.",
}


def main() -> None:
    assert set().union(*map(set, SCOPES.values())) == {f"w{n:03d}" for n in [2,6,7,8,10,11,19,29,78,88,115,122,123,124,133,136,139,153,165,166,167,180,206,207,227,252,277,289,312,326,358,387,395]}
    rows = []
    for worker, changes in SET.items():
        path = PRIMARY / f"{worker}.json"
        record = json.loads(path.read_text())
        record.update(changes)
        note = APPEND.get(worker)
        if note and note not in record["evidence"]:
            if isinstance(record["evidence"], list):
                record["evidence"].append(note)
            else:
                record["evidence"] = record["evidence"].rstrip() + "\n" + note
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
        scope = next(name for name, workers in SCOPES.items() if worker in workers)
        rows.append({"worker": worker, "correction_scope": scope, "fields": sorted(changes) + (["evidence"] if note else [])})
    for scope, workers in SCOPES.items():
        for worker in workers:
            if worker not in SET:
                rows.append({"worker": worker, "correction_scope": scope, "fields": []})
    rows.sort(key=lambda row: row["worker"])
    (LANE / "canonical-corrections.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert len(rows) == 33 and len({row["worker"] for row in rows}) == 33
    print(json.dumps({name: len(workers) for name, workers in SCOPES.items()}))


if __name__ == "__main__":
    main()
