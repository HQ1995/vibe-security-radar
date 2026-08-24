#!/usr/bin/env python3
"""Phase 3: live GraphQL advisory enumeration with cursor conservation proof.

Pages through github.com GraphQL securityAdvisories (publishedSince and
updatedSince) in 100-item pages, records per-page request cursor, response
sha256, endCursor, hasNextPage. Raw JSON pages stored ONLY under
/tmp/ghsa200-worker-clones/current-delta/raw/; the repo gets a hash manifest.
"""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_delta import OWN, SCRATCH, sha256_file  # noqa: E402

RAW = SCRATCH / "raw"
RAW.mkdir(exist_ok=True)

FROZEN_ISO = "2026-07-23T12:34:36Z"   # frozen commit timestamp
WINDOW_START = "2026-07-23T00:00:00Z"  # inclusive full-day window start

QUERY_PUBLISHED = """
query {
  securityAdvisories(
    publishedSince: "%s",
    first: 100,
    after: $cursor,
    orderBy: {field: PUBLISHED_AT, direction: ASC}
  ) {
    pageInfo { hasNextPage endCursor }
    nodes { ghsaId publishedAt updatedAt withdrawnAt }
  }
}
""" % WINDOW_START

QUERY_UPDATED = """
query {
  securityAdvisories(
    updatedSince: "%s",
    first: 100,
    after: $cursor,
    orderBy: {field: UPDATED_AT, direction: ASC}
  ) {
    pageInfo { hasNextPage endCursor }
    nodes { ghsaId publishedAt updatedAt withdrawnAt }
  }
}
""" % FROZEN_ISO


def gh_graphql(query_tpl: str, cursor: str | None) -> dict:
    if cursor is None:
        query = query_tpl.replace("after: $cursor", "after: null")
    else:
        query = query_tpl.replace("after: $cursor", f"after: {json.dumps(cursor)}")
    out = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}"],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh api failed: {out.stderr[:300]}")
    return json.loads(out.stdout)


def run_pass(name: str, query: str, out_prefix: str) -> dict:
    cursor = None
    pages = []
    ids = []
    for page_no in range(1, 500):
        try:
            resp = gh_graphql(query, cursor)
        except Exception as e:
            raise RuntimeError(f"page {page_no} failed: {e}") from e
        raw_bytes = json.dumps(resp, sort_keys=True).encode()
        h = hashlib.sha256(raw_bytes).hexdigest()
        raw_file = RAW / f"{out_prefix}-page-{page_no:04d}.json"
        raw_file.write_bytes(json.dumps(resp).encode())
        data = resp.get("data", {}).get("securityAdvisories", {})
        if not data:
            raise RuntimeError(f"page {page_no}: unexpected payload: {json.dumps(resp)[:200]}")
        info = data.get("pageInfo", {})
        nodes = data.get("nodes", [])
        pages.append({
            "page": page_no,
            "request_after_cursor": cursor,
            "response_sha256": h,
            "response_end_cursor": info.get("endCursor"),
            "has_next_page": info.get("hasNextPage"),
            "node_count": len(nodes),
            "first_id": nodes[0]["ghsaId"] if nodes else None,
            "last_id": nodes[-1]["ghsaId"] if nodes else None,
        })
        for n in nodes:
            ids.append({"ghsaId": n["ghsaId"], "publishedAt": n["publishedAt"],
                        "updatedAt": n["updatedAt"], "withdrawnAt": n.get("withdrawnAt")})
        if not info.get("hasNextPage"):
            break
        cursor = info.get("endCursor")
        if not cursor:
            raise RuntimeError(f"page {page_no}: hasNextPage true but no endCursor")
    return {"pages": pages, "ids": ids}


def main() -> int:
    out = {"schema_version": 1, "generated_at_utc": datetime.now(timezone.utc).isoformat(),
           "window": {"frozen_snapshot_iso": FROZEN_ISO, "published_since": WINDOW_START},
           "passes": {}}
    for name, q, prefix in (("published_since", QUERY_PUBLISHED, "pub"),
                            ("updated_since", QUERY_UPDATED, "upd")):
        res = run_pass(name, q, prefix)
        # cursor conservation check: endCursor(page N) == after(page N+1)
        ok = True
        for a, b in zip(res["pages"], res["pages"][1:]):
            if a["response_end_cursor"] != b["request_after_cursor"]:
                ok = False
                break
        out["passes"][name] = {
            "pages": len(res["pages"]),
            "total_nodes": len(res["ids"]),
            "cursor_conservation": "PROVEN" if ok and len(res["pages"]) > 1 else ("SINGLE_PAGE" if len(res["pages"]) == 1 else "BROKEN"),
            "page_manifest": res["pages"],
        }
        id_path = SCRATCH / f"api-{prefix}-ids.jsonl"
        with open(id_path, "w") as f:
            for r in res["ids"]:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        out["passes"][name]["ids_file"] = str(id_path)
        out["passes"][name]["ids_sha256"] = sha256_file(id_path)
        print(f"{name}: pages={len(res['pages'])} nodes={len(res['ids'])} cursor_conservation={out['passes'][name]['cursor_conservation']}")
    (OWN / "api-manifest.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print("wrote api-manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
