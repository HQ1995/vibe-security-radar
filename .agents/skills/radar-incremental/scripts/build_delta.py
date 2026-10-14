"""Build deterministic advisory intake routing; never infer causal verdicts or write Neon."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

from fetch import Capturer, STREAMS, timestamp as window_timestamp

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "cve-analyzer/src"))
from cve_analyzer.git_url import parse_repo_url
from cve_analyzer.repository_policy import is_metadata_repository

PUBLIC_ID = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2})$", re.I)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def public_ids(values) -> tuple[str, ...]:
    return tuple(sorted({str(x).upper() for x in values if PUBLIC_ID.fullmatch(str(x))}))


def known_ids(row: dict) -> tuple[str, ...]:
    values = []
    for field in ("advisory_ids", "public_ids", "advisory_aliases", "extra_aliases", "ghsa_ids"):
        values.extend(v.get("id") if isinstance(v, dict) else v for v in row.get(field, []))
    values.extend((row.get("advisory_identity") or {}).get("member_ids", []))
    return public_ids(values)


def class_id(ids) -> str:
    members = sorted("GHSA-" + x[5:].lower() if x.startswith("GHSA-") else x for x in public_ids(ids))
    if not members:
        raise ValueError("An identity requires explicit CVE/GHSA identifiers")
    return "alias-" + hashlib.sha256(("\n".join(members) + "\n").encode()).hexdigest()[:24]


@dataclass(frozen=True)
class SourceRecord:
    source: str
    source_id: str
    ids: tuple[str, ...]
    published: str
    modified: str
    retired: bool
    repo_candidates: tuple[str, ...]
    sha256: str
    path: str
    pointer: str
    reviewed_product_repository: str | None = None
    product_mapping_reference: str | None = None


def normalize(item: dict, source: str, path: str, pointer: str) -> SourceRecord:
    product_repo = product_reference = None
    if not isinstance(item, dict):
        raise ValueError(f"Expected advisory object: {path}#{pointer}")
    if source == "github":
        # This path consumes global REST list items, never repository/OSV projections.
        if "state" in item:
            raise ValueError(f"Expected global advisory without repository state: {path}#{pointer}")
        for field in ("published_at", "updated_at", "withdrawn_at"):
            value = item.get(field)
            if field in item and field == "withdrawn_at" and value is None:
                continue
            if not isinstance(value, str) or not re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
                    r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-5][0-9])", value):
                raise ValueError(f"Invalid global advisory {field}: {path}#{pointer}")
            try:
                datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"Invalid global advisory {field}: {path}#{pointer}") from exc
        arrays = {}
        for field in ("identifiers", "references"):
            if field not in item or (item[field] is not None and not isinstance(item[field], list)):
                raise ValueError(f"Expected nullable global advisory {field} array: {path}#{pointer}")
            arrays[field] = [] if item[field] is None else item[field]
        sid = item.get("ghsa_id")
        typed_ids = [("GHSA", sid)]
        if item.get("cve_id") is not None:
            typed_ids.append(("CVE", item["cve_id"]))
        for entry in arrays["identifiers"]:
            if not isinstance(entry, dict):
                raise ValueError(f"Invalid global advisory identifier entry: {path}#{pointer}")
            typed_ids.append((entry.get("type"), entry.get("value")))
        for kind, value in typed_ids:
            if (kind not in ("CVE", "GHSA") or not isinstance(value, str)
                    or not PUBLIC_ID.fullmatch(value) or not value.upper().startswith(kind + "-")):
                raise ValueError(f"Invalid global advisory identifier type/value: {path}#{pointer}")
            if kind == "GHSA" and value.upper() != sid.upper():
                raise ValueError(f"Global advisory GHSA identifier differs from ghsa_id: {path}#{pointer}")
        ids = public_ids(value for _, value in typed_ids)
        published, modified = item["published_at"], item["updated_at"]
        retired = item["withdrawn_at"] is not None
        references = arrays["references"]
        location = item.get("source_code_location")
        if any(not isinstance(ref, str) for ref in references) or (location is not None and not isinstance(location, str)):
            raise ValueError(f"Invalid global advisory reference: {path}#{pointer}")
        refs = [location, *references]
        location = parse_repo_url(location or "")
        if item.get("type") == "reviewed" and location:
            host, owner, repo = location
            candidate = f"https://{host}/{owner}/{repo}"
            for ref in references:
                url = urlsplit(ref) if isinstance(ref, str) else None
                if (url and url.scheme == "https" and url.netloc.lower() == host.lower()
                        and url.path.rstrip("/").lower() == f"/{owner}/{repo}/security/advisories/{sid}".lower()
                        and not is_metadata_repository(candidate)):
                    product_repo, product_reference = candidate, ref
                    break
    elif source == "nvd":
        sid = item["id"]
        ids = public_ids([sid])
        published, modified = item["published"], item["lastModified"]
        retired = item.get("vulnStatus", "").lower() == "rejected"
        refs = [x.get("url") for x in item.get("references", [])]
    else:
        raise ValueError(f"Unknown advisory source: {source}")
    if not ids or sid.upper() not in ids:
        raise ValueError(f"Invalid source identity: {sid}")
    repos = set()
    for url in refs:
        if not isinstance(url, str):
            continue
        parsed = parse_repo_url(url)
        if parsed:
            host, owner, repo = parsed
            candidate = f"https://{host}/{owner}/{repo}"
            if not is_metadata_repository(candidate):
                repos.add(candidate)
    raw_hash = hashlib.sha256(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return SourceRecord(source, sid.upper(), ids, published, modified, retired, tuple(sorted(repos)), raw_hash, path, pointer,
                        product_repo, product_reference)


def load_records(capture: Path, coverage: dict) -> list[SourceRecord]:
    records = {}
    required = set(STREAMS)
    streams = coverage.get("streams", [])
    if (coverage.get("status") != "COMPLETE" or len(streams) != len(required)
            or {s["name"] for s in streams} != required or not all(s.get("complete") for s in streams)):
        raise ValueError("All required source streams must be complete")
    validator = Capturer(capture, coverage["window"], None)
    if json.loads((capture / "fetch-contract.json").read_text()) != validator.contract:
        raise ValueError("Capture contract does not match the source window")
    # Reuse fetch's raw Link/NVD count/unique-ID validation without a client.
    # A hand-edited COMPLETE manifest cannot hide an unfinished page chain.
    for stream in streams:
        replay = {"pages": 0, "rows": 0, "body_paths": [], "page_receipts": []}
        validator.stream(stream["name"], replay)
        keys = ("pages", "rows", "unique_ids", "body_paths", "complete")
        if stream["name"].startswith("nvd-"):
            keys += ("total_results",)
        if any(stream.get(key) != replay[key] for key in keys):
            raise ValueError("Coverage differs from retained source pagination")
        receipts = stream["page_receipts"]
        if len(receipts) != len(replay["page_receipts"]) or any(
                {k: v for k, v in left.items() if k != "reused"} !=
                {k: v for k, v in right.items() if k != "reused"}
                for left, right in zip(receipts, replay["page_receipts"])):
            raise ValueError("Coverage differs from retained source page receipts")
    pages = [p for stream in streams for p in stream["page_receipts"]]
    paths = [p["path"].removesuffix(".receipt.json") + ".body" for p in pages]
    if len(set(paths)) != len(paths) or sorted(paths) != sorted(coverage["body_paths"]):
        raise ValueError("Coverage page manifest mismatch")
    for page, name in sorted(zip(pages, paths), key=lambda item: item[1]):
        if Path(name).name != name or not name.endswith(".body"):
            raise ValueError("Source body must be a direct child of the capture directory")
        path = capture / name
        receipt = json.loads(path.with_suffix(".receipt.json").read_text())
        if (receipt["status"] != 200 or page["status"] != 200
                or receipt["url"] != page["url"] or receipt["sha256"] != page["sha256"]):
            raise ValueError(f"Source page receipt does not match coverage: {path}")
        data = validator._checked(path.read_bytes(), receipt, page["url"], local=True,
                                  ghsa=name.startswith("ghsa-"))
        if isinstance(data, list):
            entries = ((item, "github", f"/{i}") for i, item in enumerate(data))
        elif isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            entries = ((v["cve"], "nvd", f"/vulnerabilities/{i}/cve") for i, v in enumerate(data["vulnerabilities"]))
        else:
            raise ValueError(f"Unexpected source page: {path}")
        if (len(data) if isinstance(data, list) else len(data["vulnerabilities"])) != page["rows"]:
            raise ValueError("Source body count differs from the coverage receipt")
        for item, source, pointer in entries:
            record = normalize(item, source, str(path.resolve()), pointer)
            records.setdefault((record.source, record.source_id, record.sha256), record)
    return list(records.values())


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def timestamp(value: str) -> tuple[datetime, str]:
    # Datetime supplies calendar/offset ordering; keep all fractional digits out
    # of its microsecond-limited comparison. Trim only insignificant zeroes.
    match = re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:[.,]([0-9]+))?(?:[Zz]|[+-][0-9]{2}:[0-5][0-9])?)?", value)
    if match is None:
        raise ValueError("Unsupported timestamp syntax")
    result = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    whole = result.replace(microsecond=0)
    return (whole if whole.tzinfo else whole.replace(tzinfo=timezone.utc),
            (match[1] or "").rstrip("0"))


def reconcile(records: list[SourceRecord], ledger: list[dict], universe: list[dict], occupied: dict,
              prior_deltas: list[dict] = ()) -> list[dict]:
    parent = {}
    prior_hashes, latest_status = {}, {}

    def remember_status(source, source_id, modified, retired):
        key, when = (source, source_id.upper()), timestamp(modified)
        previous = latest_status.get(key)
        if previous is None or when > previous[0]:
            latest_status[key] = (when, retired)
        elif when == previous[0]:
            # Conflicting same-time observations cannot clear a retirement.
            latest_status[key] = (when, previous[1] or retired)

    for row in prior_deltas:
        versions = defaultdict(set)
        for source in row["source_records"]:
            versions[(source["source"], source["source_id"])].add(source["sha256"])
            remember_status(source["source"], source["source_id"], source["modified"], source["retired"])
        prior_hashes.update(versions)
    for record in records:
        remember_status(record.source, record.source_id, record.modified, record.retired)
    universe = list(universe)
    conflict_owners = defaultdict(set)
    for row in prior_deltas:
        if row["identity"] == "CONFLICT":
            # Keep the observed alias edge and its original owners for routing;
            # the synthetic conflict class is never adopted as a real owner.
            for owner in set(row["ledger_class_ids"] + row["prior_universe_class_ids"]):
                universe.append({"class_id": owner, "public_ids": row["public_ids"]})
                for ident in known_ids(row):
                    conflict_owners[ident].add(owner)
        else:
            universe.append(row)
    occupancy = defaultdict(list)
    for key, holders in occupied.items():
        occupancy[key.casefold()].extend(holders)

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def join(ids):
        for value in ids:
            parent[find(value)] = find(ids[0])

    incoming = {i for record in records for i in record.ids}
    parent.update((ident, ident) for ident in incoming)
    # Import complete prior identity components touched by this increment. Revisit
    # until no new aliases appear; titles and reference URLs never create edges.
    known = [(r, known_ids(r)) for r in [*ledger, *universe]]
    pending = known
    while True:
        remaining, changed = [], False
        for row, ids in pending:
            if any(value in parent for value in ids):
                before = len(parent)
                join(ids)
                changed |= len(parent) != before
            else:
                remaining.append((row, ids))
        if not changed:
            break
        pending = remaining
    # Snapshot existing connectivity before new source edges can bridge owners.
    # Unowned new identifiers do not count as separate existing components.
    prior_roots = {find(ids[0]) for _, ids in known if ids and ids[0] in parent}
    for record in records:
        join(record.ids)
    joined_prior_components = Counter(find(root) for root in prior_roots)
    groups = defaultdict(list)
    members = defaultdict(set)
    for record in records:
        groups[find(record.ids[0])].append(record)
    for value in parent:
        members[find(value)].add(value)
    ledger_hits, universe_hits = defaultdict(set), defaultdict(set)
    for rows, dest in [(ledger, ledger_hits), (universe, universe_hits)]:
        for row in rows:
            ids = known_ids(row)
            roots = {find(i) for i in ids if i in parent}
            for root in roots:
                dest[root].add(row["class_id"])
    statuses = defaultdict(dict)
    for key, (_, retired) in latest_status.items():
        if key[1] in parent:
            statuses[find(key[1])][key] = retired
    for record in records:
        key = (record.source, record.source_id.upper())
        statuses[find(record.ids[0])][key] = latest_status[key][1]
    result = []
    for root, values in groups.items():
        ids = sorted(members[root])
        booked, prior = sorted(ledger_hits[root]), sorted(universe_hits[root])
        variants = defaultdict(set)
        for record in values:
            variants[(record.source, record.source_id)].add(record.sha256)
        conflicts = sorted(f"{s}:{i}" for (s, i), hashes in variants.items() if len(hashes) > 1)
        retained_owners = {owner for ident in ids for owner in conflict_owners.get(ident, ())}
        identity_conflict = (len(booked) > 1 or (not booked and len(prior) > 1)
                             or len(retained_owners | set(booked)) > 1
                             or (joined_prior_components[root] > 1 and len(set(booked) | set(prior)) > 1))
        cid = (class_id(ids) if identity_conflict else booked[0] if booked
               else prior[0] if prior else class_id(ids))
        holders = []
        for hit in sorted(set([cid, *booked, *prior, *ids])):
            for holder in occupancy.get(hit.casefold(), []):
                if holder not in holders:
                    holders.append(holder)
        repos = sorted({repo for record in values for repo in record.repo_candidates})
        retired = [f"{source}:{sid}" for (source, sid), value in statuses[root].items() if value]
        payload_changes = {
            f"{v.source}:{v.source_id}": (
                "PRIOR_PAYLOAD_UNAVAILABLE" if (v.source, v.source_id) not in prior_hashes
                else "PRIOR_CAPTURE_CONFLICT" if len(prior_hashes[v.source, v.source_id]) != 1
                else "UNCHANGED" if v.sha256 in prior_hashes[v.source, v.source_id] else "CHANGED")
            for v in values
        }
        if conflicts:
            route = "SOURCE_CAPTURE_CONFLICT"
        elif identity_conflict:
            route = "IDENTITY_CONFLICT"
        elif holders:
            route = "EXISTING_OWNER_HANDOFF"
        elif retired:
            route = "ADVISORY_STATUS_REVIEW"
        elif booked:
            route = "EXISTING_SOURCE_REVALIDATION"
        elif repos:
            route = "PRODUCT_SOURCE_REVIEW"
        else:
            route = "REPOSITORY_DISCOVERY"
        result.append({
            "class_id": cid, "public_ids": ids, "incoming_public_ids": sorted(set(ids) & incoming),
            "identity": "CONFLICT" if identity_conflict else "EXISTING_LEDGER" if booked else "EXISTING_UNIVERSE_NOT_IN_LEDGER" if prior else "NEW_TO_UNIVERSE",
            "ledger_class_ids": booked, "prior_universe_class_ids": prior,
            "routing": route, "occupancy": holders, "repository_candidates": repos,
            "retired_source_records": retired, "all_sources_retired": all(statuses[root].values()),
            "source_capture_conflicts": conflicts,
            "reviewed_product_repositories": sorted({v.reviewed_product_repository for v in values if v.reviewed_product_repository and not v.retired}),
            "source_records": [{"source": v.source, "source_id": v.source_id, "published": v.published,
                                "modified": v.modified, "retired": v.retired, "sha256": v.sha256,
                                "path": v.path, "pointer": v.pointer,
                                "reviewed_product_repository": v.reviewed_product_repository,
                                "product_mapping_reference": v.product_mapping_reference} for v in sorted(values, key=lambda x: (x.source, x.source_id, x.sha256))],
            "research_acceptance": "NOT_ASSESSED_BY_INTAKE", "ledger_write": False,
            "source_payload_changes": payload_changes,
            "content_delta": "CHANGED" if "CHANGED" in payload_changes.values() else
                "UNCHANGED" if set(payload_changes.values()) == {"UNCHANGED"} else "PRIOR_PAYLOAD_DIGEST_UNAVAILABLE",
        })
    return sorted(result, key=lambda x: (x["class_id"], x["public_ids"]))


def load_prior_deltas(paths: list[Path], window: dict) -> list[dict]:
    """Require intact, complete ancestry instead of forgetting off-ledger rows."""
    rows, available, seen_paths, previous_end = [], set(), set(), None
    source_pages = {}
    for path in paths:
        raw = path.read_bytes()
        pin = hashlib.sha256(raw).hexdigest()
        summary = json.loads(path.with_name("summary.json").read_text())
        if pin != summary["delta_sha256"]:
            raise ValueError("Prior delta hash mismatch")
        if path.resolve() in seen_paths:
            raise ValueError("Duplicate prior delta input")
        seen_paths.add(path.resolve())
        ancestors = {p["sha256"] for p in summary.get("prior_deltas", [])}
        if not ancestors <= available:
            raise ValueError("Missing prior delta ancestry; pass all earlier deltas oldest first")
        prior_window = summary["coverage"]["window"]
        start, end = (window_timestamp(prior_window[k]) for k in ("start", "end"))
        if start >= end or (previous_end and not start <= previous_end <= end):
            raise ValueError("Prior source windows have a gap or are out of order")
        batch = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if (summary.get("status") != "INTAKE_CLASSIFIED_NOT_RESEARCH_ACCEPTANCE"
                or summary["coverage"].get("status") != "COMPLETE"
                or len(batch) != summary["components"]):
            raise ValueError("Prior delta is not a complete classified capture")
        # Earlier projections can predate source validation. Recheck their pinned
        # global list objects instead of trusting a saved retired boolean or alias.
        for row in batch:
            for observation in row["source_records"]:
                if observation["source"] not in ("github", "nvd"):
                    raise ValueError("Unknown prior advisory source")
                if observation["source"] != "github":
                    continue
                source_path, pointer = Path(observation["path"]), observation["pointer"]
                if source_path not in source_pages:
                    source_pages[source_path] = json.loads(source_path.read_text())
                page = source_pages[source_path]
                if not isinstance(page, list) or not isinstance(pointer, str) or not re.fullmatch(r"/(0|[1-9][0-9]*)", pointer):
                    raise ValueError(f"Expected prior global advisory list-item pointer: {source_path}#{pointer}")
                record = normalize(page[int(pointer[1:])], "github", str(source_path), pointer)
                if (not isinstance(observation["retired"], bool) or any(
                        getattr(record, field) != observation[field]
                        for field in ("source_id", "sha256", "published", "modified", "retired"))):
                    raise ValueError(f"Prior source projection differs from pinned object: {source_path}#{pointer}")
        rows.extend(batch)
        available.add(pin)
        previous_end = end
    if previous_end and not window_timestamp(window["start"]) <= previous_end <= window_timestamp(window["end"]):
        raise ValueError("Current source window must overlap the previous end without moving backwards")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--prior-delta", type=Path, action="append", default=[],
                        help="Earlier delta.jsonl files, oldest first, including off-ledger dispositions")
    parser.add_argument("--occupancy", type=Path, required=True, help="JSON mapping class_id to current claim entries")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    inputs = [args.ledger, args.universe, args.occupancy, args.capture / "coverage.json",
              *args.prior_delta, *(p.with_name("summary.json") for p in args.prior_delta)]
    input_pins = {str(p.resolve()): digest(p) for p in inputs}
    coverage = json.loads((args.capture / "coverage.json").read_text())
    if coverage.get("status") != "COMPLETE":
        raise SystemExit("Required source capture is incomplete; retain its coverage gaps before classification")
    rows = reconcile(load_records(args.capture, coverage), read_jsonl(args.ledger), read_jsonl(args.universe),
                     json.loads(args.occupancy.read_text()), load_prior_deltas(args.prior_delta, coverage["window"]))
    window = coverage["window"]
    start, end = timestamp(window["start"]), timestamp(window["end"])
    for row in rows:
        publications = [timestamp(r["published"]) for r in row["source_records"] if r["published"]]
        row["source_publication_in_window"] = any(start <= value <= end for value in publications)
        row["earliest_source_publication"] = None
        if publications:
            whole, fraction = min(publications)
            formatted = whole.isoformat()
            # Preserve the existing microsecond spelling, extending it losslessly.
            row["earliest_source_publication"] = (formatted[:19] + "." + fraction.ljust(6, "0") + formatted[19:]
                                                  if fraction else formatted)
        row["older_publication_in_component"] = any(value < start for value in publications)
    if any(digest(p) != input_pins[str(p.resolve())] for p in inputs):
        raise ValueError("Classification input changed during the run; retain frozen inputs")
    args.out.mkdir(parents=True, exist_ok=False)
    with (args.out / "delta.jsonl").open("x") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = {"status": "INTAKE_CLASSIFIED_NOT_RESEARCH_ACCEPTANCE", "components": len(rows),
               "identities": dict(Counter(r["identity"] for r in rows)),
               "routing": dict(Counter(r["routing"] for r in rows)), "coverage": coverage,
               "source_publication_in_window": sum(r["source_publication_in_window"] for r in rows),
               "older_publication_in_component": sum(r["older_publication_in_component"] for r in rows),
               "input_pins": input_pins,
               "prior_deltas": [{"path": str(p.resolve()), "sha256": input_pins[str(p.resolve())]} for p in args.prior_delta],
               "fetch_implementation_sha256": digest(Path(__file__).with_name("fetch.py")),
               "implementation_sha256": digest(Path(__file__)),
               "delta_sha256": digest(args.out / "delta.jsonl"), "ledger_writes": 0}
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.out / "checkpoint.json").write_text(json.dumps({
        "source_capture_window": window, "disposition_manifest_sha256": summary["delta_sha256"],
        "source_capture_complete": True, "intake_classified": len(rows),
        "research_accepted": 0, "research_pending": len(rows), "ledger_writes": 0,
        "publication": "NOT_RUN", "overall_research_complete": False,
    }, indent=2) + "\n")
    print(json.dumps({key: summary[key] for key in ["status", "components", "identities", "routing", "ledger_writes"]}))


if __name__ == "__main__":
    main()
