"""Offline checks for the deterministic intake admission policy."""
import json
from pathlib import Path
import tempfile
import unittest

from intake_rows import select

WINDOW = {"start": "2026-10-01T00:00:00Z", "end": "2026-10-08T00:00:00Z", "inclusive": True}


def component(cid, identity="NEW_TO_UNIVERSE", repos=("https://github.com/o/p",), published="2026-10-02T00:00:00Z",
              prior=()):
    record = {"source": "github", "source_id": "GHSA-2345-6789-CFGH", "retired": False, "published": published,
              "path": "/capture/ghsa-reviewed-0000.body", "pointer": "/0", "sha256": "0" * 64,
              "reviewed_product_repository": repos[0] if repos else None,
              "product_mapping_reference": (repos[0] + "/security/advisories/GHSA-2345-6789-cfgh") if repos else None}
    return {"class_id": cid, "identity": identity, "routing": "PRODUCT_SOURCE_REVIEW", "public_ids": ["GHSA-2345-6789-CFGH"],
            "ledger_class_ids": [], "occupancy": [], "source_capture_conflicts": [], "all_sources_retired": False,
            "reviewed_product_repositories": list(repos), "prior_universe_class_ids": list(prior),
            "source_records": [record]}


class AdmissionChecks(unittest.TestCase):
    def test_policy_admits_new_and_linked_precursors_and_defers_original_universe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "coverage.json").write_text(json.dumps({"window": WINDOW}))
            (root / "universe.jsonl").write_text(json.dumps({"class_id": "alias-original"}) + "\n")
            (root / "prior.jsonl").write_text(json.dumps({"class_id": "alias-other"}) + "\n"
                                              + json.dumps({"class_id": "alias-precursor"}) + "\n")
            rows = [component("alias-new"),
                    component("alias-x", "EXISTING_UNIVERSE_NOT_IN_LEDGER", prior=["alias-precursor"]),
                    component("alias-y", "EXISTING_UNIVERSE_NOT_IN_LEDGER", prior=["alias-original"]),
                    component("alias-two-repos", repos=("https://github.com/o/p", "https://github.com/o/q")),
                    component("alias-old", published="2026-09-01T00:00:00Z"),
                    {**component("alias-held"), "occupancy": [{"owner": "someone"}]}]
            (root / "delta.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
            admitted, deferred = select(root / "delta.jsonl", root / "coverage.json", root / "universe.jsonl",
                                        [root / "prior.jsonl"])
        self.assertEqual([r["class_id"] for r in admitted], ["alias-new", "alias-precursor"])
        self.assertEqual([d["class_id"] for d in deferred], ["alias-original"])
        new, precursor = admitted
        self.assertEqual(new["status"], "UNANALYZED")
        self.assertEqual(new["repo"], "o/p")
        self.assertEqual(new["source_intake"]["repository_mapping"]["repository"], "o/p")
        self.assertNotIn("prior_identity", new["source_intake"])
        self.assertEqual(precursor["source_intake"]["prior_identity"]["line"], 2)


if __name__ == "__main__":
    unittest.main()
