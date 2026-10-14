import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from watermark import advance


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class WatermarkChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        prior = root / "prior.jsonl"
        prior.write_text('{"class_id": "alias-a"}\n')
        self.watermark = root / "source-watermark.json"
        self.watermark.write_text(json.dumps({"source_capture_watermark": "2026-10-04T08:13:00Z",
                                              "delta_chain": [{"path": "prior.jsonl", "sha256": sha(prior)}]}))
        self.run = root / "incremental-20261014"
        (self.run / "capture").mkdir(parents=True)
        (self.run / "classification").mkdir()
        delta = self.run / "classification" / "delta.jsonl"
        delta.write_text('{"class_id": "alias-b"}\n')
        self.summary = {"delta_sha256": sha(delta), "components": 1,
                        "prior_deltas": [{"path": str(prior), "sha256": sha(prior)}]}
        (self.run / "classification" / "summary.json").write_text(json.dumps(self.summary))
        self.coverage = {"status": "COMPLETE", "window": {"start": "2026-10-04T00:00:00Z",
                                                          "end": "2026-10-14T00:00:00.5Z", "inclusive": True}}
        (self.run / "capture" / "coverage.json").write_text(json.dumps(self.coverage))
        self.sources = root / "sources"

    def tearDown(self):
        self.tmp.cleanup()

    def test_complete_increment_extends_the_chain(self):
        result = advance(self.run, self.watermark, self.sources)
        self.assertEqual(result, {"source_capture_watermark": "2026-10-14T00:00:00.5Z", "chain_length": 2})
        current = json.loads(self.watermark.read_text())
        self.assertEqual(current["next_window_start"], "2026-10-14T00:00:00Z")
        self.assertTrue((self.sources / "deltas" / "002-20261014T000000.5Z" / "delta.jsonl").is_file())

    def test_incomplete_capture_or_broken_chain_keeps_the_watermark(self):
        before = self.watermark.read_text()
        (self.run / "capture" / "coverage.json").write_text(json.dumps({**self.coverage, "status": "PARTIAL"}))
        with self.assertRaises(ValueError):
            advance(self.run, self.watermark, self.sources)
        (self.run / "capture" / "coverage.json").write_text(json.dumps(self.coverage))
        (self.run / "classification" / "summary.json").write_text(json.dumps({**self.summary, "prior_deltas": []}))
        with self.assertRaises(ValueError):
            advance(self.run, self.watermark, self.sources)
        self.assertEqual(self.watermark.read_text(), before)


if __name__ == "__main__":
    unittest.main()
