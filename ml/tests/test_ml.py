import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from ml.artifact import MODEL_FILE, load_bundle, predict, save_bundle
from ml.dataset import Sample, clean_and_group, map_label, split_dataset
from ml.preprocessing import preprocess
from ml.train import make_pipeline, select_threshold


class PreprocessingTests(unittest.TestCase):
    def test_missing_fields_and_unicode(self):
        self.assertEqual(preprocess(), "")
        self.assertEqual(preprocess("Ｒｅ: Café", "NAI\u0308VE  \u200b text"), "café naïve text")
        self.assertEqual(preprocess(None, "  useful body  "), "useful body")

    def test_html_and_source_markers_are_removed(self):
        body = """<p>Confirm &amp; check</p><script>ignore this</script>
          <style>ignore this too</style><a href="https://example.test">portal</a>
          <p>Mail me@demo.test or visit https://example.test</p>"""
        self.assertEqual(preprocess("[SPAM] Enron message", body), "message confirm & check portal mail or visit")

    def test_headers_and_quoted_material_are_excluded(self):
        body = "X-Spam-Status: Yes\r\n\tcontinued\r\nFrom: test@example.test\r\n> old quote\r\nHi there"
        self.assertEqual(preprocess(None, body), "hi there")


class DatasetTests(unittest.TestCase):
    def test_label_mapping_is_specific_to_each_source(self):
        self.assertEqual(map_label("enron", "0"), 0)
        self.assertIsNone(map_label("enron", "1"))
        self.assertEqual(map_label("nazario", "1"), 1)
        with self.assertRaisesRegex(ValueError, "Unexpected label"):
            map_label("nazario", "spam")

    def test_dedup_discards_conflicting_labels_and_keeps_one_exact_copy(self):
        phrase = "tomorrow morning we can start a fresh review of all the plans discussed with our team"
        samples = [
            Sample("a", "enron", 0, phrase),
            Sample("b", "nazario", 1, phrase),
            Sample("c", "enron", 0, phrase + " today"),
            Sample("d", "enron", 0, "a separate identical message"),
            Sample("e", "enron", 0, "a separate identical message"),
        ]
        cleaned, _, counts = clean_and_group(samples)
        self.assertEqual([item.row_id for item in cleaned], ["d"])
        self.assertEqual(counts["conflicting_rows_removed"], 3)
        self.assertEqual(counts["exact_conflict_groups"], 1)
        self.assertEqual(counts["near_conflict_groups"], 1)
        self.assertEqual(counts["exact_duplicates_removed"], 1)

    def test_related_messages_cannot_cross_splits(self):
        phrase = "tomorrow morning we can start a fresh review of all the plans discussed with our team"
        samples = [
            Sample("a", "enron", 0, phrase, "weekly scheduling discussion"),
            Sample("b", "enron", 0, phrase + " today"),
            Sample("c", "enron", 0, "different reply body", "weekly scheduling discussion", True),
        ]
        samples.extend(Sample(str(i), "enron" if i % 2 == 0 else "nazario", i % 2, f"unrelated sample {i}")
                       for i in range(60))
        cleaned, groups, counts = clean_and_group(samples)
        members = dict(zip((s.row_id for s in cleaned), groups))
        self.assertEqual(members["a"], members["b"])
        self.assertEqual(members["a"], members["c"])
        self.assertEqual(counts["near_groups_retained"], 1)
        splits = split_dataset(cleaned, groups)
        split_groups = [{groups[i] for i in indexes} for indexes in splits.values()]
        self.assertEqual(sum(map(len, split_groups)), len(set.union(*split_groups)))
        again = split_dataset(cleaned, groups)
        for key in splits:
            np.testing.assert_array_equal(splits[key], again[key])


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.pipeline = make_pipeline().fit(
            ["weekly team schedule and notes", "team schedule for weekly meeting",
             "verify account and password now", "account verify your password now"],
            [0, 0, 1, 1],
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / "bundle"

    def test_model_round_trip(self):
        save_bundle(self.bundle, self.pipeline, {"threshold": 0.5})
        restored, manifest = load_bundle(self.bundle)
        expected = predict(self.pipeline, manifest, "verify your account")
        self.assertEqual(expected, predict(restored, manifest, "verify your account"))
        self.assertEqual(expected["model_prediction"], "phishing")

    def test_missing_bundle_has_actionable_error(self):
        with self.assertRaisesRegex(ValueError, "Missing model bundle.*Run ml.train"):
            load_bundle(self.bundle)

    def test_incompatible_dependencies_fail_before_deserializing(self):
        save_bundle(self.bundle, self.pipeline, {"threshold": 0.5})
        path = self.bundle / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["versions"]["scikit-learn"] = "0.0.0"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with patch("ml.artifact.joblib.load") as load:
            with self.assertRaisesRegex(ValueError, "Incompatible model dependencies: scikit-learn"):
                load_bundle(self.bundle)
            load.assert_not_called()

    def test_corruption_fails_before_deserializing(self):
        save_bundle(self.bundle, self.pipeline, {"threshold": 0.5})
        (self.bundle / MODEL_FILE).write_bytes(b"invalid data")
        with patch("ml.artifact.joblib.load") as load:
            with self.assertRaisesRegex(ValueError, "checksum"):
                load_bundle(self.bundle)
            load.assert_not_called()

    def test_validation_threshold_rejects_high_scoring_false_positive(self):
        self.assertEqual(select_threshold([0, 0, 0, 1, 1], [0.2, 0.1, 0.7, 0.8, 0.5]), 0.8)
