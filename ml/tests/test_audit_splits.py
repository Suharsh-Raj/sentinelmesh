import unittest

from ml.audit_splits import audit
from ml.evaluate import Example, OverlapIndex


def example(identifier, body, group, *, label="legitimate", source="publisher"):
    return Example(identifier, "", body, label, source, "promotion", group)


class SplitAuditTests(unittest.TestCase):
    def test_detects_train_dev_test_overlap_and_v1_reference(self):
        phrase = ("the studio shelving order arrived yesterday please note that your workspace storage "
                  "reservation includes four labeled boxes and a separate lockable cabinet")
        reference = OverlapIndex()
        reference.add(0, "a baseline message about astronomy", "")
        splits = {
            "train": [example("shared", phrase, "template-1")],
            "dev": [example("dev-1", "a baseline message about astronomy", "thread-1")],
            "test": [example("test-1", phrase + " tomorrow please", "template-1"),
                     example("shared", "a separate workshop opens tonight", "template-2"),
                     example("test-2", "a baseline message about astronomy", "thread-2")],
        }
        report = audit(splits, reference)
        collisions = report["overlap"]
        self.assertEqual(collisions["shared_ids"], 1)
        self.assertEqual(collisions["shared_groups"], 1)
        self.assertEqual(collisions["cross_split_text_pairs"]["train/test"], {"exact": 0, "near": 1})
        self.assertEqual(collisions["cross_split_text_pairs"]["dev/test"], {"exact": 1, "near": 0})
        self.assertEqual(collisions["v1_reference_overlapping_rows"]["test"]["exact"], 1)
        self.assertFalse(report["separation_passed"])

    def test_uncertain_labels_do_not_fill_coverage_and_unseen_sources_are_reported(self):
        splits = {
            "train": [example("train", "the exhibition schedule changed", "training")],
            "dev": [example("dev", "payroll closes earlier tomorrow", "development")],
            "test": [example("test", "your coffee delivery is delayed", "delivery", source="new-origin"),
                     example("unknown", "an unverified note", None, label="uncertain", source="new-origin")],
        }
        report = audit(splits, OverlapIndex())
        self.assertTrue(report["separation_passed"])
        self.assertFalse(report["coverage_passed"])
        self.assertEqual(report["coverage"]["test"]["eligible"], {"legitimate": 1, "phishing": 0})
        self.assertEqual(report["coverage"]["test"]["excluded"], {"uncertain": 1})
        self.assertEqual(report["test_sources_unseen_in_train_or_dev"], {"legitimate": 1, "phishing": 0})

    def test_missing_group_for_labeled_row_blocks_separation(self):
        splits = {"train": [], "dev": [], "test": [example("test", "your receipt is ready", None)]}
        report = audit(splits, OverlapIndex())
        self.assertFalse(report["separation_passed"])
        self.assertEqual(report["overlap"]["missing_groups"]["test"], 1)
