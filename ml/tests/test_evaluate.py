import json
import math
import tempfile
import unittest
from pathlib import Path

from ml.artifact import load_bundle, predict
from ml.evaluate import MODEL_DIR, Example, OverlapIndex, evaluate, explain, metrics, read_examples, select_examples
from ml.preprocessing import preprocess


def example(id, body, label="legitimate", subject=""):
    return Example(id, subject, body, label, "synthetic", "mechanics")


class EvaluationTests(unittest.TestCase):
    def test_metrics_and_single_class_denominators(self):
        pairs = [("legitimate", "legitimate"), ("legitimate", "phishing"),
                 ("phishing", "phishing"), ("phishing", "legitimate"), ("phishing", "legitimate")]
        self.assertEqual(metrics(pairs)["confusion_matrix"], [[1, 1], [2, 1]])
        self.assertEqual(metrics(pairs)["precision"], 0.5)
        self.assertAlmostEqual(metrics(pairs)["recall"], 1 / 3)
        self.assertEqual(metrics(pairs)["f1"], 0.4)
        self.assertEqual(metrics(pairs)["false_positive_rate"], 0.5)
        self.assertIsNone(metrics([("phishing", "legitimate")])["false_positive_rate"])
        negatives = metrics([("legitimate", "legitimate")])
        self.assertEqual(negatives["false_positive_rate"], 0)
        for name in ("precision", "recall", "f1"):
            self.assertIsNone(negatives[name])

    def test_rejects_unknown_labels_and_duplicate_ids_but_accepts_uncertain(self):
        row = dict(id="s1", subject="", body="Test message", source="synthetic", category="misc")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "examples.jsonl"
            path.write_text(json.dumps(dict(row, label="spam")), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid label"):
                read_examples(path)
            encoded = json.dumps(dict(row, label="uncertain"))
            path.write_text(encoded, encoding="utf-8")
            self.assertEqual(read_examples(path)[0].label, "uncertain")
            path.write_text(encoded + "\n" + encoded, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate example ID"):
                read_examples(path)

    def test_excludes_exact_and_near_reference_overlap_and_eval_label_conflicts(self):
        reference = OverlapIndex()
        phrase = ("the studio shelving order arrived yesterday please note that your workspace storage "
                  "reservation includes four labeled boxes and a separate lockable cabinet")
        reference.add(0, "reference subject " + phrase, phrase)
        rows = [
            example("exact", phrase, subject="Changed subject"),
            example("near", phrase + " tomorrow please", subject="New subject"),
            example("conflict-a", "Your receipt is ready", "legitimate"),
            example("conflict-b", "Your receipt is ready", "phishing"),
            example("remaining", "Let's reschedule lunch"),
            example("repeat", "Let's reschedule lunch"),
            example("unknown", "Urgent account security", "uncertain"),
        ]
        selected, removed = select_examples(rows, reference)
        self.assertEqual(list(selected), [4])
        self.assertEqual(removed, {0: "reference_exact", 1: "reference_near", 2: "duplicate_label_conflict",
                                   3: "duplicate_label_conflict", 5: "within_exact", 6: "uncertain"})

    def test_frozen_model_and_preprocessing_match_inference_and_explanation(self):
        if not (MODEL_DIR / "manifest.json").is_file():
            self.skipTest("Local model bundle unavailable")
        pipeline, manifest = load_bundle(MODEL_DIR)
        html = "<p>Review your account today.</p><a href='https://example.org/a?q=123'>Review details</a>"
        probe = Example("s1", "Fwd: Account review", html, "legitimate", "synthetic", "notice", body_is_html=True)
        expected = predict(pipeline, manifest, probe.subject, probe.body, body_is_html=True)
        wrong_label = "phishing" if expected["model_prediction"] == "legitimate" else "legitimate"
        probe = Example("s1", probe.subject, probe.body, wrong_label, "synthetic", "notice", "test-group", True)
        report, private = evaluate([probe, example("uncertain", "", "uncertain")],
                                   pipeline, manifest, details=True)
        self.assertEqual(report["overall"]["scored"], 1)
        self.assertEqual(report["overall"]["uncertain"], 1)
        self.assertEqual(report["by_category"]["notice"]["scored"], 1)
        self.assertEqual(report["distinct_scored_groups"], 1)
        self.assertEqual({key: private[0][key] for key in expected}, expected)
        self.assertNotIn("subject", private[0])
        self.assertNotIn("body", private[0])
        self.assertEqual(private[1]["excluded"], "uncertain")
        text = preprocess(probe.subject, probe.body, body_is_html=True)
        terms = explain(pipeline, text, limit=10_000)
        self.assertAlmostEqual(private[0]["contributions"]["logit"], pipeline.decision_function([text])[0])
        self.assertAlmostEqual(expected["phishing_score"], 1 / (1 + math.exp(-terms["logit"])))
        all_terms = terms["toward_phishing"] + terms["toward_legitimate"]
        self.assertTrue(all_terms)
        for term in all_terms:
            self.assertAlmostEqual(term["logit_contribution"], term["tfidf"] * term["coefficient"])
