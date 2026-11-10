"""Evaluate a trusted, frozen SentinelMesh model on labeled local JSONL."""

import argparse
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .artifact import MODEL_VERSION, load_bundle, predict
from .dataset import MIN_SHINGLES, NEAR_SIMILARITY, _Groups, _shingles, file_digest, read_dataset
from .preprocessing import preprocess

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "ml" / "data"
REPORT_DIR = DATA_DIR / "evaluation"
MODEL_DIR = ROOT / "ml" / "models" / MODEL_VERSION
CLASSES = ("legitimate", "phishing")


@dataclass(frozen=True)
class Example:
    id: str
    subject: str
    body: str
    label: str
    source: str
    category: str
    group_id: str | None = None
    body_is_html: bool = False


def read_examples(path):
    required = {"id", "subject", "body", "label", "source", "category"}
    allowed = required | {"group_id", "body_is_html"}
    ids = set()
    examples = []
    with path.open(encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict) or not required <= row.keys() <= allowed:
                    raise ValueError("expected the documented fields")
                if any(not isinstance(row[field], str) for field in required):
                    raise ValueError("required fields must be strings")
                for field in ("id", "source", "category"):
                    row[field] = row[field].strip()
                    if not row[field]:
                        raise ValueError("ID, source and category must be nonempty")
                if row["label"] not in (*CLASSES, "uncertain"):
                    raise ValueError("invalid label; use legitimate, phishing, or uncertain")
                if row["id"] in ids:
                    raise ValueError("duplicate example ID")
                group = row.get("group_id")
                if group is not None and (not isinstance(group, str) or not group.strip()):
                    raise ValueError("group_id must be null or a nonempty string")
                if type(row.get("body_is_html", False)) is not bool:
                    raise ValueError("body_is_html must be a boolean")
                ids.add(row["id"])
                examples.append(Example(**row))
            except json.JSONDecodeError:
                raise ValueError(f"Invalid JSON on line {line_no}.") from None
            except ValueError as error:
                raise ValueError(f"Invalid example on line {line_no}: {error}.") from None
    if not examples:
        raise ValueError("No examples found.")
    return examples


def metrics(pairs):
    counts = Counter(pairs)
    tn, fp = (counts["legitimate", predicted] for predicted in CLASSES)
    fn, tp = (counts["phishing", predicted] for predicted in CLASSES)

    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None

    return {
        "scored": tn + fp + fn + tp,
        "legitimate": tn + fp,
        "phishing": fn + tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


class OverlapIndex:
    """Match exact normalized text/body and token-trigram Jaccard neighbors."""

    def __init__(self):
        self.full = defaultdict(set)
        self.body = defaultdict(set)
        self.postings = defaultdict(list)

    @staticmethod
    def near_keys(text, body):
        shingles = _shingles(body)
        if len(shingles) < MIN_SHINGLES:
            shingles = _shingles(text)
        if len(shingles) < MIN_SHINGLES:
            return shingles, []
        # Any pair at the threshold must share an item in these prefixes.
        # A fixed sort order makes prefix filtering lossless for these shingles.
        length = len(shingles) - math.ceil(NEAR_SIMILARITY * len(shingles)) + 1
        return shingles, sorted(shingles)[:length]

    def add(self, key, text, body):
        self.full[text].add(key)
        if body:
            self.body[body].add(key)
        shingles, prefix = self.near_keys(text, body)
        for token in prefix:
            self.postings[token].append((key, shingles))

    def matches(self, text, body):
        exact = self.full.get(text, set()) | self.body.get(body, set())
        shingles, prefix = self.near_keys(text, body)
        near = set()
        checked = set(exact)
        for token in prefix:
            for key, other in self.postings.get(token, ()):
                if key in checked:
                    continue
                checked.add(key)
                if min(len(shingles), len(other)) < NEAR_SIMILARITY * max(len(shingles), len(other)):
                    continue
                intersection = len(shingles & other)
                if intersection >= NEAR_SIMILARITY * (len(shingles) + len(other) - intersection):
                    near.add(key)
        return exact, near


def training_reference(path):
    samples, _, _ = read_dataset(path)
    reference = OverlapIndex()
    for index, sample in enumerate(samples):
        if not sample.subject:
            body = sample.text
        elif sample.text == sample.subject:
            body = ""
        else:
            body = sample.text.removeprefix(sample.subject + " ")
        reference.add(index, sample.text, body)
    return reference, len(samples)


def select_examples(examples, reference):
    """Keep first records per duplicate group, except conflicting label groups."""
    exclusions = {}
    eligible = {}
    groups = _Groups(len(examples))
    index = OverlapIndex()
    for i, example in enumerate(examples):
        if example.label == "uncertain":
            exclusions[i] = "uncertain"
            continue
        text = preprocess(example.subject, example.body, body_is_html=example.body_is_html)
        if not text:
            exclusions[i] = "unusable_text"
            continue
        body = preprocess(body=example.body, body_is_html=example.body_is_html)
        if reference is not None:
            exact, near = reference.matches(text, body)
            if exact or near:
                exclusions[i] = "reference_exact" if exact else "reference_near"
                continue
        exact, near = index.matches(text, body)
        for earlier in exact | near:
            groups.join(i, earlier)
        index.add(i, text, body)
        eligible[i] = (text, bool(exact))

    components = defaultdict(list)
    for i in eligible:
        components[groups.find(i)].append(i)
    selected = {}
    for members in components.values():
        if len({examples[i].label for i in members}) > 1:
            exclusions.update(dict.fromkeys(members, "duplicate_label_conflict"))
            continue
        first, *duplicates = members
        selected[first] = eligible[first][0]
        for i in duplicates:
            exclusions[i] = "within_exact" if eligible[i][1] else "within_near"
    return selected, exclusions


def explain(pipeline, text, limit=5):
    tfidf = pipeline.named_steps["tfidf"]
    logreg = pipeline.named_steps["logreg"]
    vector = tfidf.transform([text])
    names = tfidf.get_feature_names_out()
    terms = []
    for i, value in zip(vector.indices, vector.data):
        weight = float(logreg.coef_[0, i])
        terms.append({"feature": str(names[i]), "tfidf": float(value), "coefficient": weight,
                      "logit_contribution": float(value * weight)})
    intercept = float(logreg.intercept_[0])
    positive = sorted((term for term in terms if term["logit_contribution"] > 0),
                      key=lambda term: -term["logit_contribution"])
    negative = sorted((term for term in terms if term["logit_contribution"] < 0),
                      key=lambda term: term["logit_contribution"])
    return {
        "intercept": intercept,
        "logit": intercept + math.fsum(term["logit_contribution"] for term in terms),
        "nonzero_features": len(terms),
        "toward_phishing": positive[:limit],
        "toward_legitimate": negative[:limit],
    }


def evaluate(examples, pipeline, manifest, reference=None, *, details=False):
    selected, exclusions = select_examples(examples, reference)
    results = {}
    private = []
    for i, example in enumerate(examples):
        if i in exclusions:
            if details:
                private.append({"id": example.id, "label": example.label, "excluded": exclusions[i]})
            continue
        prediction = predict(pipeline, manifest, example.subject, example.body, body_is_html=example.body_is_html)
        predicted = prediction["model_prediction"]
        results[i] = example.label, predicted
        if details:
            item = {"id": example.id, "label": example.label, "source": example.source,
                    "category": example.category, "group_id": example.group_id, **prediction}
            if example.label != predicted:
                item["contributions"] = explain(pipeline, selected[i])
            private.append(item)

    def summarize(indexes):
        indexes = list(indexes)
        measured = metrics(results[i] for i in indexes if i in results)
        removed = Counter(exclusions[i] for i in indexes if i in exclusions)
        measured.update(input=len(indexes), uncertain=removed["uncertain"], excluded=dict(sorted(removed.items())))
        return measured

    def by_field(field):
        buckets = defaultdict(list)
        for i, example in enumerate(examples):
            buckets[getattr(example, field)].append(i)
        return {name: summarize(indexes) for name, indexes in sorted(buckets.items())}

    report = {
        "model_version": manifest["model_version"],
        "preprocessing_version": manifest["preprocessing_version"],
        "artifact_sha256": manifest["artifact"]["sha256"],
        "threshold": manifest["threshold"],
        "matrix_order": list(CLASSES),
        "overall": summarize(range(len(examples))),
        "by_source": by_field("source"),
        "by_category": by_field("category"),
        "scored_with_group_id": sum(examples[i].group_id is not None for i in results),
        "distinct_scored_groups": len({(examples[i].source, examples[i].group_id) for i in results
                                      if examples[i].group_id is not None}),
    }
    return report, private


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("examples", type=Path, help="UTF-8 JSONL; see ml/PHASE4A.md")
    parser.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    parser.add_argument("--training-data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--skip-training-overlap", action="store_true", help="Explicitly report reference overlap as unchecked")
    parser.add_argument("--kind", required=True, choices=("independent", "diagnostic", "synthetic"))
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--details", type=Path, help="Optional private scores and error contributions")
    args = parser.parse_args()
    outputs = [path.resolve() for path in (args.report, args.details) if path is not None]
    if any(not path.is_relative_to(REPORT_DIR.resolve()) for path in outputs):
        parser.error("Write reports under the ignored ml/data/evaluation directory.")
    if len(set(outputs)) != len(outputs) or args.examples.resolve() in outputs:
        parser.error("Input, aggregate and detail files must be distinct.")
    try:
        examples = read_examples(args.examples)
        pipeline, manifest = load_bundle(args.model_dir)
        reference, rows = (None, None) if args.skip_training_overlap else training_reference(args.training_data_dir)
        report, private = evaluate(examples, pipeline, manifest, reference, details=args.details is not None)
        report.update(
            kind=args.kind,
            input_sha256=file_digest(args.examples),
            reference_overlap={"checked": reference is not None, "usable_enron_nazario_rows": rows,
                               "near_trigram_jaccard": NEAR_SIMILARITY, "minimum_distinct_trigrams": MIN_SHINGLES},
        )
        for path, data in zip(outputs, (report, private)):
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2, ensure_ascii=False, allow_nan=False)
                stream.write("\n")
    except ValueError as error:
        parser.exit(1, f"Evaluation failed: {error}\n")
    except OSError:
        parser.exit(1, "Evaluation failed: could not read input or create a new report file.\n")
    print(f"Evaluated {report['overall']['scored']} examples; reports saved locally.")


if __name__ == "__main__":
    main()
