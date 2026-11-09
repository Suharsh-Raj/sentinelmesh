"""Train and evaluate the frozen Phase 1 CPU baseline on verified local files."""

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, confusion_matrix, f1_score
from sklearn.metrics import precision_score, recall_score, roc_curve
from sklearn.pipeline import Pipeline
from threadpoolctl import threadpool_limits

from .artifact import MODEL_VERSION, save_bundle
from .dataset import (BLOCK_KEYS, MAX_BLOCK_SIZE, MAX_SHINGLE_WORDS, MIN_SHINGLES,
                      NEAR_SIMILARITY, SEED, SOURCE_LABELS, clean_and_group, read_dataset,
                      split_dataset, split_summary)

ML_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_DIR = ML_DIR / "models" / MODEL_VERSION
MAX_VALIDATION_FPR = 0.01


def make_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=40_000,
                                  sublinear_tf=True, lowercase=False)),
        ("logreg", LogisticRegression(solver="liblinear", C=1.0, max_iter=500, random_state=SEED)),
    ])


def select_threshold(labels, scores):
    fprs, recalls, thresholds = roc_curve(labels, scores, drop_intermediate=False)
    eligible = [
        (recall, -fpr, threshold)
        for fpr, recall, threshold in zip(fprs, recalls, thresholds)
        if fpr <= MAX_VALIDATION_FPR and np.isfinite(threshold)
    ]
    if float(np.max(scores)) < 1.0:
        eligible.append((0.0, 0.0, 1.0))
    if not eligible:
        raise ValueError("No finite operating threshold satisfies the validation false-positive limit.")
    return float(max(eligible)[2])


def metrics(labels, scores, predictions):
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    tn, fp, _, _ = matrix.ravel()
    return {
        "precision_phishing": float(precision_score(labels, predictions, zero_division=0)),
        "recall_phishing": float(recall_score(labels, predictions, zero_division=0)),
        "f1_phishing": float(f1_score(labels, predictions, zero_division=0)),
        "false_positive_rate": float(fp / (tn + fp)),
        "average_precision": float(average_precision_score(labels, scores)),
        "accuracy": float(accuracy_score(labels, predictions)),
        "confusion_matrix_class_order": ["legitimate", "phishing"],
        "confusion_matrix_rows_actual_columns_predicted": matrix.tolist(),
    }


def _inputs(samples, indexes):
    return [samples[i].text for i in indexes], np.array([samples[i].label for i in indexes])


def train(data_dir, model_dir, report_path):
    if model_dir.exists() or report_path.exists():
        raise ValueError("Model or report already exists. Use new --model-dir and --report paths to reproduce.")
    started = perf_counter()
    raw, ingestion, provenance = read_dataset(data_dir)
    print(f"Loaded {len(raw)} usable labeled messages. Grouping duplicates and related subjects.", flush=True)
    samples, groups, cleaning = clean_and_group(raw)
    splits = split_dataset(samples, groups)
    split_details = {name: split_summary(samples, groups, indexes) for name, indexes in splits.items()}
    print("Split sizes: " + ", ".join(f"{name}={item['rows']}" for name, item in split_details.items()), flush=True)

    pipeline = make_pipeline()
    baseline = DummyClassifier(strategy="prior")
    train_x, train_y = _inputs(samples, splits["train"])
    validation_x, validation_y = _inputs(samples, splits["validation"])
    with threadpool_limits(limits=1):
        fit_start = perf_counter()
        pipeline.fit(train_x, train_y)
        fit_seconds = perf_counter() - fit_start
        baseline.fit(np.zeros((len(train_y), 1)), train_y)
        validation_scores = pipeline.predict_proba(validation_x)[:, 1]
        threshold = select_threshold(validation_y, validation_scores)
        validation_metrics = metrics(validation_y, validation_scores, validation_scores >= threshold)
        print(f"Validation threshold frozen at {threshold:.9f}. Evaluating test once.", flush=True)

        test_x, test_y = _inputs(samples, splits["test"])
        test_scores = pipeline.predict_proba(test_x)[:, 1]
        dummy_x = np.zeros((len(test_y), 1))
        test_metrics = metrics(test_y, test_scores, test_scores >= threshold)
        dummy_metrics = metrics(test_y, baseline.predict_proba(dummy_x)[:, 1], baseline.predict(dummy_x))

    metadata = {
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": provenance,
        "original_label_mapping_by_source": SOURCE_LABELS,
        "ingestion": ingestion,
        "cleaning": cleaning,
        "grouping": {
            "exact": "Identical normalized subject and body text",
            "near_jaccard_minimum": NEAR_SIMILARITY,
            "near_shingle_words": 3,
            "near_minimum_distinct_shingles": MIN_SHINGLES,
            "near_low_hash_keys": BLOCK_KEYS,
            "near_max_block_size": MAX_BLOCK_SIZE,
            "near_max_sample_words": MAX_SHINGLE_WORDS,
            "thread_proxy": "Same source and normalized subject of at least 3 tokens, with a reply/forward prefix on at least one row",
        },
        "split_method": "StratifiedGroupKFold with five shuffled folds, fold 0 test, fold 1 validation, folds 2-4 train",
        "split_seed": SEED,
        "splits": split_details,
        "source_class_confounding": "All retained Enron rows are legitimate and all retained Nazario rows are phishing. No source-held-out binary test is possible.",
        "configuration": {
            "tfidf": {"ngram_range": [1, 2], "min_df": 2, "max_features": 40000, "sublinear_tf": True},
            "logistic_regression": {"solver": "liblinear", "C": 1.0, "max_iter": 500},
        },
        "threshold": threshold,
        "threshold_policy": {
            "max_validation_false_positive_rate": MAX_VALIDATION_FPR,
            "objective": "Maximize validation phishing recall; ties prefer lower false-positive rate, then higher threshold",
            "positive_when": "phishing_score >= threshold",
        },
        "score": "Class-1 predict_proba output. Calibration has not been evaluated.",
        "metrics": {"validation": validation_metrics, "test": test_metrics, "test_dummy_prior": dummy_metrics},
        "timing_seconds": {"pipeline_fit": fit_seconds, "prepare_fit_and_evaluate": perf_counter() - started},
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = save_bundle(model_dir, pipeline, metadata)
    with report_path.open("x", encoding="utf-8") as output:
        output.write(encoded)
    print(f"Held-out phishing F1: {test_metrics['f1_phishing']:.4f}")
    print(f"Model bundle: {model_dir}\nAggregate report: {report_path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ML_DIR / "data")
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--report", type=Path, default=ML_DIR / "reports" / f"{MODEL_VERSION}.json")
    args = parser.parse_args(argv)
    try:
        train(args.data_dir, args.model_dir, args.report)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Training error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
