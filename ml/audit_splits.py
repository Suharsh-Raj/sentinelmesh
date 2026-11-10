"""Audit offline train/dev/test separation without loading or scoring a model."""

import argparse
import json
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

from .dataset import file_digest
from .evaluate import DATA_DIR, REPORT_DIR, OverlapIndex, read_examples, select_examples, training_reference
from .preprocessing import preprocess

ROLES = ("train", "dev", "test")
LABELS = ("legitimate", "phishing")
BENIGN = ("promotion", "newsletter", "account_notice", "receipt", "correspondence")
PHISHING = ("credential", "payment", "malicious_attachment", "qr_or_other_link")


def split_coverage(examples):
    selected, excluded = select_examples(examples, None)
    labels = Counter()
    categories = Counter()
    sources = defaultdict(set)
    groups = defaultdict(set)
    for index in selected:
        item = examples[index]
        labels[item.label] += 1
        categories[item.label, item.category] += 1
        sources[item.label].add(item.source)
        if item.group_id is not None:
            groups[item.label].add(item.group_id.strip())
    return {
        "input": len(examples),
        "eligible": {label: labels[label] for label in LABELS},
        "excluded": dict(Counter(excluded.values())),
        "category_counts": {
            label: {category: categories[label, category] for category in required}
            for label, required in zip(LABELS, (BENIGN, PHISHING))
        },
        "source_counts": {label: len(sources[label]) for label in LABELS},
        "group_counts": {label: len(groups[label]) for label in LABELS},
    }, sources


def audit(splits, reference):
    index = OverlapIndex()
    ids = defaultdict(set)
    groups = defaultdict(set)
    missing_group = Counter()
    cross = {f"{a}/{b}": {"exact": 0, "near": 0} for a, b in combinations(ROLES, 2)}
    baseline = {role: {"exact": 0, "near": 0} for role in ("dev", "test")}
    coverage = {}
    split_sources = {}
    for role in ROLES:
        examples = splits[role]
        coverage[role], split_sources[role] = split_coverage(examples)
        for i, example in enumerate(examples):
            ids[example.id].add(role)
            if example.group_id is not None:
                groups[example.group_id.strip()].add(role)
            elif example.label != "uncertain":
                missing_group[role] += 1
            text = preprocess(example.subject, example.body, body_is_html=example.body_is_html)
            if not text:
                continue
            body = preprocess(body=example.body, body_is_html=example.body_is_html)
            if role in baseline:
                exact, near = reference.matches(text, body)
                if exact or near:
                    baseline[role]["exact" if exact else "near"] += 1
            exact, near = index.matches(text, body)
            for kind, matches in (("exact", exact), ("near", near)):
                for earlier, _ in matches:
                    if earlier != role:
                        cross[f"{earlier}/{role}"][kind] += 1
            index.add((role, i), text, body)

    prior_sources = set().union(*(sources for role in ("train", "dev") for sources in split_sources[role].values()))
    unseen = {label: len(split_sources["test"][label] - prior_sources) for label in LABELS}
    collisions = {
        "shared_ids": sum(len(roles) > 1 for roles in ids.values()),
        "shared_groups": sum(len(roles) > 1 for roles in groups.values()),
        "missing_groups": {role: missing_group[role] for role in ROLES},
        "cross_split_text_pairs": cross,
        "v1_reference_overlapping_rows": baseline,
    }
    clean = not (
        collisions["shared_ids"] or collisions["shared_groups"] or any(missing_group.values())
        or any(any(counts.values()) for counts in (*cross.values(), *baseline.values()))
        or any(split["excluded"].get("duplicate_label_conflict", 0) for split in coverage.values())
    )
    enough = (
        all(coverage["train"]["source_counts"][label] >= 2 for label in LABELS)
        and all(coverage["train"]["eligible"][label] > 0 for label in LABELS)
        and coverage["dev"]["eligible"]["legitimate"] >= 250
        and coverage["dev"]["eligible"]["phishing"] >= 150
        and min(coverage["dev"]["category_counts"]["legitimate"].values()) >= 50
        and min(coverage["dev"]["category_counts"]["phishing"].values()) >= 20
        and coverage["test"]["eligible"]["legitimate"] >= 500
        and coverage["test"]["eligible"]["phishing"] >= 300
        and min(coverage["test"]["category_counts"]["legitimate"].values()) >= 100
        and min(coverage["test"]["category_counts"]["phishing"].values()) >= 50
        and coverage["test"]["group_counts"]["legitimate"] >= 50
        and coverage["test"]["group_counts"]["phishing"] >= 30
        and all(coverage["test"]["source_counts"][label] >= 3 and unseen[label] >= 1 for label in LABELS)
    )
    return {"coverage": coverage, "test_sources_unseen_in_train_or_dev": unseen,
            "overlap": collisions, "separation_passed": clean, "coverage_passed": enough}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ROLES:
        parser.add_argument(f"--{role}", required=True, type=Path)
    parser.add_argument("--training-data-dir", type=Path, default=DATA_DIR,
                        help="Directory of the pinned v1 Enron/Nazario files.")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    paths = {role: getattr(args, role).resolve() for role in ROLES}
    out = args.report.resolve()
    if len({out, *paths.values()}) != 4 or any(
        not path.is_relative_to(REPORT_DIR.resolve()) for path in (out, *paths.values())
    ):
        parser.error("Use four distinct paths under the ignored ml/data/evaluation directory.")
    try:
        fingerprints = {role: file_digest(path) for role, path in paths.items()}
        splits = {role: read_examples(path) for role, path in paths.items()}
        reference, rows = training_reference(args.training_data_dir)
        result = audit(splits, reference)
        if fingerprints != {role: file_digest(path) for role, path in paths.items()}:
            raise ValueError("Input files changed during audit.")
        result.update(input_sha256=fingerprints, v1_reference_rows=rows,
                      manual_checks_required=["usage terms", "English and dates", "source and label provenance",
                                              "completeness of group IDs"])
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    except ValueError as error:
        parser.exit(1, f"Audit failed: {error}\n")
    except OSError:
        parser.exit(1, "Audit failed: could not read input or create a new report.\n")
    if not result["separation_passed"] or not result["coverage_passed"]:
        parser.exit(2, "Separation or coverage gate failed. See the local report.\n")
    print("Automated audit passed. Complete the manual provenance checks before scoring.")


if __name__ == "__main__":
    main()
