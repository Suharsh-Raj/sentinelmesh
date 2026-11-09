"""Verified CSV loading, duplicate grouping, and held-out split creation."""

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from .preprocessing import WORDS, preprocess, thread_subject

SEED = 42
MANIFEST_PATH = Path(__file__).with_name("dataset.json")
SOURCE_LABELS = {"enron": {"0": 0, "1": None}, "nazario": {"1": 1}}
NEAR_SIMILARITY = 0.82
MIN_SHINGLES = 8
BLOCK_KEYS = 8
MAX_BLOCK_SIZE = 64
MAX_SHINGLE_WORDS = 1024


@dataclass(frozen=True)
class Sample:
    row_id: str
    source: str
    label: int
    text: str
    subject: str = ""
    is_reply: bool = False


class _Groups:
    def __init__(self, size):
        self.parent = list(range(size))

    def find(self, i):
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def join(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def file_digest(path, algorithm="sha256"):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def map_label(source, original):
    """Exclude Enron spam and reject unexpected labels rather than guessing."""
    try:
        return SOURCE_LABELS[source][(original or "").strip()]
    except KeyError:
        raise ValueError(f"Unexpected label in the {source} source.") from None


def read_dataset(data_dir):
    provenance = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    csv.field_size_limit(16 * 1024 * 1024)
    samples = []
    audit = {}
    for file in provenance["files"]:
        source = file["source"]
        path = data_dir / file["name"]
        if not path.is_file():
            raise ValueError(f"Missing dataset file: {path}. See ml/README.md.")
        if file_digest(path) != file["sha256"]:
            raise ValueError(f"Dataset SHA-256 mismatch: {path.name}")

        original_labels = Counter()
        counts = Counter(raw_rows=0, excluded_label=0, unusable=0, selected_rows=0)
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream, strict=True)
            if not {"subject", "body", "label"}.issubset(reader.fieldnames or ()):
                raise ValueError(f"Missing required CSV columns in {path.name}.")
            for i, row in enumerate(reader, start=1):
                if None in row or any(row[key] is None for key in ("subject", "body", "label")):
                    raise ValueError(f"Unexpected CSV shape in {path.name}, record {i}.")
                original = row["label"].strip()
                original_labels[original] += 1
                counts["raw_rows"] += 1
                label = map_label(source, original)
                if label is None:
                    counts["excluded_label"] += 1
                    continue
                subject, is_reply = thread_subject(row["subject"])
                text = preprocess(row["subject"], row["body"])
                if not text or "folder internal data" in subject:
                    counts["unusable"] += 1
                    continue
                counts["selected_rows"] += 1
                samples.append(Sample(f"{path.name}:{i}", source, label, text, subject, is_reply))
        audit[source] = {**counts, "original_labels": dict(sorted(original_labels.items()))}
    return samples, audit, provenance


def _shingles(text):
    words = WORDS.findall(text)
    half = MAX_SHINGLE_WORDS // 2
    segments = (words[:half], words[-half:]) if len(words) > MAX_SHINGLE_WORDS else (words,)
    return {
        int.from_bytes(hashlib.blake2b(" ".join(triple).encode(), digest_size=8).digest())
        for segment in segments
        for triple in zip(segment, segment[1:], segment[2:])
    }


def _near_groups(texts):
    """Block by shared low hashes, then compare trigram Jaccard similarity."""
    shingles = [_shingles(text) for text in texts]
    keys = [sorted(values)[:BLOCK_KEYS] if len(values) >= MIN_SHINGLES else [] for values in shingles]
    postings = defaultdict(list)
    for index, hashes in enumerate(keys):
        for key in hashes:
            bucket = postings[key]
            if len(bucket) <= MAX_BLOCK_SIZE:
                bucket.append(index)

    groups = _Groups(len(texts))
    for i, hashes in enumerate(keys):
        candidates = {
            j for key in hashes if len(postings[key]) <= MAX_BLOCK_SIZE
            for j in postings[key] if j < i
        }
        for j in sorted(candidates):
            a, b = shingles[i], shingles[j]
            if min(len(a), len(b)) < NEAR_SIMILARITY * max(len(a), len(b)):
                continue
            shared = len(a & b)
            if shared >= NEAR_SIMILARITY * (len(a) + len(b) - shared):
                groups.join(i, j)
    return groups


def clean_and_group(samples):
    exact = defaultdict(list)
    for sample in samples:
        exact[sample.text].append(sample)
    texts = list(exact)
    near = _near_groups(texts)
    components = defaultdict(list)
    for i, body in enumerate(texts):
        components[near.find(i)].append(exact[body])

    kept = []
    assignments = []
    counts = Counter(exact_duplicates_removed=0, conflicting_rows_removed=0,
                     exact_conflict_groups=0, near_conflict_groups=0,
                     near_groups_retained=0, near_group_rows_retained=0,
                     reply_subject_groups_linked=0)
    threads = defaultdict(list)
    for component, buckets in components.items():
        counts["exact_conflict_groups"] += sum(len({s.label for s in bucket}) > 1 for bucket in buckets)
        if len({s.label for bucket in buckets for s in bucket}) > 1:
            counts["conflicting_rows_removed"] += sum(map(len, buckets))
            counts["near_conflict_groups"] += len(buckets) > 1
            continue
        if len(buckets) > 1:
            counts["near_groups_retained"] += 1
            counts["near_group_rows_retained"] += len(buckets)
        for bucket in buckets:
            counts["exact_duplicates_removed"] += len(bucket) - 1
            kept.append(bucket[0])
            assignments.append(component)
            for sample in bucket:
                if len(WORDS.findall(sample.subject)) >= 3:
                    threads[sample.source, sample.subject].append((component, sample.is_reply))

    for thread in threads.values():
        roots = sorted({near.find(component) for component, _ in thread})
        if len(roots) > 1 and any(is_reply for _, is_reply in thread):
            for root in roots[1:]:
                near.join(roots[0], root)
            counts["reply_subject_groups_linked"] += 1
    return kept, [near.find(component) for component in assignments], dict(counts)


def split_dataset(samples, groups, seed=SEED):
    labels = np.array([sample.label for sample in samples])
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    folds = [held_out for _, held_out in splitter.split(labels, labels, groups)]
    partitions = {
        "train": np.sort(np.concatenate(folds[2:])),
        "validation": np.sort(folds[1]),
        "test": np.sort(folds[0]),
    }
    for name, indexes in partitions.items():
        if set(labels[indexes]) != {0, 1}:
            raise ValueError(f"{name} must contain both classes after group splitting.")
    return partitions


def split_summary(samples, groups, indexes):
    items = [samples[i] for i in indexes]
    by_source = defaultdict(lambda: {"legitimate": 0, "phishing": 0})
    for item in items:
        by_source[item.source]["phishing" if item.label == 1 else "legitimate"] += 1
    fingerprint = "\n".join(item.row_id for item in items).encode()
    return {
        "rows": len(items),
        "legitimate": sum(item.label == 0 for item in items),
        "phishing": sum(item.label == 1 for item in items),
        "groups": len({groups[i] for i in indexes}),
        "source_by_class": dict(by_source),
        "row_ids_sha256": hashlib.sha256(fingerprint).hexdigest(),
    }
