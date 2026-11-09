"""Local model bundle format and compatibility checks."""

import json
import math
import platform
import tempfile
from importlib.metadata import version
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.utils.validation import check_is_fitted

from .dataset import file_digest
from .preprocessing import VERSION, preprocess

MODEL_VERSION = "mail-tfidf-v1"
MODEL_FILE = "pipeline.joblib"
FORMAT = "sentinelmesh-local-training-v1"
CLASS_MAPPING = {"0": "legitimate", "1": "phishing"}
PACKAGES = ("numpy", "scipy", "scikit-learn", "joblib", "threadpoolctl")


def runtime_versions():
    return {"python": platform.python_version(), **{name: version(name) for name in PACKAGES}}


def save_bundle(directory, pipeline, metadata):
    if directory.exists():
        raise ValueError(f"Model bundle already exists: {directory}")
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".model-", dir=directory.parent) as staging:
        staged = Path(staging) / "bundle"
        staged.mkdir()
        artifact = staged / MODEL_FILE
        joblib.dump(pipeline, artifact, compress=3)
        manifest = {
            **metadata,
            "bundle_format": FORMAT,
            "model_version": MODEL_VERSION,
            "preprocessing_version": VERSION,
            "class_mapping": CLASS_MAPPING,
            "versions": runtime_versions(),
            "artifact": {"file": MODEL_FILE, "sha256": file_digest(artifact)},
        }
        encoded = json.dumps(manifest, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        (staged / "manifest.json").write_text(encoded, encoding="utf-8")
        staged.rename(directory)
    return encoded


def load_bundle(directory):
    """Load only a bundle produced locally by trusted SentinelMesh training."""
    artifact = directory / MODEL_FILE
    manifest_file = directory / "manifest.json"
    if not artifact.is_file() or not manifest_file.is_file():
        raise ValueError(f"Missing model bundle at {directory}. Run ml.train first.")
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if (manifest["bundle_format"] != FORMAT or manifest["model_version"] != MODEL_VERSION
                or manifest["preprocessing_version"] != VERSION
                or manifest["class_mapping"] != CLASS_MAPPING):
            raise ValueError("Incompatible model bundle format, class mapping, or preprocessing version.")
        threshold = manifest["threshold"]
        if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError("Invalid model threshold.")
        required = manifest["versions"]
        installed = runtime_versions()
        mismatches = [
            f"{name}: expected {required[name]}, found {installed[name]}"
            for name in installed if required[name] != installed[name]
        ]
        if mismatches:
            raise ValueError("Incompatible model dependencies: " + "; ".join(mismatches))
        if manifest["artifact"]["file"] != MODEL_FILE or manifest["artifact"]["sha256"] != file_digest(artifact):
            raise ValueError("Model artifact checksum or filename mismatch.")
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("Invalid local model manifest.") from error

    try:
        pipeline = joblib.load(artifact)
        if (not isinstance(pipeline, Pipeline)
                or not isinstance(pipeline.named_steps["tfidf"], TfidfVectorizer)
                or not isinstance(pipeline.named_steps["logreg"], LogisticRegression)
                or list(pipeline.classes_) != [0, 1]):
            raise ValueError("Unexpected fitted pipeline or class order.")
        check_is_fitted(pipeline)
    except Exception as error:
        raise ValueError("Could not load the fitted local pipeline. Retrain in the pinned environment.") from error
    return pipeline, manifest


def predict(pipeline, manifest, subject=None, body=None, *, body_is_html=False):
    text = preprocess(subject, body, body_is_html=body_is_html)
    if not text:
        raise ValueError("Provide a subject or body with usable text.")
    score = float(pipeline.predict_proba([text])[0, 1])
    threshold = manifest["threshold"]
    return {
        "model_version": manifest["model_version"],
        "phishing_score": score,
        "model_prediction": CLASS_MAPPING[str(int(score >= threshold))],
        "threshold": threshold,
    }
