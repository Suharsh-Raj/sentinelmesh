"""Load the local Phase 1 bundle and run advisory mail inference."""

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Callable

DEFAULT_BUNDLE = Path(__file__).resolve().parents[1] / "ml" / "models" / "mail-tfidf-v1"


@dataclass(frozen=True)
class MailModel:
    status: str
    model_version: str | None = None
    threshold: float | None = None
    error: str | None = None
    scorer: Callable[[str, str], dict] | None = None

    def describe(self):
        return {
            "status": self.status,
            "model_version": self.model_version,
            "threshold": self.threshold,
            "error": self.error,
        }

    async def analyze(self, subject, body):
        result = {
            **self.describe(),
            "phishing_score": None,
            "model_prediction": None,
        }
        if self.scorer is not None:
            try:
                prediction = await asyncio.to_thread(self.scorer, subject, body)
                result.update(
                    status="analyzed",
                    phishing_score=prediction["phishing_score"],
                    model_prediction=prediction["model_prediction"],
                )
            except Exception:
                result.update(
                    status="error",
                    error="Prediction failed. Check that the message has usable text and that the local model passes the CLI smoke test.",
                )
        result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
        return result


def load_mail_model():
    if os.getenv("SENTINELMESH_ML_ENABLED") == "0":
        return MailModel("disabled")

    directory = Path(os.getenv("SENTINELMESH_MODEL_DIR") or DEFAULT_BUNDLE)
    try:
        if not all((directory / name).is_file() for name in ("manifest.json", "pipeline.joblib")):
            return MailModel(
                "unavailable",
                error="Local model bundle is missing. Restore it or set SENTINELMESH_MODEL_DIR to a trusted bundle directory.",
            )
        from ml.artifact import load_bundle, predict

        pipeline, manifest = load_bundle(directory)
    except ImportError:
        return MailModel(
            "unavailable",
            error="ML dependencies are missing. Set up .ml-venv with the manifest's Python version and pinned requirements, then restart.",
        )
    except Exception:
        return MailModel(
            "error",
            error="Local model could not be loaded. Check the trusted bundle checksum and match its Python and dependency versions.",
        )
    return MailModel(
        "ready",
        model_version=manifest["model_version"],
        threshold=manifest["threshold"],
        scorer=partial(predict, pipeline, manifest),
    )
