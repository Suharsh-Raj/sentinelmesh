"""Score a local UTF-8 text or HTML file using your own trained model bundle."""

import argparse
import json
import sys
from pathlib import Path

from .artifact import MODEL_VERSION, load_bundle, predict


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path,
                        default=Path(__file__).resolve().parent / "models" / MODEL_VERSION)
    parser.add_argument("--subject", default="")
    parser.add_argument("--body-file", type=Path, help="UTF-8 body file on this machine")
    parser.add_argument("--html", action="store_true", help="Parse body as HTML without fetching resources")
    args = parser.parse_args(argv)
    try:
        body = args.body_file.read_text(encoding="utf-8-sig") if args.body_file else ""
        pipeline, manifest = load_bundle(args.model_dir)
        result = predict(pipeline, manifest, args.subject, body, body_is_html=args.html)
    except (OSError, ValueError) as error:
        print(f"Inference error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
