"""Convert pinned public research releases to local evaluator input."""

import argparse
import csv
import json
import re
import tarfile
from email import policy
from email.parser import BytesParser
from pathlib import Path

from .dataset import file_digest
from .evaluate import REPORT_DIR

SPAPHISH_SHA256 = "656b2245d58da72d640680e5c2a168673a130b38607f2a427c773bbb167e995e"
HARD_HAM_SHA256 = "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9"


def spaphish(path):
    if file_digest(path) != SPAPHISH_SHA256:
        raise ValueError("SpaPhish v5 CSV checksum mismatch.")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for number, row in enumerate(csv.DictReader(stream, strict=True), 1):
            urls = int(row["url_count"]) > 0
            attachments = int(row["attachments_count"]) > 0
            category = f"spa_{'urls' if urls else 'no_urls'}_{'attachment' if attachments else 'no_attachment'}"
            yield {
                "id": f"spa-v5-{number}",
                "subject": row["subject"],
                "body": row["body"],
                "label": {"0": "legitimate", "1": "phishing"}[row["Label"]],
                "source": "spaphish-v5",
                "category": category,
            }


def hard_ham(path):
    if file_digest(path) != HARD_HAM_SHA256:
        raise ValueError("SpamAssassin hard_ham archive checksum mismatch.")
    with tarfile.open(path, "r:bz2") as archive:
        members = sorted((item for item in archive if item.isfile() and
                          re.fullmatch(r"hard_ham/[0-9]+\.[0-9a-f]{32}", item.name)),
                         key=lambda item: item.name)
        if len(members) != 250:
            raise ValueError("Unexpected number of SpamAssassin hard_ham messages.")
        for number, item in enumerate(members, 1):
            with archive.extractfile(item) as stream:
                message = BytesParser(policy=policy.default).parse(stream)
            part = message.get_body(preferencelist=("plain", "html"))
            body = ""
            if part is not None:
                try:
                    body = part.get_content(errors="replace")
                except LookupError:
                    body = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
            list_header = any(message[name] for name in ("List-Id", "List-Post", "List-Unsubscribe"))
            yield {
                "id": f"hard-ham-20030228-{number}",
                "subject": str(message.get("Subject", "")),
                "body": body,
                "body_is_html": part is not None and part.get_content_type() == "text/html",
                "label": "legitimate",
                "source": "spamassassin-hard-ham-20030228",
                "category": "hard_ham_list_header" if list_header else "hard_ham_other",
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spaphish", type=Path)
    parser.add_argument("--hard-ham", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(REPORT_DIR.resolve()):
        parser.error("Write prepared inputs under the ignored ml/data/evaluation directory.")
    sources = [(prepare, path) for prepare, path in ((spaphish, args.spaphish), (hard_ham, args.hard_ham)) if path]
    if not sources:
        parser.error("Choose at least one public source.")
    try:
        rows = [row for prepare, path in sources for row in prepare(path)]
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("x", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    except (OSError, csv.Error, ValueError, KeyError, tarfile.TarError):
        parser.exit(1, "Could not prepare the pinned input. Check source checksum, format and output path.\n")
    print(f"Prepared {len(rows)} local examples.")


if __name__ == "__main__":
    main()
