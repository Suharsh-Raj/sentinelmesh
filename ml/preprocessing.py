"""Subject and body normalization shared by training and local inference."""

import re
import unicodedata
from html.parser import HTMLParser

VERSION = "subject-body-v1"
WORDS = re.compile(r"(?u)\b\w\w+\b")
HTML_TAG = re.compile(r"</?(?:html|body|div|p|br|a|table|span|script|style|head|img|h[1-6]|ul|li|section)\b", re.I)
HIDDEN_TAGS = {"head", "script", "style", "template"}
BREAK_TAGS = {"br", "div", "p", "td", "th", "tr", "li", "hr", "section", "blockquote",
              "h1", "h2", "h3", "h4", "h5", "h6"}
URL = re.compile(r"\b(?:[a-z][a-z0-9+.-]*://|www\.|mailto:)[^\s<>\"']+", re.I)
ADDRESS = re.compile(r"[\w.+%'-]+@[\w.-]+\.[a-z]{2,}", re.I)
SOURCE_MARKER = re.compile(
    r"\b(?:enron(?:-spam)?|nazario(?:[_-]\d+)?|ling[- ]spam|spamassassin|trec[-_]?\d*)\b",
    re.I,
)
MAIL_HEADER = re.compile(
    r"^[ \t]*(?:from|to|cc|bcc|sender|reply-to|return-path|date|sent|subject|received|"
    r"message-id|mime-version|content-type|content-transfer-encoding|x-[\w-]+):"
    r"[^\n]*(?:\n[ \t]+[^\n]*)*",
    re.I | re.M,
)
SEPARATOR = re.compile(r"^\s*-{2,}\s*(?:original|forwarded) message\s*-{2,}\s*$", re.I | re.M)
REPLY_PREFIX = re.compile(r"^\s*(?:(?:re|fw|fwd)\s*:\s*)+", re.I)
CLASS_PREFIX = re.compile(r"^\s*(?:\[(?:spam|phishing|ham)\]\s*)+", re.I)
IDENTIFIER = re.compile(r"\b(?:[a-f0-9]{20,}|\d{8,})\b", re.I)
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = []

    def handle_starttag(self, tag, attrs):
        if tag in HIDDEN_TAGS:
            self.hidden.append(tag)
        elif not self.hidden and tag in BREAK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if not self.hidden and tag in BREAK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if self.hidden and tag == self.hidden[-1]:
            self.hidden.pop()
        elif not self.hidden and tag in BREAK_TAGS:
            self.parts.append("\n")

    def handle_data(self, text):
        if not self.hidden:
            self.parts.append(text)


def _normalize(text):
    return CONTROL.sub("", unicodedata.normalize("NFKC", text or "")).replace("\r\n", "\n").replace("\r", "\n")


def _clean(text):
    text = URL.sub(" ", text)
    text = ADDRESS.sub(" ", text)
    text = SOURCE_MARKER.sub(" ", text)
    text = IDENTIFIER.sub(" ", text)
    return " ".join(text.casefold().split())


def thread_subject(subject):
    """Return a normalized subject and whether it carried a reply/forward prefix."""
    original = CLASS_PREFIX.sub("", _normalize(subject)).strip()
    base = REPLY_PREFIX.sub("", original)
    return _clean(CLASS_PREFIX.sub("", base)), base != original


def preprocess(subject=None, body=None, *, body_is_html=False):
    """Return plain model text. URL and HTML handling perform no network access."""
    subject, _ = thread_subject(subject)
    body = _normalize(body)
    if body_is_html or HTML_TAG.search(body):
        parser = _HTMLText()
        parser.feed(body)
        parser.close()
        body = "".join(parser.parts)
    body = MAIL_HEADER.sub("", body)
    body = SEPARATOR.sub("", body)
    body = re.sub(r"^\s*>[^\n]*", "", body, flags=re.M)
    result = " ".join(part for part in (subject, _clean(body)) if part)
    return result if WORDS.search(result) else ""
