"""Parse Gmail's structured MIME response into bounded text and inert URLs."""
import base64
import binascii
import re
from email.header import decode_header
from email.message import Message
from email.utils import parseaddr
from html.parser import HTMLParser

PART_BYTES = 128 * 1024
TOTAL_BYTES = 256 * 1024
BODY_CHARS = 50000
MAX_PARTS = 100
MAX_DEPTH = 20
MAX_URLS = 30
URL = re.compile(r"""https?://[^\s<>"']+""", re.I)


def headers_of(part):
    out = {}
    for header in part.get("headers", []):
        out.setdefault(str(header.get("name", "")).lower(), str(header.get("value", "")))
    return out


def decode_text(raw, charset):
    try:
        return raw.decode(charset or "utf-8", errors="replace")
    except (LookupError, UnicodeError, TypeError):
        return raw.decode("utf-8", errors="replace")


def decoded_header(value):
    try:
        return "".join(decode_text(raw, charset) if isinstance(raw, bytes) else raw
                       for raw, charset in decode_header(value))
    except (ValueError, LookupError, UnicodeError):
        return value


def address(value):
    # Parse first: decoding a display name can introduce address delimiters.
    name, addr = parseaddr(value)
    return decoded_header(name), decoded_header(addr)


class BodyHTML(HTMLParser):
    BLOCKS = {"br", "p", "div", "li", "tr", "td", "section", "h1", "h2", "h3", "blockquote"}
    HIDDEN = {"script", "style", "head", "template", "noscript"}

    def __init__(self, collect_url):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = []
        self.collect_url = collect_url

    def handle_starttag(self, tag, attrs):
        if tag in self.HIDDEN:
            self.hidden.append(tag)
        if self.hidden:
            return
        if tag in self.BLOCKS:
            self.parts.append("\n")
        if tag in ("a", "area"):
            for name, value in attrs:
                if name == "href" and value:
                    self.collect_url(value.strip())

    def handle_startendtag(self, tag, attrs):
        if tag not in self.HIDDEN:
            self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if self.hidden:
            if tag == self.hidden[-1]:
                self.hidden.pop()
        elif tag in self.BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def parse_message(payload, get_text_part, *, header_only=False):
    top = headers_of(payload)
    display_name, sender = address(top.get("from", ""))
    _, reply_to = address(top.get("reply-to", ""))
    notices = set()
    count = 0
    remaining = TOTAL_BYTES
    plain, html, urls = [], [], []

    def add_url(url):
        if not URL.fullmatch(url):
            return
        if len(url) > 4096 or (len(urls) >= MAX_URLS and url not in urls):
            notices.add("url_limit")
        elif url not in urls:
            urls.append(url)

    def text_from(data, limit, charset):
        nonlocal remaining
        if not isinstance(data, str) or not data:
            return ""
        chars = ((limit + 2) // 3) * 4
        if len(data) > chars:
            notices.add("part_byte_limit")
            data = data[:chars]
        try:
            raw = base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            notices.add("invalid_text_encoding")
            return ""
        if len(raw) > limit:
            notices.add("part_byte_limit")
            raw = raw[:limit]
        remaining -= len(raw)
        return decode_text(raw, charset)

    def walk(part, depth):
        nonlocal count
        if count >= MAX_PARTS or depth > MAX_DEPTH:
            notices.add("mime_structure_limit")
            return
        count += 1
        headers = headers_of(part)
        meta = Message()
        for key in ("content-type", "content-disposition"):
            if headers.get(key):
                meta[key] = headers[key]
        if part.get("filename") or meta.get_filename() or meta.get_content_disposition() == "attachment":
            return
        kind = str(part.get("mimeType", "")).lower()
        if kind.startswith("multipart/"):
            for child in part.get("parts", []):
                if count >= MAX_PARTS:
                    notices.add("mime_structure_limit")
                    break
                walk(child, depth + 1)
            return
        if kind not in ("text/plain", "text/html"):
            return
        limit = min(PART_BYTES, remaining)
        if limit <= 0:
            notices.add("total_text_limit")
            return
        body = part.get("body", {})
        data = body.get("data")
        if not data and body.get("attachmentId"):
            size = body.get("size")
            if not isinstance(size, int) or not 0 <= size <= limit:
                notices.add("text_part_download_limit")
                return
            data = get_text_part(body["attachmentId"], ((limit + 2) // 3) * 4 + 4096)
            if data is None:
                notices.add("text_part_unavailable_or_oversized")
                return
        text = text_from(data, limit, meta.get_content_charset())
        if kind == "text/html":
            parser = BodyHTML(add_url)
            parser.feed(text)
            parser.close()
            text = "".join(parser.parts)
            html.append(text)
        else:
            plain.append(text)
        for match in URL.finditer(text):
            add_url(match.group().rstrip(".,;:!?)]}"))

    if header_only:
        notices.add("message_download_limit")
    else:
        walk(payload, 0)
    body = "\n".join(plain).strip() or "\n".join(html).strip()
    if len(body) > BODY_CHARS:
        body = body[:BODY_CHARS]
        notices.add("body_character_limit")
    fields = {"sender": sender, "display_name": display_name,
              "subject": decoded_header(top.get("subject", "")).strip() or "(No subject)",
              "reply_to": reply_to}
    for key, limit in {"sender": 320, "display_name": 200, "subject": 500, "reply_to": 320}.items():
        if len(fields[key]) > limit:
            notices.add("header_character_limit")
        fields[key] = fields[key][:limit]
    return dict(fields, body=body, urls=urls, content_limits=sorted(notices))
