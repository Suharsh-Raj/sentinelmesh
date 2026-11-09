"""Google Desktop OAuth with PKCE and a fixed, read-only Gmail API client."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import tomllib
import webbrowser
from dataclasses import dataclass, field
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_URL = "https://gmail.googleapis.com/gmail/v1/users/me/"
MAX_RESPONSE = 8 * 1024 * 1024
HTTP_TIMEOUT = 10


class GmailError(Exception):
    """Only fixed, user-safe messages should be passed as detail."""

    def __init__(self, state, detail, *, transient=False, code=None):
        super().__init__(detail)
        self.state, self.transient, self.code = state, transient, code


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request_json(url, *, token=None, form=None, limit=MAX_RESPONSE):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = Request(url, data=urlencode(form).encode() if form is not None else None, headers=headers)
    deadline = time.monotonic() + HTTP_TIMEOUT
    try:
        with build_opener(NoRedirects()).open(request, timeout=HTTP_TIMEOUT) as response:
            data = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError
                chunk = response.read1(min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise GmailError("api_error", "A Gmail response exceeded the download limit.", code=413)
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except HTTPError as exc:
        code = exc.code
        try:
            # Inspect Google error codes only. Never expose the response text.
            detail = json.loads(exc.read1(8192))
        except (ValueError, OSError, HTTPException):
            detail = {}
        finally:
            exc.close()
        error = detail.get("error") if isinstance(detail, dict) else None
        errors = error.get("errors", []) if isinstance(error, dict) else []
        rate_limited = isinstance(errors, list) and any(
            isinstance(item, dict) and item.get("reason") in ("rateLimitExceeded", "userRateLimitExceeded")
            for item in errors
        )
        if code == 401 or (form is not None and error in ("invalid_grant", "invalid_client", "unauthorized_client")):
            raise GmailError("authorization_required", "Gmail authorization expired or was rejected. Run Gmail setup again.", code=code) from None
        if code == 429 or code >= 500 or rate_limited:
            raise GmailError("retrying", "Google temporarily limited or could not complete the request. Retrying.", transient=True, code=code) from None
        raise GmailError("api_error", f"Google rejected a Gmail request (HTTP {code}). Check Gmail API setup and permissions.", code=code) from None
    except (URLError, OSError, HTTPException):
        raise GmailError("retrying", "The Google request failed or timed out. Retrying.", transient=True) from None
    except (ValueError, RecursionError):
        raise GmailError("api_error", "Google returned an unreadable response.") from None


def outside_project(path):
    resolved = path.expanduser().resolve()
    if resolved == ROOT or resolved.is_relative_to(ROOT):
        raise GmailError("configuration_error", "Gmail OAuth files must be stored outside the project.")
    return resolved


def gmail_home():
    default = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share") / "SentinelMesh" / "gmail"
    return outside_project(Path(os.environ.get("SENTINELMESH_GMAIL_HOME", default)))


def load_json(path, missing, invalid, state="configuration_error"):
    try:
        with path.open("rb") as file:
            data = json.loads(file.read(65537))
        if not isinstance(data, dict):
            raise ValueError
        return data
    except FileNotFoundError:
        raise GmailError(state, missing) from None
    except (ValueError, OSError, RecursionError):
        raise GmailError(state, invalid) from None


@dataclass(frozen=True)
class Config:
    account: str = field(repr=False)
    client_id: str
    client_secret: str = field(repr=False)
    token_path: Path

    @property
    def account_key(self):
        return hashlib.sha256(self.account.encode()).hexdigest()


def read_config():
    home = gmail_home()
    try:
        with outside_project(home / "gmail.toml").open("rb") as file:
            raw = tomllib.load(file)
        account = raw.get("account", "").strip().casefold()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", account) or len(account) > 320:
            raise ValueError
        client_path = Path(raw.get("client_file", home / "oauth-client.json"))
        if not client_path.is_absolute():
            client_path = home / client_path
    except FileNotFoundError:
        raise GmailError("configuration_error", "Local Gmail configuration is missing. Follow the Gmail setup in README.") from None
    except (ValueError, TypeError, AttributeError, OSError):
        raise GmailError("configuration_error", "Local Gmail configuration is invalid. Check gmail.toml.") from None
    data = load_json(outside_project(client_path), "Desktop OAuth client file is missing.", "Desktop OAuth client file could not be read.")
    desktop = data.get("installed")
    if not isinstance(desktop, dict) or not all(isinstance(desktop.get(k), str) and desktop[k] for k in ("client_id", "client_secret")):
        raise GmailError("configuration_error", "Use a Google OAuth client of type Desktop app.")
    return Config(account, desktop["client_id"], desktop["client_secret"], outside_project(home / "oauth-token.json"))


def verify_scope(data, *, required=False):
    scope = data.get("scope")
    if (required or scope is not None) and (not isinstance(scope, str) or set(scope.split()) != {SCOPE}):
        raise GmailError("authorization_required", "Authorization must grant exactly Gmail read-only access.")


class GmailClient:
    def __init__(self, access_token, transport=request_json):
        if not isinstance(access_token, str) or not access_token:
            raise GmailError("authorization_required", "Google did not return a usable access token. Run Gmail setup again.")
        self._access_token = access_token
        self.transport = transport

    def get(self, path, query=None, limit=MAX_RESPONSE):
        url = GMAIL_URL + path + ("?" + urlencode(query, doseq=True) if query else "")
        for attempt in range(3):
            try:
                return self.transport(url, token=self._access_token, limit=limit)
            except GmailError as exc:
                if not exc.transient or attempt == 2:
                    raise
                time.sleep(1 << attempt)

    def profile(self, account):
        result = self.get("profile", {"fields": "emailAddress,historyId"})
        if str(result.get("emailAddress", "")).casefold() != account:
            raise GmailError("account_mismatch", "The authorized Google account does not match local Gmail configuration. Run setup with the intended account.")
        return result

    def message(self, message_id, *, full=False):
        if full:
            query = {"format": "full", "fields": "id,internalDate,labelIds,payload"}
        else:
            query = {"format": "metadata", "metadataHeaders": ["From", "Reply-To", "Subject"],
                     "fields": "id,internalDate,labelIds,payload(headers)"}
        return self.get(f"messages/{quote(message_id, safe='')}", query)

    def text_part(self, message_id, attachment_id, limit):
        return self.get(f"messages/{quote(message_id, safe='')}/attachments/{quote(attachment_id, safe='')}", limit=limit)


class SavedAuthorization:
    """Refresh the access token in memory; only the verified refresh token is stored."""

    def __init__(self):
        self._key = None
        self._client = None
        self._refresh_by = 0

    def get_client(self, config):
        auth = load_json(config.token_path, "Gmail is not authorized. Run Gmail setup to connect.",
                         "Local Gmail authorization is invalid. Run Gmail setup again.", "authorization_required")
        verify_scope(auth, required=True)
        refresh = auth.get("refresh_token")
        if auth.get("client_id") != config.client_id or not isinstance(refresh, str) or not refresh:
            raise GmailError("authorization_required", "Gmail authorization does not match the Desktop client. Run Gmail setup again.")
        key = (config.client_id, config.client_secret, refresh)
        if self._key != key or time.monotonic() >= self._refresh_by:
            result = request_json(TOKEN_URL, form={"grant_type": "refresh_token", "refresh_token": refresh,
                                                  "client_id": config.client_id, "client_secret": config.client_secret}, limit=65536)
            verify_scope(result)
            self._client = GmailClient(result.get("access_token"))
            self._key = key
            try:
                lifetime = int(result.get("expires_in", 3600))
            except (ValueError, TypeError):
                lifetime = 0
            self._refresh_by = time.monotonic() + max(0, min(lifetime, 3600) - 60)
        return self._client

    def invalidate(self):
        self._refresh_by = 0


def write_authorization(config, refresh):
    temp = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=config.token_path.parent,
                                prefix=".oauth-", suffix=".tmp", delete=False) as file:
            temp = Path(file.name)
            json.dump({"client_id": config.client_id, "scope": SCOPE, "refresh_token": refresh}, file)
            file.flush()
            os.fsync(file.fileno())
        temp.replace(config.token_path)
    finally:
        if temp and temp.exists():
            temp.unlink()


def authorize(config):
    """Interactive browser authorization, called only by the setup CLI."""
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    callback = {}

    class Callback(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(3)
            super().setup()

        def log_message(self, *args):
            pass  # Callback URLs contain authorization codes.

        def do_GET(self):
            url = urlsplit(self.path)
            params = parse_qs(url.query)
            incoming = params.get("state", [""])[0]
            if url.path != "/" or not hmac.compare_digest(incoming.encode(), state.encode()):
                self.send_error(400, "Invalid OAuth callback")
                return
            callback.update(params)
            body = b"SentinelMesh received the authorization response. Return to the terminal to see the result."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class LoopbackServer(HTTPServer):
        def handle_error(self, request, client_address):
            pass  # Do not emit callback errors that might expose a request.

    with LoopbackServer(("127.0.0.1", 0), Callback) as server:
        redirect = f"http://127.0.0.1:{server.server_port}/"
        params = {"client_id": config.client_id, "redirect_uri": redirect, "response_type": "code",
                  "scope": SCOPE, "state": state, "code_challenge": challenge,
                  "code_challenge_method": "S256", "access_type": "offline", "prompt": "consent select_account",
                  "login_hint": config.account}
        if not webbrowser.open(AUTH_URL + "?" + urlencode(params)):
            raise GmailError("authorization_required", "Could not open the default browser. Check its configuration and try again.")
        deadline = time.monotonic() + 300
        server.timeout = 1
        while not callback and time.monotonic() < deadline:
            server.handle_request()
    code = callback.get("code", [""])[0]
    if not code or "error" in callback:
        raise GmailError("authorization_required", "Google consent was not completed or timed out.")
    result = request_json(TOKEN_URL, form={"grant_type": "authorization_code", "code": code,
                                          "redirect_uri": redirect, "code_verifier": verifier,
                                          "client_id": config.client_id, "client_secret": config.client_secret}, limit=65536)
    verify_scope(result, required=True)
    refresh = result.get("refresh_token")
    if not isinstance(refresh, str) or not refresh:
        raise GmailError("authorization_required", "Google did not grant offline access. Run Gmail setup again and complete consent.")
    return GmailClient(result.get("access_token")), refresh
