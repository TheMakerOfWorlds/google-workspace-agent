"""Gmail-only REST and desktop OAuth. Standard library; macOS Keychain secrets."""
import base64
import hashlib
import hmac
import json
import mimetypes
import re
import secrets
import subprocess
import sys
import time
from email.message import EmailMessage, Message
from email.policy import SMTP
from email.utils import formataddr, formatdate, make_msgid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from mail_errors import MailError

LEGACY_SCOPES = frozenset({"https://www.googleapis.com/auth/gmail.readonly",
                           "https://www.googleapis.com/auth/gmail.send"})
CLEANUP_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
SETTINGS_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"
SCOPES = frozenset({CLEANUP_SCOPE, SETTINGS_SCOPE})
API = "https://gmail.googleapis.com/gmail/v1/users/me"
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
DELIVERY_HEADERS = frozenset({"delivered_to", "x_original_to", "x_gm_original_to", "envelope_to",
    "x_envelope_to", "x_forwarded_to", "x_forwarded_for", "original_recipient", "final_recipient",
    "resent_to", "resent_cc", "resent_from", "resent_sender", "x_beenthere", "list_id", "list_post"})


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(data):
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise MailError("Malformed encoded message content.") from exc


def exact_scopes(value):
    if not isinstance(value, (str, list, tuple, set, frozenset)):
        raise MailError("Google did not report the granted permissions.")
    actual = set(value.split() if isinstance(value, str) else value)
    if actual != LEGACY_SCOPES and not (CLEANUP_SCOPE in actual and actual <= SCOPES | LEGACY_SCOPES):
        raise MailError("Permission mismatch: only Gmail modify, basic settings, and legacy Gmail read/send permissions are allowed. Reconnect using this plugin's dedicated OAuth client.")
    return sorted(actual)


def authorization_response(path, state):
    parsed = urlsplit(path)
    query = parse_qs(parsed.query)
    if (parsed.path != "/callback" or len(query.get("state", [])) != 1
            or not hmac.compare_digest(query["state"][0].encode(), state.encode())):
        raise MailError("Invalid authorization response.")
    if len(query.get("code", [])) != 1 or "error" in query:
        return {"error": "Authorization was declined or incomplete."}
    return {"code": query["code"][0]}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward bearer credentials to a redirected endpoint.


def http_json(url, *, token=None, payload=None, form=False, retry=False, method=None):
    path = url.split("?", 1)[0]
    method = method or ("POST" if payload is not None else "GET")
    resource = re.escape(API) + r"/(?:labels|settings/filters)(?:/[A-Za-z0-9_-]{1,200})?"
    read = method == "GET" and payload is None and (path in (API + "/profile", API + "/settings/sendAs", API + "/messages")
        or re.fullmatch(resource, path)
        or re.fullmatch(re.escape(API) + r"/messages/[A-Za-z0-9_-]{1,128}(?:/attachments/[A-Za-z0-9_-]+)?", path))
    write = method == "POST" and payload is not None and (path in (API + "/messages/send", API + "/labels", API + "/settings/filters")
        or re.fullmatch(re.escape(API) + r"/messages/[A-Za-z0-9_-]{1,128}/(?:trash|untrash|modify)", path))
    delete = method == "DELETE" and payload is None and re.fullmatch(re.escape(API) + r"/settings/filters/[A-Za-z0-9_-]{1,200}", path)
    if not (url == TOKEN_URL and method == "POST" or read or write or delete):
        raise MailError("Endpoint outside this plugin's Gmail/OAuth boundary.")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if payload is not None:
        data = (urlencode(payload) if form else json.dumps(payload)).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    attempts = 3 if retry and method == "GET" else 1
    for attempt in range(attempts):
        try:
            with build_opener(NoRedirect()).open(Request(url, data=data, headers=headers, method=method), timeout=45) as response:
                raw = response.read(40_000_001)
                no_content = response.status == 204
            if len(raw) > 40_000_000:
                raise MailError("Provider response exceeded the local size limit.")
            result = {} if not raw and (no_content or method == "DELETE") else json.loads(raw)
            if not isinstance(result, dict):
                raise MailError("Unexpected provider response shape.")
            return result
        except HTTPError as exc:
            if attempt + 1 < attempts and exc.code in (429, 500, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            reason = {400: "invalid_request_or_reauthentication_required", 401: "reauthentication_required",
                      403: "permission_or_project_policy", 404: "not_found", 429: "rate_limited"}.get(exc.code, "provider_error")
            raise MailError(f"Google request failed ({reason}, HTTP {exc.code}).") from None
        except (URLError, TimeoutError, OSError):
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
                continue
            raise MailError("Google connection failed; delivery is uncertain if sending.") from None
        except (ValueError, UnicodeError):
            raise MailError("Malformed provider response; delivery is uncertain if sending.") from None


class Keychain:
    """Only our named records. Secret values use stdin, never process arguments."""
    service = "com.themakerofworlds.email-agent"  # keychain_session.SERVICE must match

    def _run(self, args, data=None):
        if sys.platform != "darwin":
            raise MailError("Secure credential storage currently requires macOS Keychain.")
        try:
            result = subprocess.run(["/usr/bin/security", *args], input=data, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            raise MailError("macOS Keychain is unavailable or waiting for unlock.") from None
        if result.returncode != 36:
            return result
        # SSH/background sessions keep their own locked keychain view; use the logged-in desktop session.
        import keychain_session
        try:
            code, out, err = keychain_session.run_in_desktop(args, data)
        except keychain_session.SessionUnavailable:
            raise MailError("Keychain is locked here and no logged-in Mac desktop session could open it. "
                            "Log in on the Mac's screen and unlock the login keychain.") from None
        return subprocess.CompletedProcess(result.args, code, out, err)

    @staticmethod
    def _key(key):
        if not re.fullmatch(r"[A-Za-z0-9_.@+-]{1,200}", key):
            raise MailError("Invalid credential record name.")
        return key

    def get(self, key):
        result = self._run(["find-generic-password", "-s", self.service, "-a", self._key(key), "-w"])
        if result.returncode == 44:
            return None
        if result.returncode:
            raise MailError("Cannot read this plugin's Keychain record; unlock your login keychain.")
        try:
            value = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise MailError("This plugin's Keychain record is malformed.") from None

    def put(self, key, value):
        key = self._key(key)
        encoded = base64.b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()
        # security's interactive command reader receives the value through a pipe.
        # Capture both streams: even failures must never echo secret-bearing input.
        self._run(["-i"], f"add-generic-password -U -s {self.service} -a {key} -w {encoded}\n")
        if self.get(key) != value:
            raise MailError("Could not verify secure Keychain storage.")


class OAuth:
    def __init__(self, store=None, transport=None):
        self.store = store or Keychain()
        self.http = transport or http_json
        self.cache = {}
        self.scope_cache = {}

    def import_client(self, path, name="default"):
        try:
            data = json.loads(Path(path).read_text()).get("installed", {})
        except (OSError, ValueError):
            raise MailError("Cannot read the downloaded desktop OAuth client JSON.") from None
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.apps\.googleusercontent\.com", str(data.get("client_id", ""))):
            raise MailError("Use a Google OAuth Desktop app client JSON.")
        if data.get("auth_uri") != AUTH_URL or data.get("token_uri") != TOKEN_URL:
            raise MailError("Client JSON has unexpected Google authorization endpoints.")
        self.store.put("client." + name, {"client_id": data["client_id"], "client_secret": data.get("client_secret", "")})
        return {"client": name, "stored": "macOS Keychain"}

    def client(self, account):
        data = self.store.get("client." + account.get("client", "default"))
        if not data:
            raise MailError("Dedicated OAuth client is not configured. See setup.md.")
        return data

    @staticmethod
    def token_key(account, client):
        identity = account["email"] + "\n" + client["client_id"]
        return "token." + hashlib.sha256(identity.encode()).hexdigest()

    def access(self, account):
        client = self.client(account)
        key = self.token_key(account, client)
        if key in self.cache and self.cache[key][1] > time.time() + 60:
            return self.cache[key][0]
        saved = self.store.get(key)
        if not saved:
            raise MailError("Account is not connected. Run auth connect for this account.")
        if saved.get("email") != account["email"] or saved.get("client_id") != client["client_id"]:
            raise MailError("Stored credential identity does not match the requested account.")
        exact_scopes(saved.get("scopes"))
        fresh = self.http(TOKEN_URL, form=True, payload={**client, "grant_type": "refresh_token", "refresh_token": saved["refresh_token"]})
        scopes = exact_scopes(fresh.get("scope", saved["scopes"]))
        token = fresh.get("access_token")
        if not isinstance(token, str) or not token:
            raise MailError("Google returned no usable access token.")
        if fresh.get("refresh_token") and fresh["refresh_token"] != saved["refresh_token"]:
            self.store.put(key, {**saved, "refresh_token": fresh["refresh_token"]})
        self.cache[key] = (token, time.time() + int(fresh.get("expires_in", 3600)))
        self.scope_cache[key] = scopes
        return token

    def permissions(self, account):
        self.access(account)
        return self.scope_cache[self.token_key(account, self.client(account))]

    def authorize_url(self, account, client, redirect, state, verifier):
        return AUTH_URL + "?" + urlencode({"client_id": client["client_id"], "redirect_uri": redirect,
            "response_type": "code", "scope": " ".join(sorted(SCOPES)), "access_type": "offline",
            "prompt": "consent", "include_granted_scopes": "false", "login_hint": account["email"],
            "state": state, "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"})

    def finish(self, account, client, code, redirect, verifier):
        data = self.http(TOKEN_URL, form=True, payload={**client, "code": code, "code_verifier": verifier,
                        "redirect_uri": redirect, "grant_type": "authorization_code"})
        scopes = exact_scopes(data.get("scope"))
        if not SCOPES <= set(scopes):
            raise MailError("Google did not grant the requested Gmail modify and basic settings access. Existing credentials were preserved; reconnect and allow both Gmail permissions.")
        if not data.get("refresh_token") or not data.get("access_token"):
            raise MailError("Google did not grant renewable offline access; reconnect with consent.")
        profile = self.http(API + "/profile", token=data["access_token"], retry=True)
        if str(profile.get("emailAddress", "")).lower() != account["email"]:
            raise MailError("Google authenticated a different mailbox. No credentials were saved.")
        self.store.put(self.token_key(account, client), {"email": account["email"], "client_id": client["client_id"],
            "refresh_token": data["refresh_token"], "scopes": scopes, "connected_at": int(time.time()),
            "refresh_token_expires_in": data.get("refresh_token_expires_in")})
        # Prove the refresh grant works, not only the initial short-lived token.
        self.cache.clear()
        refreshed = self.http(API + "/profile", token=self.access(account), retry=True)
        if str(refreshed.get("emailAddress", "")).lower() != account["email"]:
            raise MailError("Refreshed credential did not match the intended mailbox.")
        return {"account": account["id"], "email": account["email"], "authenticated": True,
                "scopes": scopes, "storage": "macOS Keychain", "refresh_verified": True,
                "refresh_token_expires_in": data.get("refresh_token_expires_in")}

    def connect(self, account, timeout=900):
        client = self.client(account)
        verifier, state = secrets.token_urlsafe(64), secrets.token_urlsafe(32)
        received = {}
        class Callback(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                try:
                    response = authorization_response(self.path, state)
                except MailError:
                    self.send_error(400, "Invalid authorization response")
                    return
                received.update(response)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(b"Authorization received. Return to Codex for verification.")
        with HTTPServer(("127.0.0.1", 0), Callback) as server:
            server.timeout = 1
            redirect = f"http://127.0.0.1:{server.server_port}/callback"
            url = self.authorize_url(account, client, redirect, state, verifier)
            print(json.dumps({"status": "waiting_for_google", "account": account["id"], "url": url}), flush=True)
            deadline = time.monotonic() + timeout
            while not received and time.monotonic() < deadline:
                server.handle_request()
        if not received or received.get("error"):
            raise MailError("Authorization timed out or was declined; no credential was saved.")
        return self.finish(account, client, received["code"], redirect, verifier)


def headers_of(message):
    result = {}
    for header in message.get("payload", {}).get("headers", []):
        name = header["name"].lower().replace("-", "_")
        value = " ".join(header.get("value", "").split())
        if name in ("to", "cc", "bcc") and result.get(name):
            result[name] += ", " + value
        else:
            result[name] = value
    return result


def delivery_headers_of(message):
    """Preserve repeated routing headers in provider order, without inferring aliases."""
    result = {}
    for header in message.get("payload", {}).get("headers", []):
        name = header["name"].lower().replace("-", "_")
        value = " ".join(header.get("value", "").split())
        if name in DELIVERY_HEADERS and value:
            result.setdefault(name, []).append(value)
    return result


class Gmail:
    def __init__(self, auth=None, transport=None):
        self.auth = auth or OAuth()
        self.http = transport or http_json

    def get(self, account, path, **params):
        return self.http(API + path + ("?" + urlencode(params, doseq=True) if params else ""),
                         token=self.auth.access(account), retry=True)

    def profile(self, account):
        return self.get(account, "/profile")

    def permissions(self, account):
        return self.auth.permissions(account)

    def require_cleanup(self, account):
        if CLEANUP_SCOPE not in self.permissions(account):
            raise MailError("Cleanup needs Gmail modify permission. Run auth.py connect for this account; read/send still work.")

    def trash_state(self, account, message_id):
        labels = self.message_labels(account, message_id)
        return {"in_trash": "TRASH" in labels, "is_draft": "DRAFT" in labels}

    def message_labels(self, account, message_id):
        value = self.get(account, "/messages/" + message_id, format="minimal", fields="id,labelIds")
        labels = value.get("labelIds", [])
        if value.get("id") != message_id or not isinstance(labels, list) or any(not isinstance(x, str) for x in labels):
            raise MailError("Gmail returned an invalid message state.")
        return set(labels)

    def modify_labels(self, account, message_id, add, remove):
        self.require_cleanup(account)
        return self.http(API + "/messages/" + message_id + "/modify", token=self.auth.access(account),
                         payload={"addLabelIds": sorted(add), "removeLabelIds": sorted(remove)})

    def labels(self, account):
        rows = self.get(account, "/labels", fields="labels(id,name,type)").get("labels", [])
        if not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(r, dict) or not r.get("id") or not r.get("name") for r in rows):
            raise MailError("Invalid Gmail label list.")
        return rows

    def create_label(self, account, name):
        self.require_cleanup(account)
        return self.http(API + "/labels", token=self.auth.access(account), payload={"name": name})

    def require_settings(self, account):
        if SETTINGS_SCOPE not in self.permissions(account):
            raise MailError("Gmail settings access is missing. Reconnect this account with auth.py connect.")

    def filters(self, account):
        self.require_settings(account)
        rows = self.get(account, "/settings/filters").get("filter", [])
        if not isinstance(rows, list) or len(rows) > 1000 or any(not isinstance(r, dict) or not r.get("id") for r in rows):
            raise MailError("Invalid Gmail filter list.")
        return rows

    def create_filter(self, account, rule):
        self.require_settings(account)
        return self.http(API + "/settings/filters", token=self.auth.access(account), payload=rule)

    def delete_filter(self, account, filter_id):
        self.require_settings(account)
        return self.http(API + "/settings/filters/" + filter_id, token=self.auth.access(account), method="DELETE")

    def set_trash(self, account, message_id, trash):
        self.require_cleanup(account)
        operation = "trash" if trash else "untrash"
        # No write retries. The caller checks provider state after an ambiguous result.
        return self.http(API + "/messages/" + message_id + "/" + operation,
                         token=self.auth.access(account), payload={})

    def senders(self, account):
        result = self.get(account, "/settings/sendAs",
                          fields="sendAs(sendAsEmail,displayName,isPrimary,verificationStatus)")
        rows = result.get("sendAs")
        if not isinstance(rows, list) or len(rows) > 100 or any(not isinstance(row, dict) for row in rows):
            raise MailError("Unexpected Gmail sending-address response.")
        return rows

    def search(self, account, query, limit, cursor=None):
        params = {"q": query, "maxResults": limit, "fields": "messages(id),nextPageToken"}
        if re.search(r"\bin:(?:anywhere|spam|trash)\b", query, re.I):
            params["includeSpamTrash"] = "true"
        if cursor:
            params["pageToken"] = cursor
        result = self.get(account, "/messages", **params)
        rows = []
        for item in result.get("messages", [])[:limit]:
            message = self.get(account, "/messages/" + item["id"], format="metadata",
                metadataHeaders=["From", "To", "Cc", "Delivered-To", "Subject", "Date"],
                fields="id,labelIds,payload(headers)")
            rows.append({"id": message["id"], **headers_of(message),
                         "delivery": delivery_headers_of(message), "labels": message.get("labelIds", [])})
        return {"messages": rows, "nextPageToken": result.get("nextPageToken")}

    def read(self, account, message_id):
        message = self.get(account, "/messages/" + message_id, format="full")
        attachments, plain, html = [], [], []
        def visit(part):
            body, mime = part.get("body", {}), part.get("mimeType", "")
            meta = Message()
            for header in part.get("headers", []):
                if header["name"].lower() in ("content-type", "content-disposition"):
                    meta[header["name"]] = header.get("value", "")
            if part.get("filename") or meta.get_content_disposition() == "attachment":
                attachments.append({"filename": part.get("filename", "attachment"), "size": body.get("size"),
                                    "part": "root" if part.get("partId") == "" else part.get("partId"), "mime": mime})
                return
            if mime in ("text/plain", "text/html"):
                if body.get("attachmentId"):
                    body = self.get(account, "/messages/" + message_id + "/attachments/" + body["attachmentId"])
                raw = unb64(body.get("data", ""))
                try:
                    decoded = raw.decode(meta.get_content_charset() or "utf-8", errors="replace")
                except LookupError:
                    decoded = raw.decode("utf-8", errors="replace")
                (plain if mime == "text/plain" else html).append(decoded)
            for child in part.get("parts", []):
                visit(child)
        visit(message.get("payload", {}))
        return {"message": message, "headers": headers_of(message), "delivery": delivery_headers_of(message), "attachments": attachments,
                "body": "\n".join(plain or html), "html_only": not plain and bool(html)}

    def attachment(self, account, message_id, part_id, max_bytes):
        message = self.get(account, "/messages/" + message_id, format="full")
        if message.get("id") != message_id:
            raise MailError("Attachment message identity mismatch.")
        parts = []
        def visit(part):
            if ("root" if part.get("partId") == "" else part.get("partId")) == part_id:
                parts.append(part)
            for child in part.get("parts", []):
                visit(child)
        visit(message.get("payload", {}))
        if len(parts) != 1:
            raise MailError("Attachment part is missing or ambiguous; read the message again.")
        part = parts[0]
        disposition = next((h.get("value", "") for h in part.get("headers", []) if h.get("name", "").lower() == "content-disposition"), "")
        if not part.get("filename") and not disposition.lower().startswith("attachment"):
            raise MailError("The selected part is message content, not an attachment.")
        body = part.get("body", {})
        size = body.get("size")
        if type(size) is not int or not 0 <= size <= max_bytes:
            raise MailError("Attachment exceeds the download limit or has invalid size.")
        if body.get("attachmentId"):
            ident = body["attachmentId"]
            if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,4096}", ident):
                raise MailError("Invalid attachment identifier.")
            body = self.get(account, "/messages/" + message_id + "/attachments/" + ident)
        raw = unb64(body.get("data", ""))
        if len(raw) != size or len(raw) > max_bytes:
            raise MailError("Downloaded attachment size mismatch.")
        return raw, part.get("filename", "attachment"), part.get("mimeType", "application/octet-stream")

    def prepare_send(self, account, payload):
        message = EmailMessage(policy=SMTP)
        message["From"] = account["email"]
        if payload.get("send_as"):
            sender = payload["send_as"]
            matches = [row for row in self.senders(account)
                       if str(row.get("sendAsEmail", "")).lower() == sender]
            if len(matches) != 1 or matches[0].get("verificationStatus") != "accepted":
                raise MailError("Selected sending alias is not verified by Gmail for this mailbox. No email was sent.")
            name = matches[0].get("displayName", "")
            if not isinstance(name, str) or len(name) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in name):
                raise MailError("Sending alias has an invalid display name.")
            message.replace_header("From", formataddr((name, sender)))
            message["Reply-To"] = sender
        for key in ("to", "cc", "bcc"):
            if payload[key]:
                message[key.title()] = ", ".join(payload[key])
        message["Subject"] = payload["subject"]
        message["Date"] = formatdate(localtime=False, usegmt=True)
        message["Message-ID"] = make_msgid()
        thread_id = None
        if payload.get("reply_to"):
            source = self.get(account, "/messages/" + payload["reply_to"].split(":")[-1],
                              format="metadata", metadataHeaders=["Message-ID", "References", "Subject"])
            headers = headers_of(source)
            original = headers.get("message_id", "")
            if not re.fullmatch(r"<[^\s<>]+>", original):
                raise MailError("Original message lacks a safe Message-ID for threading.")
            references = headers.get("references", "").split()
            if any(not re.fullmatch(r"<[^\s<>]+>", r) for r in references):
                raise MailError("Original message has invalid threading headers.")
            message["In-Reply-To"] = original
            message["References"] = " ".join(references[-20:] + [original])
            thread_id = source.get("threadId")
        message.set_content(payload["body"])
        for attachment in payload["attachments"]:
            path = Path(attachment["path"])
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != attachment["sha256"]:
                raise MailError("Attachment changed during send preparation.")
            mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            main, sub = mime.split("/", 1)
            message.add_attachment(data, maintype=main, subtype=sub, filename=path.name)
        result = {"raw": b64(message.as_bytes())}
        if thread_id:
            result["threadId"] = thread_id
        return result

    def send(self, account, prepared):
        # Never retry a send POST automatically, including timeouts or 5xx responses.
        result = self.http(API + "/messages/send", token=self.auth.access(account), payload=prepared)
        message_id = result.get("id")
        if not isinstance(message_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", message_id):
            raise MailError("Gmail returned no valid sent-message ID; inspect Sent mail before retrying.")
        sent = self.get(account, "/messages/" + message_id, format="metadata",
                        metadataHeaders=["From"], fields="id,payload(headers)")
        if sent.get("id") != message_id:
            raise MailError("Gmail returned a different sent message; inspect Sent mail before retrying.")
        return {"from": headers_of(sent).get("from", ""), "messageId": message_id, "threadId": result.get("threadId")}
