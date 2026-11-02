import base64
from email import message_from_bytes
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import gmail_backend as gb
from mail_errors import MailError


class Store:
    def __init__(self):
        self.records = {}
        self.writes = []
    def get(self, key):
        return self.records.get(key)
    def put(self, key, value):
        self.records[key] = value
        self.writes.append(key)


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.client = {"client_id": "123.apps.googleusercontent.com", "client_secret": "CLIENT_SECRET"}
        self.store.records["client.default"] = self.client
        self.account = {"id": "work", "email": "work@example.com"}
        self.auth = gb.OAuth(self.store, self.http)
        self.calls = []
        self.scope = " ".join(sorted(gb.SCOPES))
        self.profile = self.account["email"]

    def http(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("/profile"):
            return {"emailAddress": self.profile}
        return {"access_token": "ACCESS_SECRET", "refresh_token": "REFRESH_SECRET", "expires_in": 3600, "scope": self.scope}

    def finish(self):
        return self.auth.finish(self.account, self.client, "CODE", "http://127.0.0.1:1234/callback", "VERIFIER")

    def test_authorization_requests_only_gmail_modify_and_offline_pkce(self):
        url = self.auth.authorize_url(self.account, self.client, "http://127.0.0.1:1234/callback", "state", "verifier")
        args = parse_qs(urlsplit(url).query)
        self.assertEqual(set(args["scope"][0].split()), gb.SCOPES)
        self.assertEqual(args["access_type"], ["offline"])
        self.assertEqual(args["include_granted_scopes"], ["false"])
        self.assertEqual(args["login_hint"], [self.account["email"]])
        self.assertEqual(args["code_challenge_method"], ["S256"])
        self.assertNotIn("CLIENT_SECRET", url)
        self.assertNotEqual(args["code_challenge"], ["verifier"])

    def test_legacy_grants_keep_read_send_but_reconnection_requires_cleanup(self):
        self.finish()
        key = self.auth.token_key(self.account, self.client)
        self.store.records[key]["scopes"] = sorted(gb.LEGACY_SCOPES)
        self.scope = " ".join(gb.LEGACY_SCOPES)
        self.auth.cache.clear()
        self.assertEqual(set(self.auth.permissions(self.account)), gb.LEGACY_SCOPES)
        saved = dict(self.store.records[key])
        with self.assertRaises(MailError):
            self.finish()
        self.assertEqual(self.store.records[key], saved)

    def test_scope_upgrade_accepts_redundant_gmail_grants_but_never_full_mail(self):
        self.assertEqual(set(gb.exact_scopes(gb.SCOPES | gb.LEGACY_SCOPES)), gb.SCOPES | gb.LEGACY_SCOPES)
        for scopes in ({"https://mail.google.com/"}, gb.SCOPES | {"https://mail.google.com/"}, {"openid"} | gb.SCOPES):
            with self.assertRaises(MailError):
                gb.exact_scopes(scopes)

    def test_excess_or_partial_scopes_never_saved(self):
        for scope in (self.scope + " https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/gmail.readonly", None):
            self.scope = scope
            with self.assertRaises(MailError):
                self.finish()
        self.assertEqual(self.store.writes, [])

    def test_wrong_mailbox_never_saved(self):
        self.profile = "wrong@example.com"
        with self.assertRaises(MailError):
            self.finish()
        self.assertEqual(self.store.writes, [])

    def test_initial_connection_verifies_refresh_and_redacts_tokens(self):
        result = self.finish()
        self.assertTrue(result["refresh_verified"])
        self.assertEqual(len([c for c in self.calls if c[0] == gb.TOKEN_URL]), 2)
        self.assertNotIn("SECRET", json.dumps(result))
        record = self.store.records[self.auth.token_key(self.account, self.client)]
        self.assertNotIn("access_token", record)
        self.assertEqual(record["refresh_token"], "REFRESH_SECRET")

    def test_access_cached_in_memory_and_refresh_scope_checked(self):
        self.finish()
        count = len(self.calls)
        self.auth.access(self.account)
        self.assertEqual(len(self.calls), count)
        self.auth.cache.clear()
        self.scope += " https://www.googleapis.com/auth/drive"
        with self.assertRaises(MailError):
            self.auth.access(self.account)

    def test_account_and_client_bind_credential_key(self):
        self.finish()
        with self.assertRaises(MailError):
            self.auth.access({"id": "personal", "email": "other@example.com"})
        self.store.records["client.default"] = {**self.client, "client_id": "456.apps.googleusercontent.com"}
        with self.assertRaises(MailError):
            self.auth.access(self.account)

    def test_client_import_rejects_foreign_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client.json"
            path.write_text(json.dumps({"installed": {**self.client, "auth_uri": gb.AUTH_URL, "token_uri": "https://evil.example/token"}}))
            with self.assertRaises(MailError):
                self.auth.import_client(path)
            self.assertEqual(self.store.writes, [])

    def test_callback_rejects_missing_wrong_and_duplicate_state(self):
        for path in ("/callback?code=SECRET", "/callback?state=🎸&code=SECRET", "/callback?state=wrong&code=SECRET",
                     "/callback?state=correct&state=wrong&code=SECRET", "/elsewhere?state=correct&code=SECRET"):
            with self.assertRaises(MailError):
                gb.authorization_response(path, "correct")
        self.assertEqual(gb.authorization_response("/callback?state=correct&code=SECRET", "correct"), {"code": "SECRET"})
        self.assertIn("error", gb.authorization_response("/callback?state=correct&error=access_denied", "correct"))

    def test_keychain_secret_only_uses_stdin_and_is_verified(self):
        value = {"refresh_token": "PRIVATE_SECRET"}
        encoded = base64.b64encode(json.dumps(value).encode()).decode()
        responses = [subprocess.CompletedProcess([], 0, "", ""), subprocess.CompletedProcess([], 0, encoded, "")]
        with patch.object(gb.sys, "platform", "darwin"), patch.object(gb.subprocess, "run", side_effect=responses) as run:
            gb.Keychain().put("test.work", value)
            self.assertNotIn("PRIVATE_SECRET", str(run.call_args_list[0].args))
            self.assertNotIn("-w", run.call_args_list[0].args[0])
            self.assertIn("add-generic-password", run.call_args_list[0].kwargs["input"])
            self.assertTrue(run.call_args_list[0].kwargs["capture_output"])

    def test_keychain_locked_session_uses_desktop_session(self):
        import keychain_session
        value = {"refresh_token": "PRIVATE_SECRET"}
        encoded = base64.b64encode(json.dumps(value).encode()).decode()
        locked = subprocess.CompletedProcess([], 36, "", "User interaction is not allowed.")
        with patch.object(gb.sys, "platform", "darwin"), patch.object(gb.subprocess, "run", return_value=locked), \
                patch.object(keychain_session, "run_in_desktop", return_value=(0, encoded, "")) as desktop:
            self.assertEqual(gb.Keychain().get("token.work"), value)
            desktop.assert_called_once_with(["find-generic-password", "-s", gb.Keychain.service, "-a", "token.work", "-w"], None)
        missing = subprocess.CompletedProcess([], 44, "", "")
        with patch.object(gb.sys, "platform", "darwin"), patch.object(gb.subprocess, "run", return_value=missing), \
                patch.object(keychain_session, "run_in_desktop") as desktop:
            self.assertIsNone(gb.Keychain().get("token.work"))
            desktop.assert_not_called()
        with patch.object(gb.sys, "platform", "darwin"), patch.object(gb.subprocess, "run", return_value=locked), \
                patch.object(keychain_session, "run_in_desktop", side_effect=keychain_session.SessionUnavailable("x")):
            with self.assertRaisesRegex(MailError, "desktop session"):
                gb.Keychain().get("token.work")

    def test_desktop_keychain_helper_only_allows_plugin_records(self):
        import keychain_session as ks
        self.assertEqual(ks.SERVICE, gb.Keychain.service)
        self.assertTrue(ks.allowed(["find-generic-password", "-s", ks.SERVICE, "-a", "token.abc", "-w"], None))
        self.assertTrue(ks.allowed(["-i"], f"add-generic-password -U -s {ks.SERVICE} -a token.abc -w QUJD=\n"))
        for args, data in ((["find-generic-password", "-s", "other.service", "-a", "x", "-w"], None),
                           (["find-generic-password", "-s", ks.SERVICE, "-a", "x;rm", "-w"], None),
                           (["dump-keychain"], None), (["unlock-keychain", "-p", "pw"], None),
                           (["-i"], f"add-generic-password -U -s {ks.SERVICE} -a x -w A\ndump-keychain\n"),
                           (["-i"], "delete-generic-password -s " + ks.SERVICE + "\n")):
            self.assertFalse(ks.allowed(args, data))
        with self.assertRaises(ks.SessionUnavailable):
            ks.run_in_desktop(["dump-keychain"])


class GmailTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        class Auth:
            def access(self, account):
                return "TOKEN_SECRET"
            def permissions(self, account):
                return gb.SCOPES
        self.gmail = gb.Gmail(Auth(), self.http)
        self.account = {"id": "work", "email": "work@example.com"}
        self.source = {"id": "m1", "threadId": "thread1", "payload": {"mimeType": "text/plain", "body": {"data": gb.b64(b"Hello")},
            "headers": [{"name": "Subject", "value": "Hello"}, {"name": "Message-ID", "value": "<original@example.com>"}]}}
        self.aliases = [{"sendAsEmail": "team@example.com", "verificationStatus": "accepted", "displayName": "Company Team"}]

    def http(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("/send"):
            mime = message_from_bytes(gb.unb64(kwargs["payload"]["raw"]))
            self.sent_source = {"id": "sent1", "payload": {"headers": [{"name": "From", "value": mime["From"]}]}}
            return {"id": "sent1", "threadId": "thread1"}
        if urlsplit(url).path.endswith("/settings/sendAs"):
            return {"sendAs": self.aliases}
        if urlsplit(url).path.endswith("/messages/sent1"):
            return self.sent_source
        return self.source

    def payload(self):
        return {"to": ["recipient@example.com"], "cc": [], "bcc": [], "subject": "Hello", "body": "Hi 🎸", "attachments": []}

    def test_plaintext_body_and_attachment_metadata(self):
        result = self.gmail.read(self.account, "m1")
        self.assertEqual(result["body"], "Hello")
        self.assertFalse(result["html_only"])

    def test_download_inline_and_remote_attachment_bytes(self):
        self.source["payload"]["parts"] = [{"partId": "1", "filename": "invoice.pdf", "mimeType": "application/pdf",
            "body": {"size": 3, "data": gb.b64(b"PDF")}}]
        self.assertEqual(self.gmail.attachment(self.account, "m1", "1", 10)[0], b"PDF")
        self.source["payload"]["parts"][0]["body"] = {"size": 3, "attachmentId": "remote1"}
        original = self.gmail.http
        def transport(url, **kwargs):
            if "/attachments/remote1" in url:
                self.calls.append((url, kwargs)); return {"size": 3, "data": gb.b64(b"PDF")}
            return original(url, **kwargs)
        self.gmail.http = transport
        self.assertEqual(self.gmail.attachment(self.account, "m1", "1", 10)[0], b"PDF")
        self.assertTrue(any("/attachments/remote1" in url for url, _ in self.calls))

    def test_attachment_root_part_and_wrong_message_are_checked(self):
        self.source["payload"] = {"partId": "", "filename": "file.bin", "body": {"size": 0, "data": ""}}
        self.assertEqual(self.gmail.attachment(self.account, "m1", "root", 10)[0], b"")
        with self.assertRaises(MailError): self.gmail.attachment(self.account, "other", "root", 10)

    def test_attachment_oversize_mismatch_and_nonattachment_are_blocked(self):
        self.source["payload"]["parts"] = [{"partId": "1", "filename": "invoice.pdf", "mimeType": "application/pdf",
            "body": {"size": 100, "attachmentId": "huge"}}]
        with self.assertRaises(MailError): self.gmail.attachment(self.account, "m1", "1", 10)
        self.assertFalse(any("/attachments/huge" in url for url, _ in self.calls))
        self.source["payload"]["parts"][0]["body"] = {"size": 5, "data": gb.b64(b"PDF")}
        with self.assertRaises(MailError): self.gmail.attachment(self.account, "m1", "1", 10)
        self.source["payload"]["parts"][0]["filename"] = ""
        with self.assertRaises(MailError): self.gmail.attachment(self.account, "m1", "1", 10)

    def test_filter_delete_accepts_empty_response_and_blocks_message_deletion(self):
        with patch.object(gb, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b""
            self.assertEqual(gb.http_json(gb.API + "/settings/filters/f1", method="DELETE"), {})
            for path in ("/messages/m1", "/messages/batchDelete", "/labels/Label_1", "/settings/forwardingAddresses/f1"):
                with self.assertRaises(MailError): gb.http_json(gb.API + path, method="DELETE")
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.get_method(), "DELETE")
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_empty_filter_list_204_is_a_valid_empty_object(self):
        with patch.object(gb, "build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 204; response.read.return_value = b""
            self.assertEqual(gb.http_json(gb.API + "/settings/filters"), {})

    def test_delete_and_modify_requests_are_not_retried(self):
        for path, kwargs in (("/settings/filters/f1", {"method": "DELETE"}), ("/messages/m1/modify", {"payload": {}})):
            with patch.object(gb, "build_opener") as opener:
                opener.return_value.open.side_effect = URLError("SECRET")
                with self.assertRaises(MailError): gb.http_json(gb.API + path, retry=True, **kwargs)
                self.assertEqual(opener.return_value.open.call_count, 1)

    def test_search_in_anywhere_enables_spam_trash(self):
        with patch.object(self.gmail, "get", return_value={}) as get:
            self.gmail.search(self.account, "in:anywhere filename:pdf", 10)
            self.assertEqual(get.call_args.kwargs["includeSpamTrash"], "true")
            self.gmail.search(self.account, "in:inbox", 10)
            self.assertNotIn("includeSpamTrash", get.call_args.kwargs)

    def test_trash_state_requires_matching_id_and_valid_labels(self):
        self.source["labelIds"] = ["SENT", "TRASH"]
        self.assertEqual(self.gmail.trash_state(self.account, "m1"), {"in_trash": True, "is_draft": False})
        params = parse_qs(urlsplit(self.calls[-1][0]).query)
        self.assertEqual(params["format"], ["minimal"])
        self.assertEqual(params["fields"], ["id,labelIds"])
        with self.assertRaises(MailError):
            self.gmail.trash_state(self.account, "other")
        self.source["labelIds"] = "TRASH"
        with self.assertRaises(MailError):
            self.gmail.trash_state(self.account, "m1")

    def test_trash_and_restore_post_once_and_require_permission(self):
        for target, path in ((True, "trash"), (False, "untrash")):
            self.gmail.set_trash(self.account, "m1", target)
            url, options = self.calls[-1]
            self.assertEqual(url, gb.API + "/messages/m1/" + path)
            self.assertEqual(options["payload"], {})
            self.assertNotIn("retry", options)
        with patch.object(self.gmail.auth, "permissions", return_value=gb.LEGACY_SCOPES):
            with self.assertRaises(MailError):
                self.gmail.set_trash(self.account, "m1", True)
        self.assertEqual(len(self.calls), 2)

    def test_transport_allows_trash_but_blocks_other_mail_mutations(self):
        with patch.object(gb, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{}'
            for route in ("/messages/m1/trash", "/messages/m1/untrash"):
                gb.http_json(gb.API + route, payload={})
            for route in ("/messages/m1", "/messages/m1/delete", "/messages/batchDelete", "/messages/modify", "/messages", "/drafts"):
                with self.assertRaises(MailError):
                    gb.http_json(gb.API + route, payload={})
            self.assertEqual(opener.return_value.open.call_count, 2)

    def test_trash_post_is_not_automatically_retried(self):
        with patch.object(gb, "build_opener") as opener:
            opener.return_value.open.side_effect = URLError("SECRET")
            with self.assertRaises(MailError):
                gb.http_json(gb.API + "/messages/m1/trash", payload={}, retry=True)
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_forwarding_and_group_headers_preserve_repeated_values(self):
        self.source["payload"]["headers"] += [
            {"name": "To", "value": "Team <team@example.com>"},
            {"name": "tO", "value": "Contact <contact@example.com>"},
            {"name": "Delivered-To", "value": "work@example.com"},
            {"name": "delivered-to", "value": "forwarder@example.net"},
            {"name": "X-Original-To", "value": "contact@example.com"},
            {"name": "X-BeenThere", "value": "team@example.com"},
            {"name": "List-Id", "value": "Team\r\n\t<team.example.com>"}]
        result = self.gmail.read(self.account, "m1")
        self.assertEqual(result["headers"]["to"], "Team <team@example.com>, Contact <contact@example.com>")
        self.assertEqual(result["delivery"]["delivered_to"], ["work@example.com", "forwarder@example.net"])
        self.assertEqual(result["delivery"]["x_original_to"], ["contact@example.com"])
        self.assertEqual(result["delivery"]["x_beenthere"], ["team@example.com"])
        self.assertEqual(result["delivery"]["list_id"], ["Team <team.example.com>"])
        self.assertNotIn("bcc", result["headers"])

    def test_search_fetches_recipient_context_without_body(self):
        self.source["payload"]["headers"] += [
            {"name": "To", "value": "team@example.com"},
            {"name": "Cc", "value": "other@example.com"},
            {"name": "Delivered-To", "value": "work@example.com"}]
        def transport(url, **kwargs):
            self.calls.append((url, kwargs))
            if urlsplit(url).path == urlsplit(gb.API + "/messages").path:
                return {"messages": [{"id": "m1"}]}
            return self.source
        self.gmail.http = transport
        result = self.gmail.search(self.account, "to:team@example.com", 1)
        query = parse_qs(urlsplit(self.calls[-1][0]).query)
        self.assertEqual(query["format"], ["metadata"])
        self.assertTrue({"To", "Cc", "Delivered-To"}.issubset(query["metadataHeaders"]))
        self.assertEqual(result["messages"][0]["to"], "team@example.com")
        self.assertEqual(result["messages"][0]["delivery"]["delivered_to"], ["work@example.com"])
        self.assertNotIn("body", result["messages"][0])

    def test_html_fallback_ignores_plaintext_attachment(self):
        self.source["payload"] = {"mimeType": "multipart/mixed", "parts": [
            {"mimeType": "text/html", "body": {"data": gb.b64(b"<p>Hi</p>")}},
            {"mimeType": "text/plain", "filename": "note.txt", "body": {"size": 3, "data": gb.b64(b"SECRET")}}]}
        result = self.gmail.read(self.account, "m1")
        self.assertEqual(result["body"], "<p>Hi</p>")
        self.assertTrue(result["html_only"])
        self.assertEqual(result["attachments"], [{"filename": "note.txt", "size": 3, "part": None, "mime": "text/plain"}])

    def test_mime_from_unicode_recipients_and_threading(self):
        payload = {**self.payload(), "bcc": ["private@example.com"], "reply_to": "work:identity:m1"}
        prepared = self.gmail.prepare_send(self.account, payload)
        message = message_from_bytes(gb.unb64(prepared["raw"]))
        self.assertEqual(message["From"], self.account["email"])
        self.assertEqual(message["Bcc"], "private@example.com")
        self.assertEqual(message["In-Reply-To"], "<original@example.com>")
        self.assertEqual(prepared["threadId"], "thread1")
        self.assertIn("🎸", message.get_payload(decode=True).decode())
        result = self.gmail.send(self.account, prepared)
        self.assertEqual(result["from"], self.account["email"])
        self.assertNotIn("retry", next(kwargs for url, kwargs in self.calls if url.endswith("/send")))

    def test_approved_alias_uses_selected_from_and_reply_address(self):
        prepared = self.gmail.prepare_send(self.account, {**self.payload(), "send_as": "team@example.com"})
        message = message_from_bytes(gb.unb64(prepared["raw"]))
        self.assertEqual(message["From"], "Company Team <team@example.com>")
        self.assertEqual(message["Reply-To"], "team@example.com")
        result = self.gmail.send(self.account, prepared)
        self.assertEqual(result["from"], message["From"])
        self.assertTrue(urlsplit(self.calls[-1][0]).path.endswith("/messages/sent1"))

    def test_missing_pending_and_revoked_aliases_never_send(self):
        for rows in ([], [{"sendAsEmail": "team@example.com", "verificationStatus": "pending"}],
                     [{"sendAsEmail": "team@example.com"}], [{"sendAsEmail": "other@example.com", "verificationStatus": "accepted"}]):
            self.aliases = rows
            with self.assertRaises(MailError):
                self.gmail.prepare_send(self.account, {**self.payload(), "send_as": "team@example.com"})
        self.assertFalse(any(url.endswith("/send") for url, _ in self.calls))

    def test_alias_display_name_header_injection_is_blocked(self):
        self.aliases[0]["displayName"] = "Team\r\nBcc: unwanted@example.com"
        with self.assertRaises(MailError):
            self.gmail.prepare_send(self.account, {**self.payload(), "send_as": "team@example.com"})

    def test_only_read_only_alias_settings_endpoint_is_allowed(self):
        with patch.object(gb, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{"sendAs":[]}'
            self.assertEqual(gb.http_json(gb.API + "/settings/sendAs?fields=sendAs(sendAsEmail)"), {"sendAs": []})
            for url, options in ((gb.API + "/settings/sendAs", {"payload": {}}),
                                 (gb.API + "/settings/sendAs/team@example.com", {}),
                                 (gb.API + "/settings/forwardingAddresses", {})):
                with self.assertRaises(MailError):
                    gb.http_json(url, **options)
            self.assertEqual(opener.return_value.open.call_count, 1)

    def test_send_reports_provider_stored_sender_not_assumed_sender(self):
        prepared = self.gmail.prepare_send(self.account, self.payload())
        original = self.gmail.http
        def transport(url, **kwargs):
            result = original(url, **kwargs)
            if url.endswith("/send"):
                self.sent_source["payload"]["headers"][0]["value"] = "rewritten@example.com"
            return result
        self.gmail.http = transport
        self.assertEqual(self.gmail.send(self.account, prepared)["from"], "rewritten@example.com")

    def test_attachment_changed_before_send_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comma,file.txt"
            path.write_text("before")
            payload = {**self.payload(), "attachments": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]}
            self.gmail.prepare_send(self.account, payload)
            path.write_text("after")
            with self.assertRaises(MailError):
                self.gmail.prepare_send(self.account, payload)

    def test_external_endpoints_rejected(self):
        with self.assertRaises(MailError):
            gb.http_json("https://evil.example/messages", token="PRIVATE_SECRET")

    def test_get_retries_three_times_with_sanitized_errors(self):
        with patch.object(gb, "build_opener") as opener, patch.object(gb.time, "sleep"):
            opener.return_value.open.side_effect = URLError("PRIVATE_SECRET")
            with self.assertRaises(MailError) as error:
                gb.http_json(gb.API + "/profile", token="PRIVATE_SECRET", retry=True)
            self.assertEqual(opener.return_value.open.call_count, 3)
            self.assertNotIn("PRIVATE_SECRET", str(error.exception))

    def test_send_post_not_retried_on_5xx(self):
        with patch.object(gb, "build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError(gb.API + "/messages/send", 503, "PRIVATE_SECRET", {}, io.BytesIO(b"PRIVATE_SECRET"))
            with self.assertRaises(MailError) as error:
                gb.http_json(gb.API + "/messages/send", token="PRIVATE_SECRET", payload={"raw": "MAIL"}, retry=True)
            self.assertEqual(opener.return_value.open.call_count, 1)
            self.assertNotIn("PRIVATE_SECRET", str(error.exception))


if __name__ == "__main__":
    unittest.main()
