#!/usr/bin/env python3
"""Run one of this plugin's Keychain commands in the logged-in Mac session.

SSH and background launches get their own security session, where the login
keychain stays locked even while the desktop session has it unlocked. This
helper starts a one-shot launchd job in gui/UID and exchanges the command and
result over a private socket. It never unlocks anything: the desktop session
must already be logged in, and macOS keeps its normal unlock prompt there.
"""
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import socket
import subprocess
import sys
import tempfile

SERVICE = "com.themakerofworlds.email-agent"
INTERACTION_NOT_ALLOWED = 36  # security's exit status for errSecInteractionNotAllowed
_KEY = r"[A-Za-z0-9_.@+-]{1,200}"
_ADD = re.compile(r"add-generic-password -U -s " + re.escape(SERVICE) + r" -a " + _KEY + r" -w [A-Za-z0-9+/=]+\n")


class SessionUnavailable(Exception):
    pass


def allowed(args, data):
    """Only reads/writes of this plugin's own named records."""
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return False
    if args == ["-i"]:
        return isinstance(data, str) and bool(_ADD.fullmatch(data))
    return (data is None and len(args) == 6 and args[:3] == ["find-generic-password", "-s", SERVICE]
            and args[3] == "-a" and bool(re.fullmatch(_KEY, args[4])) and args[5] == "-w")


def run_in_desktop(args, data=None):
    """Return (returncode, stdout, stderr) from /usr/bin/security run in gui/UID."""
    if not allowed(args, data):
        raise SessionUnavailable("command_not_allowed")
    base = Path.home() / ".config/email-agent"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    domain = "gui/" + str(os.getuid())
    label = "com.themakerofworlds.email-agent.keychain-" + secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix=".kc-", dir=base) as tmp:
        folder = Path(tmp)
        endpoint = folder / "pipe"
        plist = folder / "job.plist"
        # Pass public source inline: launchd jobs cannot read checkouts under privacy-protected folders.
        plist.write_bytes(plistlib.dumps({"Label": label, "RunAtLoad": True, "ProcessType": "Interactive",
                                          "ProgramArguments": [sys.executable, "-c", Path(__file__).read_text(),
                                                               "--socket", str(endpoint)]}))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(endpoint))
            endpoint.chmod(0o600)
            server.listen(1)
            server.settimeout(30)
            try:
                started = subprocess.run(["/bin/launchctl", "bootstrap", domain, str(plist)], capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                raise SessionUnavailable("no_desktop_session") from None
            if started.returncode:
                raise SessionUnavailable("no_desktop_session")
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(120)
                    connection.sendall(json.dumps({"args": args, "input": data}).encode())
                    connection.shutdown(socket.SHUT_WR)
                    with connection.makefile("rb") as stream:
                        result = json.loads(stream.read(1_000_001))
                return int(result["returncode"]), str(result["stdout"]), str(result["stderr"])
            except (OSError, ValueError, KeyError, TypeError):
                raise SessionUnavailable("desktop_session_failed") from None
            finally:
                subprocess.run(["/bin/launchctl", "bootout", domain + "/" + label], capture_output=True, timeout=15)


def serve(endpoint):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(120)
        connection.connect(endpoint)
        with connection.makefile("rb") as stream:
            request = json.loads(stream.read(1_000_001))
        args, data = request.get("args"), request.get("input")
        if not allowed(args, data):
            reply = {"returncode": 1, "stdout": "", "stderr": "command_not_allowed"}
        else:
            try:
                done = subprocess.run(["/usr/bin/security", *args], input=data, capture_output=True, text=True, timeout=90)
                reply = {"returncode": done.returncode, "stdout": done.stdout, "stderr": done.stderr}
            except (OSError, subprocess.TimeoutExpired):
                reply = {"returncode": 1, "stdout": "", "stderr": "timeout"}
        connection.sendall(json.dumps(reply).encode())


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--socket":
        serve(sys.argv[2])
    else:
        raise SystemExit("Internal helper; used by the email plugin's Keychain access.")
