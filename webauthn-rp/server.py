#!/usr/bin/env python3
"""Minimal WebAuthn Relying Party test server for HardID FIDO2 bring-up.

Uses python-fido2's fido2.server for options generation + verification.
HTTPS served with mkcert localhost certs. Credentials kept in RAM.

Endpoints:
  GET  /            -> index.html (WebAuthn test page)
  GET  /api/register -> {publicKey: ...} creation options
  POST /api/register -> verify attestation, store credential
  GET  /api/login    -> {publicKey: ...} request options (allowCredentials)
  POST /api/login    -> verify assertion signature
"""
import json
import os
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

BASE = os.path.dirname(os.path.abspath(__file__))
RP_ID = "localhost"
USER = {"id": b"user-01", "name": "alice", "displayName": "Alice"}

rp = PublicKeyCredentialRpEntity(id=RP_ID, name="HardID RP Test")
server = Fido2Server(rp)

STORE = {}      # username -> AttestedCredentialData
PENDING = {}    # "register"/"login" -> (options, state)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, code=200):
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            return self._send_file(os.path.join(BASE, "index.html"))
        if self.path == "/api/register":
            options, state = server.register_begin(
                PublicKeyCredentialUserEntity.from_dict(USER),
                user_verification="discouraged",
            )
            PENDING["register"] = (options, state)
            return self._send({"publicKey": dict(options.public_key)})
        if self.path == "/api/login":
            creds = list(STORE.values())
            if not creds:
                return self._send({"error": "no credential registered yet"}, 400)
            options, state = server.authenticate_begin(
                creds, user_verification="discouraged"
            )
            PENDING["login"] = (options, state)
            return self._send({"publicKey": dict(options.public_key)})
        return self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/register":
            if "register" not in PENDING:
                return self._send({"error": "no pending registration"}, 400)
            options, state = PENDING.pop("register")
            try:
                auth_data = server.register_complete(state, data)
                STORE[USER["name"]] = auth_data.credential_data
                return self._send(
                    {"ok": True, "user": USER["name"],
                     "credential_id": auth_data.credential_data.credential_id.hex()}
                )
            except Exception as e:
                return self._send({"error": f"register failed: {e}"}, 400)
        if self.path == "/api/login":
            if "login" not in PENDING:
                return self._send({"error": "no pending login"}, 400)
            options, state = PENDING.pop("login")
            try:
                cred_data = server.authenticate_complete(
                    state, list(STORE.values()), data
                )
                return self._send(
                    {"ok": True, "user": USER["name"],
                     "credential_id": cred_data.credential_id.hex()}
                )
            except Exception as e:
                return self._send({"error": f"login failed: {e}"}, 400)
        return self._send({"error": "not found"}, 404)


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        os.path.join(BASE, "certs", "localhost+1.pem"),
        os.path.join(BASE, "certs", "localhost+1-key.pem"),
    )
    httpd = HTTPServer(("0.0.0.0", 8443), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("HardID RP server: https://localhost:8443")
    httpd.serve_forever()