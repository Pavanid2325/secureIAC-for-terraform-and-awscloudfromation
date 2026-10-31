"""Local-only SIWC public client. Credentials belong exclusively to SecureIaC."""
import base64
import hashlib
import json
import re
import secrets
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit
from src.llm.base import LLMError

ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
TOKEN_URL = ISSUER + "/api/accounts/oauth/token"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"


class CredentialStore:
    """OS credential vault; refuse plaintext or third-party fallback backends."""
    def __init__(self):
        import keyring
        backend = keyring.get_keyring()
        if not type(backend).__module__.startswith(("keyring.backends.Windows", "keyring.backends.macOS", "keyring.backends.SecretService")):
            raise LLMError("protected_credential_storage_unavailable")
        self.keyring = keyring

    def load(self):
        value = self.keyring.get_password("SecureIaC", "siwc-manifest")
        if not value:
            return {"host_id": "urn:uuid:" + str(uuid.uuid4()), "accounts": {}, "active": None}
        manifest = json.loads(value)
        generation, count = manifest["generation"], manifest["chunks"]
        if not re.fullmatch(r"[0-9a-f]{32}", generation) or type(count) is not int or not 1 <= count <= 10000:
            raise LLMError("invalid_credential_manifest")
        chunks = [self.keyring.get_password(f"SecureIaC.siwc.{generation}.{i}", "record") for i in range(count)]
        if any(c is None for c in chunks):
            raise LLMError("incomplete_credential_record")
        serialized = "".join(chunks)
        if hashlib.sha256(serialized.encode()).hexdigest() != manifest["sha256"]:
            raise LLMError("invalid_credential_record")
        return json.loads(serialized)

    def save(self, data):
        # Small ASCII chunks fit Windows Credential Manager blob limits. Commit the
        # manifest last, so refresh rotates the entire record atomically.
        old = self.keyring.get_password("SecureIaC", "siwc-manifest")
        serialized = json.dumps(data, ensure_ascii=True)
        generation = uuid.uuid4().hex
        chunks = [serialized[i:i+1000] for i in range(0, len(serialized), 1000)]
        written = []
        try:
            for i, chunk in enumerate(chunks):
                service = f"SecureIaC.siwc.{generation}.{i}"
                self.keyring.set_password(service, "record", chunk)
                written.append(service)
            self.keyring.set_password("SecureIaC", "siwc-manifest", json.dumps({"generation": generation,
                "chunks": len(chunks), "sha256": hashlib.sha256(serialized.encode()).hexdigest()}))
        except Exception:
            for service in written:
                self.keyring.delete_password(service, "record")
            raise
        if old:
            prior = json.loads(old)
            if re.fullmatch(r"[0-9a-f]{32}", prior.get("generation", "")) and type(prior.get("chunks")) is int and 0 <= prior["chunks"] <= 10000:
                for i in range(prior["chunks"]):
                    try:
                        self.keyring.delete_password(f"SecureIaC.siwc.{prior['generation']}.{i}", "record")
                    except Exception:
                        pass  # Active manifest already points to the committed record.


class ChatGPTAuth:
    def __init__(self, store=None, http=None):
        if http is None:
            import httpx
            http = httpx.Client(timeout=30, follow_redirects=False)
        self.store = store or CredentialStore()
        self.http = http

    def discovery(self):
        response = self.http.get(ISSUER + "/.well-known/openid-configuration")
        response.raise_for_status()
        data = response.json()
        if data.get("issuer") != ISSUER:
            raise LLMError("invalid_issuer")
        for key in ("jwks_uri", "revocation_endpoint"):
            url = urlsplit(data[key])
            if url.scheme != "https" or url.hostname != "auth.openai.com":
                raise LLMError("invalid_discovery")
        return data

    def validate_tokens(self, tokens, client_id, nonce=None, subject=None):
        import jwt
        metadata = self.discovery()
        jwks = self.http.get(metadata["jwks_uri"])
        jwks.raise_for_status()
        header = jwt.get_unverified_header(tokens["id_token"])
        key_data = next((k for k in jwks.json()["keys"] if k.get("kid") == header.get("kid")), None)
        if not key_data:
            raise LLMError("invalid_signing_key")
        key = jwt.PyJWK.from_dict(key_data).key
        claims = jwt.decode(tokens["id_token"], key, algorithms=["RS256"],
                            issuer=ISSUER, audience=client_id,
                            options={"require": ["exp", "iss", "aud", "sub"]})
        if nonce is not None and (not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(claims["nonce"], nonce)):
            raise LLMError("invalid_nonce")
        if subject is not None and claims["sub"] != subject:
            raise LLMError("account_mismatch")
        if not {"chatgpt.tokens.use.direct", "resource.invoke"} <= set(tokens.get("scope", "").split()):
            raise LLMError("plan_permission_missing")
        if tokens.get("token_type", "").lower() != "bearer":
            raise LLMError("invalid_token_type")
        return claims

    def login(self, account=None):
        data = self.store.load()
        self.store.save(data)  # Persist host identity before first registration.
        existing = data["accounts"].get(account) if account else None
        if account and not existing:
            raise LLMError("unknown_account")
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        result = {}

        class Callback(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                parsed = urlsplit(self.path)
                values = parse_qs(parsed.query)
                if parsed.path != "/auth/callback" or any(len(v) != 1 for v in values.values()) or values.get("state") != [state]:
                    self.send_error(400)
                    return
                result.update({k: v[0] for k, v in values.items()})
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Return to SecureIaC to check sign-in status.")

        with HTTPServer(("127.0.0.1", 0), Callback) as server:
            server.timeout = 1
            redirect = f"http://127.0.0.1:{server.server_port}/auth/callback"
            params = {"client_id": existing["client_id"] if existing else "dynamic_agent_client",
                      "ext_agent_host_id": data["host_id"], "response_type": "code", "redirect_uri": redirect,
                      "scope": SCOPES, "resource": RESOURCE, "state": state, "nonce": nonce,
                      "code_challenge_method": "S256",
                      "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")}
            if existing:
                if existing.get("id_token"):
                    params["id_token_hint"] = existing["id_token"]
            else:
                params["agent_name_hint"] = "SecureIaC"
            if not webbrowser.open(ISSUER + "/api/accounts/authorize?" + urlencode(params)):
                raise LLMError("browser_unavailable")
            deadline = time.monotonic() + 180
            while not result and time.monotonic() < deadline:
                server.handle_request()
        if not result or "error" in result:
            raise LLMError("sign_in_cancelled_or_expired")
        client_id = result.get("client_id", existing["client_id"] if existing else None)
        if not client_id or client_id == "dynamic_agent_client" or (existing and client_id != existing["client_id"]):
            raise LLMError("invalid_client_registration")
        tokens = self._exchange({"grant_type": "authorization_code", "client_id": client_id,
                                 "code": result["code"], "code_verifier": verifier,
                                 "redirect_uri": redirect, "resource": RESOURCE})
        claims = self.validate_tokens(tokens, client_id, nonce, existing["subject"] if existing else None)
        record = {**tokens, "subject": claims["sub"], "email": claims.get("email", ""),
                  "client_id": client_id, "expires_at": time.time() + tokens["expires_in"]}
        data = self.store.load()
        data["accounts"][client_id] = record
        data["active"] = client_id
        self.store.save(data)
        return client_id

    def _exchange(self, fields):
        response = self.http.post(TOKEN_URL, data=fields)
        if response.status_code != 200:
            raise LLMError("session_expired_or_token_exchange_failed")
        return response.json()

    def access_token(self):
        # Cross-process serialization prevents rotating-refresh-token races.
        import tempfile
        from pathlib import Path
        from filelock import FileLock
        with FileLock(str(Path(tempfile.gettempdir()) / "secureiac-siwc-refresh.lock"), timeout=35):
            data = self.store.load()
            record = data["accounts"].get(data["active"])
            if not record or not record.get("access_token"):
                raise LLMError("sign_in_required")
            if record["expires_at"] <= time.time() + 60:
                if record.get("earliest_refresh_at", 0) > time.time():
                    if record["expires_at"] <= time.time():
                        raise LLMError("refresh_not_yet_permitted")
                    return record["access_token"]
                tokens = self._exchange({"grant_type": "refresh_token", "client_id": record["client_id"],
                                         "refresh_token": record["refresh_token"], "resource": RESOURCE})
                if "id_token" in tokens:
                    self.validate_tokens(tokens, record["client_id"], subject=record["subject"])
                if not {"chatgpt.tokens.use.direct", "resource.invoke"} <= set(tokens.get("scope", record["scope"]).split()):
                    raise LLMError("plan_permission_missing")
                record.update(tokens)
                record["expires_at"] = time.time() + tokens["expires_in"]
                self.store.save(data)
            return record["access_token"]

    def accounts(self):
        data = self.store.load()
        return [{"id": key, "email": value["email"], "active": key == data["active"],
                 "signed_in": bool(value.get("access_token"))} for key, value in data["accounts"].items()]

    def select(self, account):
        data = self.store.load()
        if account not in data["accounts"]:
            raise LLMError("unknown_account")
        data["active"] = account
        self.store.save(data)

    def logout(self):
        data = self.store.load()
        record = data["accounts"].get(data["active"])
        confirmed = False
        if record:
            try:
                endpoint = self.discovery()["revocation_endpoint"]
                for attempt in range(2):
                    response = self.http.post(endpoint, data={"token": record.get("refresh_token", ""),
                         "token_type_hint": "refresh_token", "client_id": record["client_id"]})
                    if response.status_code == 200:
                        confirmed = True
                        break
                    if response.status_code < 500:
                        break
                    time.sleep(1)
            except Exception:
                pass
            finally:
                for key in ("access_token", "refresh_token", "id_token"):
                    record.pop(key, None)
                self.store.save(data)
        return confirmed
