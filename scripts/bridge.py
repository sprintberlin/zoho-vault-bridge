#!/usr/bin/env python3
"""
Zoho Vault Bridge — REST API & OAuth 2.0 Client.
Provides secure programmatic access to Zoho Vault secrets, folders, and credentials
for AI agents and automated workflows without requiring an MCP server.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request
import urllib.error

SCRIPT_DIR = Path(__file__).resolve().parent
CRYPTO_HELPER = SCRIPT_DIR / "crypto_helper.js"

# Data center URLs
DC_ACCOUNTS = {
    "eu": "https://accounts.zoho.eu",
    "us": "https://accounts.zoho.com",
    "com": "https://accounts.zoho.com",
    "in": "https://accounts.zoho.in",
    "au": "https://accounts.zoho.com.au",
    "com.au": "https://accounts.zoho.com.au",
    "cn": "https://accounts.zoho.com.cn",
    "com.cn": "https://accounts.zoho.com.cn",
    "ca": "https://accounts.zoho.ca",
}

DC_VAULT = {
    "eu": "https://vault.zoho.eu",
    "us": "https://vault.zoho.com",
    "com": "https://vault.zoho.com",
    "in": "https://vault.zoho.in",
    "au": "https://vault.zoho.com.au",
    "com.au": "https://vault.zoho.com.au",
    "cn": "https://vault.zoho.com.cn",
    "com.cn": "https://vault.zoho.com.cn",
    "ca": "https://vault.zoho.ca",
}


def load_env_file(path: Path) -> Dict[str, str]:
    """Parse a .env file safely without third-party dependencies."""
    env = {}
    if not path.is_file():
        return env
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key:
                    env[key] = val
    return env


class ZohoVaultBridgeError(Exception):
    """Base exception for Zoho Vault Bridge operations."""
    pass


class ZohoVaultBridge:
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        refresh_token: Optional[str] = None,
        dc: str = "eu",
        passphrase: Optional[str] = None,
        env_file: Optional[Path] = None,
    ):
        # Load from file if provided or if .env exists in project root
        file_env = {}
        if env_file and env_file.is_file():
            file_env = load_env_file(env_file)
        else:
            default_dotenv = SCRIPT_DIR.parent / ".env"
            if default_dotenv.is_file():
                file_env = load_env_file(default_dotenv)

        def get_val(key: str, default: Optional[str] = None) -> Optional[str]:
            return os.environ.get(key) or file_env.get(key) or default

        self.client_id = client_id if client_id is not None else (get_val("ZOHO_VAULT_CLIENT_ID") or get_val("ZOHO_BRIDGE_CLIENT_ID"))
        self.client_secret = client_secret if client_secret is not None else (get_val("ZOHO_VAULT_CLIENT_SECRET") or get_val("ZOHO_BRIDGE_CLIENT_SECRET"))
        self.refresh_token = refresh_token if refresh_token is not None else (get_val("ZOHO_VAULT_REFRESH_TOKEN") or get_val("ZOHO_BRIDGE_REFRESH_TOKEN"))
        self.dc = (dc if dc is not None else (get_val("ZOHO_VAULT_DC") or get_val("ZOHO_BRIDGE_DC") or "eu")).lower()
        self.passphrase = passphrase if passphrase is not None else get_val("ZOHO_VAULT_PASSPHRASE")

        self.accounts_url = DC_ACCOUNTS.get(self.dc, DC_ACCOUNTS["eu"])
        self.vault_url = DC_VAULT.get(self.dc, DC_VAULT["eu"])

        self._access_token: Optional[str] = None
        self._access_token_expires_at: float = 0.0

        # Cryptographic session caches
        self._master_key: Optional[str] = None
        self._org_key: Optional[str] = None
        self._user_config: Optional[Dict[str, Any]] = None

    def _refresh_access_token(self) -> str:
        """Exchange the refresh token for a fresh access token."""
        if not (self.client_id and self.client_secret and self.refresh_token):
            raise ZohoVaultBridgeError(
                "Missing OAuth credentials. Set ZOHO_VAULT_CLIENT_ID, ZOHO_VAULT_CLIENT_SECRET, and ZOHO_VAULT_REFRESH_TOKEN."
            )

        token_url = f"{self.accounts_url}/oauth/v2/token"
        params = {
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
        }
        data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request(token_url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urllib.request.urlopen(req) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8")
            raise ZohoVaultBridgeError(f"OAuth token refresh failed (HTTP {e.code}): {err_msg}")
        except Exception as e:
            raise ZohoVaultBridgeError(f"OAuth token refresh failed: {e}")

        if "error" in result:
            raise ZohoVaultBridgeError(f"OAuth error: {result.get('error')}")

        access_token = result.get("access_token")
        expires_in = result.get("expires_in", 3600)
        if not access_token:
            raise ZohoVaultBridgeError(f"No access_token in token response: {result}")

        self._access_token = access_token
        self._access_token_expires_at = time.time() + float(expires_in) - 60.0  # 60s safety buffer
        return access_token

    def get_access_token(self) -> str:
        """Return a valid access token, refreshing if necessary."""
        if not self._access_token or time.time() >= self._access_token_expires_at:
            return self._refresh_access_token()
        return self._access_token

    def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        form_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute an authenticated REST API call to Zoho Vault."""
        token = self.get_access_token()
        url = f"{self.vault_url}{endpoint}"
        if params:
            query = urllib.parse.urlencode(params)
            url = f"{url}?{query}"

        body_bytes = None
        content_type = "application/json;charset=UTF-8"

        if form_data is not None:
            body_bytes = urllib.parse.urlencode(form_data).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"
        elif json_data is not None:
            body_bytes = json.dumps(json_data).encode("utf-8")
            content_type = "application/json;charset=UTF-8"

        req = urllib.request.Request(url, data=body_bytes, method=method)
        req.add_header("Authorization", f"Zoho-oauthtoken {token}")
        req.add_header("Content-Type", content_type)
        req.add_header("User-Agent", "ZohoVaultBridge/0.1.0")

        try:
            with urllib.request.urlopen(req) as resp:
                raw_response = resp.read().decode("utf-8")
                try:
                    return json.loads(raw_response)
                except json.JSONDecodeError:
                    return {"raw_text": raw_response}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            raise ZohoVaultBridgeError(f"Zoho Vault API error {e.code} on {method} {endpoint}: {err_body}")
        except Exception as e:
            raise ZohoVaultBridgeError(f"Zoho Vault API network error on {method} {endpoint}: {e}")

    # -------------------------------------------------------------------------
    # Cryptographic & Zero-Knowledge Handlers
    # -------------------------------------------------------------------------

    def _call_crypto_helper(self, action: str, *args, stdin_json: Optional[Any] = None) -> Any:
        """Invoke crypto_helper.js with arguments or JSON on stdin."""
        cmd = ["node", str(CRYPTO_HELPER), action] + list(args)
        stdin_data = json.dumps(stdin_json) if stdin_json is not None else None

        res = subprocess.run(
            cmd,
            input=stdin_data,
            text=True,
            capture_output=True,
        )
        if res.returncode != 0:
            raise ZohoVaultBridgeError(f"Crypto helper error: {res.stderr.strip() or res.stdout.strip()}")

        try:
            output = json.loads(res.stdout)
        except json.JSONDecodeError:
            raise ZohoVaultBridgeError(f"Crypto helper returned non-JSON: {res.stdout}")

        if output.get("status") == "error":
            raise ZohoVaultBridgeError(f"Crypto helper failed: {output.get('error')}")

        return output

    def get_user_config(self) -> Dict[str, Any]:
        """Fetch zero-knowledge encryption parameters (salt, iterations, passauth)."""
        if self._user_config:
            return self._user_config

        # Endpoint: POST /api/json/login with OPERATION_NAME: GET_LOGIN
        resp = self._api_request(
            "/api/json/login",
            method="POST",
            form_data={"OPERATION_NAME": "GET_LOGIN"},
        )
        operation = resp.get("operation", {})
        details = operation.get("details", {})
        if not details:
            raise ZohoVaultBridgeError(f"Failed to retrieve user login config: {resp}")

        self._user_config = details
        return details

    def get_master_key(self) -> Optional[str]:
        """Derive the Master Key from the passphrase and user config salt/iterations."""
        if self._master_key:
            return self._master_key

        if not self.passphrase:
            return None

        config = self.get_user_config()
        salt = config.get("SALT")
        iteration = config.get("ITERATION", 1000)
        passauth = config.get("PASSPHRASE")

        if not (salt and iteration):
            raise ZohoVaultBridgeError("Vault user config missing SALT or ITERATION.")

        res = self._call_crypto_helper("derive", self.passphrase, str(salt), str(iteration))
        derived_key = res.get("key")

        # Validate master key against passauth
        if passauth:
            check_res = self._call_crypto_helper("check_login", passauth, derived_key)
            if not check_res.get("valid"):
                raise ZohoVaultBridgeError("Master passphrase validation failed! Check ZOHO_VAULT_PASSPHRASE.")

        self._master_key = derived_key
        return derived_key

    def get_org_key(self) -> Optional[str]:
        """Retrieve and decrypt the Organization Key for shared secrets."""
        if self._org_key:
            return self._org_key

        master_key = self.get_master_key()
        if not master_key:
            return None

        # Fetch RSA-encrypted org key details
        resp = self._api_request("/api/rest/json/v1/user/orgkey", method="GET")
        details = resp.get("operation", {}).get("Details", {})
        enc_private_key = details.get("privateKey")
        shared_key = details.get("sharedKey")
        rsa_key_type = details.get("rsaKeyType", "RSA_4096")

        if not (enc_private_key and shared_key):
            # Not an enterprise org or no shared key configured
            return None

        if rsa_key_type != "RSA_4096":
            raise ZohoVaultBridgeError(
                f"Unsupported RSA key type {rsa_key_type!r}; only RSA_4096 is implemented."
            )

        # Decrypt private key with Master Key (AES). Zoho returns base64 PKCS#8 DER.
        res_priv = self._call_crypto_helper("decrypt", enc_private_key, master_key)
        private_key_b64 = res_priv.get("plaintext")

        # Decrypt sharedKey with RSA-OAEP (SHA-256), as the official zv CLI does.
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization
        import base64

        try:
            priv_key = serialization.load_der_private_key(base64.b64decode(private_key_b64), password=None)
            ciphertext = base64.b64decode(shared_key)
            decrypted_org_key = priv_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            ).decode("utf-8")
            self._org_key = decrypted_org_key
            return decrypted_org_key
        except Exception as e:
            raise ZohoVaultBridgeError(f"Failed to decrypt Organization Key: {type(e).__name__}")

    def decrypt_secret(self, secret: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt all sensitive fields in a secret object using the appropriate key."""
        is_shared = secret.get("isshared") == "YES"
        key = self.get_org_key() if is_shared else self.get_master_key()

        if not key:
            secret["_decrypted"] = False
            secret["_decryption_notice"] = "Passphrase not provided or key derivation unavailable"
            return secret

        secret_copy = dict(secret)
        raw_secret_data = secret.get("secretData")

        if raw_secret_data:
            res = self._call_crypto_helper("decrypt_secret_data", stdin_json={"secretData": raw_secret_data, "key": key})
            secret_copy["secretDataDecrypted"] = res.get("decrypted", {})

        # Decrypt notes if present
        notes = secret.get("notes")
        if notes and isinstance(notes, str) and len(notes) > 0:
            res_note = self._call_crypto_helper("decrypt", notes, key)
            secret_copy["notesDecrypted"] = res_note.get("plaintext", "")

        secret_copy["_decrypted"] = True
        return secret_copy

    # -------------------------------------------------------------------------
    # High-Level Vault Operations
    # -------------------------------------------------------------------------

    def list_secrets(
        self,
        filter_type: str = "ALL_SHARED",
        search: Optional[str] = None,
        chamber_id: Optional[str] = None,
        page: int = 1,
        limit: int = 50,
        decrypt: bool = True,
    ) -> List[Dict[str, Any]]:
        """List secrets with optional filtering and automatic decryption."""
        params = {
            "pageNum": str(page),
            "rowPerPage": str(limit),
            "isAsc": "true",
            "filter": filter_type,
        }
        if search:
            params["passwordName"] = search
        if chamber_id:
            params["chamberId"] = chamber_id

        resp = self._api_request("/api/rest/json/v1/secrets", method="GET", params=params)
        details = resp.get("operation", {}).get("Details", [])
        if not isinstance(details, list):
            return []

        if decrypt and self.passphrase:
            return [self.decrypt_secret(s) for s in details]
        return details

    def get_secret(self, secret_id: str, decrypt: bool = True) -> Dict[str, Any]:
        """Retrieve a single secret by its ID."""
        resp = self._api_request(f"/api/rest/json/v1/secrets/{secret_id}", method="GET")
        details = resp.get("operation", {}).get("Details", [])
        if isinstance(details, list) and len(details) > 0:
            secret = details[0]
        elif isinstance(details, dict):
            secret = details
        else:
            raise ZohoVaultBridgeError(f"Secret {secret_id} not found in response: {resp}")

        if decrypt and self.passphrase:
            return self.decrypt_secret(secret)
        return secret

    def create_secret(
        self,
        name: str,
        secret_type_id: str = "1000000000015",  # Default Web Account type
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        chamber_id: Optional[str] = None,
        is_shared: bool = True,
    ) -> Dict[str, Any]:
        """Create a new secret in Zoho Vault with client-side zero-knowledge encryption."""
        key = self.get_org_key() if is_shared else self.get_master_key()
        if not key:
            raise ZohoVaultBridgeError("Cannot create secret: Master Passphrase required for encryption.")

        raw_secret_data = {}
        if username:
            raw_secret_data["username"] = username
        if password:
            raw_secret_data["password"] = password

        enc_secret_res = self._call_crypto_helper("encrypt_secret_data", stdin_json={"secretData": raw_secret_data, "key": key})
        enc_secret_data = enc_secret_res.get("encrypted", {})

        payload: Dict[str, Any] = {
            "secretname": name,
            "secrettypeid": str(secret_type_id),
            "isshared": "YES" if is_shared else "NO",
            "secretdata": enc_secret_data,
        }
        if url:
            payload["secreturls"] = [url]
        if notes:
            enc_notes_res = self._call_crypto_helper("encrypt", notes, key)
            payload["securenote"] = enc_notes_res.get("ciphertext", "")
        if chamber_id:
            payload["chamberid"] = str(chamber_id)

        resp = self._api_request("/api/rest/json/v1/secrets", method="POST", json_data=payload)
        return resp

    def update_secret(
        self,
        secret_id: str,
        name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an existing secret (e.g. changing password or username)."""
        existing = self.get_secret(secret_id, decrypt=True)
        is_shared = existing.get("isshared") == "YES"
        key = self.get_org_key() if is_shared else self.get_master_key()

        if not key:
            raise ZohoVaultBridgeError("Cannot update secret: Master Passphrase required for encryption.")

        # Merge secretData
        current_data = existing.get("secretDataDecrypted") or {}
        new_data = dict(current_data)
        if username is not None:
            new_data["username"] = username
        if password is not None:
            new_data["password"] = password

        enc_res = self._call_crypto_helper("encrypt_secret_data", stdin_json={"secretData": new_data, "key": key})
        enc_data = enc_res.get("encrypted", {})

        payload: Dict[str, Any] = {
            "secertdata": enc_data,
            "secretname": name or existing.get("secretname") or existing.get("decsecretname"),
            "secrettypeid": existing.get("accounttype") or existing.get("secrettypeid"),
        }
        if url is not None:
            payload["secreturl"] = url
            payload["secreters"] = [url]
        if notes is not None:
            enc_notes = self._call_crypto_helper("encrypt", notes, key).get("ciphertext")
            payload["securenote"] = enc_notes

        resp = self._api_request(f"/api/rest/json/v1/secrets/{secret_id}", method="PUT", json_data=payload)
        return resp

    def delete_secret(self, secret_id: str) -> Dict[str, Any]:
        """Delete a secret from Zoho Vault."""
        return self._api_request(f"/api/rest/json/v1/secrets/{secret_id}", method="DELETE")

    def list_chambers(self) -> List[Dict[str, Any]]:
        """List all chambers (folders) in Zoho Vault."""
        resp = self._api_request("/api/rest/json/v1/chambers", method="GET")
        details = resp.get("operation", {}).get("Details", [])
        return details if isinstance(details, list) else []
