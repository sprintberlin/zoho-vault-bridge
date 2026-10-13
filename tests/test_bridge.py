#!/usr/bin/env python3
"""
Unit tests for ZohoVaultBridge core logic, DC resolution and request structures.
"""

import base64
import unittest
from pathlib import Path
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from bridge import ZohoVaultBridge, DC_ACCOUNTS, DC_VAULT


class TestZohoVaultBridge(unittest.TestCase):
    def test_dc_resolution(self):
        bridge_eu = ZohoVaultBridge(dc="eu", client_id="test", client_secret="test", refresh_token="test")
        self.assertEqual(bridge_eu.accounts_url, "https://accounts.zoho.eu")
        self.assertEqual(bridge_eu.vault_url, "https://vault.zoho.eu")

        bridge_us = ZohoVaultBridge(dc="us", client_id="test", client_secret="test", refresh_token="test")
        self.assertEqual(bridge_us.accounts_url, "https://accounts.zoho.com")
        self.assertEqual(bridge_us.vault_url, "https://vault.zoho.com")

        bridge_in = ZohoVaultBridge(dc="in", client_id="test", client_secret="test", refresh_token="test")
        self.assertEqual(bridge_in.accounts_url, "https://accounts.zoho.in")
        self.assertEqual(bridge_in.vault_url, "https://vault.zoho.in")

    def test_missing_credentials_raises(self):
        bridge = ZohoVaultBridge(client_id="", client_secret="", refresh_token="")
        with self.assertRaises(Exception):
            bridge._refresh_access_token()

    def test_list_defaults_to_zero_based_page(self):
        bridge = ZohoVaultBridge(client_id="test", client_secret="test", refresh_token="test")
        seen = []
        def api_request(endpoint, **kwargs):
            seen.append((endpoint, kwargs))
            return {"operation": {"Details": [{"secretid": "example"}]}}
        bridge._api_request = api_request
        result = bridge.list_secrets(decrypt=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(seen[0][1]["params"]["pageNum"], "0")
        bridge.list_secrets(page=2, decrypt=False)
        self.assertEqual(seen[1][1]["params"]["pageNum"], "2")

    def test_rsa_4096_org_key_uses_pkcs8_der_and_oaep_sha256(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        org_key = "test-organization-key"
        encrypted_org_key = private_key.public_key().encrypt(
            org_key.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        bridge = ZohoVaultBridge(client_id="test", client_secret="test", refresh_token="test")
        bridge.get_master_key = lambda: "synthetic-master-key"
        bridge._api_request = lambda *args, **kwargs: {
            "operation": {"Details": {
                "privateKey": "synthetic-ciphertext",
                "sharedKey": base64.b64encode(encrypted_org_key).decode(),
                "rsaKeyType": "RSA_4096",
            }}
        }
        bridge._call_crypto_helper = lambda *args, **kwargs: {
            "plaintext": base64.b64encode(private_der).decode()
        }
        self.assertEqual(bridge.get_org_key(), org_key)
        self.assertEqual(bridge.get_org_key(), org_key)  # cached

    def test_unsupported_rsa_type_fails_closed(self):
        bridge = ZohoVaultBridge(client_id="test", client_secret="test", refresh_token="test")
        bridge.get_master_key = lambda: "synthetic-master-key"
        bridge._api_request = lambda *args, **kwargs: {
            "operation": {"Details": {
                "privateKey": "synthetic-ciphertext",
                "sharedKey": "synthetic-ciphertext",
                "rsaKeyType": "RSA_1024",
            }}
        }
        with self.assertRaisesRegex(Exception, "Unsupported RSA key type"):
            bridge.get_org_key()


if __name__ == "__main__":
    unittest.main()
