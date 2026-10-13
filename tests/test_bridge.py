#!/usr/bin/env python3
"""
Unit tests for ZohoVaultBridge core logic, DC resolution and request structures.
"""

import unittest
from pathlib import Path
import sys

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


if __name__ == "__main__":
    unittest.main()
