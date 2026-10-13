#!/usr/bin/env python3
"""
Unit tests for crypto helper and Zoho Vault zero-knowledge encryption routines.
"""

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRYPTO_HELPER = ROOT / "scripts" / "crypto_helper.js"


class TestCryptoHelper(unittest.TestCase):
    def test_encrypt_decrypt_text(self):
        plaintext = "MySecretVaultPassword2026!"
        key = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

        # Encrypt
        res = subprocess.run(
            ["node", str(CRYPTO_HELPER), "encrypt", plaintext, key],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(res.stdout)
        self.assertEqual(data.get("status"), "ok")
        ciphertext = data.get("ciphertext")
        self.assertTrue(len(ciphertext) > 0)

        # Decrypt
        res_dec = subprocess.run(
            ["node", str(CRYPTO_HELPER), "decrypt", ciphertext, key],
            capture_output=True,
            text=True,
            check=True,
        )
        data_dec = json.loads(res_dec.stdout)
        self.assertEqual(data_dec.get("status"), "ok")
        self.assertEqual(data_dec.get("plaintext"), plaintext)

    def test_derive_key(self):
        passphrase = "MasterPassphrase123"
        salt = "somesalt12345678"
        iterations = "1000"

        res = subprocess.run(
            ["node", str(CRYPTO_HELPER), "derive", passphrase, salt, iterations],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(res.stdout)
        self.assertEqual(data.get("status"), "ok")
        key = data.get("key")
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 64)  # 32 bytes hex = 64 chars

    def test_encrypt_decrypt_secret_data(self):
        raw_secret_data = {
            "username": "admin@example.com",
            "password": "CorrectHorseBatteryStaple",
        }
        key = "testkey1234567890123456789012345"

        # Encrypt
        enc_res = subprocess.run(
            ["node", str(CRYPTO_HELPER), "encrypt_secret_data"],
            input=json.dumps({"secretData": raw_secret_data, "key": key}),
            capture_output=True,
            text=True,
            check=True,
        )
        enc_data = json.loads(enc_res.stdout)
        self.assertEqual(enc_data.get("status"), "ok")
        encrypted_obj = enc_data.get("encrypted")
        self.assertNotEqual(encrypted_obj["username"], raw_secret_data["username"])
        self.assertNotEqual(encrypted_obj["password"], raw_secret_data["password"])

        # Decrypt
        dec_res = subprocess.run(
            ["node", str(CRYPTO_HELPER), "decrypt_secret_data"],
            input=json.dumps({"secretData": encrypted_obj, "key": key}),
            capture_output=True,
            text=True,
            check=True,
        )
        dec_data = json.loads(dec_res.stdout)
        self.assertEqual(dec_data.get("status"), "ok")
        self.assertEqual(dec_data.get("decrypted"), raw_secret_data)


if __name__ == "__main__":
    unittest.main()
