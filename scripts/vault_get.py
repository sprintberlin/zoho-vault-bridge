#!/usr/bin/env python3
"""
CLI tool: Retrieve a single secret/password from Zoho Vault.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from bridge import ZohoVaultBridge, ZohoVaultBridgeError


def main():
    parser = argparse.ArgumentParser(description="Get a secret from Zoho Vault by ID.")
    parser.add_argument("secret_id", help="The Zoho Vault secret ID")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--show-password", action="store_true", help="Show the plaintext password in stdout")
    parser.add_argument("--no-decrypt", action="store_true", help="Skip decryption")
    args = parser.parse_args()

    try:
        bridge = ZohoVaultBridge()
        secret = bridge.get_secret(args.secret_id, decrypt=not args.no_decrypt)

        if args.json:
            # If not --show-password, mask the password in JSON output for safety
            if not args.show_password and "secretDataDecrypted" in secret:
                secret_copy = dict(secret)
                data_copy = dict(secret_copy["secretDataDecrypted"])
                if "password" in data_copy:
                    data_copy["password"] = "******** [pass --show-password to reveal]"
                secret_copy["secretDataDecrypted"] = data_copy
                print(json.dumps(secret_copy, indent=2))
            else:
                print(json.dumps(secret, indent=2))
            return

        sid = str(secret.get("secretid") or args.secret_id)
        name = secret.get("secretname") or secret.get("decsecretname") or "<unnamed>"
        sec_data = secret.get("secretDataDecrypted") or {}
        uname = sec_data.get("username") or ""
        pwd = sec_data.get("password") or ""
        notes = secret.get("notesDecrypted") or secret.get("notes") or ""
        url = secret.get("secreturl") or ""

        print(f"Secret ID: {sid}")
        print(f"Name:      {name}")
        print(f"URL:       {url}")
        print(f"Username:  {uname}")
        if args.show_password:
            print(f"Password:  {pwd}")
        else:
            print(f"Password:  {'*' * 8} (use --show-password to reveal)")
        if notes:
            print(f"Notes:     {notes}")

    except ZohoVaultBridgeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
