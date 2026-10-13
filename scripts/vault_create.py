#!/usr/bin/env python3
"""
CLI tool: Create a new secret/password in Zoho Vault.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from bridge import ZohoVaultBridge, ZohoVaultBridgeError


def main():
    parser = argparse.ArgumentParser(description="Create a new secret in Zoho Vault.")
    parser.add_argument("--name", "-n", required=True, help="Secret / Password Name")
    parser.add_argument("--username", "-u", help="Username / Login name")
    parser.add_argument("--password", "-p", help="Password (prompted securely if not provided)")
    parser.add_argument("--url", help="Service or website URL")
    parser.add_argument("--notes", help="Secure note text")
    parser.add_argument("--chamber-id", "-c", help="Target folder (chamber) ID")
    parser.add_argument("--personal", action="store_true", help="Store as personal secret instead of shared org secret")
    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Enter password for new secret: ")

    try:
        bridge = ZohoVaultBridge()
        resp = bridge.create_secret(
            name=args.name,
            username=args.username,
            password=password,
            url=args.url,
            notes=args.notes,
            chamber_id=args.chamber_id,
            is_shared=not args.personal,
        )
        print("Secret created successfully.")
        print(json.dumps(resp, indent=2))
    except ZohoVaultBridgeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
