#!/usr/bin/env python3
"""
CLI tool: Update an existing secret/password in Zoho Vault.
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
    parser = argparse.ArgumentParser(description="Update an existing secret in Zoho Vault.")
    parser.add_argument("secret_id", help="The Zoho Vault secret ID to update")
    parser.add_argument("--name", "-n", help="New secret name")
    parser.add_argument("--username", "-u", help="New username")
    parser.add_argument("--password", "-p", help="New password (pass '-' to prompt securely)")
    parser.add_argument("--url", help="New service URL")
    parser.add_argument("--notes", help="New notes text")
    args = parser.parse_args()

    password = args.password
    if password == "-":
        password = getpass.getpass("Enter new password: ")

    if not any([args.name, args.username, password is not None, args.url, args.notes]):
        print("Nothing to update. Specify at least one of --name, --username, --password, --url, or --notes.", file=sys.stderr)
        sys.exit(1)

    try:
        bridge = ZohoVaultBridge()
        resp = bridge.update_secret(
            secret_id=args.secret_id,
            name=args.name,
            username=args.username,
            password=password,
            url=args.url,
            notes=args.notes,
        )
        print(f"Secret {args.secret_id} updated successfully.")
        print(json.dumps(resp, indent=2))
    except ZohoVaultBridgeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
