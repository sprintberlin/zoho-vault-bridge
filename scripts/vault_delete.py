#!/usr/bin/env python3
"""
CLI tool: Delete a secret from Zoho Vault.
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
    parser = argparse.ArgumentParser(description="Delete a secret from Zoho Vault.")
    parser.add_argument("secret_id", help="The Zoho Vault secret ID to delete")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip interactive confirmation")
    args = parser.parse_args()

    if not args.yes:
        confirm = input(f"Are you sure you want to delete secret {args.secret_id}? (yes/no): ")
        if confirm.lower() not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    try:
        bridge = ZohoVaultBridge()
        resp = bridge.delete_secret(args.secret_id)
        print(f"Secret {args.secret_id} deleted.")
        print(json.dumps(resp, indent=2))
    except ZohoVaultBridgeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
