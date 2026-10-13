#!/usr/bin/env python3
"""
CLI tool: List and search secrets in Zoho Vault.
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
    parser = argparse.ArgumentParser(description="List and search Zoho Vault secrets.")
    parser.add_argument("--search", "-s", help="Filter by password name")
    parser.add_argument("--filter", "-f", default="ALL_SHARED", help="Filter category: ALL_SHARED (default), OWNED_BY_ME, SHARED_TO_ME, PERSONAL, ENTERPRISE")
    parser.add_argument("--chamber-id", "-c", help="Folder (chamber) ID")
    parser.add_argument("--limit", "-l", type=int, default=50, help="Max items to fetch (default: 50)")
    parser.add_argument("--page", "-p", type=int, default=0, help="Zero-based page number (default: 0)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--no-decrypt", action="store_true", help="Do not attempt zero-knowledge decryption")
    args = parser.parse_args()

    try:
        bridge = ZohoVaultBridge()
        secrets = bridge.list_secrets(
            filter_type=args.filter,
            search=args.search,
            chamber_id=args.chamber_id,
            page=args.page,
            limit=args.limit,
            decrypt=not args.no_decrypt,
        )

        if args.json:
            print(json.dumps(secrets, indent=2))
            return

        print(f"Found {len(secrets)} secrets:")
        print(f"{'ID':<18} | {'NAME':<30} | {'USERNAME':<25} | {'URL'}")
        print("-" * 95)
        for s in secrets:
            sid = str(s.get("secretid") or s.get("secret_auto_id") or "")
            name = s.get("secretname") or s.get("decsecretname") or "<unnamed>"
            sec_data = s.get("secretDataDecrypted") or {}
            uname = sec_data.get("username") or ""
            url = s.get("secreturl") or ""
            print(f"{sid:<18} | {name[:30]:<30} | {uname[:25]:<25} | {url[:30]}")

    except ZohoVaultBridgeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
