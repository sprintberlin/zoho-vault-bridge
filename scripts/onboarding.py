#!/usr/bin/env python3
"""
Zoho Vault Bridge — Interactive Self Client Onboarding.

Walks through exchanging an authorization grant code for a long-lived refresh token
and safely writes credentials to an env file with 0600 permissions.

Usage:
    python3 scripts/onboarding.py [--env-file .env]
    python3 scripts/onboarding.py --grant-code-file ./grant.txt
    python3 scripts/onboarding.py --grant-code-file -   # read grant code from stdin
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import stat
import sys
import urllib.parse
import urllib.request
import urllib.error

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from bridge import DC_ACCOUNTS


def parse_args(args=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive onboarding for Zoho Vault Bridge Self Client credentials."
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to the .env file to update (default: .env)",
    )
    parser.add_argument(
        "--grant-code",
        default=None,
        help="Grant code from the Zoho API Console. Prefer --grant-code-file so the code is not stored in shell history.",
    )
    parser.add_argument(
        "--grant-code-file",
        default=None,
        help="Read the grant code from a file, or '-' for stdin.",
    )
    return parser.parse_args(args)


def prompt_input(prompt_text: str, default: str = "") -> str:
    if default:
        full_prompt = f"{prompt_text} [{default}]: "
    else:
        full_prompt = f"{prompt_text}: "
    val = input(full_prompt).strip()
    return val if val else default


def prompt_secret(prompt_text: str) -> str:
    try:
        return getpass.getpass(f"{prompt_text}: ").strip()
    except (EOFError, getpass.GetPassWarning, Exception):
        return input(f"{prompt_text}: ").strip()


def exchange_grant_token(client_id: str, client_secret: str, code: str, dc: str = "eu") -> dict:
    accounts_url = DC_ACCOUNTS.get(dc.lower(), DC_ACCOUNTS["eu"])
    token_url = f"{accounts_url}/oauth/v2/token"
    params = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
    }
    data = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(token_url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        raise RuntimeError(f"OAuth token exchange failed (HTTP {e.code}): {err}")


def update_env_file(env_path: Path, updates: dict[str, str]) -> None:
    lines = []
    existing_keys = set()
    if env_path.is_file():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    key = stripped.split("=", 1)[0].strip()
                    if key in updates:
                        lines.append(f"{key}={updates[key]}\n")
                        existing_keys.add(key)
                        continue
                lines.append(line)

    for k, v in updates.items():
        if k not in existing_keys:
            lines.append(f"{k}={v}\n")

    env_path.parent.mkdir(parents=True, exist_ok=True)
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def main(cli_args=None) -> int:
    args = parse_args(cli_args)

    print("======================================================")
    print("        Zoho Vault Bridge — Self Client Setup         ")
    print("======================================================\n")
    print("This utility exchanges a Self Client grant token for a refresh token")
    print("and safely saves credentials to your .env file.\n")

    # 1. Data Center
    dc_input = prompt_input("Enter Data Center (eu, us, in, au, com.cn, ca)", default="eu").lower().strip()
    if dc_input not in DC_ACCOUNTS:
        print(f"Unknown DC: {dc_input}. Defaulting to 'eu'.")
        dc_input = "eu"

    # 2. Client ID & Secret
    client_id = prompt_input("Enter Self Client ID")
    if not client_id:
        print("Error: Client ID is required.", file=sys.stderr)
        return 1

    client_secret = prompt_secret("Enter Self Client Secret")
    if not client_secret:
        print("Error: Client Secret is required.", file=sys.stderr)
        return 1

    # 3. Grant Code
    print("\nIn Zoho API Console -> Self Client -> Generate Code:")
    print("Required scopes for Zoho Vault:")
    print("  ZohoVault.secrets.READ,ZohoVault.secrets.CREATE,ZohoVault.secrets.UPDATE,ZohoVault.secrets.DELETE,ZohoVault.user.READ")
    print("Scope duration: 10 minutes.")

    grant_code = None
    if args.grant_code_file:
        if args.grant_code_file == "-":
            grant_code = sys.stdin.read().strip()
        else:
            p = Path(args.grant_code_file)
            if not p.is_file():
                print(f"Error: Grant code file not found: {p}", file=sys.stderr)
                return 1
            grant_code = p.read_text(encoding="utf-8").strip()
    elif args.grant_code:
        grant_code = args.grant_code.strip()
    else:
        grant_code = prompt_input("Enter generated Grant Code")

    if not grant_code:
        print("Error: Grant Code is required.", file=sys.stderr)
        return 1

    # 4. Exchange
    print(f"\nExchanging grant code with {DC_ACCOUNTS[dc_input]}...")
    try:
        token_data = exchange_grant_token(client_id, client_secret, grant_code, dc_input)
    except Exception as e:
        print(f"Error exchanging grant token: {e}", file=sys.stderr)
        return 1

    refresh_token = token_data.get("refresh_token")
    if not refresh_token:
        print(f"Error: No refresh token returned. Response: {token_data}", file=sys.stderr)
        return 1

    print("Grant token exchanged successfully.")

    # 5. Master Passphrase
    print("\nZoho Vault uses zero-knowledge encryption for secret data (passwords, usernames).")
    print("To allow the bridge to decrypt and update passwords, specify your Master Passphrase.")
    passphrase = prompt_secret("Enter Zoho Vault Master Passphrase (leave empty to skip)")

    updates = {
        "ZOHO_VAULT_CLIENT_ID": client_id,
        "ZOHO_VAULT_CLIENT_SECRET": client_secret,
        "ZOHO_VAULT_REFRESH_TOKEN": refresh_token,
        "ZOHO_VAULT_DC": dc_input,
    }
    if passphrase:
        updates["ZOHO_VAULT_PASSPHRASE"] = passphrase

    env_path = Path(args.env_file).resolve()
    print(f"\nWriting credentials to {env_path} (mode 0600)...")
    try:
        update_env_file(env_path, updates)
        print("Credentials saved successfully.")
    except Exception as e:
        print(f"Error saving to env file: {e}", file=sys.stderr)
        return 1

    print("\nSetup completed!")
    print("Test with: python3 scripts/vault_list.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
