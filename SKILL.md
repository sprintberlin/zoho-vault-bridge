---
name: zoho-vault-bridge
description: Access, read, search, create and update passwords and secrets in Zoho Vault via OAuth 2.0 Self Client & REST API with zero-knowledge AES-256 decryption.
---

# Zoho Vault Bridge

A secure, zero-knowledge REST API and OAuth 2.0 bridge for AI agents to interact with Zoho Vault without requiring an MCP server.

Source: [sprintberlin/zoho-vault-bridge](https://github.com/sprintberlin/zoho-vault-bridge)

## Contract

- **Zero-knowledge encryption:** Secrets stored in Zoho Vault are client-side encrypted with AES-256 (PBKDF2 key derivation from Master Passphrase + Org Key RSA). The bridge automatically decrypts secrets locally when `ZOHO_VAULT_PASSPHRASE` is provided.
- **Privacy & Secret Redaction:** Never print, log, or echo plaintext passwords into group chats, logs, or unmasked transcripts unless explicitly requested by the authorized user with confirmation.
- **Self Client OAuth 2.0:** All Zoho Vault REST calls authenticate using long-lived refresh tokens issued to a Zoho API Console Self Client.
- **Multi-Data Center:** Supports EU (`vault.zoho.eu`), US (`vault.zoho.com`), IN (`vault.zoho.in`), AU (`vault.zoho.com.au`), CN (`vault.zoho.com.cn`), and CA (`vault.zoho.ca`).

## Configuration

Required in `.env` (or inherited via environment variables):

| Variable | Description | Example / Default |
|---|---|---|
| `ZOHO_VAULT_CLIENT_ID` | Zoho API Console Self Client ID | `1000.XXXXX...` |
| `ZOHO_VAULT_CLIENT_SECRET` | Zoho API Console Self Client Secret | `xxxx...` |
| `ZOHO_VAULT_REFRESH_TOKEN` | Long-lived OAuth refresh token | `1000.xxxx...` |
| `ZOHO_VAULT_DC` | Zoho Data Center location | `eu` (default), `us`, `in`, `au` |
| `ZOHO_VAULT_PASSPHRASE` | Master Passphrase for zero-knowledge decryption | `YourMasterPassphrase` |

### Required OAuth Scopes (Zoho API Console)

When generating the Self Client Grant Token in the Zoho API Console, include:
```text
ZohoVault.secrets.READ,ZohoVault.secrets.CREATE,ZohoVault.secrets.UPDATE,ZohoVault.secrets.DELETE,ZohoVault.user.READ
```

## Setup & Onboarding

Run the onboarding wizard to exchange a fresh Grant Code for a Refresh Token and store credentials in `.env` (mode 0600):

```bash
python3 scripts/onboarding.py
# Or non-interactively from a file:
python3 scripts/onboarding.py --grant-code-file ./grant.txt
```

## Agent Workflows & Commands

All scripts reside in `scripts/` and can be invoked directly with Python 3:

### 1. List and Search Secrets

```bash
# List all shared secrets (table format)
python3 scripts/vault_list.py

# Search secrets by name
python3 scripts/vault_list.py --search "GitHub"

# Filter by category: ALL_SHARED (default), OWNED_BY_ME, SHARED_TO_ME, PERSONAL, ENTERPRISE
python3 scripts/vault_list.py --filter OWNED_BY_ME

# Machine-readable JSON output
python3 scripts/vault_list.py --search "Stripe" --json
```

### 2. Retrieve a Secret / Password

```bash
# Get details with masked password
python3 scripts/vault_get.py <SECRET_ID>

# Reveal plaintext password
python3 scripts/vault_get.py <SECRET_ID> --show-password

# Output full JSON
python3 scripts/vault_get.py <SECRET_ID> --show-password --json
```

### 3. Create a Secret / Password (experimental)

```bash
# Create a new secret
python3 scripts/vault_create.py \
  --name "Staging DB" \
  --username "dbadmin" \
  --password "SecureP@ss2026!" \
  --url "https://db.internal.net" \
  --notes "Production replica"

# Create a personal (non-shared) secret
python3 scripts/vault_create.py \
  --name "Personal Key" \
  --password "Secret123" \
  --personal
```

### 4. Update an Existing Secret (experimental)

```bash
# Update password for a secret
python3 scripts/vault_update.py <SECRET_ID> --password "NewP@ssw0rd2026!"

# Update username and URL
python3 scripts/vault_update.py <SECRET_ID> --username "new-user" --url "https://app.example.com"
```

### 5. Delete a Secret (experimental)

```bash
# Delete secret with confirmation
python3 scripts/vault_delete.py <SECRET_ID>

# Delete non-interactively
python3 scripts/vault_delete.py <SECRET_ID> --yes
```

## Programmatic Python API

For embedding into custom agents or scripts:

```python
from bridge import ZohoVaultBridge

bridge = ZohoVaultBridge()

# List secrets
secrets = bridge.list_secrets(search="Hetzner")

# Get decrypted secret (never print the password unless explicitly requested)
secret = bridge.get_secret(secret_id="<SECRET_ID>")
```

Create, update and delete are experimental and not yet verified against a live vault. Run them only on a throwaway entry and with explicit approval.
