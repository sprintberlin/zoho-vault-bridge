# Zoho Vault Bridge

Agent skill and CLI for Zoho Vault via the REST API and an OAuth 2.0 Self Client. Zoho offers no MCP server for Vault.

Secrets in Zoho Vault are encrypted client-side (zero-knowledge). The bridge derives the keys locally from the master passphrase and decrypts fields on the client.

## Status

| Capability | State |
|---|---|
| OAuth token refresh, token cache | verified live |
| Master key, organization key (RSA-4096) | verified live |
| List and decrypt shared secrets | verified live |
| Get a single secret | implemented, unit-tested only |
| Create, update, delete | **experimental, not verified against a live vault** |
| RSA-1024 vaults | not supported (fails closed) |

Create and update currently send JSON. Zoho's official CLI (`@zohocorporation/vault-cli`) sends form-encoded `INPUT_DATA=<json>`. Do not rely on write operations until this is verified, see [Issues](https://github.com/sprintberlin/zoho-vault-bridge/issues).

## Requirements

- Python 3.10+ with `cryptography`
- Node.js 18+
- Zoho Vault account, Self Client in the Zoho API Console, master passphrase

## Install

```bash
git clone https://github.com/sprintberlin/zoho-vault-bridge.git ~/github_repos/zoho-vault-bridge
cd ~/github_repos/zoho-vault-bridge
pip install cryptography
npm test
```

## Configuration

Copy `.env.example` to `.env` and set mode `0600`.

| Variable | Description |
|---|---|
| `ZOHO_VAULT_CLIENT_ID` | Self Client ID |
| `ZOHO_VAULT_CLIENT_SECRET` | Self Client secret |
| `ZOHO_VAULT_REFRESH_TOKEN` | Refresh token |
| `ZOHO_VAULT_DC` | `eu`, `us`, `in`, `au`, `com.cn`, `ca` (default `eu`) |
| `ZOHO_VAULT_PASSPHRASE` | Master passphrase, required for decryption |

Scopes for the grant code:

```text
ZohoVault.secrets.READ,ZohoVault.secrets.CREATE,ZohoVault.secrets.UPDATE,ZohoVault.secrets.DELETE,ZohoVault.user.READ
```

`ZohoVault.user.READ` is required for the key material (`GET_LOGIN`, organization key).

Exchange the grant code for a refresh token:

```bash
python3 scripts/onboarding.py
python3 scripts/onboarding.py --grant-code-file ./grant.txt
```

Access tokens are cached in `.cache/oauth-token.json` (mode `0600`, gitignored) to stay below Zoho's token refresh rate limit.

## Usage

```bash
python3 scripts/vault_list.py [--search NAME] [--filter ALL_SHARED] [--page 0] [--json]
python3 scripts/vault_get.py <SECRET_ID> [--show-password]
python3 scripts/vault_create.py --name NAME [--username U] [--url URL] [--personal]   # experimental
python3 scripts/vault_update.py <SECRET_ID> --password -                              # experimental
python3 scripts/vault_delete.py <SECRET_ID> --yes                                     # experimental
```

Filters: `ALL_SHARED`, `OWNED_BY_ME`, `SHARED_TO_ME`, `PERSONAL`, `ENTERPRISE`. Pages are zero-based.

Passwords are masked unless `--show-password` is passed. `vault_create.py` and `vault_update.py` prompt for the password when it is omitted or `-`, which keeps it out of shell history.

## Encryption

1. `POST /api/json/login` (`GET_LOGIN`) returns salt, iteration count and a verification token.
2. Master key: PBKDF2-SHA256 over passphrase and salt, validated against the verification token.
3. Personal secrets: AES-256 with the master key.
4. Shared secrets: the private key from `/api/rest/json/v1/user/orgkey` is decrypted with the master key (base64 PKCS#8 DER), then RSA-OAEP/SHA-256 decrypts `sharedKey` to the organization key, which decrypts the secret fields.

## Security

- Keep `.env` and `.cache/` at mode `0600`. Both are gitignored.
- Use `--show-password` only on request. Never post plaintext passwords in group chats, logs or memory files.
- Grant least privilege: the token and passphrase give access to everything the Zoho user can see.

## Tests

```bash
npm test
```

## Credits

`scripts/vendor/zohovault.js` is Zoho's client-side cipher routine, vendored so ciphertexts stay compatible with Zoho's own clients. Zoho's published `@zohocorporation/vault-cli` declares no license, so its redistribution terms are unclear. It is not covered by this repository's MIT license.

## License

MIT, see `LICENSE` (applies to everything except `scripts/vendor/`).
