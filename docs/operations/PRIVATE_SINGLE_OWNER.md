# Private single-owner deployment

This mode is intended for a private CodeLocal Cloud deployment with one owner account.
It keeps the existing login, session, OAuth, MCP, and device-pairing flows, but removes the public signup/invite surface.

## Railway variables

Set these as Railway secrets on the CodeLocal Cloud service:

```text
CODELOCAL_PRIVATE_MODE=1
CODELOCAL_OWNER_EMAIL=owner@example.com
CODELOCAL_OWNER_PASSWORD=<strong-password>
```

`CODELOCAL_OWNER_PASSWORD` must satisfy the normal CodeLocal password policy (currently at least 10 characters). Never commit a real owner password to the repository.

## Startup behavior

When private mode is enabled, startup is fail-closed:

1. The server validates the private-mode variables.
2. It hashes the configured owner password with the existing CodeLocal password hashing implementation.
3. If the owner email does not exist yet, it creates that owner without requiring a referral code.
4. If the owner already exists, the existing account and password are left unchanged.
5. Public signup, signup verification, and invite endpoints return `404`.
6. Existing login/session behavior and `/pair/start` -> `/pair/approve` -> `/pair/claim` remain unchanged.

If private mode is disabled or unset, CodeLocal keeps its existing public behavior unchanged.

## Important deployment note

Use a fresh/private database if the deployment must truly contain only one user. Private mode does not delete or disable users that already existed in an older multi-user database; it only guarantees the configured owner exists and prevents new public signup/invites.

Changing `CODELOCAL_OWNER_PASSWORD` after the owner has already been created does not reset that account's password on restart. Use the normal account password-change/reset flow instead.
