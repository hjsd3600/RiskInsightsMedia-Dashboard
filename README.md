# Risk Insights Media Dashboard — Authentication Gate

## Summary
This update adds an authentication gate to the Streamlit dashboard so that only approved users can access the app and Snowflake queries.

- Login required before any dashboard content is shown
- Admin-managed users (no public signup)
- Passwords are stored as bcrypt hashes in Streamlit Secrets
- Unauthenticated users are blocked from all content

## Auth Approach
- Library: `streamlit-authenticator`
- Credentials location: `.streamlit/secrets.toml` (local) / Streamlit Community Cloud “Secrets” panel (production)
- Password storage: bcrypt hashes (never plaintext in the app repo)
To add a user: add a new [auth.credentials.usernames."<email>"] block with a bcrypt hash.

To remove a user: delete that user block.

Users log in with email + password (email is the username).

Password Hash Generation (Admin Workflow)

Passwords are pre-hashed using a local script and then pasted into Secrets.

Generate a pool of password/hash pairs (admin-only) and share securely (ex: a private Google Doc accessible only to admins).

Admin assigns one password to a user and pastes the matching hash into Streamlit Secrets.

Snowflake Note (MFA)

If the Snowflake user requires MFA, programmatic connections via Snowpark/connector may fail (MFA cannot be completed non-interactively).
For production deployment, use:

a dedicated service account configured for non-interactive access, or

key-pair authentication for the app user.

Security Defaults

Secrets are never committed to git (.streamlit/secrets.toml is ignored)

Passwords are stored hashed

Access is denied by default until authenticated
## How Admin Adds/Removes Users
Admin updates the credentials list in the Streamlit Cloud Secrets panel.

Example structure:

```toml
[auth]
cookie_name = "risk_insights_media_dashboard"
cookie_key = "CHANGE_ME_TO_LONG_RANDOM_SECRET"

[auth.credentials]
[auth.credentials.usernames]

[auth.credentials.usernames."user@example.com"]
name = "User Name"
email = "user@example.com"
password = "$2b$12$..."

