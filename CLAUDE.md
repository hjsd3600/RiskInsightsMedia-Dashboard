# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally (requires .streamlit/secrets.toml)
streamlit run streamlit_app.py
```

There are no tests or linters configured. The entire application is in `streamlit_app.py`.

## Architecture

This is a single-file Streamlit app (`streamlit_app.py`) that connects to Snowflake via Snowpark. The app requires user login before any content is shown.

**Execution flow:**
1. `streamlit-authenticator` login gate runs first — `st.stop()` is called if not authenticated
2. Snowpark `Session` is established via `@st.cache_resource` (RSA key-pair auth, no passwords)
3. `load_data()` (cached 5 min) queries two Snowflake tables and returns three DataFrames: `companies_df`, `funding_df`, and `merged_df` (funding left-joined to companies on `company_id`)
4. Sidebar filters are applied to `merged_df` → `filtered` DataFrame that drives all KPIs and charts
5. Tabs render from `filtered`; the Company Explorer tab uses `companies_df` directly (so companies without funding rounds still appear)

**Snowflake tables** (`RISKINSIGHTSMEDIA_DB.ANALYTICS`):
- `COMPANIES` — company profiles with `market_segment`, `subcategory`, `status`, `employee_count_min/max`
- `FUNDING_ROUNDS` — funding events with `amount_raised_total` (text), `stage_or_funding_round`, `lead_investor`, `announced_date`
- `EDIT_SUGGESTIONS` — contributor suggestions pending admin review (created on first use if absent)

**Amount handling:** `amount_raised_total` is stored as free-text (e.g. `"$5M"`, `"€2.5B"`). `parse_funding_amount()` converts these to numeric at load time, stored in a derived `amount_num` column.

**Role-based access:** `is_admin` is true when `st.session_state["username"] == "jeremy"`. `is_contributor` is true for `"jitesh"`. Admins get a full Admin Panel tab; contributors get a read-only Contributor Panel that submits suggestions to `EDIT_SUGGESTIONS` for admin approval.

**Caching pattern:** `@st.cache_resource` for the Snowpark session (shared across reruns), `@st.cache_data(ttl=300)` for query results. After any write operation, `st.cache_data.clear()` is called before `st.rerun()`.

**`@st.fragment` usage:** `show_data_tables()` is wrapped in `@st.fragment` so searching the data tables only reruns that section, not the full app.

## Secrets Configuration

Local development requires `.streamlit/secrets.toml` (never commit this file):

```toml
[snowflake]
account = "..."
user = "..."
role = "..."
warehouse = "..."
database = "RISKINSIGHTSMEDIA_DB"
schema = "ANALYTICS"
private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""

[credentials.usernames.jeremy]
email = "..."
name = "Jeremy"
password = "$2b$12$..."  # bcrypt hash

[cookie]
name = "..."
key = "..."  # min 32 chars
expiry_days = 30
```

To generate a bcrypt password hash: edit `generate_hash.py` with the desired password and run `python generate_hash.py`.

## Deployment

Deployed on Streamlit Community Cloud. Code pushes to GitHub auto-deploy. Secret changes require a manual app restart from the Streamlit Cloud dashboard. Secrets are managed in the app's **Settings → Secrets** section (not stored in the repo).
