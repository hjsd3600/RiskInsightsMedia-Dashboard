# Funding Intelligence Dashboard  

---

## Project Overview

The **Funding Intelligence Dashboard** is an interactive data analytics application built using **Streamlit** and **Snowflake**. It enables business users and analysts to explore funding activity, investors, and company insights in a visual and intuitive way.

The dashboard connects securely to Snowflake using **key-pair authentication** and provides real-time analytics on:

- Funding rounds  
- Investors  
- Company profiles  
- Aggregated KPIs  
- Employee count enrichment  

This project demonstrates **end-to-end data engineering + analytics + application deployment skills**.

---

## Architecture

### **Frontend (App Layer)**
- Streamlit Web Application  
- Interactive filters, KPIs, charts, and tables  

### **Data Layer (Snowflake)**
- `ANALYTICS.COMPANIES`  
- `ANALYTICS.FUNDING_ROUNDS`  

### **Connection Layer**
- Snowflake Snowpark Python Session  
- Key-Pair Authentication (no passwords stored)  

```
User → Login Gate → Streamlit Dashboard → Snowpark Session → Snowflake Tables
```

---

## Authentication & Access Control

The dashboard uses **streamlit-authenticator** to require login before any content or Snowflake queries are accessible.

### How It Works

1. **Login Gate**: All dashboard content is blocked until the user successfully authenticates
2. **Credentials**: Admin-managed usernames with bcrypt-hashed passwords stored in Streamlit Secrets
3. **Session Cookies**: After login, a secure cookie maintains the session (configurable expiry)
4. **Logout**: Users can log out via the sidebar button

### Security Features

- Passwords are stored as **bcrypt hashes** (never plaintext)
- Snowflake credentials use **RSA key-pair authentication** (no database passwords)
- All secrets are stored in **Streamlit Secrets** (not in code or config files)
- No dashboard content or queries are accessible without authentication

---

## Admin Guide: User Management

### Adding a New User

1. **Generate a password hash:**

   Edit `generate_hash.py` and set the desired password:
   ```python
   password = "new_user_password".encode("utf-8")
   ```

   Run the script:
   ```bash
   python generate_hash.py
   ```

   Copy the output hash (e.g., `$2b$12$abc...xyz`).

2. **Add the user to Streamlit Secrets:**

   In your Streamlit Cloud dashboard (or `.streamlit/secrets.toml` for local dev), add:
   ```toml
   [credentials.usernames.newusername]
   email = "user@example.com"
   name = "User Display Name"
   password = "$2b$12$<paste_hash_here>"
   ```

3. **Restart the app** (or it will pick up changes on next rerun).

### Removing a User

Delete the corresponding `[credentials.usernames.<username>]` block from Streamlit Secrets and restart the app.

### Changing a User's Password

1. Generate a new hash using `generate_hash.py` with the new password
2. Replace the `password` value in the user's credentials block
3. Restart the app

---

## Admin Guide: Snowflake Credential Management

### Current Authentication Method

The app uses **RSA Key-Pair Authentication** — a production-safe, non-interactive method suitable for Streamlit Community Cloud. No database passwords are used.

### Secrets Configuration

All Snowflake credentials are stored in Streamlit Secrets:

```toml
[snowflake]
account = "your_account"
user = "your_service_user"
role = "your_role"
warehouse = "your_warehouse"
database = "RISKINSIGHTSMEDIA_DB"
schema = "ANALYTICS"
private_key = """-----BEGIN PRIVATE KEY-----
<your_private_key_content>
-----END PRIVATE KEY-----"""
```

### Rotating Snowflake Credentials / Keys

1. **Generate a new RSA key pair:**
   ```bash
   openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -nocrypt
   openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub
   ```

2. **Register the new public key in Snowflake:**
   ```sql
   ALTER USER your_service_user SET RSA_PUBLIC_KEY='<contents_of_rsa_key.pub>';
   ```

3. **Update the private key in Streamlit Secrets:**
   - Go to your Streamlit Cloud app → Settings → Secrets
   - Replace the `private_key` value under `[snowflake]` with the contents of `rsa_key.p8`

4. **Restart the app** from the Streamlit Cloud dashboard.

5. **Securely delete** the local key files after updating:
   ```bash
   rm rsa_key.p8 rsa_key.pub
   ```

### Handling MFA / Auth Changes

- **Key-pair auth is not affected by MFA policies** — it is a non-interactive authentication method
- If your Snowflake account enforces MFA for all users, create a **dedicated service account** with key-pair auth:
  ```sql
  CREATE USER streamlit_service_user
    DEFAULT_ROLE = 'your_role'
    DEFAULT_WAREHOUSE = 'your_warehouse';
  ALTER USER streamlit_service_user SET RSA_PUBLIC_KEY='<public_key>';
  ```
- Grant the service user the minimum required privileges:
  ```sql
  GRANT ROLE your_role TO USER streamlit_service_user;
  GRANT USAGE ON WAREHOUSE your_warehouse TO ROLE your_role;
  GRANT USAGE ON DATABASE RISKINSIGHTSMEDIA_DB TO ROLE your_role;
  GRANT USAGE ON SCHEMA RISKINSIGHTSMEDIA_DB.ANALYTICS TO ROLE your_role;
  GRANT SELECT ON ALL TABLES IN SCHEMA RISKINSIGHTSMEDIA_DB.ANALYTICS TO ROLE your_role;
  ```

---

## Deployment on Streamlit Community Cloud

### Initial Setup

1. Push your code to GitHub (ensure `secrets.toml` is in `.gitignore`)
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your GitHub repository
4. Set the main file to `streamlit_app.py`
5. Add all secrets in **Settings → Secrets** (copy the structure from `.streamlit/secrets.toml`)

### Required Secrets Sections

```toml
[snowflake]
# Snowflake connection parameters + private key

[credentials.usernames.<username>]
# User credentials (email, name, bcrypt-hashed password)

[cookie]
name = "your_cookie_name"
key = "your_cookie_key_min_32_chars_long"
expiry_days = 30
```

### Redeployment After Changes

- Code changes pushed to GitHub are automatically deployed
- Secret changes require a manual app restart from the Streamlit Cloud dashboard

---

## Secure Snowflake Connection

The dashboard uses **RSA Key-Pair Authentication** instead of username/password.

### Private key loading

```python
private_key = serialization.load_pem_private_key(
    st.secrets["snowflake"]["private_key"].encode(),
    password=None
)
```

---

## Data Sources

###  `ANALYTICS.COMPANIES`

| Column | Description |
|-------|-------------|
| company_id | Unique company identifier |
| company_name | Company name |
| website_url | Company website |
| linkedin_url | LinkedIn company page |
| category_group | Industry category |
| status | Company status |
| employee_count | Latest employee count (synced from enrichment pipeline) |

---

### `ANALYTICS.FUNDING_ROUNDS`

| Column | Description |
|-------|-------------|
| round_id | Unique funding round ID |
| company_id | Company identifier |
| company_name | Company name |
| stage_or_funding_round | Round type (Seed, Series A, etc.) |
| amount_raised_total | Funding amount (text format) |
| lead_investor | Lead investor |
| website_url | Company website |
| linkedin_url | LinkedIn page |
| created_at | Record creation timestamp |
| updated_at | Record update timestamp |

---

## Data Processing Logic

### Funding Amount Normalization

Text values like:

```
"$5M", "€2.5B", "750K"
```

are converted into numeric values using:

```python
parse_funding_amount()
```

This allows accurate KPI aggregation.

---

### Data Merging

Funding data is joined with company attributes:

```python
merged = funding.merge(companies, on="company_id", how="left")
```

This enables filtering by:

- Category  
- Status  
- Investor  
- Funding stage  

---

## Dashboard Features

### KPI Section

Displays:

- **Total Funding (Filtered)**  
- **Total Funding Rounds**  
- **Unique Companies**  
- **Top Investor by Funding**  
- **Top Funded Company**  

---

### Rounds Analysis Tab

Visual breakdown of:

- Total funding by round type  
- Number of companies per round  

---

### Investors Tab

Insights into:

- Top investors by funding amount  
- Top investors by number of deals  
- Top funded companies  

---

### Company Explorer Tab

Interactive company cards showing:

- Company category & status  
- Website & LinkedIn links  
- Total funding received  

---

### Data Tables Section

Allows users to explore raw data:

- Funding rounds table  
- Companies table  
- Search functionality included  
- Technical columns hidden for business readability  

---

## Filters Available

Users can dynamically filter by:

- Funding Stage / Round  
- Lead Investor  
- Company Category  
- Company Status  

All KPIs and charts update in real time.

---

## Performance Optimization

- Uses `@st.cache_data(ttl=300)` to reduce repeated Snowflake queries  
- Queries only required columns  
- Uses vectorized Pandas transformations  

---

## Business Value

This dashboard helps stakeholders:

- Track funding trends  
- Identify active investors  
- Analyze high-growth companies  
- Support investment research  
- Power sales & market intelligence  

---
