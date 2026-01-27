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
User → Streamlit Dashboard → Snowpark Session → Snowflake Tables
```

---

## Secure Snowflake Connection

The dashboard uses **RSA Key-Pair Authentication** instead of username/password.

### Secrets stored in Streamlit Cloud

```toml
[snowflake]
account = "your_account"
user = "your_user"
role = "your_role"
warehouse = "your_wh"
database = "RISKINSIGHTSMEDIA_DB"
schema = "ANALYTICS"
private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""
```

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

