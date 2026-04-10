import numpy as np
import pandas as pd
import streamlit as st
import streamlit_authenticator as stauth
import uuid

# Build credentials dictionary safely from secrets
credentials = {
    "usernames": {
        username: {
            "email": user_data["email"],
            "name": user_data["name"],
            "password": user_data["password"],
        }
        for username, user_data in st.secrets["credentials"]["usernames"].items()
    }
}

authenticator = stauth.Authenticate(
    credentials,
    st.secrets["cookie"]["name"],
    st.secrets["cookie"]["key"],
    st.secrets["cookie"]["expiry_days"],
    auto_hash=False,
)

try:
    authenticator.login()
except Exception as e:
    st.error(e)

if st.session_state.get("authentication_status") is False:
    st.error("Username/password is incorrect")
    st.stop()

if st.session_state.get("authentication_status") is None:
    st.warning("Please enter your username and password")
    st.stop()

authenticator.logout("Logout", "sidebar")

from snowflake.snowpark import Session
from datetime import datetime
from cryptography.hazmat.primitives import serialization
import uuid

@st.cache_resource(show_spinner=False)
def get_session():
    private_key = serialization.load_pem_private_key(
        st.secrets["snowflake"]["private_key"].encode(),
        password=None
    )

    connection_parameters = {
        "account": st.secrets["snowflake"]["account"],
        "user": st.secrets["snowflake"]["user"],
        "role": st.secrets["snowflake"]["role"],
        "warehouse": st.secrets["snowflake"]["warehouse"],
        "database": st.secrets["snowflake"]["database"],
        "schema": st.secrets["snowflake"]["schema"],
        "private_key": private_key,
        "client_session_keep_alive": True,  # Prevent token expiry on Streamlit Cloud
    }

    return Session.builder.configs(connection_parameters).create()

#session = get_session()

# ============================================================
# Helpers
# ============================================================
def format_url(url):
    """Add protocol to URL if missing."""
    if url is None or pd.isna(url):
        return None
    url = str(url).strip()
    if url == "":
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def parse_funding_amount(series: pd.Series) -> pd.Series:
    """Convert textual amount to numeric."""
    import re

    def _parse(x):
        if pd.isna(x):
            return np.nan

        s = str(x).strip().upper()
        if s in ("", "", "NONE", "N/A", "NA", "-"):
            return np.nan

        s = s.replace(",", "")
        for sym in ["$", "€", "£"]:
            s = s.replace(sym, "")

        multiplier = 1
        if s.endswith("B"):
            multiplier = 1_000_000_000
            s = s[:-1]
        elif s.endswith("M"):
            multiplier = 1_000_000
            s = s[:-1]
        elif s.endswith("K"):
            multiplier = 1_000
            s = s[:-1]

        s = "".join(re.findall(r"[0-9.]", s))
        return float(s) * multiplier if s else np.nan

    return series.apply(_parse)


# ============================================================
# Load data from Snowflake
# ============================================================
@st.cache_data(ttl=300)
def load_data(_session):
    # COMPANIES table
    companies = _session.sql("""
        SELECT
            company_id,
            company_name,
            website      AS website_url,
            linkedin_url,
            category_group,
            subcategory,
            status,
            employee_count,
            employee_count_min,
            employee_count_max,
            updated_at,
            updated_by
        FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.COMPANIES
    """).to_pandas()

    # FUNDING_ROUNDS table
    funding = _session.sql("""
        SELECT
            round_id,
            company_id,
            company_name,
            stage_or_funding_round,
            amount_raised_total,
            lead_investor,
            website_url,
            linkedin_url,
            created_at,
            updated_at
        FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.FUNDING_ROUNDS
    """).to_pandas()

    # Lowercase columns
    companies.columns = companies.columns.str.lower()
    funding.columns = funding.columns.str.lower()

    # Parse numeric funding
    if "amount_raised_total" in funding.columns:
        funding["amount_num"] = parse_funding_amount(funding["amount_raised_total"])
    else:
        funding["amount_num"] = np.nan

    # Parse created_at
    if "created_at" in funding.columns:
        funding["created_at_dt"] = pd.to_datetime(
            funding["created_at"], errors="coerce"
        )
    else:
        funding["created_at_dt"] = pd.NaT

    # Columns for merge
    merge_cols = [
        "company_id", "company_name", "website_url", "linkedin_url",
        "category_group", "status"
    ]
    merge_cols = [c for c in merge_cols if c in companies.columns]

    merged = funding.merge(
        companies[merge_cols],
        on="company_id",
        how="left",
        suffixes=("", "_company"),
    )

    return companies, funding, merged


def get_last_updated(_session):
    try:
        df = _session.sql("""
            SELECT MAX(updated_at) AS last_update
            FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.FUNDING_ROUNDS
        """).to_pandas()

        if not df.empty and pd.notna(df.loc[0, "LAST_UPDATE"]):
            return str(df.loc[0, "LAST_UPDATE"])
    except Exception:
        pass
    return "Unknown"


# ============================================================
# Table viewer (Hides IDs + Renames Columns + No Download)
# ============================================================
def _clean_url(url):
    """Strip protocol and www for clean display while keeping the full URL for linking."""
    if url is None or pd.isna(url):
        return None
    s = str(url).strip()
    if not s:
        return None
    # Ensure full URL has protocol (for linking)
    full = s if s.startswith(("http://", "https://")) else "https://" + s
    # Clean display: strip https://, http://, www.
    display = s.replace("https://", "").replace("http://", "")
    if display.startswith("www."):
        display = display[4:]
    return full  # store full URL but display column shows clean version


def _display_url(url):
    """Return clean display text for a URL (no protocol or www)."""
    if url is None or pd.isna(url):
        return ""
    s = str(url).strip()
    s = s.replace("https://", "").replace("http://", "")
    if s.startswith("www."):
        s = s[4:]
    return s


def display_table(df: pd.DataFrame, table_name: str, is_admin: bool = False):

    # Hide ID columns + technical columns
    drop_cols = ["company_id", "round_id", "created_at", "created_at_dt"]
    if not is_admin:
        drop_cols += ["updated_at", "updated_by"]
    df = df.drop(columns=drop_cols, errors="ignore").copy()
    # Combine min/max employee count into a single formatted range column e.g. "51-200"
    # Falls back to old free-text employee_count for legacy rows where min/max are NULL
    if "employee_count_min" in df.columns and "employee_count_max" in df.columns:
        def _fmt_range(row):
            lo = row.get("employee_count_min")
            hi = row.get("employee_count_max")
            try:
                lo_i = int(lo) if pd.notna(lo) else None
                hi_i = int(hi) if pd.notna(hi) else None
            except (ValueError, TypeError):
                lo_i, hi_i = None, None
            if lo_i is not None and hi_i is not None:
                return f"{lo_i:,}" if lo_i == hi_i else f"{lo_i:,}-{hi_i:,}"
            if lo_i is not None:
                return f"{lo_i:,}+"
            # Fallback: use old free-text column for legacy rows
            legacy = row.get("employee_count")
            if legacy and str(legacy).strip() not in ("", "None", "nan"):
                return str(legacy).strip()
            return ""
        df["employee_count_range"] = df.apply(_fmt_range, axis=1)
        df = df.drop(columns=["employee_count_min", "employee_count_max", "employee_count"], errors="ignore")


    # Rename columns for display only
    rename_map = {
        "company_name": "Company",
        "stage_or_funding_round": "Funding",
        "amount_raised_total": "Amount Raised Total",
        "lead_investor": "Lead Investor",
        "website_url": "Website",
        "linkedin_url": "LinkedIn",
        "category_group": "Market Segment",
        "subcategory": "Product Category",
        "status": "Status",
        "employee_count_range": "Employee Count",
        "updated_at": "Last Edited At",
        "updated_by": "Last Edited By",
    }

    df.rename(
        columns={k: v for k, v in rename_map.items() if k in df.columns},
        inplace=True
    )

    # Build column config for URL columns (clean display text + clickable)
    col_config = {}

    # Ensure URLs have protocol so LinkColumn makes them clickable
    if "Website" in df.columns:
        df["Website"] = df["Website"].apply(format_url)
        col_config["Website"] = st.column_config.LinkColumn(
            "Website",
            display_text=r"https?://(?:www\.)?(.+)"
        )
    if "LinkedIn" in df.columns:
        df["LinkedIn"] = df["LinkedIn"].apply(format_url)
        col_config["LinkedIn"] = st.column_config.LinkColumn(
            "LinkedIn",
            display_text=r"https?://(?:www\.)?(.+)"
        )

    # Search field — use fast selectbox for company tables, text_input for others
    if "Company" in df.columns:
        company_names = [""] + sorted(df["Company"].dropna().astype(str).unique().tolist())
        selected_company_filter = st.selectbox(
            "Search / filter by company:",
            options=company_names,
            key=f"search_{table_name}"
        )
        if selected_company_filter:
            view_df = df[df["Company"] == selected_company_filter]
        else:
            view_df = df
        st.caption(f"{len(view_df)} rows")
    else:
        search_term = st.text_input(
            f"Search in {table_name}:",
            placeholder="Type to search...",
            key=f"search_{table_name}"
        )
        if search_term:
            string_cols = df.select_dtypes(include="object").columns
            mask = (
                df[string_cols].astype(str)
                .apply(lambda col: col.str.contains(search_term, case=False, na=False))
                .any(axis=1)
            )
            view_df = df[mask]
            st.caption(f"{len(view_df)} matching rows")
        else:
            view_df = df
            st.caption(f"{len(view_df)} rows")

    # Show table (no download button)
    st.dataframe(view_df, width="stretch", hide_index=True, column_config=col_config)


@st.fragment
def show_data_tables(funding_df_frag, companies_df_frag, is_admin_frag, selected_table_frag):
    """Isolated fragment so company search only re-runs this section, not the full app."""
    if selected_table_frag == "Both Tables":
        st.markdown("### Funding Rounds Table")
        display_table(funding_df_frag, "funding_rounds", is_admin=is_admin_frag)
        st.markdown("### Companies Table")
        display_table(companies_df_frag, "companies", is_admin=is_admin_frag)
    elif selected_table_frag == "funding_rounds":
        display_table(funding_df_frag, "funding_rounds", is_admin=is_admin_frag)
    elif selected_table_frag == "companies":
        display_table(companies_df_frag, "companies", is_admin=is_admin_frag)
    st.caption("Dashboard loads live data from Snowflake.")


# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(page_title="Funding Intelligence Dashboard", layout="wide")

st.title("Funding Intelligence Dashboard")
st.caption("Explore funding rounds, investors, categories, and companies from Snowflake.")

session = get_session()
companies_df, funding_df, merged_df = load_data(session)

if funding_df.empty or companies_df.empty:
    st.error("No data available in Snowflake.")
    st.stop()


# ============================================================
# Sidebar Filters
# ============================================================
st.sidebar.header("Filters")

stage_options = sorted(merged_df["stage_or_funding_round"].dropna().astype(str).unique())
selected_stages = st.sidebar.multiselect("Funding Stage / Round", stage_options)

investor_options = sorted(merged_df["lead_investor"].dropna().astype(str).unique())
selected_investors = st.sidebar.multiselect("Lead Investor", investor_options)

category_options = sorted(merged_df["category_group"].dropna().astype(str).unique()) \
    if "category_group" in merged_df.columns else []
selected_categories = st.sidebar.multiselect("Market Segment", category_options)

status_options = sorted(merged_df["status"].dropna().astype(str).unique()) \
    if "status" in merged_df.columns else []
selected_status = st.sidebar.multiselect("Company Status", status_options)

st.sidebar.markdown("---")
selected_table = st.sidebar.selectbox(
    "Select table to view:",
    ["Both Tables", "funding_rounds", "companies"],
    index=2
)

st.sidebar.markdown("---")
st.sidebar.caption(f"Last updated: **{get_last_updated(session)}**")


# ============================================================
# Apply Filters
# ============================================================
filtered = merged_df.copy()

if selected_stages:
    filtered = filtered[filtered["stage_or_funding_round"].isin(selected_stages)]
if selected_investors:
    filtered = filtered[filtered["lead_investor"].isin(selected_investors)]
if selected_categories and "category_group" in filtered.columns:
    filtered = filtered[filtered["category_group"].isin(selected_categories)]
if selected_status and "status" in filtered.columns:
    filtered = filtered[filtered["status"].isin(selected_status)]


# ============================================================
# KPIs
# ============================================================
st.subheader("Key KPIs (Filtered)")

total_funding = filtered["amount_num"].sum(skipna=True)
total_rounds = filtered["round_id"].nunique() if "round_id" in filtered.columns else 0
unique_companies = filtered["company_id"].nunique() if "company_id" in filtered.columns else 0

top_investor = (
    filtered.groupby("lead_investor")["amount_num"]
    .sum()
    .sort_values(ascending=False)
    .index[0]
    if not filtered.empty and filtered["lead_investor"].notna().any()
    else "N/A"
)

top_company = (
    filtered.groupby("company_name")["amount_num"]
    .sum()
    .sort_values(ascending=False)
    .index[0]
    if not filtered.empty and filtered["company_name"].notna().any()
    else "N/A"
)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total Funding", f"${total_funding:,.0f}" if total_funding else "N/A")
k2.metric("Funding Rounds", int(total_rounds))
k3.metric("Unique Companies", int(unique_companies))
k4.metric("Top Investor (by $)", top_investor)
k5.metric("Top Funded Company", top_company)

st.markdown("---")


# Check if logged-in user is admin
_current_user = (st.session_state.get("username") or "").lower()
_current_user_display = (st.session_state.get("name") or _current_user)  # Full name for DB writes
is_admin = _current_user == "jeremy"
is_contributor = _current_user == "jitesh"

# ============================================================
# Tabs
# ============================================================
tab_list = ["Rounds Analysis", "Investors", "Company Explorer"]
if is_admin:
    tab_list.append("Admin Panel")
elif is_contributor:
    tab_list.append("Contributor Panel")

tabs = st.tabs(tab_list)
tab1 = tabs[0]
tab2 = tabs[1]
tab3 = tabs[2]
tab4 = tabs[3] if (is_admin or is_contributor) else None


# -------------------------
# Tab 1: Rounds Analysis
# -------------------------
with tab1:
    st.markdown("### Rounds Analysis")

    c1, c2 = st.columns(2)

    if "stage_or_funding_round" in filtered.columns:
        with c1:
            st.markdown("**Funding totals by round**")
            totals = (
                filtered.groupby("stage_or_funding_round")["amount_num"]
                .sum()
                .sort_values(ascending=False)
            )
            st.bar_chart(totals)

        with c2:
            st.markdown("**Company count per round**")
            counts = (
                filtered.groupby("stage_or_funding_round")["company_id"]
                .nunique()
                .sort_values(ascending=False)
            )
            st.bar_chart(counts)


# -------------------------
# Tab 2: Investors
# -------------------------
with tab2:
    st.markdown("### Investors")

    c3, c4 = st.columns(2)

    with c3:
        st.markdown("**Top investors by funding**")
        inv_fund = (
            filtered.groupby("lead_investor")["amount_num"]
            .sum()
            .sort_values(ascending=False)
            .head(20)
        )
        st.bar_chart(inv_fund)

    with c4:
        st.markdown("**Top investors by deal count**")
        inv_count = (
            filtered.groupby("lead_investor")["round_id"]
            .nunique()
            .sort_values(ascending=False)
            .head(20)
        )
        st.bar_chart(inv_count)

    st.markdown("---")

    st.markdown("**Top funded companies**")
    comp_fund = (
        filtered.groupby("company_name")["amount_num"]
        .sum()
        .sort_values(ascending=False)
        .head(20)
    )
    st.bar_chart(comp_fund)


# -------------------------
# Tab 3: Company Explorer
# -------------------------
with tab3:
    st.markdown("### Company Explorer")

    # Build from ALL companies (not just those with funding rounds)
    explorer_base = companies_df.copy()
    if selected_categories and "category_group" in explorer_base.columns:
        explorer_base = explorer_base[explorer_base["category_group"].isin(selected_categories)]
    if selected_status and "status" in explorer_base.columns:
        explorer_base = explorer_base[explorer_base["status"].isin(selected_status)]

    # Get funding totals per company from filtered merged data
    funding_totals = (
        filtered.groupby("company_id")["amount_num"]
        .sum()
        .reset_index()
        .rename(columns={"amount_num": "total_funding"})
    )

    # Left join so ALL companies appear, with funding total where available
    company_metrics = explorer_base.merge(funding_totals, on="company_id", how="left")
    company_metrics["total_funding"] = company_metrics["total_funding"].fillna(0)

    # Sort and search
    company_search = st.text_input("🔍 Search companies", placeholder="Type a company name...", key="company_explorer_search")
    company_metrics = company_metrics.sort_values("company_name", key=lambda s: s.str.lower().fillna(""))
    if company_search.strip():
        company_metrics = company_metrics[company_metrics["company_name"].str.contains(company_search.strip(), case=False, na=False)]
    top_companies = company_metrics


    for _, row in top_companies.iterrows():
        with st.container(border=True):

            st.markdown(f"#### {row['company_name']}")

            detail_list = []
            if "category_group" in row and pd.notna(row["category_group"]):
                detail_list.append(f"Market Segment: {row['category_group']}")
            if "status" in row and pd.notna(row["status"]):
                detail_list.append(f"Status: {row['status']}")

            if detail_list:
                st.markdown(" • ".join(detail_list))

            cols = st.columns([1, 3])

            with cols[0]:
                website = format_url(row.get("website_url"))
                linkedin = format_url(row.get("linkedin_url"))

                if website:
                    st.link_button("Website", website, width="stretch")
                if linkedin:
                    st.link_button("LinkedIn", linkedin, width="stretch")

            with cols[1]:
                tf = (
                    f"${row['total_funding']:,.0f}"
                    if pd.notna(row["total_funding"])
                    else "N/A"
                )
                st.markdown("**Funding Summary**")
                st.write(f"- Total funding: {tf}")


# ============================================================
# Data Tables
# ============================================================
st.markdown("---")
st.subheader("Data Tables")

allowed_round_ids = filtered["round_id"].dropna().unique() if "round_id" in filtered.columns else []

funding_filtered = funding_df[funding_df["round_id"].isin(allowed_round_ids)]

# Companies table: filter directly from companies_df so companies with no
# funding rounds are still visible (they'd be excluded if we used allowed_company_ids)
companies_filtered = companies_df.copy()
if selected_categories and "category_group" in companies_filtered.columns:
    companies_filtered = companies_filtered[companies_filtered["category_group"].isin(selected_categories)]
if selected_status and "status" in companies_filtered.columns:
    companies_filtered = companies_filtered[companies_filtered["status"].isin(selected_status)]
# Sort alphabetically
if "company_name" in companies_filtered.columns:
    companies_filtered = companies_filtered.sort_values("company_name", key=lambda s: s.str.lower().fillna(""))


show_data_tables(funding_filtered, companies_filtered, is_admin, selected_table)



# ============================================================
# Admin Panel (Jeremy only — Direct Edit)
# ============================================================
if is_admin and tab4 is not None:
    with tab4:
        st.markdown("### 🔒 Admin Panel")
        st.caption("Only you can see this tab. Use the forms below to manage data in Snowflake.")

        admin_tab1, admin_tab2, admin_tab3, admin_tab4 = st.tabs([
            "➕ Add Company",
            "✏️ Update Company",
            "💰 Log Funding Round",
            "📋 Review Suggestions"
        ])

        # -------------------------
        # Admin Sub-Tab 1: Add Company
        # -------------------------
        with admin_tab1:
            st.markdown("#### Add a New Company")
            MARKET_SEGMENTS = [
                "",
                "Cloud & Application Security",
                "Data Security & AI Security",
                "Endpoint & IoT/OT Security",
                "Identity",
                "Network & Infrastructure Security",
                "Risk & Compliance",
                "Security Awareness & Training",
                "Security Operations",
                "Security Services",
            ]

            CATEGORIES = [
                "",
                "API Security", "Access Management (AM)", "Anomaly Detection (IoT/OT)",
                "Anti-phishing and Simulated Phishing", "Application Detection & Response (ADR)",
                "Application Security Orchestration and Correlation (ASOC)",
                "Application Security Posture Management (ASPM)",
                "Application Security Testing (AST)", "Attack Surface Management (ASM)",
                "Automated Penetration Testing", "Automated Security Control Assessment (ASCA)",
                "Backup and Recovery", "Bot Detection & Mitigation",
                "Breach and Attack Simulation (BAS)", "Cloud Access Security Broker (CASB)",
                "Cloud Detection & Response (CDR)", "Cloud IAM", "Cloud Identity Federation",
                "Cloud Infrastructure Entitlements Management (CIEM)",
                "Cloud Native Application Protection Platforms (CNAPP)",
                "Cloud Security Posture Management (CSPM)",
                "Cloud Workload Protection Platforms (CWPP)", "Compliance Management",
                "Container Security", "Continuous Threat Exposure Management (CTEM)",
                "Customer Identity", "Cyber Asset Attack Surface Management (CAASM)",
                "Cyber Insurance", "Cyber Range", "Cyber Risk Quantification",
                "Cybersecurity Education & Training", "DDoS Mitigation",
                "Data Loss Prevention (DLP)", "Data Security Posture Management (DSPM)",
                "Deception Platform", "Dynamic Application Security Testing (DAST)",
                "Email Security Software", "Encryption Key Management System (EKMS)",
                "Endpoint Detection and Response (EDR)", "Endpoint Protection Platform (EPP)",
                "Enterprise Browser Security", "Enterprise Email Security",
                "Extended Detection and Response (XDR)",
                "External Attack Surface Management (EASM)",
                "Forensic and Incident Response", "Fraud Prevention",
                "Fraud and Financial Crime Protection",
                "Governance, Risk, and Compliance (GRC)",
                "Host-Based Intrusion Detection Systems (HIDS)", "Human Risk Management",
                "Identity Governance and Administration (IGA)",
                "Identity Threat and Detection Response (ITDR)", "Identity Verification",
                "Identity and Access Management (IAM)", "Incident Response",
                "Industrial Controls Systems (ICS) Security", "Industrial IoT Security",
                "Insider Risk Management (IRM)", "Integrated Cloud Email Security (ICES)",
                "Intrusion Detection System (IDS)",
                "Intrusion Detection and Prevention Systems (IDPS)", "IoT Security",
                "Managed Detection and Response (MDR)", "Managed Security Services",
                "Mobile Application Security Testing", "Mobile Data Protection (MDP)",
                "Mobile Device Management (MDM)", "Mobile Threat Defense",
                "Network Access Control (NAC)", "Network Detection and Response (NDR)",
                "Network-Based Intrusion Detection Systems (NIDS)",
                "Operational Technology (OT) Security", "Password Management",
                "Patch Management", "Penetration Testing", "Privacy",
                "Privilege Elevation & Delegation Management (PEDM)",
                "Privileged Access Management (PAM)",
                "Privileged Account & Session Management (PASM)",
                "Privileged Identity Management (PIM)",
                "Risk Management & Compliance", "Risk-Based Vulnerability Management (RBVM)",
                "Runtime Application Self-Protection (RASP)",
                "SaaS Security Posture Management (SSPM)",
                "Secure Access Service Edge (SASE)", "Secure Collaboration and Messaging",
                "Secure Remote Access", "Secure Web Gateway (SWG)",
                "Security Awareness Computer-Based Training (SACBT)",
                "Security Awareness Training (SAT)",
                "Security Information and Event Management (SIEM)",
                "Security Orchestration and Automated Response (SOAR)",
                "Security Service Edge (SSE)", "Single Sign-On (SSO)",
                "Software Composition Analysis (SCA)", "Software Supply Chain Security",
                "Third-Party Risk Management (TPRM)", "Unified Threat Management (UTM)",
                "VPN Firewalls", "Vendor Risk Management", "Virtual Private Networks (VPNs)",
                "Vulnerability Assessment", "Vulnerability Management (IoT/OT)",
                "Vulnerability Management (VM)", "Vulnerability Risk Management (VRM)",
                "Web Application Firewall (WAF)",
                "Web Application and API Protection (WAAP)", "Wireless Security",
                "Zero Trust Edge Solutions (ZTE)", "Zero Trust Network Access (ZTNA)",
            ]

            with st.form("add_company_form"):
                new_name        = st.text_input("Company Name *", placeholder="e.g. Acme Corp")
                new_website     = st.text_input("Website", placeholder="e.g. https://acme.com")
                new_linkedin    = st.text_input("LinkedIn URL", placeholder="e.g. https://linkedin.com/company/acme")
                new_segment     = st.selectbox("Market Segment", MARKET_SEGMENTS)
                new_category    = st.selectbox("Product Category", CATEGORIES)
                new_status      = st.selectbox("Status", ["", "Private", "Acquired", "Closed", "IPO", "Unknown"])

                MIN_TO_MAX = {
                    None: None,
                    1: 10, 11: 50, 51: 200, 201: 500,
                    501: 1000, 1001: 5000, 5001: 10000, 10001: None
                }
                MIN_OPTIONS = ["", 1, 11, 51, 201, 501, 1001, 5001, 10001]
                MIN_LABELS  = ["", "1", "11", "51", "201", "501", "1,001", "5,001", "10,001+"]
                new_emp_min_label = st.selectbox("Min Employee Count (range)", MIN_LABELS)
                new_emp_exact = st.text_input("Or enter exact number (overrides range)", placeholder="e.g. 250")

                # Determine final min/max
                if new_emp_exact.strip().isdigit():
                    new_emp_min = int(new_emp_exact.strip())
                    new_emp_max = str(new_emp_min)
                else:
                    new_emp_min = MIN_OPTIONS[MIN_LABELS.index(new_emp_min_label)] if new_emp_min_label else None
                    new_emp_max = MIN_TO_MAX.get(new_emp_min)

                submitted = st.form_submit_button("Add Company ✅")
                if submitted:
                    if not new_name.strip():
                        st.error("Company Name is required.")
                    else:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            new_company_id = str(uuid.uuid4())
                            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                            def _q(val):
                                """Return SQL-quoted string or NULL."""
                                if val is None or str(val).strip() == "":
                                    return "NULL"
                                return "'" + str(val).replace("'", "''") + "'"

                            sql = f"""
                                INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.COMPANIES
                                (COMPANY_ID, COMPANY_NAME, WEBSITE, LINKEDIN_URL,
                                 CATEGORY_GROUP, SUBCATEGORY, STATUS,
                                 EMPLOYEE_COUNT_MIN, EMPLOYEE_COUNT_MAX,
                                 CREATED_AT, UPDATED_AT, CREATED_BY, UPDATED_BY)
                                VALUES (
                                    {_q(new_company_id)},
                                    {_q(new_name.strip())},
                                    {_q(new_website.strip())},
                                    {_q(new_linkedin.strip())},
                                    {_q(new_segment)},
                                    {_q(new_category)},
                                    {_q(new_status)},
                                    {'NULL' if new_emp_min is None else str(new_emp_min)},
                                    {'NULL' if new_emp_max is None else str(new_emp_max)},
                                    TO_TIMESTAMP_NTZ({_q(now_str)}),
                                    TO_TIMESTAMP_NTZ({_q(now_str)}),
                                    {_q(_current_user_display)},
                                    {_q(_current_user_display)}
                                )
                            """
                            session.sql(sql).collect()
                            st.success(f"✅ Company '{new_name}' added successfully!")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error adding company: {e}")


        # -------------------------
        # Admin Sub-Tab 2: Update Company
        # -------------------------
        with admin_tab2:
            st.markdown("#### Update an Existing Company")
            company_options = companies_df[["company_id", "company_name"]].dropna(subset=["company_name"])
            company_options = company_options.sort_values("company_name", key=lambda s: s.str.lower().fillna(""))
            company_map = dict(zip(company_options["company_name"], company_options["company_id"]))

            selected_company = st.selectbox(
                "Select Company to Update",
                options=[""] + list(company_map.keys()),
                key="update_company_select"
            )

            if selected_company:
                cid = company_map[selected_company]
                current = companies_df[companies_df["company_id"] == cid].iloc[0]

                CATEGORIES = [
                    "",
                    "API Security", "Access Management (AM)", "Anomaly Detection (IoT/OT)",
                    "Anti-phishing and Simulated Phishing", "Application Detection & Response (ADR)",
                    "Application Security Orchestration and Correlation (ASOC)",
                    "Application Security Posture Management (ASPM)",
                    "Application Security Testing (AST)", "Attack Surface Management (ASM)",
                    "Automated Penetration Testing", "Automated Security Control Assessment (ASCA)",
                    "Backup and Recovery", "Bot Detection & Mitigation",
                    "Breach and Attack Simulation (BAS)", "Cloud Access Security Broker (CASB)",
                    "Cloud Detection & Response (CDR)", "Cloud IAM", "Cloud Identity Federation",
                    "Cloud Infrastructure Entitlements Management (CIEM)",
                    "Cloud Native Application Protection Platforms (CNAPP)",
                    "Cloud Security Posture Management (CSPM)",
                    "Cloud Workload Protection Platforms (CWPP)", "Compliance Management",
                    "Container Security", "Continuous Threat Exposure Management (CTEM)",
                    "Customer Identity", "Cyber Asset Attack Surface Management (CAASM)",
                    "Cyber Insurance", "Cyber Range", "Cyber Risk Quantification",
                    "Cybersecurity Education & Training", "DDoS Mitigation",
                    "Data Loss Prevention (DLP)", "Data Security Posture Management (DSPM)",
                    "Deception Platform", "Dynamic Application Security Testing (DAST)",
                    "Email Security Software", "Encryption Key Management System (EKMS)",
                    "Endpoint Detection and Response (EDR)", "Endpoint Protection Platform (EPP)",
                    "Enterprise Browser Security", "Enterprise Email Security",
                    "Extended Detection and Response (XDR)",
                    "External Attack Surface Management (EASM)",
                    "Forensic and Incident Response", "Fraud Prevention",
                    "Fraud and Financial Crime Protection",
                    "Governance, Risk, and Compliance (GRC)",
                    "Host-Based Intrusion Detection Systems (HIDS)", "Human Risk Management",
                    "Identity Governance and Administration (IGA)",
                    "Identity Threat and Detection Response (ITDR)", "Identity Verification",
                    "Identity and Access Management (IAM)", "Incident Response",
                    "Industrial Controls Systems (ICS) Security", "Industrial IoT Security",
                    "Insider Risk Management (IRM)", "Integrated Cloud Email Security (ICES)",
                    "Intrusion Detection System (IDS)",
                    "Intrusion Detection and Prevention Systems (IDPS)", "IoT Security",
                    "Managed Detection and Response (MDR)", "Managed Security Services",
                    "Mobile Application Security Testing", "Mobile Data Protection (MDP)",
                    "Mobile Device Management (MDM)", "Mobile Threat Defense",
                    "Network Access Control (NAC)", "Network Detection and Response (NDR)",
                    "Network-Based Intrusion Detection Systems (NIDS)",
                    "Operational Technology (OT) Security", "Password Management",
                    "Patch Management", "Penetration Testing", "Privacy",
                    "Privilege Elevation & Delegation Management (PEDM)",
                    "Privileged Access Management (PAM)",
                    "Privileged Account & Session Management (PASM)",
                    "Privileged Identity Management (PIM)",
                    "Risk Management & Compliance", "Risk-Based Vulnerability Management (RBVM)",
                    "Runtime Application Self-Protection (RASP)",
                    "SaaS Security Posture Management (SSPM)",
                    "Secure Access Service Edge (SASE)", "Secure Collaboration and Messaging",
                    "Secure Remote Access", "Secure Web Gateway (SWG)",
                    "Security Awareness Computer-Based Training (SACBT)",
                    "Security Awareness Training (SAT)",
                    "Security Information and Event Management (SIEM)",
                    "Security Orchestration and Automated Response (SOAR)",
                    "Security Service Edge (SSE)", "Single Sign-On (SSO)",
                    "Software Composition Analysis (SCA)", "Software Supply Chain Security",
                    "Third-Party Risk Management (TPRM)", "Unified Threat Management (UTM)",
                    "VPN Firewalls", "Vendor Risk Management", "Virtual Private Networks (VPNs)",
                    "Vulnerability Assessment", "Vulnerability Management (IoT/OT)",
                    "Vulnerability Management (VM)", "Vulnerability Risk Management (VRM)",
                    "Web Application Firewall (WAF)",
                    "Web Application and API Protection (WAAP)", "Wireless Security",
                    "Zero Trust Edge Solutions (ZTE)", "Zero Trust Network Access (ZTNA)",
                ]
                STATUS_OPTIONS = ["", "Private", "Acquired", "Closed", "IPO", "Unknown"]

                with st.form("update_company_form"):
                    upd_name = st.text_input("Company Name", value=str(current.get("company_name", "") or ""))
                    upd_website = st.text_input("Website", value=str(current.get("website_url", "") or ""))
                    upd_linkedin = st.text_input("LinkedIn URL", value=str(current.get("linkedin_url", "") or ""))
                    MARKET_SEGMENTS_UPD = [
                        "", "Cloud & Application Security", "Data Security & AI Security",
                        "Endpoint & IoT/OT Security", "Identity",
                        "Network & Infrastructure Security", "Risk & Compliance",
                        "Security Awareness & Training", "Security Operations", "Security Services",
                    ]
                    cur_seg = str(current.get("category_group", "") or "")
                    upd_segment = st.selectbox(
                        "Market Segment",
                        MARKET_SEGMENTS_UPD,
                        index=MARKET_SEGMENTS_UPD.index(cur_seg) if cur_seg in MARKET_SEGMENTS_UPD else 0
                    )
                    cur_cat = str(current.get("subcategory", "") or "")
                    upd_category = st.selectbox(
                        "Product Category",
                        CATEGORIES,
                        index=CATEGORIES.index(cur_cat) if cur_cat in CATEGORIES else 0
                    )
                    upd_status = st.selectbox(
                        "Status",
                        STATUS_OPTIONS,
                        index=STATUS_OPTIONS.index(current.get("status", "") or ""
                        ) if (current.get("status", "") or "") in STATUS_OPTIONS else 0
                    )

                    MIN_TO_MAX_UPD = {
                        None: None,
                        1: 10, 11: 50, 51: 200, 201: 500,
                        501: 1000, 1001: 5000, 5001: 10000, 10001: None
                    }
                    MIN_OPTIONS_UPD = ["", 1, 11, 51, 201, 501, 1001, 5001, 10001]
                    MIN_LABELS_UPD  = ["", "1", "11", "51", "201", "501", "1,001", "5,001", "10,001+"]
                    cur_min_raw = current.get("employee_count_min")
                    # Safely handle NaN/None from Snowflake — int(NaN) would crash the form
                    try:
                        cur_min = int(cur_min_raw) if cur_min_raw is not None and str(cur_min_raw).strip() not in ("", "None", "nan") else None
                    except (ValueError, TypeError):
                        cur_min = None
                    cur_min_label = str(cur_min) if cur_min is not None else ""
                    if cur_min_label == "10001":
                        cur_min_label = "10,001+"
                    elif cur_min_label in ["1001","5001"]:
                        cur_min_label = f"{int(cur_min_label):,}"
                    upd_emp_min_label = st.selectbox(
                        "Min Employee Count (range)",
                        MIN_LABELS_UPD,
                        index=MIN_LABELS_UPD.index(cur_min_label) if cur_min_label in MIN_LABELS_UPD else 0
                    )
                    cur_max = str(current.get("employee_count_max") or "")
                    # Pre-fill exact box only if min==max (was entered as exact)
                    try:
                        cur_exact = cur_max if (cur_max and cur_min is not None and cur_max == str(cur_min)) else ""
                    except Exception:
                        cur_exact = ""
                    upd_emp_exact = st.text_input(
                        "Or enter exact number (overrides range)",
                        value=cur_exact,
                        placeholder="e.g. 250"
                    )
                    # Determine final min/max
                    if upd_emp_exact.strip().isdigit():
                        upd_emp_min = int(upd_emp_exact.strip())
                        upd_emp_max = str(upd_emp_min)
                    else:
                        upd_emp_min = MIN_OPTIONS_UPD[MIN_LABELS_UPD.index(upd_emp_min_label)] if upd_emp_min_label else None
                        upd_emp_max = MIN_TO_MAX_UPD.get(upd_emp_min)



                    submitted2 = st.form_submit_button("Save Changes ✅")
                    if submitted2:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            now_upd = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            session.sql(f"""
                                UPDATE RISKINSIGHTSMEDIA_DB.ANALYTICS.COMPANIES
                                SET
                                    company_name        = {repr(upd_name.strip())},
                                    website             = {repr(upd_website.strip()) if upd_website.strip() else 'NULL'},
                                    linkedin_url        = {repr(upd_linkedin.strip()) if upd_linkedin.strip() else 'NULL'},
                                    category_group      = {repr(upd_segment.strip()) if upd_segment.strip() else 'NULL'},
                                    subcategory         = {repr(upd_category.strip()) if upd_category.strip() else 'NULL'},
                                    status              = {repr(upd_status) if upd_status else 'NULL'},
                                    employee_count_min  = {'NULL' if upd_emp_min is None else str(upd_emp_min)},
                                    employee_count_max  = {'NULL' if upd_emp_max is None else str(upd_emp_max)},
                                    updated_at          = TO_TIMESTAMP_NTZ('{now_upd}'),
                                    updated_by          = {repr(_current_user_display)}
                                WHERE company_id = {repr(str(cid))}
                            """).collect()
                            st.success(f"✅ Company '{upd_name}' updated successfully!")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error updating company: {e}")

        # -------------------------
        # Admin Sub-Tab 3: Log Funding Round
        # -------------------------
        with admin_tab3:
            st.markdown("#### Log a New Funding Round")
            company_options2 = companies_df[["company_id", "company_name"]].dropna(subset=["company_name"])
            company_options2 = company_options2.sort_values("company_name", key=lambda s: s.str.lower().fillna(""))
            company_map2 = dict(zip(company_options2["company_name"], company_options2["company_id"]))

            FUNDING_STAGES = [
                "", "Pre-Seed", "Grant", "Seed", "Venture Round",
                "A", "A1", "B", "B1", "C", "C1", "D", "D1",
                "E", "E1", "F", "F1", "G", "G1", "H", "H1",
                "I", "I1", "J", "J1",
                "Private Equity Round", "Debt Financing", "Post-IPO Debt Round",
            ]

            CURRENCY_MAP = {
                "USD ($)": "$",   "EUR (€)": "\u20ac",  "GBP (£)": "\u00a3",
                "JPY (¥)": "\u00a5",  "INR (₹)": "\u20b9", "ILS (₪)": "\u20aa",
                "AUD (A$)": "A$", "CAD (C$)": "C$",  "CHF": "CHF",
                "CNY (¥)": "\u00a5", "HKD (HK$)": "HK$", "SGD (S$)": "S$",
                "NZD (NZ$)": "NZ$",
            }
            MULTIPLIER_MAP = {
                "Exact": 1,
                "K (×1,000)": 1_000,
                "M (×1,000,000)": 1_000_000,
                "B (×1,000,000,000)": 1_000_000_000,
            }

            with st.form("add_funding_form"):
                fr_company = st.selectbox(
                    "Company *",
                    options=[""] + list(company_map2.keys()),
                    key="funding_company_select"
                )
                fr_stage = st.selectbox("Funding Stage / Round *", FUNDING_STAGES)
                fr_investor = st.text_input("Lead Investor", placeholder="e.g. Sequoia Capital")

                st.markdown("**Amount Raised**")
                amt_col1, amt_col2, amt_col3 = st.columns([2, 3, 2])
                with amt_col1:
                    fr_currency_label = st.selectbox("Currency", list(CURRENCY_MAP.keys()))
                with amt_col2:
                    fr_amount_raw = st.number_input("Amount", min_value=0.0, step=1.0, format="%.0f")
                with amt_col3:
                    fr_multiplier_label = st.selectbox("Scale", list(MULTIPLIER_MAP.keys()))

                fr_press_release = st.text_input("Press Release URL", placeholder="e.g. https://company.com/press")

                submitted3 = st.form_submit_button("Log Funding Round ✅")
                if submitted3:
                    if not fr_company or not fr_stage:
                        st.error("Company and Funding Stage are required.")
                    else:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            cid2 = company_map2[fr_company]
                            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                            # Build amount string e.g. "$81000000"
                            symbol = CURRENCY_MAP[fr_currency_label]
                            multiplier = MULTIPLIER_MAP[fr_multiplier_label]
                            if fr_amount_raw > 0:
                                amount_val = f"{symbol}{int(fr_amount_raw * multiplier)}"
                            else:
                                amount_val = None

                            def _fq(val):
                                if val is None or str(val).strip() == "":
                                    return "NULL"
                                return "'" + str(val).replace("'", "''") + "'"

                            new_round_id = str(uuid.uuid4())
                            session.sql(f"""
                                INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.FUNDING_ROUNDS
                                (round_id, company_id, company_name, stage_or_funding_round,
                                 amount_raised_total, lead_investor, website_url,
                                 created_at, updated_at, created_by, updated_by)
                                VALUES
                                ({_fq(new_round_id)},
                                 {_fq(str(cid2))},
                                 {_fq(fr_company)},
                                 {_fq(fr_stage)},
                                 {_fq(amount_val)},
                                 {_fq(fr_investor.strip())},
                                 {_fq(fr_press_release.strip())},
                                 '{now}', '{now}', {repr(_current_user_display)}, {repr(_current_user_display)})
                            """).collect()
                            st.success(f"✅ Funding round logged for '{fr_company}'!")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error logging funding round: {e}")

        # -------------------------
        # Admin Sub-Tab 4: Review Suggestions
        # -------------------------
        with admin_tab4:
            st.markdown("#### 📋 Pending Suggestions from Contributors")
            try:
                session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                # Create suggestions table if it doesn't exist
                session.sql("""
                    CREATE TABLE IF NOT EXISTS RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS (
                        suggestion_id VARCHAR PRIMARY KEY,
                        submitted_by VARCHAR,
                        submission_type VARCHAR,
                        company_name VARCHAR,
                        field_name VARCHAR,
                        old_value VARCHAR,
                        new_value VARCHAR,
                        notes VARCHAR,
                        status VARCHAR DEFAULT 'pending',
                        submitted_at TIMESTAMP,
                        reviewed_at TIMESTAMP
                    )
                """).collect()

                suggestions_df = session.sql("""
                    SELECT suggestion_id, submitted_by, submission_type, company_name,
                           field_name, old_value, new_value, notes, status, submitted_at
                    FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                    WHERE status = 'pending'
                    ORDER BY submitted_at DESC
                """).to_pandas()

                if suggestions_df.empty:
                    st.info("✅ No pending suggestions right now.")
                else:
                    suggestions_df.columns = suggestions_df.columns.str.lower()
                    st.caption(f"{len(suggestions_df)} pending suggestion(s)")
                    for _, row in suggestions_df.iterrows():
                        with st.container(border=True):
                            col_info, col_actions = st.columns([3, 1])
                            with col_info:
                                st.markdown(f"**{row['submission_type']}** — {row['company_name']}")
                                st.write(f"Field: `{row['field_name']}` → **{row['new_value']}**")
                                if row.get('notes'):
                                    st.caption(f"Note: {row['notes']}")
                                st.caption(f"Submitted by {row['submitted_by']} at {row['submitted_at']}")
                            with col_actions:
                                sid = str(row['suggestion_id'])
                                if st.button("✅ Approve", key=f"approve_{sid}"):
                                    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                                    session.sql(f"""
                                        UPDATE RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                        SET status = 'approved', reviewed_at = '{now}'
                                        WHERE suggestion_id = '{sid}'
                                    """).collect()
                                    st.success("Approved!")
                                    st.cache_data.clear()
                                    st.rerun()
                                if st.button("❌ Reject", key=f"reject_{sid}"):
                                    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                                    session.sql(f"""
                                        UPDATE RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                        SET status = 'rejected', reviewed_at = '{now}'
                                        WHERE suggestion_id = '{sid}'
                                    """).collect()
                                    st.warning("Rejected.")
                                    st.rerun()
            except Exception as e:
                st.error(f"❌ Could not load suggestions: {e}")


# ============================================================
# Contributor Panel (jitesh — Suggest Edits only)
# ============================================================
if is_contributor and tab4 is not None:
    with tab4:
        st.markdown("### ✏️ Contributor Panel")
        st.caption("Suggest edits to company or funding data. Jeremy will review and approve your suggestions.")

        c_tab1, c_tab2 = st.tabs(["🏢 Suggest Company Edit", "💡 Suggest New Entry"])

        # -------------------------
        # Contributor Sub-Tab 1: Suggest Company Edit
        # -------------------------
        with c_tab1:
            st.markdown("#### Suggest a change to an existing company")
            c_options = companies_df[["company_id", "company_name"]].dropna(subset=["company_name"])
            c_map = dict(zip(c_options["company_name"], c_options["company_id"]))

            c_selected = st.selectbox("Select Company", [""] + list(c_map.keys()), key="contrib_company_select")

            if c_selected:
                c_current = companies_df[companies_df["company_id"] == c_map[c_selected]].iloc[0]

                with st.form("suggest_edit_form"):
                    field_to_edit = st.selectbox("Which field to update?", [
                        "company_name", "website", "linkedin_url", "category_group", "status", "employee_count_min"
                    ])
                    old_val = str(c_current.get(field_to_edit, "") or "")
                    st.text_input("Current value (read-only)", value=old_val, disabled=True)
                    new_val = st.text_input("Suggested new value *")
                    notes = st.text_area("Notes / reason for change", placeholder="Optional: explain why this change is needed")

                    submitted_c = st.form_submit_button("Submit Suggestion 📤")
                    if submitted_c:
                        if not new_val.strip():
                            st.error("Please enter the new value.")
                        else:
                            try:
                                session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                                session.sql("""
                                    CREATE TABLE IF NOT EXISTS RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS (
                                        suggestion_id VARCHAR PRIMARY KEY,
                                        submitted_by VARCHAR,
                                        submission_type VARCHAR,
                                        company_name VARCHAR,
                                        field_name VARCHAR,
                                        old_value VARCHAR,
                                        new_value VARCHAR,
                                        notes VARCHAR,
                                        status VARCHAR DEFAULT 'pending',
                                        submitted_at TIMESTAMP,
                                        reviewed_at TIMESTAMP
                                    )
                                """).collect()
                                now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                                sid = str(uuid.uuid4())
                                session.sql(f"""
                                    INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                    (suggestion_id, submitted_by, submission_type, company_name,
                                     field_name, old_value, new_value, notes, status, submitted_at)
                                    VALUES
                                    ('{sid}',
                                     '{st.session_state.get("username")}',
                                     'Company Edit',
                                     {repr(c_selected)},
                                     {repr(field_to_edit)},
                                     {repr(old_val)},
                                     {repr(new_val.strip())},
                                     {repr(notes.strip()) if notes.strip() else 'NULL'},
                                     'pending', '{now}')
                                """).collect()
                                st.success("✅ Suggestion submitted! Jeremy will review it shortly.")
                            except Exception as e:
                                st.error(f"❌ Error submitting suggestion: {e}")

        # -------------------------
        # Contributor Sub-Tab 2: Suggest New Entry
        # -------------------------
        with c_tab2:
            st.markdown("#### Suggest a completely new company or funding round to add")
            with st.form("suggest_new_form"):
                new_type = st.selectbox("Type of entry", ["New Company", "New Funding Round"])
                new_co_name = st.text_input("Company Name *")
                new_field = st.text_input(
                    "Key detail *",
                    placeholder="For company: website URL. For funding round: e.g. Series A — $5M"
                )
                new_notes = st.text_area("Additional notes / source", placeholder="Where did you find this info?")

                submitted_new = st.form_submit_button("Submit Suggestion 📤")
                if submitted_new:
                    if not new_co_name.strip() or not new_field.strip():
                        st.error("Company Name and Key detail are required.")
                    else:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            session.sql("""
                                CREATE TABLE IF NOT EXISTS RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS (
                                    suggestion_id VARCHAR PRIMARY KEY,
                                    submitted_by VARCHAR,
                                    submission_type VARCHAR,
                                    company_name VARCHAR,
                                    field_name VARCHAR,
                                    old_value VARCHAR,
                                    new_value VARCHAR,
                                    notes VARCHAR,
                                    status VARCHAR DEFAULT 'pending',
                                    submitted_at TIMESTAMP,
                                    reviewed_at TIMESTAMP
                                )
                            """).collect()
                            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            sid = str(uuid.uuid4())
                            session.sql(f"""
                                INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                (suggestion_id, submitted_by, submission_type, company_name,
                                 field_name, old_value, new_value, notes, status, submitted_at)
                                VALUES
                                ('{sid}',
                                 '{st.session_state.get("username")}',
                                 {repr(new_type)},
                                 {repr(new_co_name.strip())},
                                 'new_entry',
                                 NULL,
                                 {repr(new_field.strip())},
                                 {repr(new_notes.strip()) if new_notes.strip() else 'NULL'},
                                 'pending', '{now}')
                            """).collect()
                            st.success("✅ Suggestion submitted! Jeremy will review it shortly.")
                        except Exception as e:
                            st.error(f"❌ Error submitting suggestion: {e}")






